from __future__ import annotations

import ast
import re

from ..context import GitError, GitHubUnavailable
from ..model import Finding, Rule, Status

RULES = []

# Rules that are part of the standard and are deliberately NOT implemented.
#
# Both resist automation for the same reason, and it is the reason the rules
# exist. GATE-001 asks whether a guard sits where everything passes through;
# answering it means searching for the underlying PRIMITIVE, not the facade
# the guard is written against -- and a checker that inspected the facade
# would be GATE-001's own bug wearing GATE-001's clothes. XKEY-001 asks
# whether two channels are INDEPENDENT; a checker cannot tell two genuinely
# separate resolution paths from two that both bottom out in the same one.
#
# A shallow proxy here would be worse than nothing: it would report green over
# exactly the condition the rule is about. They are documented review steps
# with exact search commands, named on every run so a clean report never
# implies they were checked.
HUMAN_ONLY = ("GATE-001", "XKEY-001")


def rule(rule_id, title, basis, pending_reason=""):
    def deco(fn):
        RULES.append(Rule(rule_id, title, basis, fn, pending_reason))
        return fn
    return deco


def ok(rid, detail, ev=""):
    return Finding(rid, Status.PASS, detail, ev)


def bad(rid, detail, ev=""):
    return Finding(rid, Status.FAIL, detail, ev)


def na(rid, detail):
    return Finding(rid, Status.NOT_APPLICABLE, detail)


def unknown(rid, detail):
    return Finding(rid, Status.UNCHECKABLE, detail)


def bad_or_excepted(ctx, rid, detail, ev=""):
    """A violation, downgraded to a visible EXCEPTION if one is recorded."""
    exc = ctx.exception_for(rid)
    if exc:
        return Finding(rid, Status.EXCEPTION,
                       f"{detail} -- excepted: {exc.get('reason', 'no reason recorded')} "
                       f"(decided by {exc.get('decided_by', '?')} on {exc.get('decided', '?')})",
                       ev)
    return bad(rid, detail, ev)


# ---------------------------------------------------------------- PROT-001
@rule("PROT-001", "Default branch is protected by something that is actually in force",
      basis="evidence")
def protected_default_branch(ctx):
    rid = "PROT-001"
    br = ctx.default_branch
    try:
        prot = ctx.github.branch_protection(br)
        rulesets = ctx.github.rulesets()
    except GitHubUnavailable as exc:
        return unknown(rid, f"could not read protection for {br}: {exc}")

    if prot:
        return ok(rid, f"classic branch protection present on {br}")

    # A ruleset counts only if it is enforcing AND its ref conditions actually
    # name something. An active ruleset with an empty include reports as
    # enforcing in the UI while protecting zero refs.
    live = []
    for rs in rulesets:
        if rs.get("enforcement") != "active":
            continue
        include = (rs.get("conditions", {})
                     .get("ref_name", {})
                     .get("include", []))
        if include:
            live.append(rs.get("name"))
        else:
            return bad(rid,
                       f"ruleset {rs.get('name')!r} is active but its ref include "
                       f"is empty: it enforces nothing on {br}",
                       ev="conditions.ref_name.include == []")
    if live:
        return ok(rid, f"{br} covered by active ruleset(s): {', '.join(map(str, live))}")
    return bad_or_excepted(ctx, rid,
                           f"{br} has neither branch protection nor an enforcing ruleset")


# ---------------------------------------------------------------- CI-001
@rule("CI-001", "A bare branch push triggers CI", basis="evidence")
def ci_fires_on_push(ctx):
    rid = "CI-001"
    import yaml
    wf = list(ctx.glob("*.yml")) + list(ctx.glob("*.yaml"))
    wf = [p for p in wf if ".github/workflows" in str(p)]
    if not wf:
        return bad(rid, "no workflows under .github/workflows: nothing can fire")

    for p in wf:
        try:
            doc = yaml.safe_load(p.read_text()) or {}
        except Exception as exc:
            return unknown(rid, f"{p.name} is not parseable YAML: {exc}")
        # PyYAML resolves a bare `on:` key to the boolean True.
        trig = doc.get("on", doc.get(True))
        if trig is None:
            continue
        if isinstance(trig, str):
            trig = {trig: None}
        if isinstance(trig, list):
            trig = {k: None for k in trig}
        if "push" not in trig:
            continue
        spec = trig["push"]
        # `push:` with no filter fires on every branch. A push block that
        # filters to tags only does not measure a branch push.
        if spec is None:
            return ok(rid, f"{p.name} triggers on unfiltered push")
        if isinstance(spec, dict) and not spec.get("tags") and not spec.get("tags-ignore"):
            return ok(rid, f"{p.name} triggers on push ({sorted(spec)})")
    return bad(rid,
               "no workflow triggers on a branch push; only PR or dispatch. "
               "A bare push measures nothing.")


# ---------------------------------------------------------------- CI-002
@rule("CI-002", "CI has actually run at least once", basis="evidence")
def ci_has_run(ctx):
    rid = "CI-002"
    try:
        if ctx.github.workflow_runs_exist():
            return ok(rid, "workflow runs present in the API")
    except GitHubUnavailable as exc:
        return unknown(rid, f"could not list workflow runs: {exc}")
    return bad(rid, "zero workflow runs in the API: a run that is not there never happened")


# ---------------------------------------------------------------- GUARD-001
@rule("GUARD-001", "Structured files are checked by parsing, not substring matching",
      basis="evidence")
def guards_parse_not_grep(ctx):
    rid = "GUARD-001"
    scripts = [p for p in ctx.glob("*.py") if "/scripts/" in "/" + str(p.relative_to(ctx.root))]
    if not scripts:
        return na(rid, "no scripts/*.py guards in this repo")

    # The failure mode: deciding something about a plist/JSON/YAML document by
    # testing whether independent substrings appear anywhere in its text. Two
    # such tests are satisfiable by two unrelated places in the file.
    struct_ext = re.compile(r"\.(xcprivacy|plist|json|ya?ml|entitlements)\b")
    offenders = []
    for p in scripts:
        for i, line in enumerate(p.read_text(errors="replace").splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            if not re.search(r"\b(in|not in)\b", line):
                continue
            if "<key>" not in line and not struct_ext.search(line):
                continue
            if re.search(r'"<[^"]+>"\s+(not\s+)?in\b', line) or "<key>" in line:
                offenders.append(f"{p.relative_to(ctx.root)}:{i}: {line.strip()[:90]}")
    if offenders:
        return bad(rid,
                   f"{len(offenders)} guard line(s) decide a structured document by substring",
                   ev="\n".join(offenders[:5]))
    return ok(rid, f"no substring-matching guards across {len(scripts)} script(s)")


# ---------------------------------------------------------------- PRIV-001
@rule("PRIV-001", "Every shipped privacy manifest declares no tracking",
      basis="speculative")
def privacy_manifests_no_tracking(ctx):
    rid = "PRIV-001"
    mans = list(ctx.glob("PrivacyInfo.xcprivacy"))
    if not mans:
        return na(rid, "no privacy manifests in this repo")
    bad_ones = []
    for p in mans:
        rel = p.relative_to(ctx.root)
        try:
            d = ctx.read_plist(rel)
        except Exception as exc:
            return unknown(rid, f"{rel} is not a readable plist: {exc}")
        if d.get("NSPrivacyTracking") is not False:
            bad_ones.append(f"{rel}: NSPrivacyTracking={d.get('NSPrivacyTracking')!r}")
        if d.get("NSPrivacyTrackingDomains", []) != []:
            bad_ones.append(f"{rel}: tracking domains {d.get('NSPrivacyTrackingDomains')!r}")
    if bad_ones:
        return bad(rid, f"{len(bad_ones)} manifest violation(s)", ev="\n".join(bad_ones))
    return ok(rid, f"{len(mans)} manifest(s) declare NSPrivacyTracking=false, no domains")


# ---------------------------------------------------------------- PRIV-002
@rule("PRIV-002", "The manifest guard covers every manifest that exists", basis="evidence")
def privacy_guard_covers_all(ctx):
    rid = "PRIV-002"
    mans = {str(p.relative_to(ctx.root)) for p in ctx.glob("PrivacyInfo.xcprivacy")}
    if not mans:
        return na(rid, "no privacy manifests in this repo")
    scripts = [p for p in ctx.glob("*.py") if "/scripts/" in "/" + str(p.relative_to(ctx.root))]
    if not scripts:
        return bad(rid, f"{len(mans)} manifest(s) exist but no guard script checks any of them",
                   ev="\n".join(sorted(mans)))
    blob = "\n".join(p.read_text(errors="replace") for p in scripts)
    missing = sorted(m for m in mans if m not in blob)
    if missing:
        return bad(rid,
                   f"{len(missing)} of {len(mans)} manifest(s) are in no guard list",
                   ev="\n".join(missing))
    return ok(rid, f"all {len(mans)} manifest(s) named in a guard")


# ---------------------------------------------------------------- BRANCH-001
@rule("BRANCH-001", "No branch is ahead of the default branch without an open PR",
      basis="evidence")
def no_stranded_branches(ctx):
    rid = "BRANCH-001"
    # This rule genuinely needs history and remote refs, so it says so rather
    # than assuming a default. In a shallow or ref-less checkout it would
    # otherwise iterate zero branches and report "no stranded branches" --
    # green, having looked at nothing.
    if ctx.git("rev-parse", "--is-shallow-repository") == "true":
        return unknown(rid, "shallow clone: cannot compare branches. "
                            "This rule requires fetch-depth: 0")
    refs = ctx.git("branch", "-r", "--format=%(refname:short)").splitlines()
    base = f"origin/{ctx.default_branch}"
    if base not in [r.strip() for r in refs]:
        return unknown(rid, f"{base} is not present in this checkout: cannot "
                            f"determine what is ahead of it. Requires fetch-depth: 0")
    try:
        prs = ctx.github.open_pr_head_refs()
    except GitHubUnavailable as exc:
        return unknown(rid, f"could not list open PRs: {exc}")
    stranded = []
    for r in refs:
        r = r.strip()
        if not r or "HEAD" in r or r == f"origin/{ctx.default_branch}":
            continue
        # A remote ref is "<remote>/<branch>"; anything without a slash is not
        # one (a stray ref, a remote with no branch) and has no PR head to
        # match against.
        if "/" not in r:
            continue
        name = r.split("/", 1)[1]
        n = ctx.git("rev-list", "--count", f"origin/{ctx.default_branch}..{r}")
        if not (n.isdigit() and int(n) > 0) or name in prs:
            continue
        # Ahead in commits is not the same as carrying unmerged work: a
        # squash-merged branch keeps its original commits, which are not
        # ancestors of the default branch.
        #
        # The test is whether merging the branch would change the default
        # branch at all. A diff does not answer this -- two-dot is symmetric
        # and also reports what the default branch gained afterwards, and
        # three-dot still shows content that reached it via squash.
        #
        # Conservative by design: a branch that conflicts is reported, even if
        # its unique content is already upstream, because "cannot be merged
        # cleanly" is itself worth surfacing.
        if ctx.merge_is_noop(r):
            continue
        stranded.append((int(n), name))
    if stranded:
        stranded.sort(reverse=True)
        return bad(rid, f"{len(stranded)} branch(es) ahead of {ctx.default_branch} with no open PR",
                   ev="\n".join(f"{n:>4} commits ahead: {b}" for n, b in stranded[:10]))
    return ok(rid, f"every branch ahead of {ctx.default_branch} has an open PR")


# ---------------------------------------------------------------- PLIST-001
@rule("PLIST-001", "Info.plist mechanism is uniform within a project", basis="evidence")
def infoplist_mechanism_uniform(ctx):
    rid = "PLIST-001"
    projs = list(ctx.glob("project.pbxproj"))
    if not projs:
        return na(rid, "no Xcode project in this repo")
    out = []
    for p in projs:
        txt = p.read_text(errors="replace")
        gen = len(re.findall(r"GENERATE_INFOPLIST_FILE = YES", txt))
        filed = len(re.findall(r"^\s*INFOPLIST_FILE = ", txt, re.M))
        if gen and filed:
            out.append(f"{p.relative_to(ctx.root)}: {gen} generated + {filed} file-based")
    if out:
        return bad(rid, "project mixes generated and file-based Info.plists", ev="\n".join(out))
    return ok(rid, "Info.plist mechanism is consistent")


# ---------------------------------------------------------------- SWIFT-001
@rule("SWIFT-001", "Swift language mode is declared and uniform", basis="evidence")
def swift_mode_uniform(ctx):
    rid = "SWIFT-001"
    projs = list(ctx.glob("project.pbxproj"))
    if not projs:
        return na(rid, "no Xcode project in this repo")
    versions = set()
    for p in projs:
        versions |= set(re.findall(r"SWIFT_VERSION = ([^;]+);", p.read_text(errors="replace")))
    if not versions:
        return bad(rid, "no SWIFT_VERSION declared anywhere: the mode is whatever Xcode defaults to")
    if len(versions) > 1:
        return bad(rid, f"targets disagree on Swift version: {sorted(versions)}")
    return ok(rid, f"single Swift version declared: {versions.pop()}")


# ---------------------------------------------------------------- BUNDLE-001
@rule("BUNDLE-001", "One bundle identifier per app across platforms", basis="evidence")
def one_bundle_id_per_app(ctx):
    rid = "BUNDLE-001"
    projs = list(ctx.glob("project.pbxproj"))
    if not projs:
        return na(rid, "no Xcode project in this repo")
    ids = set()
    for p in projs:
        ids |= set(re.findall(r"PRODUCT_BUNDLE_IDENTIFIER = ([^;]+);",
                              p.read_text(errors="replace")))
    # Extensions, widgets, watch apps and test bundles legitimately carry their
    # own child identifiers. Only app-level identifiers are in scope.
    child = re.compile(r"\.(Widgets|LiveActivity|watchkitapp|Tests|UITests)$"
                       r"|(Tests|UITests)$")
    apps = {i.strip() for i in ids if not child.search(i.strip())}

    # A per-platform or per-device-class identifier is a sibling of the app's
    # own identifier, distinguished only by a platform/device suffix.
    suffix = re.compile(r"[.\-]?(mac|macos|tv|tvos|vision|visionos|pad|ipad|phone|iphone|watch)$",
                        re.I)
    offenders = {}
    for i in apps:
        base = suffix.sub("", i)
        if base != i and (base in apps or any(a != i and a.startswith(base) for a in apps)):
            offenders.setdefault(base, set()).add(i)
        elif base != i:
            # A per-device-class registration with no surviving sibling is
            # still a separate record and a separate listing.
            offenders.setdefault(base, set()).add(i)
    if offenders:
        ev = "\n".join(f"{b}: {', '.join(sorted(v))}" for b, v in sorted(offenders.items()))
        return bad_or_excepted(ctx, rid,
                               f"{sum(len(v) for v in offenders.values())} per-platform/"
                               f"per-device identifier(s): one App Store record each",
                               ev=ev)
    return ok(rid, f"one identifier per app: {', '.join(sorted(apps)) or 'none declared'}")


# ---------------------------------------------------------------- DECIDE-001
@rule("DECIDE-001", "Decisions are recorded in a doc that lands on the default branch",
      basis="evidence")
def decisions_recorded(ctx):
    """Reads the WORKING TREE, deliberately -- not `main` at HEAD.

    The question is "will this hold after merge?", and on a PR that is the
    merge result, which is what is checked out. Reading `main` at HEAD would
    fail the very PR that adds the decision doc -- punishing the change that
    fixes the violation, which trains everyone to ignore the rule.

    Reading the working tree is also structurally incapable of the
    missing-ref failure: no `git show`, no ref resolution, no dependency on a
    local default branch existing. Correct on a PR, on a push, and on a
    shallow detached checkout alike.
    """
    rid = "DECIDE-001"
    files = ctx.tracked_files()          # raises GitError -> ERROR, never a skip
    log = re.compile(r"(DECISIONS|ADR|decisions?)[^/]*\.md$|/adr/|(^|/)docs/decisions/", re.I)
    found = sorted(f for f in files if log.search(f))
    if not found:
        return bad(rid, "no decision log tracked: a determination that lives only "
                        "in a chat session or on an unmerged branch is not recorded")
    incomplete = []
    for f in found:
        try:
            body = ctx.read_text(f)
        except OSError as exc:
            # Tracked but unreadable is an unreadable input, not "no decision".
            return unknown(rid, f"{f} is tracked but could not be read: {exc}")
        if re.search(r"decided[ -]?by", body, re.I) and re.search(r"\d{4}-\d{2}-\d{2}", body):
            return ok(rid, f"decision log records who and when: {f}")
        incomplete.append(f)
    return bad(rid, "decision log(s) tracked but none record who decided and when",
               ev="\n".join(incomplete))


# ---------------------------------------------------------------- OUT-001
@rule("OUT-001", "Conformance output is not published", basis="evidence")
def conformance_output_not_public(ctx):
    """Working tree, not `main` at HEAD.

    Same reasoning as DECIDE-001 inverted: a PR that ADDS a gap report must be
    caught here, not excused because main happens to be clean.
    """
    rid = "OUT-001"
    report = re.compile(r"(CONFORMANCE|gap[-_]?report|conformance[-_]?report)", re.I)
    committed = sorted(f for f in ctx.tracked_files() if report.search(f))
    if committed:
        return bad(rid, f"{len(committed)} conformance report(s) tracked",
                   ev="\n".join(committed))

    # A public workflow must not emit another repo's conformance results.
    leaks = []
    for p in ctx.glob("*.yml"):
        if ".github/workflows" not in str(p):
            continue
        for i, line in enumerate(p.read_text(errors="replace").splitlines(), 1):
            if "conform" not in line or line.lstrip().startswith("#"):
                continue
            m = re.search(r"-m\s+conform\s+(\S+)", line)
            if m and m.group(1) not in (".", "${{", "$GITHUB_WORKSPACE"):
                leaks.append(f"{p.name}:{i}: checks {m.group(1)}, not this repo")
    if leaks:
        return bad(rid, "workflow emits conformance output for another repo",
                   ev="\n".join(leaks))
    return ok(rid, "no conformance report tracked; CI checks only this repo")


# ================================================================= IDKEY-001
#
# Invariance mismatch: a lookup key that is not invariant under the
# transformations the system applies to the thing it identifies.
#
# For a key K identifying an entity E, enumerate the transformations T the
# system performs on E. K is sound iff K(T(E)) == K(E) for every T. A path
# component fails this the moment anything copies, re-roots, stages, archives
# or re-runs the artifact into a differently named directory -- and it fails
# SILENTLY, resolving to a real-looking wrong identity instead of raising.
# That is what makes the class dangerous: a bad key does not error, it
# succeeds against the wrong entity.

# Names that mean "this variable is an identity", not merely a label.
_ID_NAME = re.compile(
    r"^(_*)(pdb|pid|uid|rid|sid|key|id|ident|identifier|"
    r"[a-z0-9]+_(id|ids|key|uuid|slug|code)|"
    r"(pdb|target|ligand|receptor|entry|record|sample|run|job|case)(_?(id|name|code))?)$",
    re.I)

# Keys a record uses to carry its own explicit identity.
_ID_KEY = re.compile(r"^(id|uuid|slug|code|[a-z0-9_]*_(id|uuid|slug|code)|"
                     r"(pdb|target|ligand|receptor|entry|sample|run|job|case)_?id)$", re.I)

# Files that ARE records: if you are standing on one of these, it carries the
# identity and the directory around it does not have to.
_RECORD_FILE = re.compile(r"\.(csv|tsv|json|jsonl|ya?ml|parquet|sdf|xml)\b", re.I)
_RECORD_READER = ("DictReader", "read_csv", "read_json", "read_parquet",
                  "safe_load", "load", "loads")


def _path_component_expr(node):
    """Describe node if it derives a value from a PATH COMPONENT, else None.

    Three idioms, all of them observed live:
      os.path.basename(os.path.dirname(p))   -- the containing directory's name
      p.parent.name / p.parents[n].name      -- same, pathlib
      str(p).split("/")[-2]                  -- same, by hand
    """
    # <expr>.parent.name  /  <expr>.parents[i].name
    if isinstance(node, ast.Attribute) and node.attr == "name":
        inner = node.value
        if isinstance(inner, ast.Subscript):
            inner = inner.value
        if isinstance(inner, ast.Attribute) and inner.attr in ("parent", "parents"):
            return f".{inner.attr}.name"
    if isinstance(node, ast.Call):
        fn = node.func
        fname = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
        # basename(dirname(x)) -- basename(x) alone names the FILE, which is a
        # different (and often legitimate) thing, so only the nested form counts.
        if fname == "basename" and node.args:
            a0 = node.args[0]
            if isinstance(a0, ast.Call):
                inner = a0.func
                iname = inner.attr if isinstance(inner, ast.Attribute) else getattr(inner, "id", "")
                if iname == "dirname":
                    return "os.path.basename(os.path.dirname(...))"
    # split("/")[-2] and friends: an index into path components.
    if isinstance(node, ast.Subscript):
        val = node.value
        if isinstance(val, ast.Call) and isinstance(val.func, ast.Attribute) \
                and val.func.attr == "split" and val.args \
                and isinstance(val.args[0], ast.Constant) and val.args[0].value in ("/", "\\"):
            return "split('/')[...]"
        if isinstance(val, ast.Attribute) and val.attr == "parts":
            return ".parts[...]"
    return None


def _record_lookup(node):
    """True if node reads an explicit ID field out of a record."""
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute) \
                and sub.func.attr == "get" and sub.args \
                and isinstance(sub.args[0], ast.Constant) \
                and isinstance(sub.args[0].value, str) and _ID_KEY.match(sub.args[0].value):
            return True
        if isinstance(sub, ast.Subscript) and isinstance(sub.slice, ast.Constant) \
                and isinstance(sub.slice.value, str) and _ID_KEY.match(sub.slice.value):
            return True
    return False


def _record_in_scope(scope):
    """Is an explicit-ID-carrying record available where this key was derived?

    Either the scope reads an ID field off a record somewhere (so the records
    demonstrably carry one), or it iterates/parses record files (so one is
    there to be read). Without this the rule would flag every legitimate use
    of a directory name -- when there is genuinely no record, a path component
    may be the only identity available, and that is not this bug.
    """
    for sub in ast.walk(scope):
        if _record_lookup(sub):
            return "a record field carrying an explicit ID is read in this scope"
        if isinstance(sub, ast.Call):
            fn = sub.func
            fname = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
            if fname in _RECORD_READER:
                return f"this scope parses records ({fname})"
        if isinstance(sub, ast.Constant) and isinstance(sub.value, str) \
                and _RECORD_FILE.search(sub.value):
            return f"this scope iterates record files ({sub.value!r})"
    return None


def _scan_identity_from_location(src, path_label):
    """Yield (line, name, idiom, why) for every identity derived from a path."""
    tree = ast.parse(src, filename=path_label)
    scopes = [n for n in ast.walk(tree)
              if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module))]
    # A site inside a function is reachable from the module scope too; report
    # it once. Keyed by (line, name) -- one source line is one site.
    seen = set()
    for scope in scopes:
        why = _record_in_scope(scope)
        if not why:
            continue
        for node in ast.walk(scope):
            # Only this scope's own statements -- a nested def is its own scope
            # and gets visited on its own pass.
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                value = node.value
            elif isinstance(node, ast.keyword) and node.arg and _ID_KEY.match(node.arg):
                targets, value = [ast.Name(id=node.arg)], node.value
            elif isinstance(node, ast.Dict):
                for k, v in zip(node.keys, node.values):
                    if isinstance(k, ast.Constant) and isinstance(k.value, str) \
                            and _ID_KEY.match(k.value) and not _record_lookup(v):
                        for sub in ast.walk(v):
                            idiom = _path_component_expr(sub)
                            if idiom:
                                site = (getattr(v, "lineno", k.lineno), k.value)
                                if site not in seen:
                                    seen.add(site)
                                    yield (*site, idiom, why)
                                break
                continue
            else:
                continue
            if value is None:
                continue
            names = [t.id for t in targets if isinstance(t, ast.Name)]
            if not any(_ID_NAME.match(n) for n in names):
                continue
            # `rec.get("pdb_id") or csv_path.parent.name` -- the record is the
            # key, the path is a last-resort fallback. That is the CORRECT
            # idiom, live in this ecosystem, and it must not be flagged.
            if _record_lookup(value):
                continue
            for sub in ast.walk(value):
                idiom = _path_component_expr(sub)
                if idiom:
                    site = (node.lineno, names[0])
                    if site not in seen:
                        seen.add(site)
                        yield (*site, idiom, why)
                    break


@rule("IDKEY-001", "An identity is not derived from a path component when the "
                   "record carries an explicit ID", basis="evidence")
def identity_not_derived_from_location(ctx):
    rid = "IDKEY-001"
    sources = [p for p in ctx.glob("*.py")]
    if not sources:
        return na(rid, "no Python sources in this repo")

    hits, unread = [], []
    for p in sources:
        rel = str(p.relative_to(ctx.root))
        try:
            src = p.read_text(errors="replace")
        except OSError as exc:
            unread.append(f"{rel}: could not be read: {exc}")
            continue
        try:
            found = list(_scan_identity_from_location(src, rel))
        except SyntaxError as exc:
            # A file this checker cannot parse is a file it did not check.
            # Recorded, never silently skipped -- but it does not erase the
            # files that WERE checked. Returning UNCHECKABLE for the whole rule
            # here let one unparseable vendored test file hide five live
            # violations in the same repo, which is the same shape of bug the
            # rule is about: an unrelated property deciding the answer.
            unread.append(f"{rel}: not parseable Python: {exc}")
            continue
        for line, name, idiom, why in found:
            hits.append(f"{rel}:{line}: {name} = {idiom} -- {why}")

    tail = ([f"-- {len(unread)} file(s) NOT CHECKED (unreadable/unparseable):"]
            + unread) if unread else []

    if hits:
        # A FAIL that also names what could not be parsed: loud about the
        # violations AND about the coverage gap. Both, never one at the cost
        # of the other.
        return bad_or_excepted(
            ctx, rid,
            f"{len(hits)} identity/identities derived from a path component while "
            f"a record carrying an explicit ID is in scope; a re-rooted, copied or "
            f"re-staged artifact resolves to the wrong entity without erroring"
            + (f" [{len(unread)} further file(s) could not be parsed]" if unread else ""),
            ev="\n".join(hits + tail))
    if unread:
        # No violations among the files that parsed -- but the rule did not
        # see every file, so this is not a pass.
        return Finding(
            rid, Status.UNCHECKABLE,
            f"no violation in {len(sources) - len(unread)} file(s), but "
            f"{len(unread)} file(s) could not be parsed and were not checked",
            "\n".join(unread))
    return ok(rid, f"no identity derived from a path component ({len(sources)} file(s) parsed)")
