from __future__ import annotations

import re

from ..context import GitError, GitHubUnavailable
from ..model import Finding, Rule, Status

RULES = []


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
