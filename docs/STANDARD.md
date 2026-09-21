# The repo standard

Fifteen rules. Each one exists because something in this ecosystem actually drifted,
not because a style guide recommends it. Every rule is checked by parsing
structure — never by matching substrings in a file's text, which is the specific
bug that made the previous generation of guards unable to fail.

**Scope of this pass: infrastructure only.** Design tokens, palette and
typography are deliberately out. The v2/v3 canonical contradiction is
unresolved, and uniformizing onto the wrong canonical is worse than the drift.

| ID | Rule | Basis |
|---|---|---|
| PROT-001 | Default branch is protected by something actually in force | evidence |
| CI-001 | A bare branch push triggers CI | evidence |
| CI-002 | CI has actually run at least once | evidence |
| GUARD-001 | Structured files are checked by parsing, not substring matching | evidence |
| PRIV-001 | Every shipped privacy manifest declares no tracking | evidence |
| PRIV-002 | The manifest guard covers every manifest that exists | evidence |
| BRANCH-001 | No branch ahead of default without an open PR | evidence |
| PLIST-001 | Info.plist mechanism is uniform within a project | evidence |
| SWIFT-001 | Swift language mode is declared and uniform | evidence |
| BUNDLE-001 | One bundle identifier per app across platforms | evidence |
| DECIDE-001 | Decisions are recorded on the default branch | evidence |
| OUT-001 | Conformance output is not published | evidence |
| IDKEY-001 | An identity is not derived from a path component | evidence |
| GATE-001 | A capability guard sits at the narrowest waist | evidence, **human-checked** |
| XKEY-001 | Two independent keys are read and asserted to agree | evidence, **human-checked** |

**Thirteen mechanically checked, two not.** `DOCS-001` was dropped — see *Rules
deliberately left out*.

## Mechanically enforced vs. documented-only

This split is part of the standard, not a caveat on it.

**Mechanically enforced (13).** PROT-001, CI-001, CI-002, GUARD-001, PRIV-001,
PRIV-002, BRANCH-001, PLIST-001, SWIFT-001, BUNDLE-001, DECIDE-001, OUT-001,
**IDKEY-001**. The checker runs them; `fixtures/prove.py` proves each fires red
before its green means anything.

**Documented-only, human review required (2).** **GATE-001** and **XKEY-001**.
There is no code for these. `conform` prints them as `NOT CHECKED` on every
run, including a clean one, so a green report never implies they were examined.

They are not automated because automating them shallowly would reproduce the
very bug each one describes:

- A GATE-001 checker that confirmed the façade was guarded would be looking at
  the façade — which is precisely GATE-001's failure mode. It would report
  green over the bypass. In *this* repo, shipping that would be the worst
  available outcome: a check that cannot fail, inside the standard that exists
  to eliminate checks that cannot fail.
- An XKEY-001 checker can see that two reads happen. It cannot see that they
  are **independent**. Two channels that both bottom out in the same resolver
  agree perfectly and verify nothing, which has already happened here.

Each is shipped below with the exact commands a reviewer runs. A rule a human
performs with a written procedure is enforcement; a rule a machine performs
against the wrong object is theatre.

## The central invariant

**An unreadable input is a failure, never a skip.** No bare `except: pass`, no
`if not found: return ok`, no defaulting to conforming. A read that fails raises;
`Context.git()` raises `GitError` rather than returning `""`, because a rule that
cannot distinguish "no output" from "the command failed" will eventually report
one as the other. Both happened here — see *Reading the default branch*.

Five statuses are non-green: `FAIL`, `UNCHECKABLE` (inputs unreadable),
`ERROR` (the rule itself raised), `EXCEPTION` and `PENDING`. `--allow-unchecked`
tolerates `UNCHECKABLE` only; an `ERROR` fails the run regardless, because if a
crashing rule could be tolerated then every rule is potentially a check that
cannot fail and none of the others mean anything. `fixtures/prove.py` injects a
deliberate exception on every run and asserts the run goes red.

## Reading the default branch

Rules that ask "is this recorded?" read the **working tree**, not a ref.

On a pull request the working tree is the merge result, which is what the
question actually means: *will this hold after merge?* Reading `main` at HEAD
would fail the very PR that adds the decision doc — punishing the change that
fixes the violation. It is also structurally incapable of the missing-ref
failure: a CI checkout of a PR branch is shallow and detached, with no local
`main`.

A rule that genuinely needs history says so. `BRANCH-001` refuses to run on a
shallow clone and reports `UNCHECKABLE` naming `fetch-depth: 0`, rather than
iterating zero branches and reporting green having looked at nothing.

`PRIV-001` is marked **speculative**: it is implemented and provable, but no
repo scanned actually violates it. Every other rule has a live violation behind
it.

## Provenance

Every claim below was re-verified against the repos on 2026-09-21 (local date,
from `date`, not a UTC timestamp). Four items from the original brief did **not**
survive that check and were corrected or dropped; they are marked *Corrected*
where they appear. A standard built on a stale observation enforces the wrong
thing, confidently.

---

## PROT-001 — Default branch is protected by something actually in force

**Asserts.** The default branch is covered either by classic branch protection,
or by a ruleset that is `active` *and* whose `conditions.ref_name.include` is
non-empty.

**Checked by.** Reading `branches/{branch}/protection` and every entry of
`repos/{slug}/rulesets` through the API, and inspecting the include list as a
list. The empty-include case is called out separately because it is the
dangerous one: the UI reports the ruleset as enforcing while it governs no refs.

**Observed violation.** 4 of 68 repos gate their default branch: `NRGsuite`
(classic, on `master`), `repo-standard` (classic), and
`SymphonyInstrumentAnalysis` and `lebonhommepharma.github.io` (active rulesets
on `~DEFAULT_BRANCH`, requiring PR and status checks). One more, `FlexAIDdS`,
has an active ruleset with an empty include. The remaining 63 have nothing.

**Corrected twice — both times my own scan, not the repos.**

1. The first scan reported *0 of 67*. It assumed every repo's default branch was
   `main`. In fact 46 use `main`, 17 `master`, 2 `develop`, 2 `Bonhomme`, and one
   has none — so for 22 repos it queried protection on a branch that does not
   exist and read the 404 as "unprotected".
2. The second reported *1 of 68*. It queried only
   `branches/{branch}/protection`, which returns 404 **even when a ruleset
   protects the branch**. Two repos protected by ruleset were counted as
   unprotected.

Both were false findings dressed as real ones, and both are the exact failure
this standard exists to prevent. The checker itself was right about these two
repos from the start — it consults rulesets as well as classic protection, and
resolves the default branch before asking. The hand-rolled account scan did
neither. That is the argument for the tool over the ad-hoc query, made at my own
expense.

**Account shape.** `LeBonhommePharma` is a **User account on the free plan**,
not an organization. 57 repos public, 11 private. Public repos can be protected
for free; private repos on this plan cannot be protected at all — both classic
protection and rulesets return HTTP 403.

**Observed violation (empty include).** `LeBonhommePharma/FlexAIDdS` carries a
ruleset named `Protected: branch`, `enforcement: active`, rules `deletion` and
`non_fast_forward` — and `conditions.ref_name.include == []`. It reports as
enforcing and governs no refs. The name is the most misleading part.

**Evidence note.** The empty-include ruleset was originally reported on
*NATURaL*. That is **not reproducible**: `repos/LeBonhommePharma/NATURaL/rulesets`
returns `[]`. The pattern is real, but it is on FlexAIDdS, not NATURaL.

---

## CI-001 — A bare branch push triggers CI

**Asserts.** At least one workflow has a `push` trigger that is unfiltered, or
filtered by branch rather than exclusively by tag. A workflow that fires only on
`pull_request` or `workflow_dispatch` does not measure a branch push.

**Checked by.** Parsing each workflow with `yaml.safe_load` and inspecting the
trigger mapping. Note that PyYAML resolves a bare `on:` key to the boolean
`True`, which is why the checker looks under both `"on"` and `True` — a
substring search for `on: push` would miss the common formatting.

**Observed violation.** Ten repos have no `.github/workflows` at all, so
nothing can fire: BonhommeNotch, DP, FindBon, FlexAID, GetCleft, Get_Cleft,
HatchPet, LosslessSwitcher, MonteCarlo, NRGsuite.

**Corrected.** The brief's claim that a bare branch push fires nothing did not
hold. **NATURaL passes this rule** — `.github/workflows/ci.yml` carries an
unfiltered `push:`.

---

## CI-002 — CI has actually run at least once

**Asserts.** `actions/runs` reports a non-zero `total_count`.

**Checked by.** API read. A configured workflow that has never produced a run is
a claim, not a measurement.

---

## GUARD-001 — Structured files are checked by parsing, not substring matching

**Asserts.** No guard script decides a property of a plist, JSON, YAML or
entitlements document by testing whether substrings appear anywhere in its text.

**Checked by.** Scanning `scripts/*.py` for membership tests (`in` / `not in`)
whose operand is an XML key literal or a structured-file path. Comment lines are
skipped, so a file may document the old bug without reintroducing it.

**Observed violation (live).** `ClusterFuck/scripts/mutation_harness.py:12-13`
decides whether a watch Info.plist declares `WKApplication` by testing for two
hard-coded whitespace spellings of the same XML — tab-indented and
space-indented — neither of which is a property of the parsed document.

**Known false positive.** The rule also flags
`ClusterFuck/scripts/test_mutation_harness.py:141`, where the substring test is
*inside a quoted string* used as input to the harness's own test. The checker
skips comment lines but does not parse Python string literals, so guard-shaped
text inside test data reads as a guard. Two of ClusterFuck's three hits are
genuine; one is this. Recorded rather than tuned away, because narrowing the
rule to avoid it would risk missing real single-line guards.

**Observed violation (historical).** NATURaL's manifest guard formerly tested
`"<key>NSPrivacyTracking</key>" in text and "<false/>" in text`. Those are two
independent substrings: a manifest declaring tracking **true** passed as long as
any other key in the file was false. Fixed in flight (the guard now uses
`plistlib`); the file retains the bug as a comment at
`scripts/test_contracts.py:661`.

---

## PRIV-001 — Every shipped privacy manifest declares no tracking

**Asserts.** For each `PrivacyInfo.xcprivacy`: `NSPrivacyTracking is False` and
`NSPrivacyTrackingDomains == []`.

**Checked by.** `plistlib.load`, then identity and equality on parsed values.
`is not False` rather than a truthiness test, so a missing key fails rather than
passing as falsy.

---

## PRIV-002 — The manifest guard covers every manifest that exists

**Asserts.** Every `PrivacyInfo.xcprivacy` in the source tree is named by some
guard script. A guard that checks a hand-maintained list silently stops covering
anything added after the list was written.

**Observed violation.** `ShannonUI` ships two privacy manifests and has no
guard script checking any of them.

**Corrected — the NATURaL/BonhommeMac claim was wrong, and it was my error.**
NATURaL's guard loop at `scripts/test_contracts.py:652-658` does name only seven
of its eight manifests, but `BonhommeMac/PrivacyInfo.xcprivacy` *is* checked —
at `scripts/validate-submission.py:216`, with `plistlib`. I asserted it was "in
neither the loop nor any other check" after reading one file. NATURaL passes
this rule.

**Note.** Build output is excluded from the scan — `.build/`, `build/`,
`DerivedData`, `Pods/` — so copies of a manifest inside a compiled bundle do not
count as separate manifests needing guards.

---

## BRANCH-001 — No branch ahead of default without an open PR

**Asserts.** Every remote branch with commits not on the default branch has an
open PR.

**Checked by.** `git rev-list --count origin/main..<ref>` per remote branch,
against the set of open PR head refs. Counting commits catches *additive* edits
to files that already exist on `main` — invisible to a missing-file search.

**Requires full history.** On a shallow clone, or one without
`origin/<default>`, this rule reports `UNCHECKABLE` naming `fetch-depth: 0`. It
does not iterate zero branches and call that green.

**A silent pass lived here.** Before `git()` raised, `git branch -r` failing
returned `""`, the loop ran zero times, and the rule reported
`PASS: "every branch ahead of main has an open PR"` — in a directory that was
not a git repository at all. That is the check-that-cannot-fail this whole repo
exists to eliminate, shipped inside it.

**Observed violation.** 2026-09-21: FlexAIDdS 343 stranded branches, NATURaL 17
(including `claude/pose-accent-ramp-brand-arc` at 40 commits and
`codex/app-store-native-refinement-20260919` at 34), Shannon 5, Transit 4,
BonhommeNotch 3, ClusterFuck 1.

**Implementation note.** `refs/remotes/origin/HEAD` shortens to a bare `origin`
with no `<remote>/<branch>` slash, which made the first version of this rule
raise `IndexError`. It reported `UNCHECKABLE`, not `PASS` — which is the whole
reason that status exists. Fixed, with the bare ref added to the fixture.

---

## PLIST-001 — Info.plist mechanism is uniform within a project

**Asserts.** A project does not mix `GENERATE_INFOPLIST_FILE = YES` targets with
`INFOPLIST_FILE = ` targets.

**Observed violation.** NATURaL: 4 generated, 32 file-based, in one pbxproj.

---

## SWIFT-001 — Swift language mode is declared and uniform

**Asserts.** `SWIFT_VERSION` is declared, and all targets agree.

**Observed violation.** `DP` declares no `SWIFT_VERSION` anywhere: its language
mode is whatever Xcode currently defaults to, which changes across releases.
NATURaL declares `5.0` uniformly and passes.

---

## BUNDLE-001 — One bundle identifier per app across platforms

**Asserts.** One identifier per app across iOS, macOS, tvOS and visionOS.
Per-platform and per-device-class identifiers are a violation. Extensions,
widgets, Live Activities, watch apps and test bundles keep their own child
identifiers and are excluded.

**Decided by LP, 2026-09-21** (local date, from `date`). Recorded in
[DECISIONS.md](DECISIONS.md). **Rationale:** consolidated ratings and review
counts rather than split four ways; cross-platform purchase for the user; one
submission per update instead of four independent trips through review.

**No longer pending.** This rule was held PENDING and applied to nothing until
the App Store Connect rules for sharing a single record across platforms were
confirmed. That verification came back, so the rule is now applied.

**Checked by.** Extracting every `PRODUCT_BUNDLE_IDENTIFIER` from the pbxproj,
dropping child bundles, and testing whether any remaining identifier is another
one plus a platform or device-class suffix (`mac`, `tv`, `vision`, `pad`,
`phone`, `watch`, …).

**Observed violation.** NATURaL: `com.natural.BonhommeTV`,
`com.natural.BonhommeVision`, `com.natural.Bonhomme.mac` — three separate App
Store records and three separate listings for one app. The fixture additionally
models `com.lebonhommepharma.exergy.pad`, a real orphan per-device-class
registration; **that registration is left alone**, only its shape is reproduced.

**Exception — NATURaL, granted 2026-09-21.** Its App Store records are live and
its SKU is permanent, so the identifiers cannot be consolidated after the fact.
The checker reports NATURaL as `EXCEPTION`, never `PASS`:

```
EXCEPTION  BUNDLE-001  3 per-platform/per-device identifier(s): one App Store
           record each -- excepted: grandfathered; App Store records are live
           and the SKU is permanent ... (decided by LP on 2026-09-21)
           | com.natural.Bonhomme: com.natural.Bonhomme.mac,
             com.natural.BonhommeTV, com.natural.BonhommeVision
```

Exceptions live in `exceptions.json` **in this repo**, keyed by `OWNER/REPO` —
never in the repo being checked, so a repo cannot exempt itself. An exception
that is invisible is indistinguishable from a rule that does not work.

---

## DECIDE-001 — Decisions are recorded in a doc that lands on the default branch

**Asserts.** A decision log exists on the default branch and records who decided
and when (a `decided by` attribution and an ISO date).

**Checked by.** `git ls-files` for a tracked decision-log filename, then reading
the file from the **working tree**. No `git show`, no ref resolution, no
dependency on a local default branch existing.

**The semantics were wrong before the mechanism was.** The first version read
`main` at HEAD, which meant a PR adding the decision doc failed the check — the
PR that fixes the violation punished for it. On a PR the working tree is the
merge result, which answers the question the rule is actually asking.

**What the old version did when the read failed.** It reported
`FAIL: "decision log(s) present but none record who decided and when"` — on a
repo whose log was present and complete. So it failed loudly rather than
silently passing, which is the safe direction; but it blamed the content for an
infrastructure failure, and the `try/except` around the read was dead code
because `git()` returned `""` instead of raising. The same swallow produced a
genuine silent pass in `BRANCH-001` — see that rule.

**Observed violation.** Tonight the export-compliance determination was
re-litigated from scratch because its reasoning lived on an unmerged branch.
NATURaL, FlexAIDdS and every other repo scanned fail this rule.

---

## OUT-001 — Conformance output is not published

**Asserts.** No conformance or gap report is committed, and no workflow runs the
checker against a path other than its own repo.

**Checked by.** Scanning the default branch's tree for report filenames, and
parsing each workflow for a `-m conform <path>` invocation whose target is not
this repo.

**Observed violation.** This repo's own first iteration committed
`docs/CONFORMANCE-2026-09-21.md` while private. That history is why this repo
exists at a fresh URL rather than being flipped to public — see the README.

**Why it is a rule.** A gap report names which repos lack protection, which
guards do not check anything, and where work is stranded: an inventory of soft
spots, and a map for anyone who wants one. The same reasoning as not committing
secrets — the value is in the tool, the blast radius is in the findings.
Sharing a report later is trivial and reversible; un-publishing git history is
not. Reports are generated locally to a gitignored path.

---

## The invariance-mismatch class

IDKEY-001, GATE-001 and XKEY-001 are three instances of one pattern, all three
observed on 2026-09-21.

**A lookup key was used that is not invariant under the transformations the
system actually applies to the thing being identified.**

The criterion. For a key `K` identifying an entity `E`, enumerate the
transformations `T` the system performs on `E` — copy, move, re-root, stage,
archive, re-run, re-export, rename, merge, mirror. `K` is sound **iff
`K(T(E)) == K(E)` for every `T`**. Any `T` that breaks the equality is a
latent misidentification.

**The class is dangerous because a bad key does not error — it succeeds against
the wrong entity.** A missing key raises and gets fixed in minutes. A key that
is merely *not invariant* returns a real-looking answer about something else,
and every downstream number is confidently wrong. Nothing in a test suite fails
until someone notices the result belongs to a different entity.

The three instances differ only in what plays the part of `K`:

| | `K` is | `T` that breaks it |
|---|---|---|
| IDKEY-001 | the directory an artifact happens to sit in | copy, re-root, re-stage, re-run into a new dir |
| GATE-001 | the façade a capability is assumed to be reached through | any call path reaching the primitive directly |
| XKEY-001 | one resolution channel, trusted alone | any transformation that channel is blind to |

---

## IDKEY-001 — An identity is not derived from a path component

**Asserts.** No identifier is derived from a path component in a scope where a
record carrying an explicit ID is available.

**Checked by.** Parsing each `.py` file with `ast` — never by matching text —
and reporting an assignment whose *target* names an identity (`pdb_id`, `pid`,
`*_id`, `*_key`, …) and whose *value* derives from a path component, in a scope
where a record with an explicit ID is in reach.

Three idioms are recognised, all of them observed live:

```
os.path.basename(os.path.dirname(csv_path))   # the containing directory's name
csv_path.parent.name / p.parents[n].name      # same, pathlib
str(p).split('/')[-2]  /  Path(p).parts[-2]   # same, by hand
```

`os.path.basename(p)` **alone** is not flagged: naming the file is a different
and often legitimate operation. Only the containing-directory forms count.

**The condition matters.** The rule fires only where a record with an explicit
ID is in scope — the scope reads an ID field off a record, parses records
(`DictReader`, `read_csv`, `safe_load`, …), or iterates record files
(`*/result.csv`). Where there genuinely is no record, a path component may be
the only identity available, and that is not this bug. Without this condition
the rule would flag every legitimate use of a directory name and be tuned off
within a week.

**The correct idiom is not flagged, and that is tested.** The record is the
key; the path is a last-resort fallback:

```python
pdb_id = (rec.get("pdb_id") or csv_path.parent.name).strip()
```

**Observed violation.** `FlexAIDdS`, both sides of the same codebase.
Broken form — `scripts/failure_classify.py:270`, `scripts/lib_launch.py:66`,
`scripts/run_panel_native_cf_oracle.py:99`, `scripts/patch_bcr_from_poses.py:52`,
`scripts/benchmark_ops_monitor.py:554`. Correct idiom, already live —
`scripts/rmsd_symmcorr.py:304`, `scripts/benchmark_ops_monitor.py:412`,
`scripts/bootstrap_3dsig_s_top10.py:334`. The fixture is built from the real
broken form and the real correct one, not from invented examples: the
non-conforming fixture goes red on four sites, the conforming fixture — which
carries all three correct idioms — stays green.

**An unparseable file does not erase the files that were checked.** The first
version returned `UNCHECKABLE` for the whole rule on the first `SyntaxError`.
Run against FlexAIDdS, one unparseable vendored benchmark file
(`tests/benchmarks/casf2016/docking_power.py`) made the rule report
`UNCHECKABLE` and **hid all five live violations in the same repo**. That is the
same shape as the bug the rule is about: an unrelated property of an unrelated
file decided the answer. Now every file that cannot be read or parsed is
recorded by name, and reported *alongside* the violations rather than instead of
them — `FAIL` when there are hits, `UNCHECKABLE` when there are none and
coverage was incomplete, `PASS` only when every file parsed. Loud about the
violations and about the coverage gap, never one at the cost of the other.

**Why it is not a style rule.** `result.csv` carries `pdb_id`. The directory is
whatever the run wrote into. Copy a campaign directory, re-stage one target
under a new name, re-run into a dated folder, and the derived key silently
becomes a different target's ID while the row's own `pdb_id` still says what it
always said. No exception is raised. The comparison just answers about the
wrong molecule.

---

## GATE-001 — A capability guard sits at the narrowest waist

**Documented-only. There is no checker for this rule.**

**Asserts.** A guard restricting a capability sits where every path to that
capability passes through, and the absence of a bypass is **demonstrated by
searching for the underlying primitive**, not by confirming the intended façade
is guarded.

**Observed violation.** `MedicationTracker` reached `HKClinicalType` directly,
bypassing `isClinicalMedicationTypeAvailable`. Gating the façade would have
looked complete and done nothing: the availability check was real, correct, and
not on the path anything actually took.

**The review procedure.** Name the primitive, not the façade, and search for it:

```sh
# 1. Name the primitive the capability ultimately bottoms out in.
#    Not the wrapper you wrote -- the type/symbol the platform provides.
PRIMITIVE='HKClinicalType'
FACADE='isClinicalMedicationTypeAvailable'

# 2. Every call site of the primitive. This is the denominator.
rg -n --no-heading "$PRIMITIVE" -g '!*Tests*' -g '!*.md'

# 3. Every call site of the facade. This is what you THINK is the denominator.
rg -n --no-heading "$FACADE"

# 4. The bypasses: primitive reached without the facade anywhere in the file.
for f in $(rg -l "$PRIMITIVE" -g '!*Tests*'); do
  rg -q "$FACADE" "$f" || echo "BYPASS: $f reaches $PRIMITIVE, never calls $FACADE"
done

# 5. Same-file is necessary, not sufficient: confirm by reading that the guard
#    dominates the call, rather than merely sharing a file with it.
```

**A review that only ran step 3 has not performed this check.** Step 2 is the
rule. If the counts in steps 2 and 3 differ, the difference is the bypass set.

**Why no checker.** A mechanical version would have to decide what the
primitive is, and the only machine-available answer is the façade the code
names — which is the object the bug is about. A checker that inspected the
façade would report green over precisely this failure. Shipping that inside
this repo would be a check that cannot fail, in the standard written to abolish
them.

---

## XKEY-001 — Two independent keys are read and asserted to agree

**Documented-only. There is no checker for this rule.**

**Asserts.** Where an identity matters, two **independent** keys are read and
asserted to agree, failing loudly on mismatch. Where only one channel exists,
the result is recorded as **"single-channel, unverified"** — explicitly, in the
output — rather than being presented as verified.

**Independence is the whole rule.** Two verification methods in this project
once agreed with each other while both resolved the entity by path. Agreement
was guaranteed and meant nothing: one channel wearing a disguise. Two channels
are independent only if there exists a transformation `T` that changes one
key's answer and not the other's. If no such `T` exists, you have one channel
counted twice.

**The review procedure.**

```sh
# 1. Name both channels and the resolution each one bottoms out in.
#    Write them down. "Two methods" is not the claim -- two RESOLUTIONS is.
#
#    e.g. channel A: row["pdb_id"] read from result.csv   (record content)
#         channel B: SHA-256 of the pose file             (artifact content)
#         -> independent: renaming the directory changes neither; swapping a
#            file changes B and not A.
#
#    Counter-example, NOT independent:
#         channel A: csv_path.parent.name
#         channel B: work_dir.name
#         -> both are the path. They agree always, and verify nothing.

# 2. Prove independence by finding the transformation that separates them.
#    If you cannot name a T that moves one and not the other, it is ONE key.

# 3. Find the assertion. Agreement that is computed but not asserted is not a
#    check -- confirm it FAILS, not warns.
rg -n "mismatch|disagree|!=|assert" -- <the comparison site>

# 4. Where only one channel exists, confirm the output says so, verbatim:
rg -n "single-channel, unverified"
```

**The limit is part of the rule.** A single-channel result is not a failure —
sometimes one channel is all there is. Presenting it as verified is the
failure. It is recorded as `single-channel, unverified` so the distinction
survives into whatever reads the output.

**Why no checker.** A checker can see that two reads happen and that a
comparison follows. It cannot see that the two reads are independent, which is
the entire content of the rule. It would pass the exact case that already
occurred here — two channels agreeing because they were one.

---

## Rules deliberately left out

Written down so their absence is a decision, not an oversight.

- **DOCS-001 — "docs are reachable from the default branch". Dropped.** Its
  observed violation did not survive re-checking: NATURaL "failed" it with five
  files, but the repo was checked out on `claude/measure-active-pose-render-latency`
  — the PR branch that *ports those very docs to `main`*. The rule was measuring
  which branch happened to be checked out, and reporting the PR that fixes the
  problem as the violation. The genuine concern underneath it, work sitting on a
  branch that is not heading for `main`, is already `BRANCH-001`. Removed rather
  than repaired, because repairing it would have made it a duplicate.

- **Export-compliance declaration.** `ITSAppUsesNonExemptEncryption` lives in a
  generated Info.plist for some targets, where its value is not present in any
  file the checker can read without invoking `xcodebuild`. A rule that reads
  only the file-based targets would pass repos it never actually examined. Left
  out rather than shipped as a check that silently covers a subset.
- **Entitlements consistency.** The correct entitlement set is per-app and
  per-capability; there is no repo-independent assertion to make. Any rule here
  would encode NATURaL's specific capabilities as if they were universal.
- **Design tokens, palette, typography.** Out of scope this pass — the v2/v3
  canonical contradiction is unresolved. For the record, the "four copies of the
  design tokens" situation cited as motivation was re-checked on 2026-09-21 and
  is **partly consolidated**: `lebonhommepharma.github.io` carries four
  `tokens.css`, but three (`entropy/`, `entropy/es/`, `entropy/fr/`) are
  byte-identical, and only the root copy has diverged — by 85 lines, including
  an entire foreground-contrast block the other three lack. So it is real,
  live duplication drift, but smaller than "four independent copies". It
  motivates the single-implementation choice for the checker; it is **not** a
  rule, because tokens are out of scope.
