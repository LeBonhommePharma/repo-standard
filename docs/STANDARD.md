# The repo standard

Ten rules. Each one exists because something in this ecosystem actually drifted,
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

**Observed violation.** 2026-09-21: FlexAIDdS 362 stranded branches, NATURaL 19
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

## DECIDE-001 — Decisions are recorded on the default branch

**Asserts.** A decision log exists on the default branch and records who decided
and when (a `decided by` attribution and an ISO date).

**Checked by.** Listing the default branch's tree for a decision-log filename,
then reading it from that branch — not from the working tree, which is the whole
point: a log that exists only locally or on a branch is not recorded.

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

## DOCS-001 — The standard/spec lives on the default branch

**Asserts.** Every `docs/*.md` and `README*` in the working tree is reachable
from the default branch.

**Observed violation.** NATURaL, 5 docs unreachable from `main` (including
`Docs/AppStore/colorset-dark-twins.md`); FlexAIDdS 4; Exergy 1.

**Partially corrected.** PR #46 ported three stranded docs, but five remain, so
the rule still fails on NATURaL — fewer than reported, not zero.

---

## Rules deliberately left out

Written down so their absence is a decision, not an oversight.

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
