# Decisions

A determination that exists only in a chat session is not recorded. Tonight the
export-compliance question was re-litigated from scratch because its reasoning
lived on an unmerged branch. Decisions land here, on `main`, with who decided,
when, and why. Enforced by `DECIDE-001`.

---

## One bundle identifier per app across platforms

- **Decided by:** LP
- **Date:** 2026-09-21
- **Rule:** `BUNDLE-001`

One identifier per app across iOS, macOS, tvOS and visionOS — one App Store
record, one listing per app. Per-platform or per-device-class identifiers are a
violation.

**Why.** Ratings and review counts consolidate onto one record instead of being
split four ways. Purchase carries across platforms for the user. One submission
per update, instead of four independent trips through review.

**Verification.** The App Store Connect rules for which platforms can share a
single record under one bundle ID were confirmed before this was decided; the
rule was held PENDING until then and applied to nothing.

**Exception — NATURaL, granted.** `com.natural.BonhommeTV`,
`com.natural.BonhommeVision` and `com.natural.Bonhomme.mac` stay as they are.
Its App Store records are live and its SKU is permanent, so the identifiers
cannot be consolidated after the fact. Recorded in `exceptions.json`; the
checker reports NATURaL as `EXCEPTION`, not `PASS`. An exception that is
invisible is indistinguishable from a rule that does not work.

---

## Conformance output is not public by default

- **Decided by:** LP
- **Date:** 2026-09-21
- **Rule:** `OUT-001`

The spec, the checker, the fixtures and the docs are public. Any gap report
naming a real repo and its failures is not: not committed, not emitted by CI.
Reports are generated locally to a gitignored path.

**Why.** "Which repos lack branch protection, which guards do not actually
check anything, where work is stranded" is an inventory of soft spots — a map
for anyone who wants one. The same reasoning as not committing secrets: the
value is in the tool, the blast radius is in the findings. Sharing a report
later is trivial and reversible; un-publishing git history is not.

---

## Scope of the first pass: infrastructure only

- **Decided by:** LP
- **Date:** 2026-09-21

Design tokens, palette and typography are out. The v2/v3 canonical
contradiction is unresolved, and uniformizing onto the wrong canonical is worse
than the drift.
