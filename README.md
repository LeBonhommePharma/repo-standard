# repo-standard

*Working name — renaming is cheap, so this is not blocking. LP's call.*

A declared infrastructure standard for the `LeBonhommePharma` repos, plus a
single conformance checker that can be run against any repo path.

The point is not a set of uniformized repos. Uniformizing by hand once resets
the clock and the drift comes back. The point is an instrument that makes
non-uniformity **visible and refusable**.

## Use

```sh
python3 -m conform /path/to/repo                 # infers OWNER/REPO from origin
python3 -m conform /path/to/repo --offline       # no API; GitHub rules go UNCHECKABLE
python3 -m conform /path/to/repo --json
```

Exit status is 1 if any rule failed or could not be checked.

There is **one implementation**, run against a path. It is deliberately not
copied into each repo: copies drift from each other, and then you need a checker
for the checkers. This ecosystem's website repo carries four copies of `tokens.css`, three
identical and one diverged by 85 lines, from exactly that mistake.

## Prove it can fail

```sh
python3 fixtures/prove.py
```

Builds a deliberately non-conforming repo and a conforming one under `tempfile`,
runs the checker against both, and prints red then green. A conformance checker
that has never refused anything is indistinguishable from one that cannot.

## Conformance reports are not published

The spec, the checker, the fixtures and the docs are public. **Gap reports are
not.** A report naming which repos lack protection, which guards do not check
anything, and where work is stranded is an inventory of soft spots. Generate one
locally; `.gitignore` already covers `CONFORMANCE-*.md` and friends, and CI
checks only this repo. Enforced by `OUT-001`, decided in
[docs/DECISIONS.md](docs/DECISIONS.md).

> An earlier private iteration of this repo did commit a gap report. Because
> that is in its git history and history is not rewritten here, it was left
> private under a different name rather than flipped to public. This repo is a
> fresh history that has never contained one.

## Statuses

`PASS` · `FAIL` · `UNCHECKABLE` (inputs unreadable — counts as a violation, on
purpose) · `N/A` (rule's inputs absent from this repo) · `EXCEPTION` (violated,
with a recorded exception in `exceptions.json` — never `PASS`, because an
invisible exception is indistinguishable from a broken rule) · `PENDING` (rule
written but gated behind an unfinished verification; never green, never red —
currently unused).

## The rules

See [docs/STANDARD.md](docs/STANDARD.md). Each rule records what it asserts, how
it is checked, the observed violation behind it, and where the fixture proves it
fires. Rules with no observed violation are marked speculative: currently one,
`PRIV-001`. The other twelve come from drift observed on 2026-09-21. Rules that were considered and
deliberately left out are listed at the end, with the reason.

<!-- protection probe -->
