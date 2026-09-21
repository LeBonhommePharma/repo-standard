"""conform -- one checker, run against any repo path.

    python3 -m conform <repo-path> [--slug OWNER/REPO] [--offline]
                                   [--github-data FILE] [--apply-pending]

Exit status is 1 if any rule FAILed or was UNCHECKABLE, else 0.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .context import (Context, GitError, GitHubUnavailable, LiveGitHub,
                       NoGitHub, StaticGitHub)
from .model import Finding, Status
from .rules import RULES

COLOR = {
    Status.PASS: "\033[32m", Status.FAIL: "\033[31m",
    Status.PENDING: "\033[35m", Status.EXCEPTION: "\033[36m",
    Status.ERROR: "\033[31;1m", Status.NOT_APPLICABLE: "\033[90m",
    Status.UNCHECKABLE: "\033[33m",
}


def infer_slug(root: Path):
    import subprocess
    p = subprocess.run(["git", "-C", str(root), "remote", "get-url", "origin"],
                       capture_output=True, text=True)
    if p.returncode != 0:
        return None
    url = p.stdout.strip()
    for pre in ("https://github.com/", "git@github.com:"):
        if url.startswith(pre):
            return url[len(pre):].removesuffix(".git")
    return None


def resolve_default_branch(root: Path, gh) -> str:
    """Never assume "main".

    22 of this account's repos use master, develop or something else. A scan
    that assumes "main" reports "not protected" for a branch that does not
    exist, which is a false finding dressed as a real one.
    """
    try:
        b = gh.default_branch()
        if b:
            return b
    except Exception:
        pass
    import subprocess
    # origin/HEAD records what the remote said its default was at clone time.
    p = subprocess.run(["git", "-C", str(root), "symbolic-ref",
                        "--short", "refs/remotes/origin/HEAD"],
                       capture_output=True, text=True)
    if p.returncode == 0 and "/" in p.stdout:
        return p.stdout.strip().split("/", 1)[1]
    for cand in ("main", "master"):
        p = subprocess.run(["git", "-C", str(root), "rev-parse", "--verify",
                            f"refs/remotes/origin/{cand}"],
                           capture_output=True, text=True)
        if p.returncode == 0:
            return cand
    return "main"


def main(argv=None):
    ap = argparse.ArgumentParser(prog="conform")
    ap.add_argument("repo", type=Path)
    ap.add_argument("--slug")
    ap.add_argument("--default-branch",
                    help="override; otherwise resolved from the remote, then git")
    ap.add_argument("--offline", action="store_true",
                    help="refuse GitHub reads; GitHub rules report UNCHECKABLE")
    ap.add_argument("--github-data", type=Path,
                    help="read GitHub facts from a JSON file instead of the API")
    ap.add_argument("--apply-pending", action="store_true",
                    help="also apply rules gated pending external verification")
    ap.add_argument("--exceptions", type=Path,
                    default=Path(__file__).resolve().parent.parent / "exceptions.json",
                    help="recorded exceptions, keyed by OWNER/REPO")
    ap.add_argument("--allow-unchecked", action="store_true",
                    help="exit 0 despite UNCHECKABLE rules (inputs unavailable, "
                         "e.g. CI without an admin token). Still printed as "
                         "UNCHECKABLE. NEVER tolerates ERROR: a crashing rule is "
                         "a broken checker, not an unavailable input.")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--no-color", action="store_true")
    a = ap.parse_args(argv)

    if a.github_data:
        gh = StaticGitHub(json.loads(a.github_data.read_text()))
    elif a.offline:
        gh = NoGitHub()
    else:
        slug = a.slug or infer_slug(a.repo)
        gh = LiveGitHub(slug) if slug else NoGitHub()

    branch = a.default_branch or resolve_default_branch(a.repo, gh)
    ctx = Context(a.repo, gh, branch, apply_pending=a.apply_pending)
    ctx.slug = a.slug or infer_slug(a.repo)
    ctx.exceptions = {}
    if a.exceptions and a.exceptions.exists():
        ctx.exceptions = json.loads(a.exceptions.read_text()).get(ctx.slug or "", {})

    findings = []
    for r in RULES:
        try:
            f = r.check(ctx)
        except (GitError, GitHubUnavailable) as exc:
            # An input could not be read. The rule did not run.
            f = Finding(r.rule_id, Status.UNCHECKABLE, f"{type(exc).__name__}: {exc}")
        except Exception as exc:
            # The rule itself is broken. Distinct from UNCHECKABLE because a
            # crashing rule must never be tolerable, even with
            # --allow-unchecked.
            import traceback
            f = Finding(r.rule_id, Status.ERROR,
                        f"rule raised {type(exc).__name__}: {exc}",
                        evidence="".join(traceback.format_exc().splitlines(True)[-3:]).rstrip())
        findings.append((r, f))

    if a.json:
        print(json.dumps([{"rule": r.rule_id, "title": r.title, "basis": r.basis,
                           "status": f.status.value, "detail": f.detail,
                           "evidence": f.evidence} for r, f in findings], indent=2))
    else:
        use_color = not a.no_color and sys.stdout.isatty()
        print(f"conform: {a.repo}")
        for r, f in findings:
            c, z = (COLOR[f.status], "\033[0m") if use_color else ("", "")
            tag = "" if r.basis == "evidence" else "  [speculative]"
            print(f"  {c}{f.status.value:<12}{z} {r.rule_id}  {f.detail}{tag}")
            for line in (f.evidence.splitlines() if f.evidence else []):
                print(f"                   | {line}")
        n_fail = sum(1 for _, f in findings if f.is_violation)
        n_err = sum(1 for _, f in findings if f.status is Status.ERROR)
        extra = f", {n_err} ERROR (checker bug)" if n_err else ""
        print(f"  -- {n_fail} violation(s) of {len(findings)} rule(s){extra}")

    def counts(f):
        if f.status in (Status.FAIL, Status.ERROR):
            return True          # ERROR is never tolerable
        if f.status is Status.UNCHECKABLE:
            return not a.allow_unchecked
        return False

    return 1 if any(counts(f) for _, f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
