"""What a rule is allowed to look at.

Two hard rules in here, both learned from bugs this checker shipped:

1. **A failed read raises.** `git()` used to return "" on a non-zero exit, so
   a rule could not tell "no output" from "the command failed". That produced a
   FAIL with a false reason in one rule and a silent PASS in another. Callers
   that genuinely treat a non-zero exit as information use `git_rc()` and say so.

2. **Nothing reads a ref that a PR checkout might not have.** A CI checkout of
   a PR branch has no local `main`, and may be shallow and detached.
"""
from __future__ import annotations

import json
import plistlib
import subprocess
from pathlib import Path


class GitHubUnavailable(Exception):
    """A GitHub read could not be performed. Never means "nothing found"."""


class GitError(Exception):
    """A git command failed. Never means "empty output"."""


class LiveGitHub:
    def __init__(self, slug: str):
        self.slug = slug

    def _api(self, path: str):
        proc = subprocess.run(["gh", "api", path], capture_output=True, text=True)
        if proc.returncode != 0:
            raise GitHubUnavailable(proc.stderr.strip()[:200] or f"gh api {path} failed")
        return json.loads(proc.stdout or "null")

    def branch_protection(self, branch: str):
        """None only when GitHub SAYS the branch is unprotected.

        A 403 (no admin rights, plan limit) or a network error is not an
        answer; it propagates. Conflating "forbidden" with "unprotected" would
        report a protected repo as a violation, and would hide the fact that
        nothing was actually read.
        """
        try:
            return self._api(f"repos/{self.slug}/branches/{branch}/protection")
        except GitHubUnavailable as exc:
            msg = str(exc)
            if "Branch not protected" in msg or "404" in msg:
                return None
            raise

    def rulesets(self):
        return [self._api(f"repos/{self.slug}/rulesets/{r['id']}")
                for r in (self._api(f"repos/{self.slug}/rulesets") or [])]

    def open_pr_head_refs(self):
        proc = subprocess.run(
            ["gh", "pr", "list", "--repo", self.slug, "--state", "open",
             "--limit", "300", "--json", "headRefName"],
            capture_output=True, text=True)
        if proc.returncode != 0:
            raise GitHubUnavailable(proc.stderr.strip()[:200] or "gh pr list failed")
        return {p["headRefName"] for p in json.loads(proc.stdout or "[]")}

    def workflow_runs_exist(self):
        return (self._api(f"repos/{self.slug}/actions/runs?per_page=1")
                or {}).get("total_count", 0) > 0

    def default_branch(self):
        return (self._api(f"repos/{self.slug}") or {}).get("default_branch")


class StaticGitHub:
    """GitHub facts supplied as JSON. Used by fixtures."""

    def __init__(self, data: dict):
        self.data = data

    def _maybe_raise(self, key):
        # Fixtures use this to simulate an unavailable API.
        if key in self.data.get("unavailable", []):
            raise GitHubUnavailable(f"simulated failure: {key}")

    def branch_protection(self, branch):
        self._maybe_raise("branch_protection")
        return self.data.get("branch_protection", {}).get(branch)

    def rulesets(self):
        self._maybe_raise("rulesets")
        return self.data.get("rulesets", [])

    def open_pr_head_refs(self):
        self._maybe_raise("open_pr_head_refs")
        return set(self.data.get("open_pr_head_refs", []))

    def workflow_runs_exist(self):
        self._maybe_raise("workflow_runs_exist")
        return bool(self.data.get("workflow_runs_exist", False))

    def default_branch(self):
        self._maybe_raise("default_branch")
        return self.data.get("default_branch")


class NoGitHub:
    def _fail(self, *a, **k):
        raise GitHubUnavailable("no GitHub source configured (--offline)")
    branch_protection = rulesets = open_pr_head_refs = _fail
    workflow_runs_exist = default_branch = _fail


class Context:
    def __init__(self, root: Path, github, default_branch="main",
                 apply_pending=False):
        self.root = Path(root)
        self.github = github
        self.default_branch = default_branch
        self.apply_pending = apply_pending
        self.slug = None
        self.exceptions = {}

    def exception_for(self, rule_id):
        """A recorded exception for this repo and rule, or None.

        Exceptions live in the standard's own repo, never in the repo being
        checked -- a repo must not be able to exempt itself.
        """
        return self.exceptions.get(rule_id)

    # ------------------------------------------------------------ filesystem
    def read_text(self, rel) -> str:
        return (self.root / rel).read_text(errors="replace")

    def read_plist(self, rel):
        with open(self.root / rel, "rb") as fh:
            return plistlib.load(fh)

    def glob(self, pattern):
        """Project files only -- never build output or vendored checkouts."""
        skip = (".git/", "/.build/", "/build/", "DerivedData",
                "/Pods/", "/.swiftpm/", "/fixtures/")
        for p in sorted(self.root.rglob(pattern)):
            rel = "/" + str(p.relative_to(self.root))
            if any(s in rel for s in skip):
                continue
            yield p

    # ------------------------------------------------------------------ git
    def git(self, *args) -> str:
        """Run git. Raise GitError on failure -- never return "" for it."""
        proc = subprocess.run(["git", "-C", str(self.root), *args],
                              capture_output=True, text=True)
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout).strip().splitlines()
            raise GitError(f"git {' '.join(args)}: "
                           f"{detail[0] if detail else f'exit {proc.returncode}'}")
        return proc.stdout.strip()

    def git_rc(self, *args):
        """(returncode, stdout) for callers where non-zero is information.

        Only for commands whose failure is a meaningful answer rather than an
        error -- `merge-tree` exiting non-zero means "conflict", not "broken".
        """
        proc = subprocess.run(["git", "-C", str(self.root), *args],
                              capture_output=True, text=True)
        return proc.returncode, proc.stdout.strip()

    def tracked_files(self) -> set:
        """Files tracked in the working tree.

        On a PR checkout this is the merge result, which is what every rule
        about "is this recorded" actually wants to know. Works on a shallow,
        detached checkout with no local default branch.
        """
        return set(self.git("ls-files").splitlines())

    def merge_is_noop(self, ref) -> bool:
        """True if merging `ref` into the default branch would change nothing."""
        base = f"origin/{self.default_branch}"
        rc, out = self.git_rc("merge-tree", "--write-tree", base, ref)
        if rc != 0 or not out:
            return False          # conflict, or could not compute: report it
        return out.splitlines()[0].strip() == self.git("rev-parse", f"{base}^{{tree}}")
