"""What a rule is allowed to look at.

The GitHub side is an interface with two implementations: a live one that
shells out to `gh`, and a static one loaded from JSON. Fixtures use the static
one so that a rule about branch protection can be proven to fire without
creating 67 throwaway GitHub repos.
"""
from __future__ import annotations

import json
import plistlib
import subprocess
from pathlib import Path


class GitHubUnavailable(Exception):
    pass


class LiveGitHub:
    """Reads the real GitHub API through an already-authenticated `gh`."""

    def __init__(self, slug: str):
        self.slug = slug

    def _api(self, path: str):
        proc = subprocess.run(
            ["gh", "api", path],
            capture_output=True, text=True,
        )
        if proc.returncode != 0:
            raise GitHubUnavailable(proc.stderr.strip()[:200])
        return json.loads(proc.stdout or "null")

    def branch_protection(self, branch: str):
        try:
            return self._api(f"repos/{self.slug}/branches/{branch}/protection")
        except GitHubUnavailable:
            # 404 from this endpoint is the documented way GitHub says
            # "this branch is not protected". That is a real answer, not a
            # failure to read, so it is None rather than an exception.
            return None

    def rulesets(self):
        out = []
        for r in self._api(f"repos/{self.slug}/rulesets") or []:
            out.append(self._api(f"repos/{self.slug}/rulesets/{r['id']}"))
        return out

    def open_pr_head_refs(self):
        proc = subprocess.run(
            ["gh", "pr", "list", "--repo", self.slug, "--state", "open",
             "--limit", "300", "--json", "headRefName"],
            capture_output=True, text=True,
        )
        if proc.returncode != 0:
            raise GitHubUnavailable(proc.stderr.strip()[:200])
        return {p["headRefName"] for p in json.loads(proc.stdout or "[]")}

    def workflow_runs_exist(self):
        data = self._api(f"repos/{self.slug}/actions/runs?per_page=1")
        return (data or {}).get("total_count", 0) > 0

    def default_branch(self):
        return (self._api(f"repos/{self.slug}") or {}).get("default_branch")


class StaticGitHub:
    """GitHub facts supplied as JSON. Used by fixtures."""

    def __init__(self, data: dict):
        self.data = data

    def branch_protection(self, branch):
        return self.data.get("branch_protection", {}).get(branch)

    def rulesets(self):
        return self.data.get("rulesets", [])

    def open_pr_head_refs(self):
        return set(self.data.get("open_pr_head_refs", []))

    def workflow_runs_exist(self):
        return bool(self.data.get("workflow_runs_exist", False))

    def default_branch(self):
        return self.data.get("default_branch")


class NoGitHub:
    def _fail(self, *a, **k):
        raise GitHubUnavailable("no GitHub source configured (--offline)")
    branch_protection = rulesets = open_pr_head_refs = workflow_runs_exist = _fail
    default_branch = _fail


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
        """A recorded, reviewed exception for this repo and rule, or None.

        Exceptions live in the standard's own repo, not in the repo being
        checked -- a repo must not be able to exempt itself.
        """
        return self.exceptions.get(rule_id)

    # --- filesystem helpers, all read-only ---
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

    def default_tree(self):
        """Files on the default branch, preferring the remote-tracking ref.

        On a CI checkout of a PR branch the local `main` does not exist; only
        `origin/main` does. A rule that reads the bare branch name works
        locally and silently fails there.
        """
        for ref in (f"origin/{self.default_branch}", self.default_branch):
            out = self.git("ls-tree", "-r", "--name-only", ref)
            if out:
                return set(out.splitlines()), ref
        return None, None

    def show_on_default(self, path):
        for ref in (f"origin/{self.default_branch}", self.default_branch):
            out = self.git("show", f"{ref}:{path}")
            if out:
                return out
        return ""

    def git(self, *args):
        proc = subprocess.run(
            ["git", "-C", str(self.root), *args],
            capture_output=True, text=True,
        )
        return proc.stdout.strip() if proc.returncode == 0 else ""
