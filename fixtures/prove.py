"""Build deliberately non-conforming and conforming repos, and prove each rule
can fire. Everything lives under tempfile and is removed by the context
manager -- no rm, no deletion of anything outside the temp tree.
"""
from __future__ import annotations

import json
import plistlib
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent


def git(root, *a):
    subprocess.run(["git", "-C", str(root), *a], check=True,
                   capture_output=True, text=True)


def plist(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as fh:
        plistlib.dump(data, fh)


def base_repo(root: Path):
    git(root, "init", "-q", "-b", "main")
    git(root, "config", "user.email", "fixture@example.invalid")
    git(root, "config", "user.name", "fixture")


def commit(root, msg="c"):
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", msg)


def make_bad(root: Path):
    base_repo(root)
    (root / ".github/workflows").mkdir(parents=True)
    # CI-001: PR-only + dispatch. A bare push fires nothing.
    (root / ".github/workflows/ci.yml").write_text(
        "name: ci\non:\n  pull_request:\n  workflow_dispatch:\njobs:\n"
        "  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: true\n")

    # PRIV-001: tracking TRUE, alongside another key that is false. The old
    # substring guard passed this.
    plist(root / "App/PrivacyInfo.xcprivacy", {
        "NSPrivacyTracking": True,
        "NSPrivacyCollectedDataTypes": [],
        "NSPrivacyTrackingDomains": ["ads.example.com"],
        "NSPrivacyAccessedAPITypes": [{"NSPrivacyAccessedAPIType": "X",
                                       "NSPrivacyAccessedAPITypeReasons": []}],
    })
    # PRIV-002: a second manifest that no guard mentions.
    plist(root / "MacApp/PrivacyInfo.xcprivacy", {
        "NSPrivacyTracking": False, "NSPrivacyTrackingDomains": []})

    # GUARD-001: decides a plist by two independent substrings.
    (root / "scripts").mkdir()
    (root / "scripts/test_contracts.py").write_text(
        'text = open("App/PrivacyInfo.xcprivacy").read()\n'
        'if "<key>NSPrivacyTracking</key>" in text and "<false/>" in text:\n'
        '    pass\n')

    # PLIST-001 + SWIFT-001 + BUNDLE-001
    (root / "App.xcodeproj").mkdir()
    (root / "App.xcodeproj/project.pbxproj").write_text(
        "\t\tGENERATE_INFOPLIST_FILE = YES;\n"
        "\t\tINFOPLIST_FILE = App/Info.plist;\n"
        "\t\tSWIFT_VERSION = 5.0;\n"
        "\t\tSWIFT_VERSION = 6.0;\n"
        "\t\tPRODUCT_BUNDLE_IDENTIFIER = com.example.App;\n"
        "\t\tPRODUCT_BUNDLE_IDENTIFIER = com.example.AppTV;\n"
        "\t\tPRODUCT_BUNDLE_IDENTIFIER = com.example.AppVision;\n"
        "\t\tPRODUCT_BUNDLE_IDENTIFIER = com.example.App.mac;\n"
        # Modelled on a real orphan per-device-class registration
        # (com.lebonhommepharma.exergy.pad). That registration is left alone;
        # only its shape is reproduced here.
        "\t\tPRODUCT_BUNDLE_IDENTIFIER = com.example.App.pad;\n")
    # OUT-001: a committed gap report, and a workflow emitting another repo's
    # conformance output.
    (root / "docs").mkdir(exist_ok=True)
    (root / "docs/CONFORMANCE-2026-01-01.md").write_text("| repo | PROT-001 |\n")
    (root / ".github/workflows/leak.yml").write_text(
        "name: leak\non:\n  pull_request:\njobs:\n  x:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - run: python3 -m conform /srv/OtherRepo\n")
    commit(root, "initial")

    # DOCS-001: a doc that exists in the tree but never reached main.
    git(root, "checkout", "-q", "-b", "docs-only")
    (root / "docs").mkdir(exist_ok=True)
    (root / "docs/app-store.md").write_text("# stranded\n")
    commit(root, "docs on a branch")
    # BRANCH-001: leave the branch ahead of main and check it out, so the doc
    # is in the working tree while main does not carry it.
    git(root, "update-ref", "refs/remotes/origin/main", "main")
    git(root, "update-ref", "refs/remotes/origin/docs-only", "docs-only")
    # Regression: refs/remotes/origin/HEAD shortens to a bare "origin" with no
    # slash, so a "HEAD" substring filter does not catch it. A real repo had
    # one, and it made BRANCH-001 raise instead of reporting.
    git(root, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")

    return {
        # PROT-001: active ruleset, empty include -- enforcing nothing.
        "branch_protection": {},
        "rulesets": [{"name": "main-guard", "enforcement": "active",
                      "conditions": {"ref_name": {"include": [], "exclude": []}},
                      "rules": []}],
        "open_pr_head_refs": [],      # BRANCH-001
        "workflow_runs_exist": False,  # CI-002
        "default_branch": "main",
    }


def make_good(root: Path):
    base_repo(root)
    (root / ".github/workflows").mkdir(parents=True)
    (root / ".github/workflows/ci.yml").write_text(
        "name: ci\non:\n  push:\n  pull_request:\njobs:\n"
        "  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: true\n")
    plist(root / "App/PrivacyInfo.xcprivacy",
          {"NSPrivacyTracking": False, "NSPrivacyTrackingDomains": []})
    plist(root / "MacApp/PrivacyInfo.xcprivacy",
          {"NSPrivacyTracking": False, "NSPrivacyTrackingDomains": []})
    (root / "scripts").mkdir()
    (root / "scripts/test_contracts.py").write_text(
        "import plistlib\n"
        "for rel in ['App/PrivacyInfo.xcprivacy', 'MacApp/PrivacyInfo.xcprivacy']:\n"
        "    d = plistlib.load(open(rel, 'rb'))\n"
        "    assert d.get('NSPrivacyTracking') is False\n")
    (root / "App.xcodeproj").mkdir()
    (root / "App.xcodeproj/project.pbxproj").write_text(
        "\t\tINFOPLIST_FILE = App/Info.plist;\n"
        "\t\tSWIFT_VERSION = 6.0;\n"
        "\t\tPRODUCT_BUNDLE_IDENTIFIER = com.example.App;\n"
        "\t\tPRODUCT_BUNDLE_IDENTIFIER = com.example.AppTests;\n"
        "\t\tPRODUCT_BUNDLE_IDENTIFIER = com.example.App.Widgets;\n")
    (root / "docs").mkdir(exist_ok=True)
    (root / "docs/DECISIONS.md").write_text(
        "# Decisions\n\n## One bundle ID per app\n\n"
        "Decided by: LP\nDate: 2026-09-21\n\nWhy: one record, one listing.\n")
    (root / "docs/app-store.md").write_text("# on main\n")
    commit(root, "initial")
    git(root, "update-ref", "refs/remotes/origin/main", "main")
    # Reproduce a CI checkout of a PR branch: only origin/main exists, the
    # local "main" does not. A rule that reads "main:<path>" instead of
    # "origin/main:<path>" passes locally and fails here.
    git(root, "branch", "-m", "main", "pr-branch")
    # A squash-merged branch: ahead of origin/main in commits, no open PR, but
    # contributing no diff. Must NOT be reported as stranded.
    git(root, "checkout", "-q", "-b", "already-merged")
    (root / "docs/app-store.md").write_text("# edited\n")
    commit(root, "edit")
    (root / "docs/app-store.md").write_text("# on main\n")
    commit(root, "revert the edit")
    git(root, "update-ref", "refs/remotes/origin/already-merged", "already-merged")
    git(root, "checkout", "-q", "pr-branch")
    return {
        "branch_protection": {"main": {"required_pull_request_reviews": {}}},
        "rulesets": [],
        "open_pr_head_refs": [],
        "workflow_runs_exist": True,
        "default_branch": "main",
    }


def run(root, data, apply_pending):
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(data, fh)
        dpath = fh.name
    cmd = [sys.executable, "-m", "conform", str(root),
           "--github-data", dpath, "--no-color"]
    if apply_pending:
        cmd.append("--apply-pending")
    p = subprocess.run(cmd, capture_output=True, text=True, cwd=HERE)
    return p.stdout + p.stderr


def main():
    for label, builder, pending in (
        ("NON-CONFORMING FIXTURE", make_bad, True),
        ("CONFORMING FIXTURE", make_good, True),
    ):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "repo"
            root.mkdir()
            data = builder(root)
            print("=" * 68)
            print(label)
            print("=" * 68)
            print(run(root, data, pending))





# ===================================================================
# Targeted scenarios for the failure modes that actually shipped.
# ===================================================================

def _seed(root: Path, decisions):
    root.mkdir(parents=True, exist_ok=True)
    base_repo(root)
    (root / "docs").mkdir()
    (root / "README.md").write_text("# r\n")
    if decisions is not None:
        (root / "docs/DECISIONS.md").write_text(decisions)
    commit(root, "seed")
    return root


def decide_scenarios():
    """DECIDE-001: absent -> red, incomplete -> red, complete -> green."""
    cases = [
        ("doc absent", None, "FAIL"),
        ("doc present, no decision recorded", "# Decisions\n\nNothing yet.\n", "FAIL"),
        ("doc present and complete",
         "# Decisions\n\n## X\n\nDecided by: LP\nDate: 2026-09-21\n\nWhy: reasons.\n", "PASS"),
    ]
    print("=" * 68)
    print("DECIDE-001 SCENARIOS")
    print("=" * 68)
    for label, body, expect in cases:
        with tempfile.TemporaryDirectory() as td:
            root = _seed(Path(td) / "r", body)
            out = run(root, {"default_branch": "main"}, False)
            line = next(l for l in out.splitlines() if "DECIDE-001" in l)
            got = line.split()[0]
            flag = "ok" if got == expect else "UNEXPECTED"
            print(f"  [{flag}] {label:<36} -> {line.strip()}")


def pr_checkout_scenario():
    """The exact condition that broke: a CI checkout of a PR branch.

    Shallow (depth 1), detached HEAD, no local `main`, no `origin/main`.
    Built by fetching a single ref from a bare origin, which is what
    actions/checkout does for a pull_request event.
    """
    print("=" * 68)
    print("PR CHECKOUT: shallow, detached, no local or remote `main`")
    print("=" * 68)
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        origin = td / "origin.git"
        work = td / "seed"
        _seed(work, "# Decisions\n\n## X\n\nDecided by: LP\nDate: 2026-09-21\n\nWhy: y.\n")
        (work / ".github/workflows").mkdir(parents=True)
        (work / ".github/workflows/ci.yml").write_text(
            "name: ci\non:\n  push:\njobs:\n  c:\n    runs-on: ubuntu-latest\n"
            "    steps:\n      - run: true\n")
        commit(work, "ci")
        git(work, "checkout", "-q", "-b", "pr-branch")
        (work / "docs/note.md").write_text("# pr adds a doc\n")
        commit(work, "pr work")
        subprocess.run(["git", "clone", "-q", "--bare", str(work), str(origin)], check=True)

        co = td / "checkout"
        co.mkdir()
        git(co, "init", "-q")
        git(co, "remote", "add", "origin", str(origin))
        git(co, "fetch", "-q", "--depth", "1", "origin", "pr-branch")
        git(co, "checkout", "-q", "--detach", "FETCH_HEAD")

        print(f"  shallow={git_out(co, 'rev-parse', '--is-shallow-repository')}  "
              f"HEAD={git_out(co, 'rev-parse', '--abbrev-ref', 'HEAD')}  "
              f"local branches={git_out(co, 'branch', '--format=%(refname:short)') or '(none)'}  "
              f"remote refs={git_out(co, 'branch', '-r', '--format=%(refname:short)') or '(none)'}")
        print()
        print(run(co, {"default_branch": "main", "branch_protection": {"main": {"x": 1}},
                       "rulesets": [], "open_pr_head_refs": [], "workflow_runs_exist": True},
                  False))


def injected_error_scenario():
    """Meta-check: a rule that raises must turn the run red, not green.

    Without this, every rule is potentially a check that cannot fail and none
    of the others mean anything. Also asserts --allow-unchecked does NOT
    rescue an ERROR.
    """
    print("=" * 68)
    print("INJECTED EXCEPTION: a crashing rule must fail the run")
    print("=" * 68)
    inject = (
        "import conform.rules as R\n"
        "def boom(ctx):\n"
        "    raise RuntimeError('deliberate fault injected into PRIV-001')\n"
        "for r in R.RULES:\n"
        "    if r.rule_id == 'PRIV-001':\n"
        "        r.check = boom\n"
        "import conform.cli as C, sys\n"
        "sys.exit(C.main(sys.argv[1:]))\n"
    )
    with tempfile.TemporaryDirectory() as td:
        root = _seed(Path(td) / "r",
                     "# Decisions\n\nDecided by: LP\nDate: 2026-09-21\n")
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump({"default_branch": "main"}, fh)
            dp = fh.name
        for extra in ([], ["--allow-unchecked"]):
            p = subprocess.run(
                [sys.executable, "-c", inject, str(root), "--github-data", dp,
                 "--no-color", *extra],
                capture_output=True, text=True, cwd=HERE)
            label = "with --allow-unchecked" if extra else "default"
            line = next((l for l in p.stdout.splitlines() if "PRIV-001" in l), "(missing)")
            red = "RED (correct)" if p.returncode != 0 else "GREEN (WRONG)"
            print(f"  {label:<22} exit={p.returncode}  {red}")
            print(f"    {line.strip()}")


def git_out(root, *a):
    return subprocess.run(["git", "-C", str(root), *a],
                          capture_output=True, text=True).stdout.strip().replace("\n", ",")


if __name__ == "__main__":
    main()
    decide_scenarios()
    pr_checkout_scenario()
    injected_error_scenario()
