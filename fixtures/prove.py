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


if __name__ == "__main__":
    main()
