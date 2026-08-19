#!/usr/bin/env python3
"""Keep install/update paths coherent with what release CI actually produces.

Two failures shipped together once and neither surface complained:

  1. `install.sh`, `install.ps1`, and the Rust self-update resolved a GitHub
     release asset bundle that no workflow built, signed, or uploaded. Because
     every consumer searched BACKWARD for a release carrying a complete bundle,
     a dead channel did not fail - it silently installed the last release that
     still had assets, 33 versions behind the current one.
  2. `crates/cli/src/installer/release.rs` documented its trust model as
     "signed ... in the `sign` job of `.github/workflows/release.yml`". That
     job did not exist.

So this gate enforces two invariants:

  A. If any shipped install/update path consumes release assets, some workflow
     must produce them. A consumer with no producer is a frozen channel.
  B. A prose reference to a named workflow job must resolve to a real job.

Invariant A fails closed on a NEW consumer as well as a deleted producer: add
an asset-consuming path without adding a producer and this goes red.
"""

from __future__ import annotations

import pathlib
import re
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parents[2]

# Paths that ship to users and may try to install or update a binary.
CONSUMER_ROOTS = [
    "install.sh",
    "install.ps1",
    "crates/cli/src/installer",
    "crates/cli/src/subcommands",
]

# Resolving or fetching a release asset. Plain release *links* for humans are
# fine; these are the machine-consumption shapes.
CONSUMER_PATTERNS = [
    (re.compile(r"api\.github\.com/repos/[^\s\"']+/releases"),
     "queries the releases API to pick a version"),
    (re.compile(r"releases/download/"), "downloads a release asset"),
    (re.compile(r"releases/latest/download"), "downloads a latest-release asset"),
    (re.compile(r"\bbrowser_download_url\b"), "fetches a release asset URL"),
]

# A workflow that actually builds and publishes binary assets.
PRODUCER_PATTERNS = [
    re.compile(r"gh\s+release\s+upload"),
    re.compile(r"softprops/action-gh-release"),
    re.compile(r"actions/create-release"),
    re.compile(r"\bminisign\b\s+-S"),
]

# "the `sign` job of `.github/workflows/release.yml`" and close variants.
JOB_REF = re.compile(
    r"`(?P<job>[A-Za-z0-9_-]+)`\s+job\s+of\s+`?(?P<wf>\.github/workflows/[A-Za-z0-9_.-]+)`?"
)

JOB_REF_ROOTS = CONSUMER_ROOTS + ["docs/src", "README.md"]

TEXT_SUFFIXES = {".md", ".ps1", ".py", ".rs", ".sh", ".toml", ".yml", ".yaml"}


def iter_files(root: pathlib.Path):
    if root.is_file():
        yield root
        return
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.suffix in TEXT_SUFFIXES:
            yield path


def workflow_jobs(path: pathlib.Path) -> set[str]:
    """Top-level job ids: two-space-indented keys under `jobs:`."""
    jobs: set[str] = set()
    in_jobs = False
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if re.match(r"^jobs:\s*$", line):
            in_jobs = True
            continue
        if in_jobs:
            if line.strip() and not line.startswith(" "):
                in_jobs = False
                continue
            m = re.match(r"^  (?P<job>[A-Za-z0-9_-]+):\s*$", line)
            if m:
                jobs.add(m.group("job"))
    return jobs


def check(repo: pathlib.Path) -> tuple[list[str], list[str], list[str]]:
    """Return (failures, consumers, producers) for the tree at `repo`."""
    failures: list[str] = []
    workflows = repo / ".github" / "workflows"

    consumers: list[str] = []
    for rel in CONSUMER_ROOTS:
        root = repo / rel
        if not root.exists():
            continue
        for path in iter_files(root):
            text = path.read_text(encoding="utf-8", errors="replace")
            for lineno, line in enumerate(text.splitlines(), 1):
                for pattern, why in CONSUMER_PATTERNS:
                    if pattern.search(line):
                        consumers.append(f"{path.relative_to(repo)}:{lineno}: {why}")

    producers: list[str] = []
    if workflows.is_dir():
        for path in sorted(workflows.glob("*.y*ml")):
            text = path.read_text(encoding="utf-8", errors="replace")
            if any(p.search(text) for p in PRODUCER_PATTERNS):
                producers.append(path.name)

    if consumers and not producers:
        failures.append(
            "Frozen release channel: install/update code consumes GitHub "
            "release assets, but no workflow builds, signs, or uploads them.\n"
            "  Consumers found:\n"
            + "\n".join(f"    {c}" for c in consumers)
            + "\n  Fix by removing the asset-consuming path, or by adding a "
              "workflow that uploads and signs the assets it expects.\n"
              "  Do NOT leave a consumer that searches older releases for a "
              "complete bundle: that installs a stale binary instead of failing."
        )

    for rel in JOB_REF_ROOTS:
        root = repo / rel
        if not root.exists():
            continue
        for path in iter_files(root):
            text = path.read_text(encoding="utf-8", errors="replace")
            for lineno, line in enumerate(text.splitlines(), 1):
                for m in JOB_REF.finditer(line):
                    wf = repo / m.group("wf")
                    job = m.group("job")
                    if not wf.exists():
                        failures.append(
                            f"{path.relative_to(repo)}:{lineno}: references "
                            f"{m.group('wf')}, which does not exist."
                        )
                    else:
                        jobs = workflow_jobs(wf)
                        if job not in jobs:
                            failures.append(
                                f"{path.relative_to(repo)}:{lineno}: references the "
                                f"`{job}` job of {m.group('wf')}, which has no such "
                                f"job (has: {', '.join(sorted(jobs)) or 'none'})."
                            )

    return failures, consumers, producers


def _fixture(root: pathlib.Path, files: dict[str, str]) -> pathlib.Path:
    for rel, body in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    return root


def self_test() -> int:
    """Prove the gate catches each failure it exists to catch."""
    cases: list[tuple[str, dict[str, str], bool]] = [
        (
            "consumer with no producer is caught",
            {
                "install.sh": "curl -fsSL https://github.com/o/r/releases/download/v1/x\n",
                ".github/workflows/release.yml": "jobs:\n  publish:\n    runs-on: x\n",
            },
            True,
        ),
        (
            "consumer WITH a producer passes",
            {
                "install.sh": "curl -fsSL https://github.com/o/r/releases/download/v1/x\n",
                ".github/workflows/release.yml":
                    "jobs:\n  sign:\n    runs-on: x\n    steps:\n"
                    "      - run: gh release upload v1 x\n",
            },
            False,
        ),
        (
            "no consumer and no producer passes",
            {
                "install.sh": "echo cargo install keyhog --locked\n",
                ".github/workflows/release.yml": "jobs:\n  publish:\n    runs-on: x\n",
            },
            False,
        ),
        (
            "reference to a nonexistent workflow job is caught",
            {
                "install.sh": "echo hi\n",
                "crates/cli/src/installer/release.rs":
                    "//! signed in the `sign` job of `.github/workflows/release.yml`\n",
                ".github/workflows/release.yml": "jobs:\n  publish:\n    runs-on: x\n",
            },
            True,
        ),
        (
            "reference to a real workflow job passes",
            {
                "install.sh": "echo hi\n",
                "crates/cli/src/installer/release.rs":
                    "//! signed in the `publish` job of `.github/workflows/release.yml`\n",
                ".github/workflows/release.yml": "jobs:\n  publish:\n    runs-on: x\n",
            },
            False,
        ),
        (
            "a Rust consumer using browser_download_url is caught",
            {
                "crates/cli/src/subcommands/update.rs":
                    "let u = &asset.browser_download_url;\n",
                ".github/workflows/release.yml": "jobs:\n  publish:\n    runs-on: x\n",
            },
            True,
        ),
    ]

    failed = 0
    for name, files, expect_failure in cases:
        with tempfile.TemporaryDirectory() as tmp:
            root = _fixture(pathlib.Path(tmp), files)
            failures, _, _ = check(root)
            got = bool(failures)
            if got != expect_failure:
                failed += 1
                print(f"  FAIL self-test: {name} "
                      f"(expected {'failure' if expect_failure else 'pass'}, "
                      f"got {'failure' if got else 'pass'})")
            else:
                print(f"  ok: {name}")
    if failed:
        print(f"release channel coherence self-test: {failed} case(s) FAILED")
        return 1
    print(f"release channel coherence self-test: OK ({len(cases)} cases)")
    return 0


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return self_test()
    failures, consumers, producers = check(REPO)
    if failures:
        print("release channel coherence: FAIL")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(
        f"release channel coherence: OK "
        f"({len(consumers)} asset consumer(s), {len(producers)} producer workflow(s))"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
