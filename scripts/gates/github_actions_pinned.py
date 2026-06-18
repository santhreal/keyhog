#!/usr/bin/env python3
"""Reject mutable GitHub Action refs in repo-owned CI.

Remote `uses:` entries execute code in GitHub-hosted jobs. Tags and branches are
mutable, so every remote action in `.github/workflows/` and `.github/actions/`
must be pinned to a full commit SHA and keep the human ref in a trailing comment.
Local actions (`./...`) are allowed.
"""

from __future__ import annotations

import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]
SCAN_ROOTS = (REPO / ".github" / "workflows", REPO / ".github" / "actions")
USES_RE = re.compile(r"^\s*(?:-\s*)?uses:\s*(?P<body>.+?)\s*$")
SHA_RE = re.compile(r"[0-9a-f]{40}")


def _split_value_and_comment(body: str) -> tuple[str, str]:
    quote: str | None = None
    for idx, char in enumerate(body):
        if char in {"'", '"'}:
            quote = None if quote == char else char if quote is None else quote
        elif char == "#" and quote is None:
            return body[:idx].strip().strip("'\""), body[idx + 1 :].strip()
    return body.strip().strip("'\""), ""


def _is_local_action(value: str) -> bool:
    return value.startswith("./") or value.startswith("../")


def _is_pinned_remote_action(value: str) -> bool:
    if "@" not in value:
        return False
    ref = value.rsplit("@", 1)[1]
    return SHA_RE.fullmatch(ref) is not None


def iter_yaml_files() -> list[pathlib.Path]:
    files: list[pathlib.Path] = []
    for root in SCAN_ROOTS:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if path.suffix in {".yml", ".yaml"} and path.is_file():
                files.append(path)
    return sorted(files)


def collect_violations() -> list[tuple[str, int, str]]:
    violations: list[tuple[str, int, str]] = []
    for path in iter_yaml_files():
        rel = path.relative_to(REPO).as_posix()
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            match = USES_RE.match(line)
            if match is None:
                continue
            value, comment = _split_value_and_comment(match.group("body"))
            if _is_local_action(value):
                continue
            if not _is_pinned_remote_action(value):
                violations.append((rel, lineno, f"{value} is not pinned to a 40-hex commit SHA"))
                continue
            if not comment:
                violations.append((rel, lineno, f"{value} is missing trailing human ref comment"))
    return violations


def self_test() -> int:
    samples = {
        "      - uses: actions/checkout@v4": True,
        "        uses: dtolnay/rust-toolchain@stable": True,
        "        uses: ./.github/actions/keyhog": False,
        "        uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4": False,
        "        uses: github/codeql-action/upload-sarif@dd903d2e4f5405488e5ef1422510ee31c8b32357 # v3": False,
        "        uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5": True,
    }
    ok = True
    for line, want_violation in samples.items():
        match = USES_RE.match(line)
        if match is None:
            got_violation = False
        else:
            value, comment = _split_value_and_comment(match.group("body"))
            got_violation = (
                not _is_local_action(value)
                and (not _is_pinned_remote_action(value) or not comment)
            )
        if got_violation != want_violation:
            print(
                f"self-test mismatch want_violation={want_violation} "
                f"got={got_violation}: {line}",
                file=sys.stderr,
            )
            ok = False
    print("self-test PASS" if ok else "self-test FAIL", file=sys.stderr)
    return 0 if ok else 1


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return self_test()
    violations = collect_violations()
    if violations:
        print(
            f"FAIL - {len(violations)} mutable or undocumented GitHub Action ref(s):",
            file=sys.stderr,
        )
        for rel, lineno, message in violations:
            print(f"  {rel}:{lineno}: {message}", file=sys.stderr)
        print(
            "\nPin remote actions to owner/repo[/path]@<40-hex-sha> # <tag-or-branch>.",
            file=sys.stderr,
        )
        return 1
    print("OK - every remote GitHub Action in .github is SHA-pinned with a ref comment.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
