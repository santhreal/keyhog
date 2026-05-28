#!/usr/bin/env python3
"""Sync expected_companions in companion contracts from scanner parity output."""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
COMPANION = REPO / "crates" / "scanner" / "tests" / "contracts" / "companion"

MISMATCH_RE = re.compile(
    r"^\s+- (?P<detector>[^:]+): positive_with_companion companion mismatch - "
    r"expected companions\[(?P<name>[^\]]+)\]=.*?, got Some\(\"(?P<actual>(?:\\.|[^\"])*)\"\)"
)
MISMATCH_NONE_RE = re.compile(
    r"^\s+- (?P<detector>[^:]+): positive_with_companion companion mismatch - "
    r"expected companions\[(?P<name>[^\]]+)\]=.*?, got None"
)


def unescape(s: str) -> str:
    return bytes(s, "utf-8").decode("unicode_escape")


def update_expected(path: pathlib.Path, name: str, value: str) -> bool:
    text = path.read_text()
    key = name if re.fullmatch(r"[A-Za-z0-9_-]+", name) else f'"{name}"'
    pat = re.compile(
        rf"(expected_companions = \{{[^}}]*\b{re.escape(name if ' ' not in name else name)}\s*=\s*)\"(?:\\.|[^\"])*\""
    )
    # simpler: replace line with expected_companions block rebuild
    lines = text.splitlines()
    out: list[str] = []
    in_map = False
    replaced = False
    for line in lines:
        if line.startswith("expected_companions = {"):
            in_map = True
            # parse existing map
            m = re.search(r"\{(.+)\}", line)
            entries: dict[str, str] = {}
            if m:
                body = m.group(1)
                for part in re.finditer(r'(\w+|\"[^\"]+\")\s*=\s*\"((?:\\.|[^\"])*)\"', body):
                    k = part.group(1).strip('"')
                    entries[k] = unescape(part.group(2))
            entries[name] = value
            parts = []
            for k, v in sorted(entries.items()):
                kk = k if re.fullmatch(r"[A-Za-z0-9_-]+", k) else f'"{k}"'
                esc = v.replace("\\", "\\\\").replace('"', '\\"')
                parts.append(f"{kk} = \"{esc}\"")
            out.append("expected_companions = { " + ", ".join(parts) + " }")
            replaced = True
            in_map = False
            continue
        out.append(line)
    if not replaced:
        return False
    path.write_text("\n".join(out) + "\n")
    return True


def main() -> int:
    proc = subprocess.run(
        [
            "cargo",
            "test",
            "-p",
            "keyhog-scanner",
            "--test",
            "companion_contracts_runner",
            "--",
            "--nocapture",
        ],
        cwd=REPO,
        capture_output=True,
        text=True,
        timeout=300,
    )
    out = proc.stdout + proc.stderr
    updated = 0
    for line in out.splitlines():
        m = MISMATCH_RE.match(line)
        if not m:
            continue
        det = m.group("detector")
        name = m.group("name")
        actual = unescape(m.group("actual"))
        path = COMPANION / f"{det}.toml"
        if path.exists() and update_expected(path, name, actual):
            print(f"synced {det} [{name}]")
            updated += 1
    print(f"updated {updated} expected_companions", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
