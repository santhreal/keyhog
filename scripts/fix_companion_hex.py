#!/usr/bin/env python3
"""Replace suppressed ascending-placeholder hex in companion contracts."""

from __future__ import annotations

import pathlib
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
COMPANION = REPO / "crates" / "scanner" / "tests" / "contracts" / "companion"

REPLACEMENTS = {
    "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d": "a4f2c891e7b0635d2c8f4e1a9b7d6c3e",
    "a1b2c3d4e5f6789012345678901234ab": "c8e4f1a92d7b0653e9c4a8f2b1d6e7a0",
    "AC1b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d": "ACa4f2c891e7b0635d2c8f4e1a9b7d6c3e",
    "4c9a8f6e3b7d1a2c5e8f0b9d6a3c4e1f": "f3e8a1c94b7d602e5a9c8f1b3d6e4a7c",
}


def main() -> int:
    changed = 0
    for path in sorted(COMPANION.glob("*.toml")):
        raw = path.read_text()
        new = raw
        for old, repl in REPLACEMENTS.items():
            new = new.replace(old, repl)
        if new != raw:
            path.write_text(new)
            changed += 1
            print(f"hex-fix: {path.name}")
    print(f"hex replacements in {changed} files", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
