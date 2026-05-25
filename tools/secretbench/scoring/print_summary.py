#!/usr/bin/env python3
"""Print a one-line leaderboard summary from a results JSON file.

Used by the secretbench-nightly CI workflow. Reading the file via a
discrete script (instead of inlining the Python in the workflow YAML)
keeps the YAML free of escape-sensitive multi-line strings.
"""
from __future__ import annotations
import json
import sys
from pathlib import Path

def main(path: str) -> int:
    data = json.loads(Path(path).read_text())
    for entry in data.get("ranking", []):
        print(
            f"{entry['rank']}. {entry['scanner']:<12} "
            f"F1={entry['f1']:.4f}  "
            f"P={entry['precision']:.4f}  "
            f"R={entry['recall']:.4f}  "
            f"({entry['total_time_ms'] / 1000:.1f}s)"
        )
    return 0

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: print_summary.py <leaderboard.json>", file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
