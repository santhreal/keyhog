#!/usr/bin/env python3
"""Triage adversarial_explosion_runner misses into E (engine/wrapper) vs C (contract) buckets."""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
CONTRACTS = REPO / "crates" / "scanner" / "tests" / "contracts"


def main() -> int:
    proc = subprocess.run(
        [
            "cargo",
            "run",
            "-p",
            "keyhog-scanner",
            "--profile",
            "release-fast",
            "--example",
            "adv_triage",
        ],
        cwd=REPO,
        text=True,
        capture_output=True,
    )
    out = proc.stdout + proc.stderr
    print(out)

    # Parse extended triage by patching adv_triage output
    m = re.search(r"TOTAL=(\d+) BARE_FAIL=(\d+) WRAP_FAIL_E=(\d+)", out)
    if not m:
        return 1
    total, bare_fail, wrap_e = map(int, m.groups())
    print(f"\nSummary: total_cases={total} bare_fail_C={bare_fail} wrap_only_E={wrap_e}", file=sys.stderr)
    print(f"adversarial_miss_estimate={bare_fail + wrap_e} (partial wrapper misses not counted)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
