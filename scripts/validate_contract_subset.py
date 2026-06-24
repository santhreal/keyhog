#!/usr/bin/env python3
"""Validate a subset of contract TOMLs against the Rust contracts_runner."""

from __future__ import annotations

import argparse
import pathlib
import re
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
CONTRACTS = REPO / "crates" / "scanner" / "tests" / "contracts"


def extract_top50_from_r1_log() -> list[str]:
    log = pathlib.Path("/tmp/round-r1-red-wall-full.log").read_text()
    out: list[str] = []
    seen: set[str] = set()
    for line in log.splitlines():
        if "positive MISSED" not in line or "scanner saw []" not in line:
            continue
        m = re.search(r"-\s+([^:]+): positive MISSED", line)
        if not m:
            continue
        det = m.group(1).strip()
        if det in seen:
            continue
        seen.add(det)
        out.append(det)
        if len(out) >= 50:
            break
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ids-file", type=pathlib.Path)
    ap.add_argument("--ids", nargs="*")
    args = ap.parse_args()

    if args.ids_file:
        ids = [
            line.strip()
            for line in args.ids_file.read_text().splitlines()
            if line.strip() and not line.startswith("#")
        ]
    elif args.ids:
        ids = args.ids
    else:
        ids = extract_top50_from_r1_log()

    cmd = [
        "cargo",
        "test",
        "-p",
        "keyhog-scanner",
        "--test",
        "contracts_runner",
        "--profile",
        "release-fast",
        "--",
        "every_contract_passes_positives_negatives_evasions",
        "--nocapture",
    ]
    print(f"Running contracts_runner for {len(ids)} detectors...", flush=True)
    proc = subprocess.run(
        cmd,
        cwd=REPO,
        text=True,
        capture_output=True,
    )
    combined = proc.stdout + proc.stderr
    failing: list[str] = []
    for det in ids:
        if f"{det}: positive MISSED" in combined:
            failing.append(det)

    print(f"PASS {len(ids) - len(failing)}/{len(ids)}")
    if failing:
        print("STILL FAILING:")
        for det in failing:
            for line in combined.splitlines():
                if det in line and "positive MISSED" in line:
                    print(f"  {line.strip()}")
                    break
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
