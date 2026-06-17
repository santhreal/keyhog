#!/usr/bin/env python3
"""Gate #5 — COMPLEXITY BUDGET (a ratchet that can only tighten).

The disease behind the silent fallbacks is sprawl: `walk -> match -> emit`
spread across a dozen `fallback_*` lanes and several divergent backends, each
re-implementing a slice of the same job, each free to drift and hide its own
silent drop. Prose ("keep it simple") never stopped that growth. This gate makes
growth a RED BUILD: the scan engine may not gain a new fallback lane, a new
backend, or net LOC beyond the pinned budgets without a deliberate edit to the
budgets below — which shows up in the diff as "I am making this more complex on
purpose," the exact decision that was never made consciously here.

The budgets are a RATCHET: every number is the CURRENT measured value. When you
collapse a lane, LOWER the matching budget in the same commit. They must only
ever go DOWN. CI fails if the real count exceeds the budget.

Run: python3 scripts/gates/complexity_budget.py   (exit 1 on breach)
"""
from __future__ import annotations

import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]
ENGINE = REPO / "crates" / "scanner" / "src" / "engine"
SELECT = REPO / "crates" / "scanner" / "src" / "hw_probe" / "select.rs"

# ── BUDGETS (ratchet — only ever DECREASE these) ──────────────────────
# Pinned to the measured state on 2026-06-15. Lowering one as you simplify is
# the whole point; raising one must be a conscious, reviewed exception.
BUDGET = {
    "fallback_lanes": 12,        # engine/fallback_*.rs files (exact ratchet)
    "scan_backends": 4,          # ScanBackend:: variants (exact ratchet)
    "engine_files": 45,          # *.rs files under engine/ (exact ratchet)
    # LOC carries ~3% headroom so ordinary in-file edits don't trip it; the
    # structural counts above are the real "new divergent path" signal. Lower
    # all four as you collapse the engine.
    "engine_loc": 12000,         # total non-blank LOC under engine/ (now 11633)
}


def count_fallback_lanes() -> int:
    return len(list(ENGINE.glob("fallback_*.rs")))


def count_scan_backends() -> int:
    if not SELECT.exists():
        return 0
    text = SELECT.read_text()
    # `enum ScanBackend { Variant, ... }` — count the variant identifiers.
    m = re.search(r"enum\s+ScanBackend\s*\{(.*?)\}", text, re.S)
    if not m:
        # Fall back to distinct `ScanBackend::Variant` references.
        return len(set(re.findall(r"ScanBackend::([A-Z][A-Za-z0-9]+)", text)))
    body = m.group(1)
    return len(re.findall(r"^\s*([A-Z][A-Za-z0-9]+)\s*,", body, re.M))


def count_engine_loc() -> int:
    total = 0
    for f in ENGINE.glob("*.rs"):
        total += sum(1 for ln in f.read_text(errors="replace").splitlines() if ln.strip())
    return total


def count_engine_files() -> int:
    return len(list(ENGINE.glob("*.rs")))


def main() -> int:
    measured = {
        "fallback_lanes": count_fallback_lanes(),
        "scan_backends": count_scan_backends(),
        "engine_loc": count_engine_loc(),
        "engine_files": count_engine_files(),
    }
    breaches = []
    print("complexity budget (measured / budget):")
    for k, budget in BUDGET.items():
        got = measured[k]
        flag = "OK " if got <= budget else "OVER"
        print(f"  [{flag}] {k:16} {got} / {budget}")
        if got > budget:
            breaches.append((k, got, budget))

    if breaches:
        print("\nFAIL — the scan engine grew past its complexity budget:", file=sys.stderr)
        for k, got, budget in breaches:
            print(f"  {k}: {got} > {budget}. Either remove the new complexity, "
                  f"or — if it is genuinely necessary — raise the budget in "
                  f"scripts/gates/complexity_budget.py IN THIS COMMIT and say why.",
                  file=sys.stderr)
        return 1
    print("\nOK — scan engine within its complexity budget.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
