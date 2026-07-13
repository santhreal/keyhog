"""LANE 2 (the ONE prevention-gate entrypoint (`scripts/gates/run_all.sh`)).

These tests pin three contracts that the "merge every audit into one" change
made true, asserting EXACT values (never `is_empty`/`is_ok`):

  1. `run_all.sh` exits 0 on a clean tree (source-only mode), and the asset
     gates LOUD-SKIP rather than silently vanish (Law 10).
  2. EVERY audit keyhog has is referenced by `run_all.sh`: if a gate script is
     added to `scripts/gates/` or an audit is created and NOT wired into the one
     entrypoint, this test fails (the whole point of the merge: one runner, not
     a scatter a human forgets).
  3. The no-silent-fallbacks gate now covers the `cli` and `verifier` crates
     (the ~186-candidate blind spot) and its baseline records exactly the per-
     crate counts the merge produced.

Run from the benchmarks/ dir like every other bench test:
    python3 -B -m pytest -p no:cacheprovider bench/tests/test_run_all_gates_entrypoint.py
"""

from __future__ import annotations

import pathlib
import subprocess
import sys

import pytest

# benchmarks/bench/tests/<this> -> repo root is parents[3].
REPO = pathlib.Path(__file__).resolve().parents[3]
GATES = REPO / "scripts" / "gates"
RUN_ALL = GATES / "run_all.sh"
BASELINE = GATES / "silent_fallback_baseline.txt"
NSF = GATES / "no_silent_fallbacks.py"


def _run_all_text() -> str:
    return RUN_ALL.read_text()


# ---------------------------------------------------------------------------
# 1. Clean-tree exit code + loud (never silent) skips.
# ---------------------------------------------------------------------------

def test_run_all_exists_and_is_executable():
    assert RUN_ALL.is_file(), f"missing entrypoint: {RUN_ALL}"
    # rwx for owner at minimum; CI invokes it via `bash` so the bit is belt-and-
    # suspenders, but a non-executable canonical entrypoint is a smell.
    mode = RUN_ALL.stat().st_mode
    assert mode & 0o100, f"{RUN_ALL} is not owner-executable (mode {oct(mode)})"


def test_run_all_source_only_exits_zero_on_clean_tree():
    """GATES_SOURCE_ONLY=1 runs only the fast source/org gates (no corpus, no
    built binary, no network) and MUST exit 0 on a clean tree. This is the
    hermetic, deterministic clean-tree contract, a new RED here is a real gate
    regression, never something to weaken.

    Diagnostic note for a multi-lane integration run: if the ONLY failing gate is
    the complexity/org-audit pair (engine_loc over budget), that is a SIBLING
    lane's engine churn, not a defect in this entrypoint, the message below names
    it so the integrator reconciles the engine budget before merge rather than
    chasing run_all.sh. The assertion still REQUIRES exit 0 on the settled tree."""
    proc = subprocess.run(
        ["bash", str(RUN_ALL)],
        cwd=REPO,
        env={"GATES_SOURCE_ONLY": "1", "PATH": _path()},
        capture_output=True,
        text=True,
        timeout=300,
    )
    combined = proc.stdout + proc.stderr
    only_complexity = (
        proc.returncode != 0
        and "engine_loc:" in combined
        and "OVER" in combined
        # every gate this lane owns + the other source gates printed OK:
        and "no new silent fallbacks" in proc.stdout
        and "every subcommand surface has real-process coverage" in proc.stdout
    )
    diag = ""
    if only_complexity:
        diag = ("\n[diagnosis] The failing gate is the engine complexity budget "
                "(engine_loc OVER), owned by a SIBLING engine lane, not this "
                "audit-merge entrypoint. Integrator: reconcile the engine budget "
                "(trim engine LOC or raise BUDGET in complexity_budget.py) so this "
                "settled-tree contract is green.")
    assert proc.returncode == 0, (
        f"run_all.sh (source-only) exited {proc.returncode}, expected 0.{diag}\n"
        f"--- output ---\n{combined}"
    )
    assert "ALL PREVENTION GATES GREEN." in proc.stdout, combined


def test_run_all_source_only_loud_skips_every_asset_gate():
    """Every asset-bearing gate must announce its skip out loud (Law 10): a
    silent skip is a coverage hole nobody can see. In source-only mode all four
    asset gates skip, each printing a `SKIP (loud):` line."""
    proc = subprocess.run(
        ["bash", str(RUN_ALL)],
        cwd=REPO,
        env={"GATES_SOURCE_ONLY": "1", "PATH": _path()},
        capture_output=True,
        text=True,
        timeout=300,
    )
    out = proc.stdout
    asset_skips = [
        line
        for line in out.splitlines()
        if "SKIP (loud): GATES_SOURCE_ONLY=1" in line
    ]
    assert len(asset_skips) == 4, (
        f"expected 4 source-only asset skips, got {len(asset_skips)}\n{out}"
    )
    for marker in (
        "backend parity + recall floor",
        "differential bench gate",
        "cargo audit not run",
        "ML feature-parity gate not run",
    ):
        assert marker in out, f"missing loud-skip for {marker!r}:\n{out}"


def test_run_all_rejects_mutually_exclusive_modes():
    """GATES_SOURCE_ONLY=1 + STRICT_ASSETS=1 is a contradiction (force-skip all
    asset gates AND fail on any skip) and must hard-fail with exit 2, not run a
    guaranteed-red pass."""
    proc = subprocess.run(
        ["bash", str(RUN_ALL)],
        cwd=REPO,
        env={"GATES_SOURCE_ONLY": "1", "STRICT_ASSETS": "1", "PATH": _path()},
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 2, (
        f"expected exit 2 for mutually-exclusive modes, got {proc.returncode}\n"
        f"{proc.stdout}{proc.stderr}"
    )
    assert "mutually exclusive" in (proc.stdout + proc.stderr)


def _path() -> str:
    import os
    return os.environ.get("PATH", "/usr/bin:/bin")


# ---------------------------------------------------------------------------
# 2. Every audit is referenced by the one entrypoint.
# ---------------------------------------------------------------------------

# The canonical set of audits the merge folded into run_all.sh. Each entry is a
# (kind, path-or-token) the entrypoint MUST reference. A new gate script under
# scripts/gates/ that is not wired in fails `test_every_gate_script_is_wired`.
REQUIRED_REFERENCES = [
    "scripts/gates/no_silent_fallbacks.py",
    "scripts/gates/surface_coverage.py",
    "scripts/gates/complexity_budget.py",
    "scripts/org_audit.py",
    "scripts/audit.sh",
    "tests/docs/cli_claims_check.sh",
    "tests/integration/entrypoints_check.sh",
    "tools/ci-operability/Cargo.toml",
    "ml/parity_check.py",
    "bench/tests/test_backend_parity.py",
    "bench/tests/test_creddata_recall_matrix.py",
    "-m bench gate",  # the differential/regression bench gate
]


@pytest.mark.parametrize("ref", REQUIRED_REFERENCES)
def test_required_audit_is_referenced_by_run_all(ref: str):
    assert ref in _run_all_text(), (
        f"run_all.sh does not reference required audit {ref!r}; the one "
        f"entrypoint must invoke every audit."
    )


def test_every_gate_script_is_wired_into_run_all():
    """Any executable gate under scripts/gates/ (except this entrypoint and the
    baseline data file) must be referenced by run_all.sh, so adding a gate and
    forgetting to wire it is a RED build, not silent dead code."""
    text = _run_all_text()
    unwired = []
    for script in sorted(GATES.glob("*.py")):
        rel = f"scripts/gates/{script.name}"
        if rel not in text:
            unwired.append(rel)
    assert unwired == [], (
        f"gate script(s) under scripts/gates/ not wired into run_all.sh: "
        f"{unwired}. Wire each into scripts/gates/run_all.sh."
    )


# ---------------------------------------------------------------------------
# 3. no_silent_fallbacks now covers cli + verifier; baseline counts are pinned.
# ---------------------------------------------------------------------------

# cli + verifier are covered by the no-silent-fallbacks gate and the baseline is
# now empty. A non-zero count here means the zero-debt cleanup regressed.
EXPECTED_CLI = 0
EXPECTED_VERIFIER = 0
EXPECTED_BASELINE_BY_CRATE = {
    "cli": EXPECTED_CLI,
    "verifier": EXPECTED_VERIFIER,
}
EXPECTED_BASELINE_TOTAL = 0


def _baseline_by_crate() -> dict[str, int]:
    counts: dict[str, int] = {}
    for ln in BASELINE.read_text().splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        # key form: crates/<crate>/src/...::<code>
        parts = ln.split("/")
        if len(parts) >= 2 and parts[0] == "crates":
            counts[parts[1]] = counts.get(parts[1], 0) + 1
    return counts


def test_no_silent_fallbacks_gate_covers_cli_and_verifier():
    """The CRATES list in the gate MUST include cli + verifier (the prior blind
    spot)."""
    src = NSF.read_text()
    import re
    m = re.search(r"CRATES\s*=\s*\[([^\]]*)\]", src)
    assert m, "could not find CRATES = [...] in no_silent_fallbacks.py"
    crates = set(re.findall(r'"([a-z]+)"', m.group(1)))
    assert {"scanner", "sources", "core", "cli", "verifier"} <= crates, (
        f"no_silent_fallbacks CRATES must cover cli+verifier; got {sorted(crates)}"
    )


def test_baseline_cli_verifier_counts_are_exact():
    """cli + verifier coverage must not reintroduce baseline debt."""
    by_crate = _baseline_by_crate()
    assert by_crate.get("cli", 0) == EXPECTED_CLI, (
        f"cli baseline {by_crate.get('cli', 0)} != pinned {EXPECTED_CLI}"
    )
    assert by_crate.get("verifier", 0) == EXPECTED_VERIFIER, (
        f"verifier baseline {by_crate.get('verifier', 0)} != pinned {EXPECTED_VERIFIER}"
    )


def test_baseline_has_no_cli_or_verifier_entries_after_cleanup():
    """Spot-pin that cli + verifier stayed at the zero-debt baseline."""
    lines = [ln.strip() for ln in BASELINE.read_text().splitlines()
             if ln.strip() and not ln.startswith("#")]
    cli_entries = [ln for ln in lines if ln.startswith("crates/cli/src/")]
    ver_entries = [ln for ln in lines if ln.startswith("crates/verifier/src/")]
    assert cli_entries == [], cli_entries
    assert ver_entries == [], ver_entries


def test_gate_is_clean_on_current_tree():
    """The no-silent-fallbacks gate itself must exit 0 (no NEW candidate outside
    the baseline). The gate's `known` count is the LIVE candidate count, which is
    must remain exactly zero."""
    proc = subprocess.run(
        [sys.executable, str(NSF)],
        cwd=REPO,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, (
        f"no_silent_fallbacks gate is RED:\n{proc.stdout}{proc.stderr}"
    )
    import re
    m = re.search(r"(\d+) known", proc.stdout)
    assert m, f"gate did not print a `<n> known` count:\n{proc.stdout}"
    live = int(m.group(1))
    assert live == EXPECTED_BASELINE_TOTAL, (
        f"live candidate count {live} != pinned zero-debt baseline "
        f"{EXPECTED_BASELINE_TOTAL}:\n{proc.stdout}"
    )
