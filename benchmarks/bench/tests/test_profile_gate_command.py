"""Locks the bench profile-gate / profile-matrix command behavior."""

import json
import pathlib

from bench.__main__ import main
from bench.trials import NoiseReceipt, Trial, TrialSet

_BENCHMARKS = pathlib.Path(__file__).resolve().parents[2]


def _profile_file(path, stage_ns, *, run_id="run"):
    payload = {
        "version": 5,
        "envelope": {
            "version": 1,
            "schema": "keyhog-profile",
            "schema_version": {"version": 1, "major": 2, "minor": 4},
        },
        "identity": {"version": 1, "run_id": run_id},
        "wall_time_ns": sum(stage_ns.values()),
        "stages": [
            {"version": 1, "stage": name, "elapsed_ns": elapsed,
             "calls": 1, "attributed_ns": elapsed}
            for name, elapsed in stage_ns.items()
        ],
    }
    path.write_text(json.dumps(payload))
    return path


def _trial_set_file(path, workload, wall_ms):
    trial_set = TrialSet(
        schema_version="trial-set-v1",
        workload=workload,
        role="control",
        trials=(
            Trial(
                index=0, cache_state="steady", wall_ms=wall_ms, profile=None,
                noise=NoiseReceipt(
                    affinity_requested=True, affinity_applied=True,
                    affinity_cpus=8, governor="performance",
                    governor_required="performance", frequency_mhz=4200.0,
                    load_avg_before=(0.1, 0.1, 0.1),
                    load_avg_after=(0.1, 0.1, 0.1),
                ),
                invalid_reasons=(),
            ),
        ),
    )
    path.write_text(json.dumps(trial_set.to_json()))
    return path


_BUDGETS = _BENCHMARKS / "profile-gates" / "budgets.toml"


def _stage_budgets(tmp_path):
    path = tmp_path / "budgets.toml"
    path.write_text(
        "schema_version = 1\n"
        "[workflow.mirror]\n"
        "max_regression_ratio = 1.02\n"
        "[workflow.mirror.stages]\n"
        "decode = 1.05\n"
    )
    return path


def test_profile_gate_stage_pass(tmp_path, capsys):
    """The stage gate passes a candidate inside its decode ceiling."""
    control = _profile_file(tmp_path / "c.json", {"decode": 1_000_000})
    candidate = _profile_file(tmp_path / "k.json", {"decode": 1_040_000})
    code = main([
        "profile-gate", "--budgets", str(_stage_budgets(tmp_path)),
        "--workflow", "mirror",
        "--control-profile", str(control),
        "--candidate-profile", str(candidate),
    ])
    assert code == 0
    assert "PROFILE GATE PASSED" in capsys.readouterr().err


def test_profile_gate_stage_fail(tmp_path, capsys):
    """A 20% decode regression fails the command with the exact ratio."""
    control = _profile_file(tmp_path / "c.json", {"decode": 1_000_000})
    candidate = _profile_file(tmp_path / "k.json", {"decode": 1_200_000})
    code = main([
        "profile-gate", "--budgets", str(_stage_budgets(tmp_path)),
        "--workflow", "mirror",
        "--control-profile", str(control),
        "--candidate-profile", str(candidate),
    ])
    assert code == 1
    err = capsys.readouterr().err
    assert "PROFILE GATE FAILED" in err
    assert "1.2000" in err


def test_profile_gate_overhead_pass_and_fail(tmp_path, capsys):
    """The overhead gate compares profiled vs unprofiled trial walls against
    the committed 1.03 budget: 2% passes, 5% fails."""
    profiled_ok = _trial_set_file(tmp_path / "p1.json", "mirror", 102.0)
    profiled_bad = _trial_set_file(tmp_path / "p2.json", "mirror", 105.0)
    unprofiled = _trial_set_file(tmp_path / "u.json", "mirror", 100.0)
    code = main([
        "profile-gate", "--budgets", str(_BUDGETS),
        "--profiled-trials", str(profiled_ok),
        "--unprofiled-trials", str(unprofiled),
    ])
    assert code == 0
    capsys.readouterr()
    code = main([
        "profile-gate", "--budgets", str(_BUDGETS),
        "--profiled-trials", str(profiled_bad),
        "--unprofiled-trials", str(unprofiled),
    ])
    assert code == 1
    err = capsys.readouterr().err
    assert "overhead ratio 1.0500" in err


def test_profile_gate_undecidable_cases(tmp_path, capsys):
    """No gate selected, an unknown workflow, and a workload mismatch are all
    exit 2, never silent passes."""
    code = main(["profile-gate", "--budgets", str(_BUDGETS)])
    assert code == 2
    assert "no gate selected" in capsys.readouterr().err

    control = _profile_file(tmp_path / "c.json", {"decode": 1_000_000})
    candidate = _profile_file(tmp_path / "k.json", {"decode": 1_000_000})
    code = main([
        "profile-gate", "--budgets", str(_stage_budgets(tmp_path)),
        "--workflow", "nope",
        "--control-profile", str(control),
        "--candidate-profile", str(candidate),
    ])
    assert code == 2
    assert "no workflow 'nope' budget" in capsys.readouterr().err

    profiled = _trial_set_file(tmp_path / "p.json", "mirror", 100.0)
    unprofiled = _trial_set_file(tmp_path / "u.json", "creddata", 100.0)
    code = main([
        "profile-gate", "--budgets", str(_BUDGETS),
        "--profiled-trials", str(profiled),
        "--unprofiled-trials", str(unprofiled),
    ])
    assert code == 2
    assert "workload mismatch" in capsys.readouterr().err


def test_profile_matrix_plan_command(capsys):
    """The matrix command emits the deterministic 15-job nightly plan."""
    code = main([
        "profile-matrix",
        "--matrix", str(_BENCHMARKS / "profile-matrix" / "nightly.toml"),
    ])
    assert code == 0
    out = capsys.readouterr().out
    jobs = json.loads(out)
    assert len(jobs) == 15
    assert jobs[0]["job_id"] == "linux-arm64-hosted/creddata"
    assert jobs[0]["workload"]["steady"] == 5


def test_profile_matrix_rejects_bad_file(tmp_path, capsys):
    """A malformed matrix is exit 2 with the reason."""
    bad = tmp_path / "m.toml"
    bad.write_text("schema_version = 9\n")
    code = main(["profile-matrix", "--matrix", str(bad)])
    assert code == 2
    assert "schema_version" in capsys.readouterr().err
