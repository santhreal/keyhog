from __future__ import annotations

import json
import pathlib
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[3]
VALIDATOR = REPO / "scripts" / "gpu_crossover_artifact.py"
GIT_HASH = "0123456789012345678901234567890123456789"


def valid_artifact() -> dict[str, object]:
    return {
        "schema_version": 8,
        "git_hash": GIT_HASH,
        "build_source_tree_state": "clean",
        "source_tree_state": "clean",
        "diagnostic": False,
        "production_comparable": True,
        "crossover_passed": True,
        "source_bytes": 8 * 1024 * 1024,
        "held_out_pairs": 100,
        "selection_rounds": 20,
        "full_result_parity": True,
        "gpu_degraded": False,
        "ratio_ci95_high": 0.98,
        "fastest_hyperscan_backend": "simd-hyperscan",
        "selected_gpu_backend": "gpu-cuda-region-presence",
        "selected_gpu_driver": "cuda",
        "selected_gpu_driver_version": "0.6.5",
        "selected_gpu_device": "NVIDIA RTX 5090",
        "selected_gpu_runtime": "CUDA 13",
        "compiled_features": "simd=true,gpu=true,decode=true,entropy=true",
        "resolved_tuning": "ResolvedScannerTuningConfig { fallback_hs: true }",
        "binary_sha256": "a" * 64,
        "detector_spec_blake3": "b" * 64,
        "scanner_detector_digest": "c" * 16,
    }


def run_validator(tmp_path: pathlib.Path, artifact: dict[str, object]) -> subprocess.CompletedProcess[str]:
    path = tmp_path / "gpu-crossover.toml"
    encoded = []
    for key, value in artifact.items():
        if isinstance(value, bool):
            rendered = str(value).lower()
        elif isinstance(value, str):
            rendered = json.dumps(value)
        else:
            rendered = str(value)
        encoded.append(f"{key} = {rendered}")
    path.write_text("\n".join(encoded) + "\n")
    return subprocess.run(
        [sys.executable, str(VALIDATOR), str(path), "--git-hash", GIT_HASH],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=False,
    )


def test_accepts_complete_candidate_bound_evidence(tmp_path: pathlib.Path) -> None:
    result = run_validator(tmp_path, valid_artifact())
    assert result.returncode == 0, result.stderr
    assert result.stdout == f"GPU crossover evidence accepted: {tmp_path / 'gpu-crossover.toml'}\n"


def test_rejects_dirty_stale_or_nonwinning_evidence(tmp_path: pathlib.Path) -> None:
    artifact = valid_artifact()
    artifact.update(
        git_hash="f" * 40,
        build_source_tree_state="dirty",
        production_comparable=False,
        crossover_passed=False,
        full_result_parity=False,
        gpu_degraded=True,
        ratio_ci95_high=1.01,
    )
    result = run_validator(tmp_path, artifact)
    assert result.returncode == 1
    assert result.stderr.splitlines() == [
        "GPU crossover evidence rejected: git_hash must match the candidate source",
        "GPU crossover evidence rejected: benchmark binary must be built from a clean tree",
        "GPU crossover evidence rejected: production_comparable must be true",
        "GPU crossover evidence rejected: crossover_passed must be true",
        "GPU crossover evidence rejected: full finding parity must pass",
        "GPU crossover evidence rejected: GPU execution must not be degraded",
        "GPU crossover evidence rejected: GPU/Hyperscan 95% ratio upper bound must be finite and below 1.0",
    ]
