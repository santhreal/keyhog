"""Behavioral contracts for pinned performance hardware and software identities."""

from __future__ import annotations

import json
import pathlib

import pytest

from bench.target_matrix import (
    REQUIRED_TARGET_IDS,
    TargetMatrixError,
    load_target_matrix,
    target_matrix_sha256,
    validate_target_evidence,
)

BENCHMARKS = pathlib.Path(__file__).resolve().parents[2]
MATRIX_PATH = BENCHMARKS / "target-matrix.toml"


def _matrix_text() -> str:
    return MATRIX_PATH.read_text(encoding="utf-8")


def _load_text(tmp_path: pathlib.Path, text: str):
    path = tmp_path / "target-matrix.toml"
    path.write_text(text, encoding="utf-8")
    return load_target_matrix(path)


def test_canonical_target_matrix_pins_every_release_lane_and_evidence() -> None:
    """WHY: performance evidence without an exact host or constrained runner identity cannot support cross-run release claims."""
    matrix = load_target_matrix(MATRIX_PATH)
    validate_target_evidence(matrix, BENCHMARKS)
    assert {target.target_id for target in matrix.targets} == REQUIRED_TARGET_IDS
    assert matrix.software.workspace_version == "0.5.68"
    assert matrix.software.rustc == "1.89.0 (29483883e 2025-08-04)"
    assert matrix.software.vyre == "0.7.2"
    assert matrix.software.hyperscan == "5.4.2"
    assert len(target_matrix_sha256(MATRIX_PATH)) == 64


def test_exact_desktop_and_mac_targets_match_recorded_host_receipts() -> None:
    """WHY: hand-written host labels must agree with the authoritative captured hardware bytes rather than naming aspirational devices."""
    matrix = load_target_matrix(MATRIX_PATH)
    by_id = {target.target_id: target for target in matrix.targets}
    cases = [
        (
            by_id["linux-x86_64-rtx5090"],
            BENCHMARKS / "target-evidence/linux-x86_64-rtx5090.json",
        ),
        (
            by_id["macos-arm64-m4-pro"],
            BENCHMARKS / "target-evidence/macos-arm64-m4-pro.json",
        ),
    ]
    for target, path in cases:
        host = json.loads(path.read_text(encoding="utf-8"))["host"]
        assert target.cpu == host["cpu"]
        assert target.logical_cores == host["cores"]
        assert target.min_ram_mb == host["ram_mb"]
        if host["gpu"]:
            assert target.gpu == host["gpu"]
            assert target.min_gpu_vram_mb == host["gpu_vram_mb"]


def test_target_matrix_rejects_a_missing_release_lane(tmp_path: pathlib.Path) -> None:
    """WHY: deleting Windows or a constrained host from the matrix must not redefine the release around the fastest development machine."""
    text = _matrix_text()
    start = text.index('[[target]]\nid = "windows-x86_64-laptop"')
    partial = text[:start]
    with pytest.raises(TargetMatrixError, match="missing=.*windows-x86_64-laptop"):
        _load_text(tmp_path, partial)


def test_target_matrix_rejects_backend_coverage_loss(tmp_path: pathlib.Path) -> None:
    """WHY: every target must exercise automatic selection and its scalar correctness peer, even when accelerators are unavailable."""
    weakened = _matrix_text().replace(
        'required_backends = ["auto", "cpu", "simd"]',
        'required_backends = ["simd"]',
        1,
    )
    with pytest.raises(TargetMatrixError, match="must gate both cpu and auto"):
        _load_text(tmp_path, weakened)


def test_target_matrix_rejects_untraceable_evidence(tmp_path: pathlib.Path) -> None:
    """WHY: a target row without existing evidence bytes is a marketing label, not a pinned measurement identity."""
    broken = _matrix_text().replace(
        "target-evidence/linux-x86_64-rtx5090.json",
        "target-evidence/missing.json",
        1,
    )
    matrix = _load_text(tmp_path, broken)
    with pytest.raises(TargetMatrixError, match="evidence does not exist.*linux-x86_64-rtx5090"):
        validate_target_evidence(matrix, BENCHMARKS)


def test_target_matrix_rejects_path_escape(tmp_path: pathlib.Path) -> None:
    """WHY: host identity must remain bound to reviewed benchmark artifacts and cannot substitute ambient files outside the repository."""
    escaped = _matrix_text().replace(
        "profile-matrix/nightly.toml", "../ambient-host.json", 1
    )
    matrix = _load_text(tmp_path, escaped)
    with pytest.raises(TargetMatrixError, match="evidence must be benchmark-relative"):
        validate_target_evidence(matrix, BENCHMARKS)
