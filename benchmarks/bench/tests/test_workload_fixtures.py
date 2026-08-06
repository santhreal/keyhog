"""Determinism and fail-closed contracts for canonical workload fixtures."""

from __future__ import annotations

import json
import pathlib

import pytest

from bench.workload_catalog import load_workload_catalog
from bench.workload_fixtures import (
    CANARY,
    CANARY_SHA256,
    WorkloadFixtureError,
    materialize_catalog,
    materialize_fixture,
    _remove_fixture_tree_iterative,
    validate_fixture_lock,
)

CATALOG_PATH = pathlib.Path(__file__).resolve().parents[2] / "workload-catalog.toml"
LOCK_PATH = pathlib.Path(__file__).resolve().parents[2] / "workload-fixtures.lock.json"


def test_every_catalog_workload_materializes_with_exact_receipts(
    tmp_path: pathlib.Path,
) -> None:
    """WHY: a workload without real input and answer bytes cannot participate in baseline, parity, memory, or speed gates."""
    catalog = load_workload_catalog(CATALOG_PATH)
    receipts = materialize_catalog(CATALOG_PATH, tmp_path, scale=0.0001)
    assert len(receipts) == len(catalog.workloads) == 59
    assert {receipt.workload_id for receipt in receipts} == {
        workload.workload_id for workload in catalog.workloads
    }
    for receipt in receipts:
        assert len(receipt.input_sha256) == 64
        assert len(receipt.answer_sha256) == 64
        assert receipt.input_bytes >= 0
        assert receipt.input_files >= 0
        assert (receipt.root / "fixture.json").is_file()
        assert (receipt.root / "answers.json").is_file()


def test_materialization_is_byte_deterministic_across_roots(tmp_path: pathlib.Path) -> None:
    """WHY: baseline comparisons require the same workload identity on different hosts and cannot include temporary path spelling."""
    catalog = load_workload_catalog(CATALOG_PATH)
    workload = next(
        item for item in catalog.workloads if item.workload_id == "filesystem-many-small-files"
    )
    first = materialize_fixture(workload, tmp_path / "first", scale=0.001)
    second = materialize_fixture(workload, tmp_path / "second", scale=0.001)
    assert first.input_sha256 == second.input_sha256
    assert first.answer_sha256 == second.answer_sha256
    assert first.input_bytes == second.input_bytes
    assert first.input_files == second.input_files
    assert first.expected_findings == second.expected_findings == 1


def test_answer_key_contains_only_canary_digest(tmp_path: pathlib.Path) -> None:
    """WHY: benchmark receipts may be committed or uploaded, so they bind expected credentials without copying plaintext into answer artifacts."""
    catalog = load_workload_catalog(CATALOG_PATH)
    workload = next(
        item for item in catalog.workloads if item.workload_id == "stdin-tiny"
    )
    receipt = materialize_fixture(workload, tmp_path)
    answer_bytes = (receipt.root / "answers.json").read_bytes()
    assert CANARY.encode() not in answer_bytes
    assert CANARY_SHA256.encode() in answer_bytes


def test_unreadable_fixture_digest_precedes_runtime_permission_mutation(
    tmp_path: pathlib.Path,
) -> None:
    """WHY: chmod-based coverage fixtures still need a complete input digest; making them unreadable before hashing silently omitted the canary bytes."""
    catalog = load_workload_catalog(CATALOG_PATH)
    workload = next(
        item for item in catalog.workloads if item.workload_id == "filesystem-unreadable-tree"
    )
    receipt = materialize_fixture(workload, tmp_path)
    assert receipt.input_files == 2
    assert receipt.input_bytes > len(CANARY)
    assert (receipt.root / "input/locked/secret.env").read_text().strip().endswith(CANARY)
    assert (receipt.root / "input/unreadable-plan.json").is_file()


def test_unknown_fixture_selection_fails_before_writing(tmp_path: pathlib.Path) -> None:
    """WHY: misspelled workload filters must not yield an empty successful benchmark that appears to cover the requested route."""
    with pytest.raises(WorkloadFixtureError, match="unknown workload fixture ids"):
        materialize_catalog(CATALOG_PATH, tmp_path, only={"missing-workload"})
    assert not any(tmp_path.iterdir())


def test_invalid_fixture_scale_fails_closed(tmp_path: pathlib.Path) -> None:
    """WHY: zero or super-canonical scale silently changes workload shape and invalidates its performance identity."""
    catalog = load_workload_catalog(CATALOG_PATH)
    workload = catalog.workloads[0]
    for scale in (0.0, -1.0, 1.01):
        with pytest.raises(WorkloadFixtureError, match="fixture scale"):
            materialize_fixture(workload, tmp_path / str(scale), scale=scale)


def test_materializer_refuses_unowned_destination(tmp_path: pathlib.Path) -> None:
    """WHY: fixture regeneration must never delete an operator directory that lacks the materializer ownership receipt."""
    catalog = load_workload_catalog(CATALOG_PATH)
    workload = next(
        item for item in catalog.workloads if item.workload_id == "stdin-tiny"
    )
    destination = tmp_path / workload.workload_id
    destination.mkdir()
    sentinel = destination / "operator-data"
    sentinel.write_text("preserve me", encoding="utf-8")
    with pytest.raises(WorkloadFixtureError, match="refusing to replace unowned"):
        materialize_fixture(workload, tmp_path)
    assert sentinel.read_text(encoding="utf-8") == "preserve me"


def test_committed_lock_records_every_exact_input_and_answer_digest() -> None:
    """WHY: performance rows must bind the exact generated input and oracle bytes instead of a mutable corpus nickname."""
    payload = validate_fixture_lock(CATALOG_PATH, LOCK_PATH)
    rows = payload["workloads"]
    assert isinstance(rows, list)
    assert len(rows) == 59
    assert all(row["input_sha256"] != row["answer_sha256"] for row in rows)
    assert sum(row["input_bytes"] for row in rows) > 700 * 1024 * 1024
    assert sum(row["input_files"] for row in rows) > 200_000


def test_fixture_lock_rejects_catalog_drift(tmp_path: pathlib.Path) -> None:
    """WHY: adding or changing a workload invalidates every claim that still points at the previous fixture generation."""
    payload = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
    payload["catalog_sha256"] = "0" * 64
    lock = tmp_path / "drifted.json"
    lock.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(WorkloadFixtureError, match="catalog digest does not match"):
        validate_fixture_lock(CATALOG_PATH, lock)


def test_fixture_lock_rejects_missing_workload_receipt(tmp_path: pathlib.Path) -> None:
    """WHY: a partial lock must not let unmeasured workloads disappear from release-wide speed and memory claims."""
    payload = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
    payload["workloads"].pop()
    lock = tmp_path / "partial.json"
    lock.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(WorkloadFixtureError, match="does not cover the complete catalog"):
        validate_fixture_lock(CATALOG_PATH, lock)


def test_fixture_lock_rejects_malformed_digest(tmp_path: pathlib.Path) -> None:
    """WHY: truncated or noncanonical hashes cannot bind a result to exact fixture bytes and must never be accepted as provenance."""
    payload = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
    payload["workloads"][0]["input_sha256"] = "ABC"
    lock = tmp_path / "malformed.json"
    lock.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(WorkloadFixtureError, match="input_sha256 must be lowercase SHA-256"):
        validate_fixture_lock(CATALOG_PATH, lock)


def test_stdin_fixture_sizes_preserve_tiny_medium_and_bounded_large_regimes(
    tmp_path: pathlib.Path,
) -> None:
    """WHY: reusing one tiny canary for every stdin row would manufacture identical timings and leave buffering and bounded-memory behavior unmeasured."""
    catalog = load_workload_catalog(CATALOG_PATH)
    expected = {"stdin-tiny": len(f"GITHUB_TOKEN={CANARY}\n"), "stdin-medium": 64 * 1024, "stdin-large-bounded": 8 * 1024 * 1024}
    for workload_id, byte_count in expected.items():
        workload = next(item for item in catalog.workloads if item.workload_id == workload_id)
        receipt = materialize_fixture(workload, tmp_path)
        assert (receipt.root / "input/stdin.bin").stat().st_size == byte_count
        assert receipt.expected_findings == 1


def test_one_long_line_fixture_is_one_line_with_a_delimited_canary(
    tmp_path: pathlib.Path,
) -> None:
    """WHY: newline-bearing filler or an alphanumeric byte after the canary turns this into an ordinary-line workload or invalidates the expected credential."""
    catalog = load_workload_catalog(CATALOG_PATH)
    workload = next(
        item
        for item in catalog.workloads
        if item.workload_id == "filesystem-one-long-line"
    )
    receipt = materialize_fixture(workload, tmp_path, scale=0.001)
    payload = (receipt.root / "input/single-line.json").read_bytes()
    assert len(payload) == int(50 * 1024 * 1024 * 0.001)
    assert payload.startswith(f"GITHUB_TOKEN={CANARY} ".encode())
    assert b"\n" not in payload
    assert receipt.expected_findings == 1
    assert receipt.expected_coverage_gap is True

def test_fixture_oracles_require_expected_coverage_gaps(
    tmp_path: pathlib.Path,
) -> None:
    """WHY: zero-byte sources, bounded truncation, shallow history, and hosted-clone default exclusions must preserve their honest coverage warnings in baseline parity."""
    catalog = load_workload_catalog(CATALOG_PATH)
    gap_ids = {
        "filesystem-empty-directory",
        "filesystem-single-large-file",
        "filesystem-one-long-line",
        "filesystem-sparse-files",
        "stdin-empty",
        "stdin-large-bounded",
        "git-shallow-clone",
        "github-organization-repositories",
        "gitlab-group-projects",
        "bitbucket-workspace-repositories",
    }
    for workload_id in gap_ids:
        workload = next(item for item in catalog.workloads if item.workload_id == workload_id)
        scale = (
            0.001
            if workload_id
            in {
                "filesystem-single-large-file",
                "filesystem-one-long-line",
                "filesystem-sparse-files",
            }
            else 1.0
        )
        assert materialize_fixture(workload, tmp_path, scale=scale).expected_coverage_gap is True
    binary = next(
        item for item in catalog.workloads if item.workload_id == "filesystem-binary-rejection"
    )
    binary_receipt = materialize_fixture(binary, tmp_path)
    assert binary_receipt.expected_findings == 1
    assert binary_receipt.expected_coverage_gap is False
    complete = next(item for item in catalog.workloads if item.workload_id == "stdin-medium")
    assert materialize_fixture(complete, tmp_path).expected_coverage_gap is False


def test_web_fixtures_exercise_javascript_source_map_wasm_and_multi_url_bytes(
    tmp_path: pathlib.Path,
) -> None:
    """WHY: four URL workload names backed by the same text file never exercise source-map extraction, binary WASM handling, or multi-response merging."""
    catalog = load_workload_catalog(CATALOG_PATH)
    receipts = {}
    for workload_id in ("web-javascript", "web-source-map", "web-wasm-binary", "web-multiple-urls"):
        workload = next(item for item in catalog.workloads if item.workload_id == workload_id)
        receipts[workload_id] = materialize_fixture(workload, tmp_path)
    assert (receipts["web-wasm-binary"].root / "input/responses/module.wasm").read_bytes().startswith(b"\x00asm")
    source_map = json.loads((receipts["web-source-map"].root / "input/responses/app.js.map").read_text())
    assert source_map["sourcesContent"] == [f"GITHUB_TOKEN={CANARY}\n"]
    assert receipts["web-multiple-urls"].expected_findings == 2
    assert receipts["web-javascript"].expected_findings == 1


def test_daemon_fixtures_bind_warm_and_mass_transport_shapes(tmp_path: pathlib.Path) -> None:
    """WHY: one shared file cannot prove stdin framing, directory mass batching, and remote mass batching through their distinct production routes."""
    catalog = load_workload_catalog(CATALOG_PATH)
    expected = {
        "daemon-warm-single-file": "request/secret.env",
        "daemon-warm-stdin": "request/stdin.bin",
        "daemon-mass-filesystem": "request/tree/secret.env",
        "daemon-mass-remote": "responses/secret.env",
    }
    for workload_id, relative in expected.items():
        workload = next(item for item in catalog.workloads if item.workload_id == workload_id)
        receipt = materialize_fixture(workload, tmp_path)
        assert (receipt.root / "input" / relative).read_bytes() == f"GITHUB_TOKEN={CANARY}\n".encode()


def test_deep_fixture_can_be_atomically_replaced_without_python_recursion(tmp_path: pathlib.Path) -> None:
    """WHY: canonical regeneration replaces the 4096-level tree; shutil.rmtree recursed past Python's limit and prevented fixture-lock updates after the first capture."""
    catalog=load_workload_catalog(CATALOG_PATH)
    workload=next(item for item in catalog.workloads if item.workload_id=="filesystem-deep-directory-tree")
    try:
        first=materialize_fixture(workload,tmp_path,scale=0.25)
        second=materialize_fixture(workload,tmp_path,scale=0.25)
        assert second.input_sha256==first.input_sha256
        assert second.answer_sha256==first.answer_sha256
        assert second.input_files==2
    finally:
        destination=tmp_path/workload.workload_id
        if destination.exists(): _remove_fixture_tree_iterative(destination)
