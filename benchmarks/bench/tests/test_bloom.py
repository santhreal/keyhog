from __future__ import annotations

import hashlib
import csv
import json
import pathlib
import subprocess

import pytest

from bench import bloom


def _write_meta(root: pathlib.Path, rows: list[dict[str, str]]) -> None:
    meta = root / "meta"
    meta.mkdir(parents=True)
    with (meta / "records.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["FilePath", "GroundTruth", "LineStart", "LineEnd"],
        )
        writer.writeheader()
        writer.writerows(rows)


def test_fixture_selects_fx_record_spans_and_declares_missing_inputs(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "CredData"
    (root / "data" / "repo").mkdir(parents=True)
    (root / "data" / "repo" / "negative.txt").write_text("ordinary source\n")
    (root / "data" / "repo" / "mixed.txt").write_text("mixed labels\n")
    _write_meta(
        root,
        [
            {
                "FilePath": "data/repo/negative.txt",
                "GroundTruth": "F",
                "LineStart": "1",
                "LineEnd": "1",
            },
            {
                "FilePath": "data/repo/negative.txt",
                "GroundTruth": "X",
                "LineStart": "1",
                "LineEnd": "1",
            },
            {
                "FilePath": "data/repo/mixed.txt",
                "GroundTruth": "F",
                "LineStart": "1",
                "LineEnd": "1",
            },
            {
                "FilePath": "data/repo/mixed.txt",
                "GroundTruth": "T",
                "LineStart": "1",
                "LineEnd": "1",
            },
            {
                "FilePath": "data/repo/missing.txt",
                "GroundTruth": "X",
                "LineStart": "1",
                "LineEnd": "1",
            },
        ],
    )
    monkeypatch.setattr(bloom, "_git_revision", lambda _: bloom.CREDDATA_PIN)
    output = tmp_path / "fixture.json"

    fixture = bloom.build_fixture(root=root, output=output)

    assert fixture["schema_version"] == bloom.FIXTURE_SCHEMA
    assert fixture["declared_input_count"] == 4
    assert fixture["inputs"] == [
        {
            "id": "creddata-record:records.csv:3:data/repo/mixed.txt:1:1",
            "path": "data/repo/mixed.txt",
            "labels": ["F"],
            "line_start": 1,
            "line_end": 1,
        },
        {
            "id": "creddata-record:records.csv:1:data/repo/negative.txt:1:1",
            "path": "data/repo/negative.txt",
            "labels": ["F"],
            "line_start": 1,
            "line_end": 1,
        },
        {
            "id": "creddata-record:records.csv:2:data/repo/negative.txt:1:1",
            "path": "data/repo/negative.txt",
            "labels": ["X"],
            "line_start": 1,
            "line_end": 1,
        },
    ]
    assert fixture["unavailable_inputs"] == [
        {
            "id": "creddata-record:records.csv:5:data/repo/missing.txt:1:1",
            "path": "data/repo/missing.txt",
            "category": bloom.UNAVAILABLE_SOURCE_FILE_MISSING,
            "reason": "source file absent from configured pinned CredData checkout",
        }
    ]
    assert json.loads(output.read_text()) == fixture


def _result(rejected: int = 4, identical: bool = True) -> dict[str, object]:
    digest = "a" * 64
    return {
        "schema_version": bloom.RESULT_SCHEMA,
        "corpus_name": "creddata-test",
        "corpus_revision": bloom.CREDDATA_PIN,
        "fixture_sha256": "f" * 64,
        "detector_corpus_sha256": "e" * 64,
        "declared_input_count": 12,
        "executable_sha256": "b" * 64,
        "workspace_detector_corpus_sha256": "7" * 64,
        "unavailable_input_count": 2,
        "unavailable_reason_counts": {bloom.UNAVAILABLE_SOURCE_FILE_MISSING: 2},
        "rejected_input_count": rejected,
        "input_count": 10,
        "eligible_input_count": 8,
        "admitted_input_count": 10 - rejected,
        "rejection_basis_points": rejected * 1_000,
        "populated_slots": 18_437,
        "total_slots": 65_536,
        "saturation_threshold_slots": 39_322,
        "density_basis_points": 2_813,
        "state": "healthy",
        "enabled_finding_count": 3,
        "bypass_finding_count": 3,
        "enabled_findings_sha256": digest,
        "bypass_findings_sha256": digest if identical else "b" * 64,
        "findings_identical": identical,
        "corpus_sha256": "c" * 64,
        "scanner_detector_digest": "d" * 16,
    }


def test_report_renders_exact_rejection_identity_and_parity_fields() -> None:
    report = bloom.render_report(_result())

    assert "`creddata-test`" in report
    assert "**4/10 (40.00%)**; 6 admitted" in report
    assert "3/3 findings" in report
    assert "**IDENTICAL**" in report
    assert "`aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`" in report
    assert "reasons: source-file-missing=2" in report
    assert "byte span, and credential SHA-256" in report


def test_measure_persists_positive_rejection_and_exact_differential(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "CredData"
    (root / "data").mkdir(parents=True)
    (root / "meta").mkdir()
    emitted = _result()
    keyhog = tmp_path / "keyhog"
    keyhog.write_bytes(b"measured executable")
    monkeypatch.setattr(
        bloom,
        "workspace_detector_corpus_sha256",
        lambda: "7" * 64,
    )
    monkeypatch.setattr(
        bloom.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args=args[0], returncode=0, stdout=json.dumps(emitted), stderr=""
        ),
    )
    emitted.pop("executable_sha256")
    emitted.pop("workspace_detector_corpus_sha256")
    output = tmp_path / "result.json"

    result = bloom.measure(
        keyhog=keyhog,
        fixture=tmp_path / "fixture.json",
        corpus_root=root,
        output=output,
    )

    expected = emitted | {
        "executable_sha256": hashlib.sha256(b"measured executable").hexdigest(),
        "workspace_detector_corpus_sha256": "7" * 64,
    }
    assert result == expected
    assert json.loads(output.read_text()) == expected


@pytest.mark.parametrize(
    ("emitted", "message"),
    [
        (_result(rejected=0), "rejected zero inputs"),
        (_result(identical=False), "finding parity"),
        (
            _result() | {"unavailable_reason_counts": {"unknown": 2}},
            "reason accounting",
        ),
    ],
)
def test_measure_refuses_zero_rejection_or_nonidentical_findings(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    emitted: dict[str, object],
    message: str,
) -> None:
    root = tmp_path / "CredData"
    (root / "data").mkdir(parents=True)
    (root / "meta").mkdir()
    keyhog = tmp_path / "keyhog"
    keyhog.write_bytes(b"measured executable")
    emitted.pop("executable_sha256")
    emitted.pop("workspace_detector_corpus_sha256")
    monkeypatch.setattr(
        bloom,
        "workspace_detector_corpus_sha256",
        lambda: "7" * 64,
    )
    monkeypatch.setattr(
        bloom.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args=args[0], returncode=0, stdout=json.dumps(emitted), stderr=""
        ),
    )

    with pytest.raises(SystemExit, match=message):
        bloom.measure(
            keyhog=keyhog,
            fixture=tmp_path / "fixture.json",
            corpus_root=root,
            output=tmp_path / "result.json",
        )
