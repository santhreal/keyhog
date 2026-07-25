"""Dedicated tests for canonical baseline inventory selection (KH-019).

These tests prove:
* one declared canonical baseline is selected per corpus,
* missing, duplicate, and ambiguous inventory entries fail loudly,
* files under ``archive/`` cannot win even when they have a newer generated_at
  or a higher F1,
* the regression gate wraps inventory errors as undecidable ``GateError``.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from bench import baseline_inventory, gate
from bench.schema import (
    CorpusInfo,
    Detection,
    Host,
    Outcome,
    RunResult,
    Scanner,
    ScannerConfig,
    Speed,
)


def _write_result(path: pathlib.Path, run: RunResult) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(run.to_json()))


def _make_run(
    corpus: str,
    scanner: str,
    tp: int,
    fp: int,
    fn: int,
    *,
    generated_at: str = "2026-01-01T00:00:00",
) -> RunResult:
    return RunResult(
        schema_version="bench-v3",
        generated_at=generated_at,
        host=Host(),
        scanner=Scanner(name=scanner, config=ScannerConfig(), version="test"),
        corpus=CorpusInfo(
            name=corpus,
            fixture_count=tp + fn,
            labeled_positives=tp + fn,
            bytes=0,
        ),
        detection=Detection(overall=Outcome(tp=tp, fp=fp, fn=fn)),
        speed=Speed(),
        finding_count=tp + fp,
    )


def _fresh_baselines(tmp_path: pathlib.Path) -> pathlib.Path:
    d = tmp_path / "baselines"
    d.mkdir()
    (d / "archive").mkdir()
    return d


def _write_inventory(d: pathlib.Path, text: str) -> None:
    (d / "canonical.toml").write_text(text)


def test_canonical_selection_ignores_newer_historical_file(tmp_path: pathlib.Path):
    """Only the declared active baseline is loaded; a newer/higher-F1 archived
    file must not win by filename or generated_at ordering."""
    d = _fresh_baselines(tmp_path)
    active = _make_run("mirror", "keyhog", 6, 4, 0, generated_at="2026-07-20T00:00:00")
    historical = _make_run(
        "mirror", "keyhog", 10, 0, 0, generated_at="2026-07-21T00:00:00"
    )
    _write_result(d / "mirror-keyhog-baseline.json", active)
    _write_result(d / "archive" / "mirror-keyhog-baseline-v99.json", historical)
    _write_inventory(d, '[mirror]\npath = "mirror-keyhog-baseline.json"\n')

    chosen = baseline_inventory.load_canonical("mirror", baselines_dir=d)
    assert chosen.generated_at == active.generated_at
    assert chosen.detection.overall.f1() == active.detection.overall.f1()
    assert chosen.detection.overall.f1() != historical.detection.overall.f1()


def test_resolve_rejects_missing_inventory(tmp_path: pathlib.Path):
    d = _fresh_baselines(tmp_path)
    with pytest.raises(baseline_inventory.BaselineInventoryError, match="missing canonical baseline inventory"):
        baseline_inventory.load_canonical("mirror", baselines_dir=d)


def test_resolve_rejects_missing_corpus(tmp_path: pathlib.Path):
    d = _fresh_baselines(tmp_path)
    other = _make_run("other", "keyhog", 1, 0, 0)
    _write_result(d / "other.json", other)
    _write_inventory(d, '[other]\npath = "other.json"\n')

    with pytest.raises(baseline_inventory.BaselineInventoryError, match="no canonical baseline declared for corpus 'mirror'"):
        baseline_inventory.load_canonical("mirror", baselines_dir=d)


def test_resolve_rejects_canonical_path_in_archive(tmp_path: pathlib.Path):
    d = _fresh_baselines(tmp_path)
    historical = _make_run("mirror", "keyhog", 10, 0, 0)
    _write_result(d / "archive" / "mirror-keyhog-baseline.json", historical)
    _write_inventory(d, '[mirror]\npath = "archive/mirror-keyhog-baseline.json"\n')

    with pytest.raises(baseline_inventory.BaselineInventoryError, match="points into the archive"):
        baseline_inventory.load_canonical("mirror", baselines_dir=d)


def test_resolve_rejects_ambiguous_path_across_corpora(tmp_path: pathlib.Path):
    d = _fresh_baselines(tmp_path)
    run = _make_run("mirror", "keyhog", 1, 0, 0)
    _write_result(d / "shared.json", run)
    _write_inventory(
        d,
        '[mirror]\npath = "shared.json"\n[other]\npath = "shared.json"\n',
    )

    with pytest.raises(
        baseline_inventory.BaselineInventoryError,
        match="ambiguous canonical baseline: path 'shared.json' is declared for multiple corpora",
    ):
        baseline_inventory.load_canonical("mirror", baselines_dir=d)


def test_resolve_rejects_path_escape(tmp_path: pathlib.Path):
    d = _fresh_baselines(tmp_path)
    escape = tmp_path / "escape.json"
    run = _make_run("mirror", "keyhog", 1, 0, 0)
    _write_result(escape, run)
    _write_inventory(d, '[mirror]\npath = "../escape.json"\n')
    with pytest.raises(
        baseline_inventory.BaselineInventoryError,
        match="must be a relative path without '..'",
    ):
        baseline_inventory.load_canonical("mirror", baselines_dir=d)


def test_resolve_rejects_missing_baseline_file(tmp_path: pathlib.Path):
    d = _fresh_baselines(tmp_path)
    _write_inventory(d, '[mirror]\npath = "missing.json"\n')

    with pytest.raises(
        baseline_inventory.BaselineInventoryError,
        match="does not exist",
    ):
        baseline_inventory.load_canonical("mirror", baselines_dir=d)


def test_resolve_rejects_non_file_path(tmp_path: pathlib.Path):
    d = _fresh_baselines(tmp_path)
    (d / "directory").mkdir()
    _write_inventory(d, '[mirror]\npath = "directory"\n')

    with pytest.raises(
        baseline_inventory.BaselineInventoryError,
        match="is not a file",
    ):
        baseline_inventory.load_canonical("mirror", baselines_dir=d)


def test_resolve_rejects_invalid_runresult(tmp_path: pathlib.Path):
    d = _fresh_baselines(tmp_path)
    (d / "bad.json").write_text('{"not": "valid"}')
    _write_inventory(d, '[mirror]\npath = "bad.json"\n')

    with pytest.raises(
        baseline_inventory.BaselineInventoryError,
        match="is not a valid RunResult",
    ):
        baseline_inventory.load_canonical("mirror", baselines_dir=d)


def test_resolve_rejects_non_keyhog_baseline(tmp_path: pathlib.Path):
    d = _fresh_baselines(tmp_path)
    run = _make_run("mirror", "titus", 1, 0, 0)
    _write_result(d / "titus.json", run)
    _write_inventory(d, '[mirror]\npath = "titus.json"\n')

    with pytest.raises(
        baseline_inventory.BaselineInventoryError,
        match="not a keyhog result",
    ):
        baseline_inventory.load_canonical("mirror", baselines_dir=d)


def test_resolve_rejects_wrong_corpus_name(tmp_path: pathlib.Path):
    d = _fresh_baselines(tmp_path)
    run = _make_run("other", "keyhog", 1, 0, 0)
    _write_result(d / "other.json", run)
    _write_inventory(d, '[mirror]\npath = "other.json"\n')

    with pytest.raises(
        baseline_inventory.BaselineInventoryError,
        match="has corpus.name=",
    ):
        baseline_inventory.load_canonical("mirror", baselines_dir=d)


def test_gate_uses_canonical_inventory(tmp_path: pathlib.Path):
    d = _fresh_baselines(tmp_path)
    active = _make_run("mirror", "keyhog", 6, 4, 0, generated_at="2026-07-20T00:00:00")
    historical = _make_run(
        "mirror", "keyhog", 10, 0, 0, generated_at="2026-07-21T00:00:00"
    )
    _write_result(d / "mirror-keyhog-baseline.json", active)
    _write_result(d / "archive" / "mirror-keyhog-baseline-v99.json", historical)
    _write_inventory(d, '[mirror]\npath = "mirror-keyhog-baseline.json"\n')

    row = gate._baseline_keyhog_row(d, "mirror")
    assert row.generated_at == active.generated_at
    assert row.detection.overall.f1() == active.detection.overall.f1()


def test_gate_explicit_file_bypasses_inventory(tmp_path: pathlib.Path):
    d = _fresh_baselines(tmp_path)
    run = _make_run("mirror", "keyhog", 10, 0, 0)
    path = d / "explicit.json"
    _write_result(path, run)

    row = gate._baseline_keyhog_row(path, "mirror")
    assert row.generated_at == run.generated_at


def test_gate_wraps_inventory_error_as_gate_error(tmp_path: pathlib.Path):
    d = _fresh_baselines(tmp_path)
    with pytest.raises(gate.GateError, match="cannot load benchmark baseline"):
        gate._baseline_keyhog_row(d, "mirror")


def test_gate_explicit_file_rejects_wrong_corpus(tmp_path: pathlib.Path):
    """An explicit file path is still a declared identity: it must match the
    requested corpus or the gate is undecidable."""
    d = _fresh_baselines(tmp_path)
    run = _make_run("other", "keyhog", 10, 0, 0)
    path = d / "explicit.json"
    _write_result(path, run)

    with pytest.raises(gate.GateError, match="for corpus 'other', expected 'mirror'"):
        gate._baseline_keyhog_row(path, "mirror")


def test_gate_explicit_file_rejects_non_keyhog(tmp_path: pathlib.Path):
    d = _fresh_baselines(tmp_path)
    run = _make_run("mirror", "titus", 10, 0, 0)
    path = d / "explicit.json"
    _write_result(path, run)

    with pytest.raises(gate.GateError, match="not a keyhog result"):
        gate._baseline_keyhog_row(path, "mirror")


def test_gate_explicit_file_rejects_unavailable(tmp_path: pathlib.Path):
    d = _fresh_baselines(tmp_path)
    run = _make_run("mirror", "keyhog", 10, 0, 0)
    run.available = False
    run.error = "exploded"
    path = d / "explicit.json"
    _write_result(path, run)

    with pytest.raises(gate.GateError, match="is unavailable: exploded"):
        gate._baseline_keyhog_row(path, "mirror")
