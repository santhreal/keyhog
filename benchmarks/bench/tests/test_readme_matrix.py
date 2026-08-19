"""Behavioral contracts for generated README configuration benchmark panels."""

from __future__ import annotations

import json

import pytest

from bench import readme_matrix
from bench.schema import (
    CorpusInfo,
    Detection,
    Host,
    Outcome,
    RunResult,
    Scanner,
    ScannerConfig,
    Speed,
    StaticRecoveryMetrics,
)


HOST = Host(
    hostname_hash="1" * 12,
    os="Linux 6.17",
    kernel="test-kernel",
    cpu="Test CPU",
    cores=16,
    ram_mb=32768,
    gpu="Test GPU",
    gpu_vram_mb=24576,
)


def _config(config_id: str) -> ScannerConfig:
    """Test helper / contract verification."""
    parts = config_id.rsplit("-", 3)
    backend = parts[0]
    cache = "on" if parts[1] == "cache" else "off"
    daemon = "on" if parts[2] == "daemon" else "off"
    return ScannerConfig(backend=backend, cache=cache, daemon=daemon, mode=parts[3])


def _row(config_id: str, corpus: CorpusInfo) -> RunResult:
    """Test helper / contract verification."""
    cfg = _config(config_id)
    return RunResult(
        generated_at="2026-07-28T12:00:00Z",
        host=HOST,
        scanner=Scanner(
            name="keyhog",
            version=(
                f"KeyHog v{readme_matrix.workspace_version()}\n"
                f"Commit: {'a' * 40}\nDetector Set: 923 (923-{'b' * 16})"
            ),
            config=cfg,
            executable_sha256="c" * 64,
            detector_corpus_sha256="d" * 64,
            execution_route="daemon" if cfg.daemon == "on" else "in_process",
            daemon_pid=42 if cfg.daemon == "on" else 0,
            daemon_requests=2 if cfg.daemon == "on" else 0,
        ),
        corpus=corpus,
        detection=Detection(overall=Outcome(tp=90, fp=3, fn=10)),
        speed=Speed(
            wall_ms=100.0 if cfg.daemon == "on" else 400.0,
            throughput_mb_s=20.0 if cfg.daemon == "on" else 5.0,
            peak_rss_kb=512 * 1024,
        ),
        finding_count=93,
        exit_code=1,
        static_recovery=StaticRecoveryMetrics(),
    )


def _write_rows(path, config_ids: set[str], corpus: CorpusInfo) -> None:
    """Test helper / contract verification."""
    path.mkdir()
    for config_id in sorted(config_ids):
        row = _row(config_id, corpus)
        (path / f"{corpus.name}-keyhog-{config_id}.json").write_text(
            json.dumps(row.to_json()),
            encoding="utf-8",
        )


def _matrix_fixture(tmp_path):
    """Test helper / contract verification."""
    config_results = tmp_path / "config"
    daemon_results = tmp_path / "daemon"
    daemon_corpus = tmp_path / "daemon.txt"
    readme_matrix.generate_daemon_corpus(daemon_corpus)
    _write_rows(
        config_results,
        readme_matrix.REQUIRED_CONFIGS,
        CorpusInfo(name="mirror", fixture_count=15000, labeled_positives=3000, bytes=2430321),
    )
    _write_rows(
        daemon_results,
        set(readme_matrix.DAEMON_CONFIGS),
        CorpusInfo(name="daemon-file", fixture_count=1, labeled_positives=0, bytes=readme_matrix.DAEMON_CORPUS_BYTES),
    )
    return config_results, daemon_results, daemon_corpus


def test_daemon_corpus_generation_is_byte_deterministic(tmp_path) -> None:
    """The automatic daemon panel must always measure the same exact regular-file bytes."""
    first = tmp_path / "first.bin"
    second = tmp_path / "second.bin"

    first_digest = readme_matrix.generate_daemon_corpus(first)
    second_digest = readme_matrix.generate_daemon_corpus(second)

    assert first.stat().st_size == readme_matrix.DAEMON_CORPUS_BYTES
    assert first.read_bytes() == second.read_bytes()
    assert first_digest == second_digest == "afafbe7b6487fd62866f510e7c281a9e7bfeaa8dc585d7b0478c92ee6c4f5ef5"


def test_capture_binds_every_required_configuration_to_one_identity(tmp_path) -> None:
    """A publishable snapshot must conserve every selected row, binary digest, detector digest, and host."""
    config_results, daemon_results, daemon_corpus = _matrix_fixture(tmp_path)

    snapshot = readme_matrix.capture_snapshot(
        config_results,
        daemon_results,
        daemon_corpus,
        "clean",
    )

    assert snapshot["schema_version"] == readme_matrix.SNAPSHOT_SCHEMA
    assert snapshot["source_state"] == "clean"
    assert len(snapshot["configuration_rows"]) == len(readme_matrix.REQUIRED_CONFIGS)
    assert len(snapshot["daemon_rows"]) == len(readme_matrix.DAEMON_CONFIGS)
    assert snapshot["daemon_corpus"] == {
        "bytes": readme_matrix.DAEMON_CORPUS_BYTES,
        "sha256": "afafbe7b6487fd62866f510e7c281a9e7bfeaa8dc585d7b0478c92ee6c4f5ef5",
    }


def test_capture_rejects_same_size_noncanonical_daemon_bytes(tmp_path) -> None:
    """A same-size replacement must not inherit the deterministic daemon workload identity."""
    config_results, daemon_results, daemon_corpus = _matrix_fixture(tmp_path)
    daemon_corpus.write_bytes(b"x" * readme_matrix.DAEMON_CORPUS_BYTES)

    with pytest.raises(readme_matrix.MatrixError, match="differ from the deterministic"):
        readme_matrix.capture_snapshot(
            config_results,
            daemon_results,
            daemon_corpus,
            "clean",
        )


def test_cli_capture_requires_explicit_source_state(tmp_path, capsys) -> None:
    """A capture command must never silently label unclassified workspace evidence clean."""
    config_results, daemon_results, daemon_corpus = _matrix_fixture(tmp_path)

    exit_code = readme_matrix.main(
        [
            "--config-results",
            str(config_results),
            "--daemon-results",
            str(daemon_results),
            "--daemon-corpus",
            str(daemon_corpus),
            "--snapshot",
            str(tmp_path / "snapshot.json"),
        ]
    )

    assert exit_code == 1
    assert "requires explicit --source-state" in capsys.readouterr().err


def test_capture_rejects_one_unavailable_required_route(tmp_path) -> None:
    """A failed GPU, CPU, SIMD, preset, cache, or daemon row must block the generated panel instead of vanishing."""
    config_results, daemon_results, daemon_corpus = _matrix_fixture(tmp_path)
    target = config_results / "mirror-keyhog-gpu-cuda-nocache-nodaemon-full.json"
    value = json.loads(target.read_text(encoding="utf-8"))
    value.update(available=False, error="GPU dispatch failed")
    target.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(readme_matrix.MatrixError, match="unavailable configs"):
        readme_matrix.capture_snapshot(
            config_results,
            daemon_results,
            daemon_corpus,
            "clean",
        )


def test_capture_rejects_stale_scanner_versions(tmp_path) -> None:
    """A README panel must not combine the current docs with a stale KeyHog executable."""
    config_results, daemon_results, daemon_corpus = _matrix_fixture(tmp_path)
    target = config_results / "mirror-keyhog-simd-nocache-nodaemon-full.json"
    value = json.loads(target.read_text(encoding="utf-8"))
    value["scanner"]["version"] = "KeyHog v0.0.1\nCommit: stale"
    target.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(readme_matrix.MatrixError, match="scanner versions"):
        readme_matrix.capture_snapshot(
            config_results,
            daemon_results,
            daemon_corpus,
            "clean",
        )


def test_render_explains_policy_and_daemon_boundaries(tmp_path) -> None:
    """Generated prose must keep detection presets separate from daemon route scope."""
    config_results, daemon_results, daemon_corpus = _matrix_fixture(tmp_path)
    snapshot = readme_matrix.capture_snapshot(
        config_results,
        daemon_results,
        daemon_corpus,
        "developer-dirty",
    )

    accuracy = readme_matrix.render_accuracy(snapshot)
    config = readme_matrix.render_configuration(snapshot)
    daemon = readme_matrix.render_daemon(snapshot)

    assert "| 0.9677 | 0.9000 | 0.9326 | 90 | 3 | 10 |" in accuracy
    assert "answer-key manifest was excluded" in accuracy
    assert "Full scan by execution route" in config
    assert "Detection policy on Hyperscan/SIMD" in config
    assert "does not bind the selected persisted route" in config
    assert "development-host configuration comparisons" in config
    assert "| Deep | 400 ms | 0.9677 | 0.9000 | 0.9326 | 93 |" in config
    assert "one warmup request" in daemon
    assert "| Pure-Rust CPU | 400 ms | 100 ms | 0.25× | 512 MiB | 512 MiB |" in daemon
    assert "mass route also accepts bounded directory and remote-source batches" in daemon


def test_readme_check_detects_hand_edited_generated_bytes(tmp_path) -> None:
    """A hand-edited benchmark number must fail the idempotence check rather than becoming product truth."""
    config_results, daemon_results, daemon_corpus = _matrix_fixture(tmp_path)
    snapshot = readme_matrix.capture_snapshot(
        config_results,
        daemon_results,
        daemon_corpus,
        "clean",
    )
    sections = readme_matrix.render_sections(snapshot)
    readme = tmp_path / "README.md"
    readme.write_text(
        "before\n<!-- BENCH:accuracy:start -->\nold\n<!-- BENCH:accuracy:end -->\n"
        "<!-- BENCH:config:start -->\nold\n<!-- BENCH:config:end -->\n"
        "<!-- BENCH:daemon:start -->\nold\n<!-- BENCH:daemon:end -->\n"
        "after\n",
        encoding="utf-8",
    )
    readme_matrix.update_readme(readme, sections, check=False)
    readme_matrix.update_readme(readme, sections, check=True)
    readme.write_text(readme.read_text().replace("400 ms", "401 ms", 1), encoding="utf-8")

    with pytest.raises(readme_matrix.MatrixError, match="panels are stale"):
        readme_matrix.update_readme(readme, sections, check=True)


def test_snapshot_loader_rejects_unknown_schema(tmp_path) -> None:
    """A changed snapshot schema must fail closed until the renderer explicitly supports it."""
    snapshot = tmp_path / "snapshot.json"
    snapshot.write_text('{"schema_version":"future"}', encoding="utf-8")

    with pytest.raises(readme_matrix.MatrixError, match="unsupported"):
        readme_matrix.load_snapshot(snapshot)


def test_render_accuracy_renders_multi_corpus_snapshot_dynamically(tmp_path) -> None:
    """Accuracy panel must derive all rows and headings dynamically from snapshot."""
    config_results, daemon_results, daemon_corpus = _matrix_fixture(tmp_path)
    snapshot = readme_matrix.capture_snapshot(
        config_results,
        daemon_results,
        daemon_corpus,
        "clean",
    )
    mirror_row = snapshot["configuration_rows"][0]
    homefield_row = dict(mirror_row)
    homefield_row["corpus"] = {
        "name": "homefield",
        "fixture_count": 2399,
        "labeled_positives": 1057,
        "bytes": 772974,
        "workload_sha256": "9" * 64,
    }
    homefield_row["detection"] = {
        "precision": 0.9582,
        "recall": 0.8874,
        "f1": 0.9214,
        "tp": 938,
        "fp": 41,
        "fn": 119,
    }
    snapshot["accuracy_rows"] = [mirror_row, homefield_row]

    accuracy_md = readme_matrix.render_accuracy(snapshot)
    assert "| **mirror** |" in accuracy_md
    assert "| **homefield** | 2,399 | 1,057 | 773 KB | 0.9582 | 0.8874 | 0.9214 | 938 | 41 | 119 |" in accuracy_md
    assert "both the synthetic **mirror** corpus and competitor **homefield** rule ground-truth" in accuracy_md


def test_render_accuracy_fails_closed_on_missing_default_row() -> None:
    """Accuracy renderer must raise MatrixError when default rows are missing."""
    with pytest.raises(readme_matrix.MatrixError, match="lacks the default Hyperscan/SIMD accuracy row"):
        readme_matrix.render_accuracy({"configuration_rows": []})
