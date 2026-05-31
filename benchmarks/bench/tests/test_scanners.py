import json
import sqlite3
import sys

from bench import scanners
from bench.scanners import keyhog as keyhog_adapter
from bench.scanners import base
from bench.schema import ScannerConfig


def test_keyhog_normalizer_reads_json_array_shape():
    data = [
        {
            "detector_id": "github-classic-pat",
            "credential_redacted": "ghp_secret",
            "confidence": 0.87,
            "location": {"file_path": "secret.env", "line": 4},
        }
    ]

    # confidence rides along (the calibration loop's tuning signal); absent
    # confidence normalises to None, exercised in the additional-locations test.
    assert scanners._normalize_keyhog(data) == [
        {
            "file": "secret.env",
            "line": 4,
            "value": "ghp_secret",
            "detector": "github-classic-pat",
            "confidence": 0.87,
        }
    ]


def test_keyhog_normalizer_scores_additional_locations_as_findings():
    data = [
        {
            "detector_id": "ssh-private-key",
            "credential_redacted": "-----BEGIN EC PRIVATE KEY-----",
            "location": {"file_path": "primary.pem", "line": 1},
            "additional_locations": [
                {"file_path": "alias.pem", "line": 1},
                {"file": "legacy-path.pem", "line": "2"},
            ],
        }
    ]

    assert scanners._normalize_keyhog(data) == [
        {
            "file": "primary.pem",
            "line": 1,
            "value": "-----BEGIN EC PRIVATE KEY-----",
            "detector": "ssh-private-key",
            "confidence": None,
        },
        {
            "file": "alias.pem",
            "line": 1,
            "value": "-----BEGIN EC PRIVATE KEY-----",
            "detector": "ssh-private-key",
            "confidence": None,
        },
        {
            "file": "legacy-path.pem",
            "line": 2,
            "value": "-----BEGIN EC PRIVATE KEY-----",
            "detector": "ssh-private-key",
            "confidence": None,
        },
    ]


def test_betterleaks_normalizer_reads_gitleaks_json_shape():
    data = [{"File": "a.env", "StartLine": 2, "Secret": "sekret", "RuleID": "aws"}]

    assert scanners._normalize_betterleaks(data) == [
        {"file": "a.env", "line": 2, "value": "sekret", "detector": "aws"}
    ]


def test_kingfisher_normalizer_skips_summary_lines():
    text = "\n".join(
        [
            json.dumps(
                {
                    "rule": {"id": "np.github.1"},
                    "finding": {"path": "a.env", "line": 3, "snippet": "ghp_secret"},
                }
            ),
            json.dumps({"findings": 1, "blobs_scanned": 1}),
        ]
    )

    assert scanners._normalize_kingfisher_jsonl(text) == [
        {"file": "a.env", "line": 3, "value": "ghp_secret", "detector": "np.github.1"}
    ]


def test_noseyparker_normalizer_reads_report_json_shape():
    data = [
        {
            "rule_text_id": "np.github.1",
            "matches": [
                {
                    "provenance": [{"kind": "file", "path": "/tmp/a.env"}],
                    "location": {"source_span": {"start": {"line": 5}}},
                    "snippet": {"matching": "ghp_secret"},
                }
            ],
        }
    ]

    assert scanners._normalize_nosey_report(data) == [
        {"file": "/tmp/a.env", "line": 5, "value": "ghp_secret", "detector": "np.github.1"}
    ]


def test_titus_normalizer_reads_datastore_sqlite(tmp_path):
    db = tmp_path / "datastore.db"
    with sqlite3.connect(db) as con:
        con.executescript(
            """
            create table matches (
              id integer primary key,
              blob_id text not null,
              rule_id text not null,
              start_line integer,
              snippet_matching blob
            );
            create table provenance (
              id integer primary key,
              blob_id text not null,
              path text
            );
            insert into matches(blob_id, rule_id, start_line, snippet_matching)
              values ('blob-1', 'np.github.1', 7, X'6768705F736563726574');
            insert into provenance(blob_id, path) values ('blob-1', '/tmp/a.env');
            """
        )

    assert scanners._normalize_titus_datastore(db) == [
        {"file": "/tmp/a.env", "line": 7, "value": "ghp_secret", "detector": "np.github.1"}
    ]


def test_requested_competitor_adapters_are_registered():
    assert {"betterleaks", "kingfisher", "noseyparker", "titus"}.issubset(scanners.SCANNERS)


def test_requested_competitor_adapters_resolve_to_measured_scanners():
    for name in ["betterleaks", "kingfisher", "noseyparker", "titus"]:
        scanner = scanners.resolve_scanner(name)
        cfg = scanner.default_config()

        assert scanner.name == name
        assert cfg.backend == "default"
        assert cfg.cache == "off"
        assert cfg.daemon == "off"


def test_scanner_exit_contracts_distinguish_findings_from_failures():
    keyhog = scanners.resolve_scanner("keyhog")
    betterleaks = scanners.resolve_scanner("betterleaks")

    assert keyhog.exit_success(0)
    assert keyhog.exit_success(1)
    assert keyhog.exit_success(10)
    assert not keyhog.exit_success(2)
    assert betterleaks.exit_success(0)
    assert not betterleaks.exit_success(1)
    assert scanners.resolve_scanner("kingfisher").exit_success(200)


def test_keyhog_gpu_benchmark_rows_require_real_gpu():
    scanner = scanners.KeyhogScanner()

    assert scanner._env(ScannerConfig(backend="gpu")) == {
        "KEYHOG_NO_GPU": "0",
        "KEYHOG_REQUIRE_GPU": "1",
    }
    assert scanner._env(ScannerConfig(backend="megascan")) == {
        "KEYHOG_NO_GPU": "0",
        "KEYHOG_REQUIRE_GPU": "1",
    }
    assert scanner._env(ScannerConfig(backend="auto")) == {
        "KEYHOG_NO_GPU": "1",
        "KEYHOG_REQUIRE_GPU": "0",
    }
    assert scanner._env(ScannerConfig(backend="simd")) == {
        "KEYHOG_NO_GPU": "1",
        "KEYHOG_REQUIRE_GPU": "0",
    }


def test_keyhog_benchmark_prefers_fresh_release_binary(monkeypatch, tmp_path):
    target_dir = tmp_path / "cargo-target"
    release_dir = target_dir / "release"
    release_dir.mkdir(parents=True)
    binary = release_dir / "keyhog"
    binary.write_text("#!/bin/sh\n")

    monkeypatch.delenv("KEYHOG_BIN", raising=False)
    monkeypatch.setenv("CARGO_TARGET_DIR", str(target_dir))

    assert scanners.resolve_scanner("keyhog").binary == str(binary)


def test_keyhog_benchmark_uses_release_fast_when_release_missing(monkeypatch, tmp_path):
    target_dir = tmp_path / "cargo-target"
    release_fast_dir = target_dir / "release-fast"
    release_fast_dir.mkdir(parents=True)
    binary = release_fast_dir / "keyhog"
    binary.write_text("#!/bin/sh\n")

    monkeypatch.delenv("KEYHOG_BIN", raising=False)
    monkeypatch.setenv("CARGO_TARGET_DIR", str(target_dir))

    assert scanners.resolve_scanner("keyhog").binary == str(binary)


def test_keyhog_benchmark_prefers_release_over_release_fast(monkeypatch, tmp_path):
    target_dir = tmp_path / "cargo-target"
    release_dir = target_dir / "release"
    release_fast_dir = target_dir / "release-fast"
    release_dir.mkdir(parents=True)
    release_fast_dir.mkdir(parents=True)
    release_binary = release_dir / "keyhog"
    release_fast_binary = release_fast_dir / "keyhog"
    release_binary.write_text("#!/bin/sh\n")
    release_fast_binary.write_text("#!/bin/sh\n")

    monkeypatch.delenv("KEYHOG_BIN", raising=False)
    monkeypatch.setenv("CARGO_TARGET_DIR", str(target_dir))

    assert scanners.resolve_scanner("keyhog").binary == str(release_binary)


def test_keyhog_benchmark_binary_overrides_win(monkeypatch, tmp_path):
    target_dir = tmp_path / "cargo-target"
    (target_dir / "release").mkdir(parents=True)
    (target_dir / "release" / "keyhog").write_text("#!/bin/sh\n")

    monkeypatch.setenv("CARGO_TARGET_DIR", str(target_dir))
    monkeypatch.setenv("KEYHOG_BIN", "/env/keyhog")

    assert scanners.KeyhogScanner().binary == "/env/keyhog"
    assert scanners.KeyhogScanner(binary="/explicit/keyhog").binary == "/explicit/keyhog"


def test_keyhog_benchmark_reads_cargo_config_target_dir(monkeypatch, tmp_path):
    home = tmp_path / "home"
    target_dir = tmp_path / "configured-target"
    (target_dir / "release").mkdir(parents=True)
    (target_dir / "release" / "keyhog").write_text("#!/bin/sh\n")
    (home / ".cargo").mkdir(parents=True)
    (home / ".cargo" / "config.toml").write_text(
        f'[build]\ntarget-dir = "{target_dir}"\n'
    )

    monkeypatch.delenv("CARGO_TARGET_DIR", raising=False)
    monkeypatch.delenv("KEYHOG_BIN", raising=False)
    monkeypatch.setattr(keyhog_adapter.pathlib.Path, "home", lambda: home)

    assert scanners.resolve_scanner("keyhog").binary == str(target_dir / "release" / "keyhog")


def test_run_measured_falls_back_without_gnu_time(monkeypatch):
    monkeypatch.setattr(base, "_GNU_TIME", None)

    stdout, stderr, stats = base.run_measured(
        [sys.executable, "-c", "print('ok')"],
        timeout=30,
    )

    assert stdout.strip() == "ok"
    assert stderr == ""
    assert stats.exit_code == 0
    assert stats.wall_ms > 0
    assert stats.peak_rss_kb > 0
