import json
import os
import sqlite3
import sys
import time

import pytest

from bench import scanners
from bench.scanners import keyhog as keyhog_adapter
from bench.scanners import base
from bench.schema import ScannerConfig


def _pid_running(pid: int) -> bool:
    proc_stat = f"/proc/{pid}/stat"
    try:
        stat = open(proc_stat, encoding="utf-8").read()
        if ") Z " in stat:
            return False
    except OSError:
        pass
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


@pytest.mark.skipif(
    os.name != "posix" or not os.path.isdir("/proc"),
    reason="process-group child liveness assertion requires POSIX /proc",
)
def test_run_measured_timeout_kills_wrapped_child_process_group(tmp_path):
    pid_file = tmp_path / "child.pid"
    script = f"""
import pathlib
import subprocess
import sys
import time

child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
pathlib.Path({str(pid_file)!r}).write_text(str(child.pid))
time.sleep(60)
"""

    _stdout, _stderr, stats = base.run_measured(
        [sys.executable, "-c", script],
        timeout=1,
    )

    assert stats.timed_out
    deadline = time.time() + 5
    while not pid_file.exists() and time.time() < deadline:
        time.sleep(0.05)
    assert pid_file.exists(), "parent process must write the child pid before timeout"
    child_pid = int(pid_file.read_text())
    while _pid_running(child_pid) and time.time() < deadline:
        time.sleep(0.05)
    assert not _pid_running(child_pid), (
        "run_measured timeout must kill the scanner child process group, not only "
        "the /usr/bin/time wrapper")


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
            "offset": 0,
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
            "offset": 0,
            "value": "-----BEGIN EC PRIVATE KEY-----",
            "detector": "ssh-private-key",
            "confidence": None,
        },
        {
            "file": "alias.pem",
            "line": 1,
            "offset": 0,
            "value": "-----BEGIN EC PRIVATE KEY-----",
            "detector": "ssh-private-key",
            "confidence": None,
        },
        {
            "file": "legacy-path.pem",
            "line": 2,
            "offset": 0,
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


def test_keyhog_gpu_benchmark_rows_use_explicit_gpu_policy(tmp_path):
    scanner = scanners.KeyhogScanner()

    gpu_cmd = scanner._cmd(
        tmp_path, ScannerConfig(backend="gpu"), tmp_path / "gpu.json", None
    )
    auto_cmd = scanner._cmd(
        tmp_path, ScannerConfig(backend="auto"), tmp_path / "auto.json", None
    )
    simd_cmd = scanner._cmd(
        tmp_path, ScannerConfig(backend="simd"), tmp_path / "simd.json", None
    )

    assert "--require-gpu" in gpu_cmd
    assert "--no-gpu" in auto_cmd
    assert "--no-gpu" in simd_cmd
    assert scanner._env(ScannerConfig(backend="gpu")) == {}


def test_keyhog_scanner_reports_timeout_as_timeout(monkeypatch, tmp_path):
    scanner = scanners.KeyhogScanner(binary="/unused/keyhog")
    timed_out = base.RunStats(exit_code=-1, timed_out=True)
    monkeypatch.setattr(
        keyhog_adapter,
        "run_measured",
        lambda *args, **kwargs: ("", "last scanner diagnostic", timed_out),
    )

    with pytest.raises(TimeoutError, match=r"timed out after 7s") as exc:
        scanner.run(
            tmp_path,
            ScannerConfig(backend="gpu"),
            output=tmp_path / "unused.json",
            timeout=7,
        )

    assert "last scanner diagnostic" in str(exc.value)


def test_keyhog_min_confidence_floor_is_harvest_only(tmp_path):
    """The optional report-floor override threads to `--min-confidence` ONLY
    when set, and never forks the leaderboard's stable `config_id`.

    This is the harvest-loop knob: the ML harvest scans at a LOW floor so the
    training corpus captures the sub-floor candidates the default ~0.30 floor
    hides (the fix for the kubernetes-bootstrap-token +203-FP retrain blind
    spot). Every leaderboard config leaves it None, so the scored command and
    the matrix key are byte-identical to before the knob existed.
    """
    scanner = scanners.KeyhogScanner(binary="/bin/true")
    root = tmp_path / "corpus"
    out = tmp_path / "out.json"

    # Leaderboard default: no override -> no flag, canonical config_id.
    lb = ScannerConfig(backend="simd")
    cmd_lb = scanner._cmd(root, lb, out, None)
    assert "--min-confidence" not in cmd_lb
    assert lb.config_id == "simd-nocache-nodaemon-full"
    assert "min_confidence" not in lb.to_json()

    # Harvest: floor 0.0 captures every scored candidate; flag present, but the
    # config_id MUST be unchanged so the harvest scan can never masquerade as a
    # distinct leaderboard row.
    harvest = ScannerConfig(backend="simd", min_confidence=0.0)
    cmd_h = scanner._cmd(root, harvest, out, None)
    i = cmd_h.index("--min-confidence")
    assert cmd_h[i + 1] == "0.0"
    assert harvest.config_id == "simd-nocache-nodaemon-full"
    assert harvest.to_json()["min_confidence"] == 0.0

    # A fractional floor round-trips through the CLI float formatting.
    frac = ScannerConfig(backend="cpu", min_confidence=0.05)
    cmd_f = scanner._cmd(root, frac, out, None)
    j = cmd_f.index("--min-confidence")
    assert cmd_f[j + 1] == "0.05"
    assert ScannerConfig.from_json(frac.to_json()).min_confidence == 0.05


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
