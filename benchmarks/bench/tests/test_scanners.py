import contextlib
import hashlib
import json
import math
import os
import pathlib
import shutil
import sqlite3
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from bench import executable_snapshot, keyhog_daemon, scanners
from bench.scanners import keyhog as keyhog_adapter
from bench.scanners import base
from bench.schema import ScannerConfig


_REAL_BINARY_SNAPSHOT = keyhog_adapter.KeyhogScanner._binary_snapshot


def test_keyhog_daemon_is_directly_importable_from_a_fresh_process():
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            "import bench.keyhog_daemon as module; print(module.__file__)",
        ],
        cwd=pathlib.Path(__file__).parents[2],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert pathlib.Path(completed.stdout.strip()).resolve() == (
        pathlib.Path(__file__).parents[1] / "keyhog_daemon.py"
    ).resolve()


@pytest.fixture(autouse=True)
def _stub_keyhog_binary_snapshot(monkeypatch):
    @contextlib.contextmanager
    def snapshot(_scanner):
        yield pathlib.Path("/snapshot/keyhog"), "a" * 64, "KeyHog test snapshot", ()

    monkeypatch.setattr(keyhog_adapter.KeyhogScanner, "_binary_snapshot", snapshot)


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


def _keyhog_finding(**overrides):
    finding = {
        "detector_id": "github-classic-pat",
        "credential_redacted": "ghp_secret",
        "confidence": 0.87,
        "location": {"file_path": "secret.env", "line": 4},
    }
    finding.update(overrides)
    return finding


@pytest.mark.parametrize(
    "data, message",
    [
        ({"findings": {}}, "findings.*array"),
        ([_keyhog_finding(), "unexpected"], "finding 1 must be an object"),
        ([_keyhog_finding(location=None)], "location must be an object"),
        ([_keyhog_finding(location={"line": 4})], "no non-empty file path"),
        ([_keyhog_finding(confidence="high")], "finite number in"),
        (
            [_keyhog_finding(additional_locations=["unexpected"])],
            "additional location 0 must be an object",
        ),
        (
            [_keyhog_finding(additional_locations={})],
            "additional_locations must be an array",
        ),
    ],
)
def test_keyhog_normalizer_rejects_malformed_finding_shapes(data, message):
    with pytest.raises(RuntimeError, match=message):
        scanners._normalize_keyhog(data)


def test_keyhog_normalizer_dedup_keeps_max_confidence_independent_of_order():
    low = _keyhog_finding(confidence=0.2)
    high = _keyhog_finding(confidence=0.9)

    forward = scanners._normalize_keyhog([low, high])
    reverse = scanners._normalize_keyhog([high, low])

    assert forward == reverse
    assert forward[0]["confidence"] == 0.9


def test_keyhog_parser_rejects_empty_success_artifact_but_accepts_json_array(tmp_path):
    output = tmp_path / "keyhog.json"
    output.write_text("")
    with pytest.raises(RuntimeError, match="empty output artifact"):
        scanners.KeyhogScanner._parse(output, config_id="deep")

    output.write_text("[]")
    assert scanners.KeyhogScanner._parse(output, config_id="deep") == []


def test_keyhog_parser_requires_complete_resolved_mode_envelope(tmp_path):
    output = tmp_path / "result.json"
    output.write_text(
        json.dumps(
            {
                "schema_version": {"major": 1, "minor": 5},
                "scan_status": "success",
                "metadata": {
                    "resolved_scan": {
                        "schema_version": 1,
                        "preset": "deep",
                        "effective": {"max_decode_depth": "10"},
                        "overrides": [],
                    }
                },
                "findings": [],
            }
        )
    )
    assert scanners.KeyhogScanner._parse(output, config_id="deep") == []
    assert scanners.KeyhogScanner._read_scan_manifest(output)["preset"] == "deep"

    recovered = json.loads(output.read_text())
    recovered["scan_status"] = "complete_after_recovery"
    output.write_text(json.dumps(recovered))
    assert scanners.KeyhogScanner._parse(output, config_id="deep") == []

    output.write_text(
        json.dumps(
            {
                "schema_version": {"major": 1, "minor": 5},
                "scan_status": "partial",
                "metadata": {"resolved_scan": {}},
                "findings": [],
            }
        )
    )
    with pytest.raises(RuntimeError, match="terminal scan_status"):
        scanners.KeyhogScanner._parse(output, config_id="deep")

    output.write_text(
        json.dumps(
            {
                "schema_version": {"major": 1, "minor": 5},
                "scan_status": "success",
                "metadata": {},
                "findings": [],
            }
        )
    )
    with pytest.raises(RuntimeError, match="resolved_scan manifest"):
        scanners.KeyhogScanner._parse(output, config_id="deep")


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


@pytest.mark.parametrize("backend", ["gpu-cuda", "gpu-wgpu"])
def test_keyhog_gpu_benchmark_rows_use_exact_gpu_policy(tmp_path, backend):
    scanner = scanners.KeyhogScanner()

    gpu_cmd = scanner._cmd(
        tmp_path, ScannerConfig(backend=backend), tmp_path / f"{backend}.json", None,
        pathlib.Path("/unused/keyhog"),
    )
    auto_cmd = scanner._cmd(
        tmp_path, ScannerConfig(backend="auto"), tmp_path / "auto.json", None,
        pathlib.Path("/unused/keyhog"),
    )
    simd_cmd = scanner._cmd(
        tmp_path, ScannerConfig(backend="simd"), tmp_path / "simd.json", None,
        pathlib.Path("/unused/keyhog"),
    )

    assert "--require-gpu" in gpu_cmd
    assert gpu_cmd[gpu_cmd.index("--backend") + 1] == backend
    assert "--no-gpu" not in auto_cmd
    assert "--no-gpu" in simd_cmd
    detector_index = auto_cmd.index("--detectors")
    assert pathlib.Path(auto_cmd[detector_index + 1]) == keyhog_adapter._DETECTOR_CORPUS
    assert scanner.detector_corpus_sha256() == keyhog_adapter.compute_detector_corpus_sha256(
        keyhog_adapter._DETECTOR_CORPUS
    )
    assert scanner._env(ScannerConfig(backend=backend)) == {}


def test_keyhog_single_file_perf_command_keeps_daemon_fixture_policy(tmp_path):
    input_file = tmp_path / "workload.txt"
    input_file.write_text("public workload", encoding="utf-8")
    cmd = scanners.KeyhogScanner()._cmd(
        input_file,
        ScannerConfig(backend="simd"),
        tmp_path / "result.json",
        None,
        pathlib.Path("/unused/keyhog"),
    )

    assert "--no-suppress-test-fixtures" not in cmd


def test_keyhog_presets_are_explicit_and_matrix_owned(tmp_path):
    scanner = scanners.KeyhogScanner(binary="/bin/true")
    deep = ScannerConfig(backend="simd", mode="deep")
    precision = ScannerConfig(backend="simd", mode="precision")
    full = ScannerConfig(backend="simd", mode="full")

    executable = pathlib.Path("/bin/true")
    deep_cmd = scanner._cmd(tmp_path, deep, tmp_path / "deep.json", None, executable)
    precision_cmd = scanner._cmd(
        tmp_path, precision, tmp_path / "precision.json", None, executable
    )
    full_cmd = scanner._cmd(tmp_path, full, tmp_path / "full.json", None, executable)

    assert "--deep" in deep_cmd
    assert "--precision" in precision_cmd
    assert "--deep" not in full_cmd
    assert "--precision" not in full_cmd
    assert {cfg.mode for cfg in scanner.matrix(["mode"])} == {
        "full",
        "fast",
        "deep",
        "precision",
    }
    assert deep.config_id == "simd-nocache-nodaemon-deep"
    assert precision.config_id == "simd-nocache-nodaemon-precision"


@pytest.mark.parametrize(
    "field,value",
    [
        ("backend", "default"),
        ("cache", "warm"),
        ("daemon", "auto"),
        ("mode", "thorough"),
    ],
)
def test_keyhog_adapter_rejects_unknown_config_axes(tmp_path, field, value):
    scanner = scanners.KeyhogScanner(binary="/bin/true")
    values = {
        "backend": "simd",
        "cache": "off",
        "daemon": "off",
        "mode": "full",
    }
    values[field] = value

    with pytest.raises(ValueError, match=rf"benchmark {field} .*choose one of"):
        scanner._cmd(
            tmp_path,
            ScannerConfig(**values),
            tmp_path / "result.json",
            None,
            pathlib.Path("/bin/true"),
        )


@pytest.mark.parametrize("value", [-0.01, 1.01, math.nan, math.inf])
def test_keyhog_adapter_rejects_invalid_confidence_before_execution(tmp_path, value):
    scanner = scanners.KeyhogScanner(binary="/bin/true")

    with pytest.raises(ValueError, match=r"finite number in \[0, 1\]"):
        scanner._cmd(
            tmp_path,
            ScannerConfig(backend="simd", min_confidence=value),
            tmp_path / "result.json",
            None,
            pathlib.Path("/bin/true"),
        )


def test_keyhog_matrix_rejects_unknown_and_duplicate_axes():
    scanner = scanners.KeyhogScanner(binary="/bin/true")

    with pytest.raises(ValueError, match=r"unsupported .* axes: mystery"):
        scanner.matrix(["mode", "mystery"])
    with pytest.raises(ValueError, match=r"duplicate .* axes: mode"):
        scanner.matrix(["mode", "mode"])


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
            ScannerConfig(backend="gpu-wgpu"),
            output=tmp_path / "unused.json",
            timeout=7,
        )

    assert "last scanner diagnostic" in str(exc.value)


def test_keyhog_warmup_failure_stops_before_timed_scan_and_cleans_artifacts(
    monkeypatch, tmp_path
):
    scanner = scanners.KeyhogScanner(binary="/unused/keyhog")
    calls = []

    def fail_warmup(cmd, **kwargs):
        calls.append(cmd)
        return "", "warmup failed", base.RunStats(exit_code=2)

    monkeypatch.setattr(keyhog_adapter, "run_measured", fail_warmup)
    with pytest.raises(RuntimeError, match=r"warmup exited 2"):
        scanner.run(tmp_path, ScannerConfig(backend="simd", cache="on"))

    assert len(calls) == 1
    warm_output = pathlib.Path(calls[0][calls[0].index("--output") + 1])
    incremental = pathlib.Path(
        calls[0][calls[0].index("--incremental-cache") + 1]
    )
    assert not warm_output.parent.exists()
    assert warm_output.parent == incremental.parent


def test_keyhog_warmup_and_timed_scan_launch_the_same_snapshot(
    monkeypatch, tmp_path
):
    scanner = scanners.KeyhogScanner(binary="/unused/keyhog")
    commands = []

    def successful_scan(cmd, **kwargs):
        commands.append(cmd)
        pathlib.Path(cmd[cmd.index("--output") + 1]).write_text("[]")
        return "", "", base.RunStats(exit_code=0)

    monkeypatch.setattr(keyhog_adapter, "run_measured", successful_scan)

    scanner.run(tmp_path, ScannerConfig(backend="simd", cache="on"))

    assert len(commands) == 2
    assert commands[0][0] == commands[1][0] == "/snapshot/keyhog"


def test_keyhog_owned_plaintext_output_is_cleaned_after_parse_failure(
    monkeypatch, tmp_path
):
    scanner = scanners.KeyhogScanner(binary="/unused/keyhog")
    output_paths = []

    def malformed_output(cmd, **kwargs):
        output = pathlib.Path(cmd[cmd.index("--output") + 1])
        output_paths.append(output)
        output.write_text("not json")
        return "", "", base.RunStats(exit_code=0)

    monkeypatch.setattr(keyhog_adapter, "run_measured", malformed_output)
    with pytest.raises(RuntimeError, match=r"invalid JSON"):
        scanner.run(tmp_path, ScannerConfig(backend="simd"))

    assert len(output_paths) == 1
    assert not output_paths[0].parent.exists()


def test_keyhog_caller_output_without_cache_allocates_only_detector_snapshot(
    monkeypatch, tmp_path
):
    detector_corpus = tmp_path / "detectors"
    detector_corpus.mkdir()
    (detector_corpus / "one.toml").write_text("[detector]\nid = 'one'\n")
    scanner = scanners.KeyhogScanner(
        binary="/unused/keyhog", detector_corpus=detector_corpus,
    )
    output = tmp_path / "caller-owned.json"
    monkeypatch.setenv("KEYHOG_BENCH_SNAPSHOT_DIR", str(tmp_path / "snapshots"))
    real_tempdir = keyhog_adapter.tempfile.TemporaryDirectory
    prefixes = []

    def detector_snapshot_only(*args, **kwargs):
        prefixes.append(kwargs.get("prefix", args[0] if args else None))
        return real_tempdir(*args, **kwargs)

    def successful_scan(cmd, **kwargs):
        pathlib.Path(cmd[cmd.index("--output") + 1]).write_text("[]")
        return "", "", base.RunStats(exit_code=0)

    monkeypatch.setattr(
        keyhog_adapter.tempfile, "TemporaryDirectory", detector_snapshot_only,
    )
    monkeypatch.setattr(keyhog_adapter, "run_measured", successful_scan)
    findings, stats = scanner.run(
        tmp_path,
        ScannerConfig(backend="simd", cache="off"),
        output=output,
    )

    assert findings == []
    assert stats.exit_code == 0
    assert output.read_text() == "[]"
    assert prefixes == ["keyhog-bench-detectors-"]


def test_keyhog_run_binds_digest_and_scan_to_immutable_detector_snapshot(
    monkeypatch, tmp_path
):
    detector_corpus = tmp_path / "detectors"
    detector_corpus.mkdir()
    detector = detector_corpus / "one.toml"
    initial = b"[detector]\nid = 'initial'\n"
    detector.write_bytes(initial)
    scanner = scanners.KeyhogScanner(
        binary="/unused/keyhog", detector_corpus=detector_corpus,
    )
    snapshot_root = tmp_path / "snapshots"
    monkeypatch.setenv("KEYHOG_BENCH_SNAPSHOT_DIR", str(snapshot_root))
    scanned_detector_paths = []

    def successful_scan(cmd, **kwargs):
        selected = pathlib.Path(cmd[cmd.index("--detectors") + 1])
        scanned_detector_paths.append(selected)
        assert selected != detector_corpus
        assert (selected / "one.toml").read_bytes() == initial
        detector.write_bytes(b"[detector]\nid = 'transient'\n")
        detector.write_bytes(initial)
        pathlib.Path(cmd[cmd.index("--output") + 1]).write_text("[]")
        return "", "", base.RunStats(exit_code=0)

    monkeypatch.setattr(keyhog_adapter, "run_measured", successful_scan)

    findings, stats, provenance = scanner.run_with_provenance(
        tmp_path, ScannerConfig(backend="simd"),
    )
    second_findings, second_stats, second_provenance = scanner.run_with_provenance(
        tmp_path, ScannerConfig(backend="simd"),
    )

    assert findings == []
    assert stats.exit_code == 0
    assert provenance.executable_sha256 == "a" * 64
    assert provenance.detector_corpus_sha256 == (
        keyhog_adapter.compute_detector_corpus_sha256(detector_corpus)
    )
    assert second_findings == []
    assert second_stats.exit_code == 0
    assert second_provenance == provenance
    assert len(scanned_detector_paths) == 2
    assert scanned_detector_paths[0] == scanned_detector_paths[1]
    assert scanned_detector_paths[0].is_dir()
    assert len(list(snapshot_root.iterdir())) == 1


@pytest.mark.parametrize("backend", ["gpu-cuda", "gpu-wgpu"])
def test_keyhog_daemon_commands_keep_server_and_client_ownership_separate(tmp_path, backend):
    executable = tmp_path / "keyhog"
    socket_path = tmp_path / "daemon.sock"
    detectors = tmp_path / "detectors"
    input_file = tmp_path / "input.txt"
    output = tmp_path / "result.json"

    server = keyhog_daemon.daemon_server_command(
        executable, socket_path, detectors, backend,
    )
    client = keyhog_daemon.daemon_client_command(
        executable, socket_path, input_file, output,
    )

    assert server == [
        str(executable), "daemon", "start", "--socket", str(socket_path),
        "--detectors", str(detectors), "--backend", backend,
    ]
    assert client == [
        str(executable), "scan", "--format", "json-envelope", "--no-config",
        "--daemon=on", "--daemon-socket", str(socket_path),
        "--output", str(output), str(input_file),
    ]
    forbidden_client_flags = {
        "--backend", "--detectors", "--show-secrets", "--no-gpu",
        "--require-gpu", "--incremental", "--fast", "--deep", "--precision",
        "--no-suppress-test-fixtures",
    }
    assert forbidden_client_flags.isdisjoint(client)


@pytest.mark.parametrize(
    "backend,cache,mode,message",
    [
        ("auto", "off", "full", "explicit"),
        ("simd", "on", "full", "incremental cache"),
        ("simd", "off", "deep", "only full mode"),
        ("simd", "off", "precision", "only full mode"),
    ],
)
def test_keyhog_daemon_validation_rejects_unproven_axes(
    tmp_path, backend, cache, mode, message,
):
    input_file = tmp_path / "input.txt"
    input_file.write_text("public benchmark bytes", encoding="utf-8")

    with pytest.raises(RuntimeError, match=message):
        keyhog_daemon.validate_daemon_benchmark(input_file, backend, cache, mode)


def test_keyhog_daemon_validation_rejects_directory_corpus(tmp_path):
    with pytest.raises(RuntimeError, match="one regular file"):
        keyhog_daemon.validate_daemon_benchmark(tmp_path, "simd", "off", "full")


def test_keyhog_daemon_status_requires_served_and_active_counts(monkeypatch):
    daemon = keyhog_daemon.OwnedKeyhogDaemon(
        pathlib.Path("/snapshot/keyhog"), (), pathlib.Path("/detectors"), "simd", 30,
    )
    completed = type(
        "Completed", (),
        {"stdout": "keyhog daemon: uptime 7s · 2 scans served · 0 active · 4 detectors"},
    )()
    monkeypatch.setattr(daemon, "_assert_owned_peer", lambda: None)
    monkeypatch.setattr(daemon, "_admin", lambda *_args, **_kwargs: completed)

    assert daemon.status() == (2, 0)


def test_keyhog_daemon_rejects_partial_coverage_even_with_findings(monkeypatch, tmp_path):
    daemon = keyhog_daemon.OwnedKeyhogDaemon(
        pathlib.Path("/snapshot/keyhog"), (), pathlib.Path("/detectors"), "simd", 30,
    )
    monkeypatch.setattr(daemon, "_assert_owned_peer", lambda: None)
    monkeypatch.setattr(
        keyhog_daemon,
        "run_measured",
        lambda *_args, **_kwargs: (
            "",
            "warning: daemon input coverage was incomplete (1 source gap(s))",
            base.RunStats(exit_code=1),
        ),
    )

    with pytest.raises(RuntimeError, match="partial-file throughput"):
        daemon.run_client(tmp_path / "input", tmp_path / "output", 30)


@pytest.mark.skipif(os.name == "nt", reason="owned daemon lifecycle is Unix only")
def test_keyhog_daemon_startup_timeout_reaps_owned_process(tmp_path):
    executable = tmp_path / "never-ready"
    executable.write_text("#!/bin/sh\nsleep 60\n", encoding="utf-8")
    executable.chmod(0o700)
    daemon = keyhog_daemon.OwnedKeyhogDaemon(
        executable, (), tmp_path / "detectors", "simd", 0,
    )

    with pytest.raises(TimeoutError, match="was not ready"):
        with daemon:
            raise AssertionError("unreachable")

    assert daemon._process is not None
    assert daemon._process.poll() is not None
    assert daemon._tempdir is None


def test_keyhog_daemon_spawn_failure_cleans_private_artifacts(tmp_path):
    daemon = keyhog_daemon.OwnedKeyhogDaemon(
        tmp_path / "missing-keyhog", (), tmp_path / "detectors", "simd", 30,
    )

    with pytest.raises(FileNotFoundError):
        with daemon:
            raise AssertionError("unreachable")

    assert daemon._stderr_handle is None
    assert daemon._tempdir is None


def test_keyhog_daemon_cleanup_preserves_primary_failure(monkeypatch):
    daemon = keyhog_daemon.OwnedKeyhogDaemon(
        pathlib.Path("/snapshot/keyhog"), (), pathlib.Path("/detectors"), "simd", 30,
    )
    monkeypatch.setattr(
        daemon, "_stop_and_reap", lambda: (_ for _ in ()).throw(OSError("stop failed")),
    )
    monkeypatch.setattr(
        daemon, "_close_artifacts", lambda: (_ for _ in ()).throw(OSError("close failed")),
    )
    primary = ValueError("scan failed")

    with pytest.raises(ValueError, match="scan failed") as caught:
        daemon.__exit__(ValueError, primary, primary.__traceback__)

    assert isinstance(caught.value.__cause__, RuntimeError)
    assert "stop failed" in str(caught.value.__cause__)
    assert "close failed" in str(caught.value.__cause__)


def test_keyhog_daemon_run_records_owned_pid_and_exact_request_count(
    monkeypatch, tmp_path,
):
    detector_corpus = tmp_path / "detectors"
    detector_corpus.mkdir()
    (detector_corpus / "one.toml").write_text(
        "[detector]\nid = 'one'\n", encoding="utf-8",
    )
    input_file = tmp_path / "input.txt"
    input_file.write_text("public benchmark bytes", encoding="utf-8")
    scanner = scanners.KeyhogScanner(
        binary="/unused/keyhog", detector_corpus=detector_corpus,
    )
    monkeypatch.setenv("KEYHOG_BENCH_SNAPSHOT_DIR", str(tmp_path / "snapshots"))
    instances = []

    class FakeOwnedDaemon:
        def __init__(self, executable, pass_fds, detectors, backend, timeout):
            self.pid = 4242
            self.requests = 0
            self.args = (executable, pass_fds, detectors, backend, timeout)
            instances.append(self)

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def run_client(self, root, output, timeout):
            assert root == input_file
            assert timeout == 3600
            self.requests += 1
            output.write_text("[]", encoding="utf-8")
            return base.RunStats(wall_ms=12.5, peak_rss_kb=1, exit_code=0)

        def status(self):
            return self.requests, 0

        def evidence(self):
            return keyhog_daemon.DaemonEvidence(
                pid=self.pid,
                scans_served=self.requests,
                active_scans=0,
                peak_rss_kb=8192,
            )

    monkeypatch.setattr(keyhog_adapter, "OwnedKeyhogDaemon", FakeOwnedDaemon)

    findings, stats, provenance = scanner.run_with_provenance(
        input_file,
        ScannerConfig(backend="simd", cache="off", daemon="on", mode="full"),
    )

    assert findings == []
    assert stats.wall_ms == 12.5
    assert stats.peak_rss_kb == 8192
    assert provenance.execution_route == "daemon"
    assert provenance.daemon_pid == 4242
    assert provenance.daemon_requests == 2
    assert len(instances) == 1
    assert instances[0].args[3] == "simd"


def test_keyhog_binary_snapshot_is_sibling_byte_copy_bound_to_one_opened_source(
    monkeypatch, tmp_path
):
    source = tmp_path / ("keyhog.exe" if os.name == "nt" else "keyhog")
    initial = b"first executable bytes"
    source.write_bytes(initial)
    source.chmod(0o700)
    scanner = scanners.KeyhogScanner(binary=str(source))
    snapshots = []

    def assert_current(path, *, pass_fds=()):
        launch_path = pathlib.Path(path)
        snapshot = launch_path.resolve()
        snapshots.append(snapshot)
        assert snapshot.parent == source.parent
        if source.suffix:
            assert snapshot.suffix == source.suffix
        assert snapshot.read_bytes() == initial
        if os.name != "nt":
            assert pass_fds
        return "KeyHog verified snapshot"

    monkeypatch.setattr(
        keyhog_adapter.KeyhogScanner, "_binary_snapshot", _REAL_BINARY_SNAPSHOT,
    )
    monkeypatch.setattr(keyhog_adapter, "assert_keyhog_binary_current", assert_current)

    with scanner._binary_snapshot() as (snapshot, digest, version, pass_fds):
        replacement = tmp_path / "replacement"
        replacement.write_bytes(b"replacement executable bytes")
        os.replace(replacement, source)
        restored = tmp_path / "restored"
        restored.write_bytes(initial)
        os.replace(restored, source)
        assert snapshot.read_bytes() == initial
        assert digest == hashlib.sha256(initial).hexdigest()
        assert version == "KeyHog verified snapshot"
        if os.name != "nt":
            assert pass_fds

    assert snapshots and not snapshots[0].exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX descriptor execution required")
def test_keyhog_binary_snapshot_executes_held_inode_after_path_replacement(tmp_path):
    source = tmp_path / "keyhog"
    shutil.copyfile("/bin/true", source)
    source.chmod(0o700)
    saved = tmp_path / "saved-snapshot"

    with keyhog_adapter.sibling_executable_snapshot(str(source)) as snapshot:
        os.replace(snapshot.path, saved)
        shutil.copyfile("/bin/false", snapshot.path)
        snapshot.path.chmod(0o500)
        _stdout, _stderr, stats = base.run_measured(
            [str(snapshot.launch_path)], pass_fds=snapshot.pass_fds, timeout=10,
        )
        assert stats.exit_code == 0
        snapshot.path.unlink()
        os.replace(saved, snapshot.path)


def test_keyhog_binary_snapshot_rejects_basename_coupled_loader_artifacts(tmp_path):
    source = tmp_path / ("keyhog.exe" if os.name == "nt" else "keyhog")
    source.write_bytes(b"executable bytes")
    source.chmod(0o700)
    (tmp_path / f"{source.name}.local").write_bytes(b"loader configuration")

    with pytest.raises(RuntimeError, match="basename-coupled loader artifacts"):
        with executable_snapshot.sibling_executable_snapshot(str(source)):
            pytest.fail("an unbound runtime bundle must not execute")


def test_keyhog_binary_snapshot_reports_protected_install_remedy(
    monkeypatch, tmp_path
):
    source = tmp_path / ("keyhog.exe" if os.name == "nt" else "keyhog")
    source.write_bytes(b"executable bytes")
    source.chmod(0o700)

    def deny_snapshot(*args, **kwargs):
        raise PermissionError("read-only installation")

    monkeypatch.setattr(executable_snapshot.tempfile, "mkstemp", deny_snapshot)

    with pytest.raises(RuntimeError, match="writable private runtime bundle"):
        with executable_snapshot.sibling_executable_snapshot(str(source)):
            pytest.fail("a failed snapshot must not execute")


def test_keyhog_binary_snapshot_fails_closed_on_unproven_darwin_launch(
    monkeypatch, tmp_path
):
    source = tmp_path / "keyhog"
    source.write_bytes(b"executable bytes")
    source.chmod(0o700)
    monkeypatch.setattr(executable_snapshot.sys, "platform", "darwin")

    with pytest.raises(RuntimeError, match="not yet proven for Darwin"):
        with executable_snapshot.sibling_executable_snapshot(str(source)):
            pytest.fail("Darwin must not emit unproven executable evidence")


def test_keyhog_binary_snapshot_rejects_mutation_and_still_cleans_up(tmp_path):
    source = tmp_path / ("keyhog.exe" if os.name == "nt" else "keyhog")
    source.write_bytes(b"executable bytes")
    source.chmod(0o700)
    snapshot_path = None

    with pytest.raises(RuntimeError, match="snapshot changed during the scan"):
        with keyhog_adapter.sibling_executable_snapshot(str(source)) as snapshot:
            snapshot_path = snapshot.path
            snapshot.path.chmod(0o700)
            snapshot.path.write_bytes(b"tampered")

    assert snapshot_path is not None
    assert not snapshot_path.exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX directory permissions required")
def test_keyhog_snapshot_cleanup_failure_preserves_scan_error(tmp_path):
    source = tmp_path / "keyhog"
    source.write_bytes(b"executable bytes")
    source.chmod(0o700)
    snapshot_path = None

    try:
        with pytest.raises(ValueError, match="scan failed") as caught:
            with keyhog_adapter.sibling_executable_snapshot(str(source)) as snapshot:
                snapshot_path = snapshot.path
                tmp_path.chmod(0o500)
                raise ValueError("scan failed")
        assert isinstance(caught.value.__cause__, RuntimeError)
        assert "failed to remove benchmark snapshot" in str(caught.value.__cause__)
    finally:
        tmp_path.chmod(0o700)
        if snapshot_path is not None and snapshot_path.exists():
            snapshot_path.chmod(0o700)
            snapshot_path.unlink()


def test_keyhog_warm_runs_are_private_under_concurrency_and_ignore_old_paths(
    monkeypatch, tmp_path
):
    scanner = scanners.KeyhogScanner(binary="/unused/keyhog")
    cfg = ScannerConfig(backend="simd", cache="on")
    output_parents = []

    old_warm = tmp_path / f"keyhog-bench-warm-{cfg.config_id}.json"
    sentinel = tmp_path / "sentinel"
    sentinel.write_text("unchanged")
    old_warm.symlink_to(sentinel)
    monkeypatch.setattr(keyhog_adapter.tempfile, "tempdir", str(tmp_path))

    def successful_scan(cmd, **kwargs):
        output = pathlib.Path(cmd[cmd.index("--output") + 1])
        output_parents.append(output.parent)
        output.write_text("[]")
        return "", "", base.RunStats(exit_code=0)

    monkeypatch.setattr(keyhog_adapter, "run_measured", successful_scan)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: scanner.run(tmp_path, cfg), range(2)))

    assert [findings for findings, _stats in results] == [[], []]
    run_dirs = set(output_parents)
    assert len(run_dirs) == 2
    assert all(not run_dir.exists() for run_dir in run_dirs)
    assert old_warm.is_symlink()
    assert sentinel.read_text() == "unchanged"


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
    executable = pathlib.Path("/bin/true")
    cmd_lb = scanner._cmd(root, lb, out, None, executable)
    assert "--min-confidence" not in cmd_lb
    assert lb.config_id == "simd-nocache-nodaemon-full"
    assert "min_confidence" not in lb.to_json()

    # Harvest: floor 0.0 captures every scored candidate; flag present, but the
    # config_id MUST be unchanged so the harvest scan can never masquerade as a
    # distinct leaderboard row.
    harvest = ScannerConfig(backend="simd", min_confidence=0.0)
    cmd_h = scanner._cmd(root, harvest, out, None, executable)
    i = cmd_h.index("--min-confidence")
    assert cmd_h[i + 1] == "0.0"
    assert harvest.config_id == "simd-nocache-nodaemon-full"
    assert harvest.to_json()["min_confidence"] == 0.0

    # A fractional floor round-trips through the CLI float formatting.
    frac = ScannerConfig(backend="cpu", min_confidence=0.05)
    cmd_f = scanner._cmd(root, frac, out, None, executable)
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
