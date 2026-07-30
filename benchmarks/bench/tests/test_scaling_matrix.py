"""Behavioral contracts for reproducible README scaling evidence."""

from __future__ import annotations

import json
import pathlib
import time

import pytest

from bench import scaling_matrix
from bench.measurement import RunStats
from bench.schema import Host


def _successful_runner(
    command: list[str], *, timeout: int, pass_fds: tuple[int, ...]
) -> tuple[str, str, RunStats]:
    del timeout, pass_fds
    output = pathlib.Path(command[command.index("--output") + 1])
    output.write_text(
        json.dumps(
            {
                "schema_version": {"major": 1, "minor": 8},
                "scan_status": "success",
                "metadata": {"resolved_scan": {}, "static_recovery": {}},
                "findings": [],
            }
        ),
        encoding="utf-8",
    )
    return "", "", RunStats(wall_ms=125.0, peak_rss_kb=2048, exit_code=0)


def _evidence() -> dict[str, object]:
    host = Host(
        hostname_hash="1" * 12,
        os="Linux test",
        kernel="test",
        cpu="Test CPU",
        cores=8,
        affinity_cores=8,
        cgroup_quota_cores=8.0,
        ram_mb=16384,
    )
    workloads = [
        {
            "name": name,
            "files": files,
            "bytes_per_file": size,
            "total_bytes": files * size,
            "sha256": character * 64,
        }
        for name, files, size, character in (
            ("small", 2, 1024, "1"),
            ("medium", 4, 1024, "2"),
            ("large", 8, 1024, "3"),
        )
    ]
    rows: list[dict[str, object]] = []

    def row(
        panel: str,
        label: str,
        *,
        storage: str = "workspace",
        workload: str = "medium",
        processes: int = 1,
        threads: int = 8,
        readers: int = 0,
        total_bytes: int = 4096,
        total_files: int = 4,
        wall_ms: float = 100.0,
        rss_kb: int = 2048,
    ) -> None:
        rows.append(
            {
                "panel": panel,
                "label": label,
                "storage": storage,
                "workload": workload,
                "processes": processes,
                "threads_per_process": threads,
                "reader_threads": readers,
                "total_bytes": total_bytes,
                "total_files": total_files,
                "page_cache": scaling_matrix.page_cache_policy(panel),
                "trials": [
                    {
                        "wall_ms": wall_ms,
                        "peak_rss_kb": rss_kb,
                        "max_process_rss_kb": rss_kb,
                        "exit_codes": [0] * processes,
                        "finding_count": 0,
                    },
                    {
                        "wall_ms": wall_ms + 20,
                        "peak_rss_kb": rss_kb + 1024,
                        "max_process_rss_kb": rss_kb + 1024,
                        "exit_codes": [0] * processes,
                        "finding_count": 0,
                    },
                ],
            }
        )

    row("threads", "1", threads=1, wall_ms=200)
    row("threads", "8", threads=8, wall_ms=100)
    row("readers", "1", readers=1, wall_ms=120)
    row("readers", "4", readers=4, wall_ms=90)
    row("sizes", "small", workload="small", total_bytes=2048, total_files=2)
    row("sizes", "medium")
    row("sizes", "large", workload="large", total_bytes=8192, total_files=8)
    row("storage", "workspace")
    row("storage", "local-temp", storage="local-temp", wall_ms=80)
    row(
        "partitions",
        "1",
        workload="small",
        threads=8,
        total_bytes=2048,
        total_files=2,
    )
    row(
        "partitions",
        "2",
        workload="small",
        processes=2,
        threads=4,
        total_bytes=4096,
        total_files=4,
        wall_ms=60,
        rss_kb=4096,
    )
    return {
        "schema": scaling_matrix.SCHEMA,
        "generated_at": "2026-07-28T00:00:00Z",
        "source_state": "clean",
        "scanner": {
            "version": "keyhog 0.5.48",
            "executable_sha256": "a" * 64,
            "detector_corpus_sha256": "b" * 64,
            "backend": "simd",
        },
        "host": host.to_json(),
        "effective_cores": 8,
        "warmups": 1,
        "trial_count": 2,
        "workloads": workloads,
        "storages": [
            {"label": "workspace", "filesystem": "nfs4", "device_id": 1},
            {"label": "local-temp", "filesystem": "ext4", "device_id": 2},
        ],
        "storage_corpus_sha256": {
            "workspace": {item["name"]: item["sha256"] for item in workloads},
            "local-temp": {item["name"]: item["sha256"] for item in workloads},
        },
        "rows": rows,
    }


def test_prepare_corpus_is_byte_deterministic_and_repairs_same_size_mutation(
    tmp_path: pathlib.Path,
) -> None:
    """A same-size corpus mutation must be repaired instead of contaminating published timings."""
    workload = scaling_matrix.Workload("small", files=3, bytes_per_file=97)

    first = scaling_matrix.prepare_corpus(tmp_path, workload)
    corpus = tmp_path / "small"
    assert len(list(corpus.iterdir())) == 3
    assert sum(path.stat().st_size for path in corpus.iterdir()) == 291
    (corpus / "record-000001.txt").write_bytes(b"x" * 97)
    mutated = scaling_matrix.corpus_digest(corpus)
    assert mutated != first

    repaired = scaling_matrix.prepare_corpus(tmp_path, workload)
    assert repaired == first
    assert scaling_matrix.corpus_digest(corpus) == first


def test_effective_core_and_axis_planning_respect_every_host_limit() -> None:
    """Thread axes must not oversubscribe affinity or finite cgroup quotas on constrained runners."""
    host = Host(cores=32, affinity_cores=12, cgroup_quota_cores=6.8)

    assert scaling_matrix.effective_cores(host) == 6
    assert scaling_matrix.power_points(6) == (1, 2, 4, 6)
    assert scaling_matrix.power_points(32, cap=4) == (1, 2, 4)
    assert scaling_matrix.parse_points("8,1,4,4", (2,)) == (1, 4, 8)


@pytest.mark.parametrize("raw", ["", "0,1", "-1,2", "2,4"])
def test_explicit_axis_points_reject_empty_or_nonpositive_values(raw: str) -> None:
    """Malformed release inputs must fail before an incomplete matrix can be labeled reproducible."""
    with pytest.raises(ValueError, match="positive comma-separated"):
        scaling_matrix.parse_points(raw, (1, 2))


def test_scan_command_pins_every_behavioral_route_and_optional_reader_count(
    tmp_path: pathlib.Path,
) -> None:
    """Scaling runs must never inherit config, daemon routing, excludes, or an implicit backend."""
    command = scaling_matrix._command(
        pathlib.Path("/bin/keyhog"),
        tmp_path / "corpus",
        tmp_path / "report.json",
        tmp_path / "cache",
        "simd",
        8,
        3,
    )

    assert command == [
        "/bin/keyhog",
        "scan",
        str(tmp_path / "corpus"),
        "--format",
        "json-envelope",
        "--output",
        str(tmp_path / "report.json"),
        "--no-config",
        "--no-default-excludes",
        "--quiet",
        "--daemon=off",
        "--backend",
        "simd",
        "--cache-dir",
        str(tmp_path / "cache"),
        "--threads",
        "8",
        "--reader-threads",
        "3",
    ]

def test_benchmark_cache_lives_under_keyhog_configured_path_allowlist() -> None:
    """The harness must not place `--cache-dir` in a generic temp path that KeyHog rejects."""
    with scaling_matrix.benchmark_cache_directory() as cache:
        retained = cache
        assert cache.parent == pathlib.Path.home()
        assert cache.name.startswith(".keyhog-bench-scaling-cache-")
        assert cache.stat().st_mode & 0o777 == 0o700
    assert not retained.exists()


def test_single_process_case_uses_scanner_owned_status_and_exact_measurement(
    tmp_path: pathlib.Path,
) -> None:
    """A successful timing row must come from a complete JSON envelope, not exit code alone."""
    case = scaling_matrix.Case(
        "threads", "2", "workspace", "small", 1, 2, 0, 1024, 1
    )
    (tmp_path / "workspace" / "small").mkdir(parents=True)
    output = tmp_path / "output"
    output.mkdir()

    trial = scaling_matrix.run_case(
        case,
        executable=pathlib.Path("/bin/keyhog"),
        pass_fds=(),
        roots={"workspace": tmp_path / "workspace"},
        cache_dir=tmp_path / "cache",
        backend="simd",
        output_root=output,
        runner=_successful_runner,
    )

    assert trial == scaling_matrix.Trial(125.0, 2048, 2048, (0,), 0)


def test_concurrent_partition_case_aggregates_process_memory_and_exit_identity(
    tmp_path: pathlib.Path,
) -> None:
    """Partition evidence must expose all process exits and summed memory, not one lucky child."""
    roots = {"workspace": tmp_path / "workspace"}
    for index in range(2):
        (roots["workspace"] / f"partition-{index}" / "small").mkdir(parents=True)
    output = tmp_path / "output"
    output.mkdir()
    case = scaling_matrix.Case(
        "partitions", "2", "workspace", "small", 2, 2, 0, 2048, 2
    )

    trial = scaling_matrix.run_case(
        case,
        executable=pathlib.Path("/bin/keyhog"),
        pass_fds=(),
        roots=roots,
        cache_dir=tmp_path / "cache",
        backend="simd",
        output_root=output,
        runner=_successful_runner,
    )

    assert trial.exit_codes == (0, 0)
    assert trial.peak_rss_kb == 4096
    assert trial.max_process_rss_kb == 2048
    assert trial.finding_count == 0
    assert trial.wall_ms > 0


def test_failed_process_cannot_be_published_as_a_timing_row(tmp_path: pathlib.Path) -> None:
    """A backend failure must stop capture instead of disappearing behind a wall-time number."""
    output = tmp_path / "report.json"

    def failed_runner(command, *, timeout, pass_fds):
        del command, timeout, pass_fds
        return "", "backend unavailable", RunStats(
            wall_ms=10, peak_rss_kb=1, exit_code=3
        )

    with pytest.raises(RuntimeError, match="exit 3.*backend unavailable"):
        scaling_matrix._run_process([], output, (), failed_runner)


def test_incomplete_json_envelope_cannot_be_published(tmp_path: pathlib.Path) -> None:
    """Exit zero with partial source coverage must remain a failed benchmark contract."""
    output = tmp_path / "report.json"

    def partial_runner(command, *, timeout, pass_fds):
        del command, timeout, pass_fds
        output.write_text(
            json.dumps(
                {
                    "schema_version": {"major": 1, "minor": 8},
                    "scan_status": "partial",
                    "metadata": {"resolved_scan": {}},
                    "findings": [],
                }
            ),
            encoding="utf-8",
        )
        return "", "", RunStats(wall_ms=10, peak_rss_kb=1, exit_code=0)

    with pytest.raises(RuntimeError, match="terminal scan_status='partial'"):
        scaling_matrix._run_process([], output, (), partial_runner)


def test_validation_rejects_missing_panels_findings_and_unknown_schema() -> None:
    """Hand-shaped snapshots must fail closed when required axes or clean-corpus truth disappear."""
    missing = _evidence()
    missing["rows"] = [row for row in missing["rows"] if row["panel"] != "storage"]
    with pytest.raises(ValueError, match="missing panel"):
        scaling_matrix.validate(missing)

    finding = _evidence()
    finding["rows"][0]["trials"][0]["finding_count"] = 1
    with pytest.raises(ValueError, match="was not finding-free"):
        scaling_matrix.validate(finding)

    schema = _evidence()
    schema["schema"] = "keyhog-readme-scaling-v2"
    with pytest.raises(ValueError, match="unsupported scaling schema"):
        scaling_matrix.validate(schema)

def test_validation_rejects_storage_byte_drift_and_axis_tampering() -> None:
    """Published comparisons must bind byte-identical storage copies and the declared axis."""
    storage_drift = _evidence()
    storage_drift["storage_corpus_sha256"]["local-temp"]["medium"] = "f" * 64
    with pytest.raises(ValueError, match="bytes differ from canonical"):
        scaling_matrix.validate(storage_drift)

    axis_drift = _evidence()
    axis_drift["rows"][1]["threads_per_process"] = 7
    with pytest.raises(ValueError, match="thread scaling row axes"):
        scaling_matrix.validate(axis_drift)


def test_validation_rejects_nonfinite_time_and_missing_process_exit() -> None:
    """NaN timings and incomplete child exits must never enter speedup or memory tables."""
    nonfinite = _evidence()
    nonfinite["rows"][0]["trials"][0]["wall_ms"] = float("nan")
    with pytest.raises(ValueError, match="invalid wall time"):
        scaling_matrix.validate(nonfinite)

    missing_exit = _evidence()
    partition = next(
        row
        for row in missing_exit["rows"]
        if row["panel"] == "partitions" and row["processes"] == 2
    )
    partition["trials"][0]["exit_codes"] = [0]
    with pytest.raises(ValueError, match="invalid process exit codes"):
        scaling_matrix.validate(missing_exit)


def test_validation_accepts_explicit_cross_platform_page_cache_identity() -> None:
    """A Linux docs gate must accept evidence captured on a platform without page eviction."""
    evidence = _evidence()
    for row in evidence["rows"]:
        if row["panel"] != "threads":
            row["page_cache"] = "warm-platform-no-eviction-api"

    scaling_matrix.validate(evidence)


def test_render_emits_all_five_detailed_panels_from_measured_rows() -> None:
    """README output must retain every requested tuning axis and computed comparison column."""
    rendered = scaling_matrix.render(_evidence())

    assert "#### Scan worker scaling" in rendered
    assert "#### Filesystem reader scaling" in rendered
    assert "#### Corpus-size scaling" in rendered
    assert "#### Storage scaling" in rendered
    assert "#### Concurrent partition scaling" in rendered
    assert "| 8 | auto | 110.0 ms | 120.0 ms |" in rendered
    assert "| local-temp | `ext4` | `2` | 90.0 ms | 100.0 ms |" in rendered
    assert "| 2 | 4 | 8 | 4 | 0 MiB | 70.0 ms |" in rendered
    assert "These rows are measurements, not universal tuning constants." in rendered


def test_readme_check_detects_manual_table_drift(tmp_path: pathlib.Path) -> None:
    """A hand-edited scaling number must fail the docs gate instead of becoming product truth."""
    readme = tmp_path / "README.md"
    readme.write_text(
        f"before\n{scaling_matrix.BEGIN}\nstale\n{scaling_matrix.END}\nafter\n",
        encoding="utf-8",
    )
    rendered = scaling_matrix.render(_evidence())

    with pytest.raises(ValueError, match="scaling tables are stale"):
        scaling_matrix.update_readme(readme, rendered, check=True)
    scaling_matrix.update_readme(readme, rendered, check=False)
    scaling_matrix.update_readme(readme, rendered, check=True)
    assert readme.read_text(encoding="utf-8") == f"before\n{rendered}\nafter\n"
