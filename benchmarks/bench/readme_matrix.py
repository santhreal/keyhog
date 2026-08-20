"""Capture and render the README configuration benchmark panels.

Raw RunResult files remain host-specific and ignored. This module reduces the
selected rows to one committed, provenance-bound snapshot, renders Markdown
reports from that snapshot, and keeps the README marker blocks byte-stable.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys
from typing import Any

from .report import inject, load_results

BENCH_ROOT = pathlib.Path(__file__).resolve().parents[1]
REPO_ROOT = BENCH_ROOT.parent
SNAPSHOT_SCHEMA = "readme-config-matrix-v1"
DAEMON_CORPUS_BYTES = 8 * 1024 * 1024
DAEMON_PATTERN = b"ordinary configuration value for keyhog daemon benchmark\n"
DAEMON_CORPUS_SHA256 = "afafbe7b6487fd62866f510e7c281a9e7bfeaa8dc585d7b0478c92ee6c4f5ef5"
IO_CHUNK_BYTES = 1024 * 1024

ROUTE_CONFIGS = (
    "simd-nocache-nodaemon-full",
    "cpu-nocache-nodaemon-full",
    "gpu-cuda-nocache-nodaemon-full",
    "gpu-wgpu-nocache-nodaemon-full",
    "auto-nocache-nodaemon-full",
)
POLICY_CONFIGS = (
    "simd-nocache-nodaemon-fast",
    "simd-nocache-nodaemon-full",
    "simd-nocache-nodaemon-deep",
    "simd-nocache-nodaemon-precision",
)
CACHE_CONFIGS = (
    "simd-nocache-nodaemon-full",
    "simd-cache-nodaemon-full",
)
DAEMON_CONFIGS = tuple(
    f"{backend}-nocache-{lifetime}-full"
    for backend in ("simd", "cpu", "gpu-cuda", "gpu-wgpu")
    for lifetime in ("nodaemon", "daemon")
)
REQUIRED_CONFIGS = set(ROUTE_CONFIGS + POLICY_CONFIGS + CACHE_CONFIGS)


class MatrixError(ValueError):
    """Raised when matrix evidence is incomplete, stale, or contradictory."""


def workspace_version() -> str:
    """Return the workspace package version used by the measured binary."""
    text = (REPO_ROOT / "Cargo.toml").read_text(encoding="utf-8")
    match = re.search(
        r"(?ms)^\[workspace\.package\]\s*.*?^version\s*=\s*\"([^\"]+)\"",
        text,
    )
    if match is None:
        raise MatrixError("cannot read [workspace.package].version")
    return match.group(1)


def _sha256_file(path: pathlib.Path) -> str:
    """Hash a file without allocating its complete contents."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(IO_CHUNK_BYTES):
            digest.update(chunk)
    return digest.hexdigest()


def generate_daemon_corpus(path: pathlib.Path, size: int = DAEMON_CORPUS_BYTES) -> str:
    """Write one deterministic regular-file workload and return its SHA-256."""
    if size <= 0:
        raise MatrixError("daemon corpus size must be positive")
    path.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    block = DAEMON_PATTERN * max(1, IO_CHUNK_BYTES // len(DAEMON_PATTERN))
    remaining = size
    with path.open("wb") as handle:
        while remaining:
            chunk = block[:remaining]
            handle.write(chunk)
            digest.update(chunk)
            remaining -= len(chunk)
    return digest.hexdigest()


def _index_results(path: pathlib.Path) -> dict[str, Any]:
    """Index KeyHog result rows by configuration ID."""
    rows = load_results(path)
    selected: dict[str, Any] = {}
    for row in rows:
        if row.scanner.name != "keyhog":
            continue
        config_id = row.scanner.config_id
        if config_id in selected:
            raise MatrixError(f"{path}: duplicate KeyHog config {config_id!r}")
        selected[config_id] = row
    return selected


def _select(index: dict[str, Any], required: set[str], label: str) -> list[Any]:
    """Select and validate required configuration result rows from index."""
    missing = sorted(required.difference(index))
    if missing:
        raise MatrixError(f"{label} results lack required configs: {', '.join(missing)}")
    unavailable = sorted(config for config in required if not index[config].available)
    if unavailable:
        details = "; ".join(
            f"{config}: {index[config].error or 'unavailable'}" for config in unavailable
        )
        raise MatrixError(f"{label} results contain unavailable configs: {details}")
    return [index[config] for config in sorted(required)]


def _assert_common_identity(config_rows: list[Any], daemon_rows: list[Any]) -> None:
    """Verify that all configuration and daemon rows share an identical host and binary."""
    rows = [*config_rows, *daemon_rows]
    expected_version = f"KeyHog v{workspace_version()}"
    versions = {row.scanner.version.splitlines()[0] for row in rows}
    if versions != {expected_version}:
        raise MatrixError(
            f"matrix scanner versions must be exactly {expected_version!r}, found {sorted(versions)!r}"
        )
    executable_digests = {row.scanner.executable_sha256 for row in rows}
    if len(executable_digests) != 1 or not next(iter(executable_digests), ""):
        raise MatrixError("matrix rows must bind one nonempty executable SHA-256")
    detector_digests = {row.scanner.detector_corpus_sha256 for row in rows}
    if len(detector_digests) != 1 or not next(iter(detector_digests), ""):
        raise MatrixError("matrix rows must bind one nonempty detector corpus SHA-256")
    hosts = {
        (
            row.host.hostname_hash,
            row.host.os,
            row.host.cpu,
            row.host.cores,
            row.host.gpu,
            row.host.gpu_vram_mb,
        )
        for row in rows
    }
    if len(hosts) != 1:
        raise MatrixError("configuration and daemon rows must use one exact host")


def _snapshot_row(row: Any) -> dict[str, Any]:
    """Extract JSON-serializable snapshot row dictionary from result."""
    overall = row.detection.overall
    return {
        "generated_at": row.generated_at,
        "host": row.host.to_json(),
        "scanner": row.scanner.to_json(),
        "corpus": row.corpus.to_json(),
        "speed": row.speed.to_json(),
        "detection": {
            "tp": overall.tp,
            "fp": overall.fp,
            "fn": overall.fn,
            "precision": round(overall.precision(), 4),
            "recall": round(overall.recall(), 4),
            "f1": round(overall.f1(), 4),
        },
        "finding_count": row.finding_count,
    }


def capture_snapshot(
    config_results: pathlib.Path,
    daemon_results: pathlib.Path,
    daemon_corpus: pathlib.Path,
    source_state: str,
) -> dict[str, Any]:
    """Reduce raw matrix runs to the exact rows used by README panels."""
    if source_state not in {"clean", "developer-dirty"}:
        raise MatrixError("source state must be clean or developer-dirty")
    config_index = _index_results(config_results)
    daemon_index = _index_results(daemon_results)
    config_rows = _select(config_index, REQUIRED_CONFIGS, "configuration")
    daemon_rows = _select(daemon_index, set(DAEMON_CONFIGS), "daemon")
    _assert_common_identity(config_rows, daemon_rows)
    if not daemon_corpus.is_file():
        raise MatrixError(f"daemon corpus is not one regular file: {daemon_corpus}")
    corpus_size = daemon_corpus.stat().st_size
    if corpus_size != DAEMON_CORPUS_BYTES:
        raise MatrixError(
            f"daemon corpus must be {DAEMON_CORPUS_BYTES} bytes, found {corpus_size}"
        )
    corpus_sha256 = _sha256_file(daemon_corpus)
    if corpus_sha256 != DAEMON_CORPUS_SHA256:
        raise MatrixError(
            "daemon corpus bytes differ from the deterministic generated workload: "
            f"expected {DAEMON_CORPUS_SHA256}, found {corpus_sha256}"
        )
    if any(row.corpus.bytes != DAEMON_CORPUS_BYTES for row in daemon_rows):
        raise MatrixError("daemon result byte counts differ from the measured corpus")

    selected_config_ids = sorted(REQUIRED_CONFIGS)
    selected_daemon_ids = sorted(DAEMON_CONFIGS)
    cat_file = BENCH_ROOT / "workload-catalog.toml"
    cat_digest = _sha256_file(cat_file) if cat_file.exists() else None
    return {
        "schema_version": SNAPSHOT_SCHEMA,
        "source_state": source_state,
        "catalog_sha256": cat_digest,
        "daemon_corpus": {
            "bytes": corpus_size,
            "sha256": corpus_sha256,
        },
        "configuration_rows": [
            _snapshot_row(config_index[config]) for config in selected_config_ids
        ],
        "daemon_rows": [
            _snapshot_row(daemon_index[config]) for config in selected_daemon_ids
        ],
    }


def load_snapshot(path: pathlib.Path) -> dict[str, Any]:
    """Load and validate the committed matrix snapshot."""
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise MatrixError(f"cannot load matrix snapshot {path}: {error}") from error
    if not isinstance(value, dict) or value.get("schema_version") != SNAPSHOT_SCHEMA:
        raise MatrixError(f"{path}: unsupported matrix snapshot schema")
    for key in ("source_state", "daemon_corpus", "configuration_rows", "daemon_rows"):
        if key not in value:
            raise MatrixError(f"{path}: missing {key!r}")
    if value["source_state"] not in {"clean", "developer-dirty"}:
        raise MatrixError(f"{path}: invalid source_state")
    if not isinstance(value["configuration_rows"], list) or not isinstance(
        value["daemon_rows"], list
    ):
        raise MatrixError(f"{path}: matrix rows must be arrays")
    return value


def _rows_by_config(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Index snapshot rows by configuration ID."""
    indexed: dict[str, dict[str, Any]] = {}
    for row in rows:
        config_id = row.get("scanner", {}).get("config_id", "")
        if not config_id or config_id in indexed:
            raise MatrixError(f"snapshot contains invalid or duplicate config {config_id!r}")
        indexed[config_id] = row
    return indexed


def _fmt_time(wall_ms: float) -> str:
    """Format millisecond wall duration for Markdown tables."""
    return f"{wall_ms:.0f} ms" if wall_ms < 1000 else f"{wall_ms / 1000:.2f} s"


def _fmt_rss(peak_rss_kb: int) -> str:
    """Format peak RSS in megabytes for Markdown tables."""
    return f"{peak_rss_kb / 1024:.0f} MiB"


def _context(snapshot: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Extract common host and scanner metadata from snapshot."""
    rows = snapshot["configuration_rows"]
    if not rows:
        raise MatrixError("snapshot contains no configuration rows")
    first = rows[0]
    return first["host"], first["scanner"]


def _qualification(snapshot: dict[str, Any], scanner: dict[str, Any]) -> str:
    """Format source cleanliness qualification text for reports."""
    if snapshot["source_state"] == "clean":
        return "The tracked source tree was clean."
    version = scanner["version"].splitlines()[0]
    return (
        f"Documentation changes were uncommitted; the measured {version} executable "
        "and detector digests were identical across every row. Treat these as "
        "development-host configuration comparisons, not release routing evidence."
    )


def render_accuracy(snapshot: dict[str, Any]) -> str:
    """Render the default-policy accuracy panel for evaluated corpora."""
    accuracy_rows = snapshot.get("accuracy_rows")
    if not accuracy_rows:
        rows = _rows_by_config(snapshot["configuration_rows"])
        row = rows.get("simd-nocache-nodaemon-full")
        if row is None:
            raise MatrixError("snapshot lacks the default Hyperscan/SIMD accuracy row")
        accuracy_rows = [row]

    host, scanner = _context(snapshot)
    corpus_names = [f"**{r['corpus']['name']}**" for r in accuracy_rows]
    if len(corpus_names) == 1:
        corpus_phrase = f"the {corpus_names[0]} corpus"
    else:
        corpus_phrase = f"{', '.join(corpus_names[:-1])} and {corpus_names[-1]} corpora"

    lines = [
        f"KeyHog `{scanner['version'].splitlines()[0]}` evaluated on {corpus_phrase} on **{host['cpu']}** with the explicit Hyperscan/SIMD default route. The answer-key manifest was excluded from the scan tree.",
        "",
        "| Corpus | Fixtures | Positives | Input size | Precision | Recall | F1 | True positives | False positives | False negatives |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in accuracy_rows:
        corpus = row["corpus"]
        detection = row["detection"]
        bytes_val = corpus["bytes"]
        if bytes_val >= 1024 * 1024:
            size_str = f"{bytes_val / (1024 * 1024):.2f} MB"
        else:
            size_str = f"{bytes_val / 1024:.0f} KB"
        lines.append(
            f"| **{corpus['name']}** | {corpus['fixture_count']:,} | {corpus['labeled_positives']:,} | {size_str} | {detection['precision']:.4f} | {detection['recall']:.4f} | {detection['f1']:.4f} | {detection['tp']:,} | {detection['fp']:,} | {detection['fn']:,} |"
        )
    lines.extend(["", _qualification(snapshot, scanner)])
    return "\n".join(lines)

def render_configuration(snapshot: dict[str, Any]) -> str:
    """Render backend, policy, and incremental comparisons."""
    rows = _rows_by_config(snapshot["configuration_rows"])
    missing = sorted(REQUIRED_CONFIGS.difference(rows))
    if missing:
        raise MatrixError(f"snapshot lacks configuration rows: {', '.join(missing)}")
    host, scanner = _context(snapshot)
    corpus = rows[ROUTE_CONFIGS[0]]["corpus"]
    qualification = _qualification(snapshot, scanner)
    lines = [
        f"Measured on **{host['cpu']}** with **{host.get('gpu') or 'no GPU'}**, "
        f"{host['cores']} logical cores, {corpus['fixture_count']:,} fixtures, "
        f"{corpus['labeled_positives']:,} labeled positives, and "
        f"{corpus['bytes']:,} input bytes. Scanner: "
        f"`{scanner['version'].splitlines()[0]}`. {qualification}",
        "",
        "#### Full scan by execution route",
        "",
        "All rows use the default detection policy with incremental cache and daemon off. "
        "The automatic row records the requested policy, but the benchmark result does not "
        "bind the selected persisted route, so it is not routing proof. GPU rows include "
        "acquisition and full scanner startup on this small corpus; they are not GPU kernel "
        "crossover measurements.",
        "",
        "| Requested route | Wall | Throughput | Peak RSS | F1 |",
        "|---|---:|---:|---:|---:|",
    ]
    labels = {
        "simd": "Hyperscan/SIMD",
        "cpu": "Pure-Rust CPU",
        "gpu-cuda": "CUDA",
        "gpu-wgpu": "WGPU",
        "auto": "Automatic",
    }
    for config_id in ROUTE_CONFIGS:
        row = rows[config_id]
        cfg = row["scanner"]["config"]
        speed = row["speed"]
        lines.append(
            f"| {labels[cfg['backend']]} | {_fmt_time(speed['wall_ms'])} | "
            f"{speed['throughput_mb_s']:.2f} MB/s | "
            f"{_fmt_rss(speed['peak_rss_kb'])} | {row['detection']['f1']:.4f} |"
        )
    lines.extend(
        [
            "",
            "#### Detection policy on Hyperscan/SIMD",
            "",
            "The route, cache, daemon state, corpus, and host remain fixed. Presets change "
            "detection work, so compare precision and recall as well as time.",
            "",
            "| Policy | Wall | Precision | Recall | F1 | Findings |",
            "|---|---:|---:|---:|---:|---:|",
        ]
    )
    policy_labels = {"fast": "Fast", "full": "Default", "deep": "Deep", "precision": "Precision"}
    for config_id in POLICY_CONFIGS:
        row = rows[config_id]
        mode = row["scanner"]["config"]["mode"]
        detection = row["detection"]
        lines.append(
            f"| {policy_labels[mode]} | {_fmt_time(row['speed']['wall_ms'])} | "
            f"{detection['precision']:.4f} | {detection['recall']:.4f} | "
            f"{detection['f1']:.4f} | {row['finding_count']:,} |"
        )
    lines.extend(
        [
            "",
            "#### Incremental warm rerun",
            "",
            "The benchmark populates the BLAKE3 Merkle index, then times the second identical "
            "scan. The small synthetic tree changes little because scanner startup dominates; "
            "measure your repository before claiming a speedup.",
            "",
            "| Hyperscan/SIMD default policy | Wall | Throughput | Peak RSS |",
            "|---|---:|---:|---:|",
        ]
    )
    for config_id, label in zip(CACHE_CONFIGS, ("Cache off", "Warm incremental cache")):
        row = rows[config_id]
        speed = row["speed"]
        lines.append(
            f"| {label} | {_fmt_time(speed['wall_ms'])} | "
            f"{speed['throughput_mb_s']:.2f} MB/s | {_fmt_rss(speed['peak_rss_kb'])} |"
        )
    return "\n".join(lines)


def render_daemon(snapshot: dict[str, Any]) -> str:
    """Render one-shot versus warm daemon latency by explicit backend."""
    rows = _rows_by_config(snapshot["daemon_rows"])
    missing = sorted(set(DAEMON_CONFIGS).difference(rows))
    if missing:
        raise MatrixError(f"snapshot lacks daemon rows: {', '.join(missing)}")
    corpus = snapshot["daemon_corpus"]
    lines = [
        f"One deterministic {corpus['bytes'] / (1024 * 1024):.0f} MiB regular file "
        f"(`sha256:{corpus['sha256']}`) was scanned once in process and once through an "
        "owned daemon after one warmup request. Daemon time is the client request; daemon "
        "RSS belongs to the resident server.",
        "",
        "| Explicit route | In process | Warm daemon | Warm / one-shot | In-process RSS | Daemon RSS |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    labels = {
        "simd": "Hyperscan/SIMD",
        "cpu": "Pure-Rust CPU",
        "gpu-cuda": "CUDA",
        "gpu-wgpu": "WGPU",
    }
    for backend in ("simd", "cpu", "gpu-cuda", "gpu-wgpu"):
        cold = rows[f"{backend}-nocache-nodaemon-full"]
        warm = rows[f"{backend}-nocache-daemon-full"]
        cold_ms = cold["speed"]["wall_ms"]
        warm_ms = warm["speed"]["wall_ms"]
        lines.append(
            f"| {labels[backend]} | {_fmt_time(cold_ms)} | {_fmt_time(warm_ms)} | "
            f"{warm_ms / cold_ms:.2f}× | {_fmt_rss(cold['speed']['peak_rss_kb'])} | "
            f"{_fmt_rss(warm['speed']['peak_rss_kb'])} |"
        )
    lines.extend(
        [
            "",
            "These rows cover the warm single-file route. The mass route also accepts bounded "
            "directory and remote-source batches; its incremental filesystem path is measured "
            "separately.",
        ]
    )
    return "\n".join(lines)




def render_sections(snapshot: dict[str, Any]) -> dict[str, str]:
    """Render every generated README matrix marker."""
    return {
        "accuracy": render_accuracy(snapshot),
        "config": render_configuration(snapshot),
        "daemon": render_daemon(snapshot),
    }

def write_reports(sections: dict[str, str], reports: pathlib.Path) -> None:
    reports.mkdir(parents=True, exist_ok=True)
    (reports / "accuracy-matrix.md").write_text(
        "# KeyHog accuracy matrix\n\n" + sections["accuracy"] + "\n",
        encoding="utf-8",
    )
    (reports / "configuration-matrix.md").write_text(
        "# KeyHog configuration matrix\n\n" + sections["config"] + "\n",
        encoding="utf-8",
    )
    (reports / "daemon-matrix.md").write_text(
        "# KeyHog daemon matrix\n\n" + sections["daemon"] + "\n",
        encoding="utf-8",
    )

def update_readme(readme: pathlib.Path, sections: dict[str, str], check: bool) -> None:
    """Inject generated sections or fail when the README is stale."""
    original = readme.read_text(encoding="utf-8")
    updated = original
    for name, body in sections.items():
        start_marker = f"<!-- BENCH:{name}:start -->"
        if start_marker not in updated:
            raise MatrixError(f"README.md missing section marker: {start_marker}")
        updated = inject(updated, name, body)
    if check:
        if updated != original:
            raise MatrixError("README configuration benchmark panels are stale")
        return
    readme.write_text(updated, encoding="utf-8")

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command line arguments for README matrix renderer."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--generate-daemon-corpus", type=pathlib.Path)
    parser.add_argument("--config-results", type=pathlib.Path)
    parser.add_argument("--daemon-results", type=pathlib.Path)
    parser.add_argument("--daemon-corpus", type=pathlib.Path)
    parser.add_argument("--source-state", choices=("clean", "developer-dirty"))
    parser.add_argument("--snapshot", type=pathlib.Path, default=BENCH_ROOT / "reports/readme-matrix.json")
    parser.add_argument("--reports", type=pathlib.Path, default=BENCH_ROOT / "reports")
    parser.add_argument("--readme", type=pathlib.Path, default=REPO_ROOT / "README.md")
    parser.add_argument("--inject", action="store_true")
    parser.add_argument("--check", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Main CLI entry point for README matrix capture and rendering."""
    args = parse_args(argv)
    try:
        if args.generate_daemon_corpus is not None:
            digest = generate_daemon_corpus(args.generate_daemon_corpus)
            print(
                f"wrote {DAEMON_CORPUS_BYTES} byte daemon corpus "
                f"sha256:{digest} to {args.generate_daemon_corpus}",
                file=sys.stderr,
            )
        capture_paths = (args.config_results, args.daemon_results, args.daemon_corpus)
        if any(path is not None for path in capture_paths):
            if not all(path is not None for path in capture_paths):
                raise MatrixError(
                    "capture requires --config-results, --daemon-results, and --daemon-corpus"
                )
            if args.source_state is None:
                raise MatrixError(
                    "capture requires explicit --source-state clean or developer-dirty"
                )
            snapshot = capture_snapshot(
                args.config_results,
                args.daemon_results,
                args.daemon_corpus,
                args.source_state,
            )
            args.snapshot.parent.mkdir(parents=True, exist_ok=True)
            args.snapshot.write_text(
                json.dumps(snapshot, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        elif args.snapshot.exists():
            snapshot = load_snapshot(args.snapshot)
        else:
            if args.generate_daemon_corpus is not None:
                return 0
            raise MatrixError(f"matrix snapshot does not exist: {args.snapshot}")

        sections = render_sections(snapshot)
        if args.check:
            expected_reports = {
                args.reports / "accuracy-matrix.md": (
                    "# KeyHog accuracy matrix\n\n" + sections["accuracy"] + "\n"
                ),
                args.reports / "configuration-matrix.md": (
                    "# KeyHog configuration matrix\n\n" + sections["config"] + "\n"
                ),
                args.reports / "daemon-matrix.md": (
                    "# KeyHog daemon matrix\n\n" + sections["daemon"] + "\n"
                ),
            }
            for path, expected in expected_reports.items():
                if not path.is_file() or path.read_text(encoding="utf-8") != expected:
                    raise MatrixError(f"generated benchmark report is stale: {path}")
        else:
            write_reports(sections, args.reports)
        if args.inject or args.check:
            update_readme(args.readme, sections, args.check)
    except (MatrixError, OSError) as error:
        print(f"README benchmark matrix error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
