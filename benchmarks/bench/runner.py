"""Measured benchmark runner."""

from __future__ import annotations

import json
import pathlib
import shutil
# timezone.utc (not datetime.UTC, which is 3.11+) (macOS ships Python 3.9).
from datetime import datetime, timezone
from typing import Protocol

from . import hardware
from .corpora import resolve_corpus
from .corpora.base import Corpus
from .scanners import resolve_scanner
from .scanners.base import Finding, MeasurementProvenance, RunStats
from .schema import Detection, RunResult
from .schema import Scanner as ScannerRecord
from .schema import ScannerConfig, Speed, is_sha256
from .executable_snapshot import sha256_file
from .score import score


class _ScannerAdapter(Protocol):
    name: str

    def available(self) -> bool: ...
    def version(self) -> str: ...
    def default_config(self) -> ScannerConfig: ...
    def exit_success(self, code: int) -> bool: ...
    def run(
        self,
        root: pathlib.Path,
        cfg: ScannerConfig,
        output: pathlib.Path | None = None,
        timeout: int = 3600,
    ) -> tuple[list[Finding], RunStats]: ...


def _scanner_detector_corpus_sha256(scanner: _ScannerAdapter) -> str:
    digest = getattr(scanner, "detector_corpus_sha256", None)
    return digest() if callable(digest) else ""


def _scanner_executable_sha256(scanner: _ScannerAdapter) -> str:
    """Hash the exact executable selected for a non-snapshot scanner.

    KeyHog supplies a held-inode digest through ``MeasurementProvenance``;
    competitor adapters do not, so the common runner records their immutable
    input here instead of leaving version-only rows that cannot be reproduced.
    """
    raw = getattr(scanner, "binary", "")
    if not raw:
        # Minimal test doubles and library-only adapters may intentionally have
        # no subprocess binary. Production adapters expose ``binary`` and are
        # required to carry a digest in their result rows.
        return ""
    candidate = pathlib.Path(raw)
    if not candidate.is_file():
        resolved = shutil.which(str(raw))
        if resolved is None:
            raise FileNotFoundError(f"scanner executable {raw!r} is not a file")
        candidate = pathlib.Path(resolved)
    return sha256_file(candidate.resolve(strict=True))


def _assert_scanner_freshness(scanner: _ScannerAdapter) -> str | None:
    check = getattr(scanner, "assert_freshness", None)
    if callable(check):
        value = check()
        return value if isinstance(value, str) and value else None
    return None


def resolve_corpus_with_root(name: str, root: str | pathlib.Path | None = None) -> Corpus:
    if root is None:
        return resolve_corpus(name)
    if name in ("mirror", "ioc-recovery", "ioc_recovery") or name.startswith("homefield"):
        return resolve_corpus(name, corpus_dir=root)
    return resolve_corpus(name, root=root)


def build_result(
    *,
    scanner_name: str,
    scanner_version: str,
    cfg: ScannerConfig,
    corpus: Corpus,
    findings: list[Finding],
    stats: RunStats,
    executable_sha256: str = "",
    detector_corpus_sha256: str = "",
    execution_route: str = "",
    daemon_pid: int = 0,
    daemon_requests: int = 0,
    scan_manifest: dict[str, object] | None = None,
) -> RunResult:
    info = corpus.info()
    throughput = 0.0
    if stats.wall_ms > 0 and info.bytes > 0:
        throughput = (info.bytes / 1_048_576.0) / (stats.wall_ms / 1000.0)
    detection = Detection()
    records = corpus.records()
    if records:
        detection = score(records, findings, corpus.file_root)
    return RunResult(
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        host=hardware.capture(),
        scanner=ScannerRecord(
            name=scanner_name,
            version=scanner_version,
            config=cfg,
            executable_sha256=executable_sha256,
            detector_corpus_sha256=detector_corpus_sha256,
            execution_route=execution_route,
            daemon_pid=daemon_pid,
            daemon_requests=daemon_requests,
        ),
        corpus=info,
        detection=detection,
        speed=Speed(
            wall_ms=stats.wall_ms,
            throughput_mb_s=throughput,
            peak_rss_kb=stats.peak_rss_kb,
        ),
        finding_count=len(findings),
        exit_code=stats.exit_code,
        timed_out=stats.timed_out,
        available=True,
        error="" if stats.exit_code >= 0 and not stats.timed_out else "scanner timed out",
        scan_manifest=dict(scan_manifest or {}),
    )


def _run_resolved_scanner(
    scanner: _ScannerAdapter,
    version: str,
    cfg: ScannerConfig,
    corpus: Corpus,
) -> RunResult:
    """Measure one resolved scanner/config with one provenance contract."""
    if scanner.name == "keyhog" and cfg.daemon == "on" and corpus.is_labeled():
        return _unavailable_result(
            scanner,
            version,
            cfg,
            corpus,
            "daemon benchmark rows require an unlabeled perf corpus because the "
            "production daemon CLI forbids plaintext credential rendering",
        )
    try:
        measured_version = _assert_scanner_freshness(scanner)
        if measured_version is not None:
            version = measured_version
    except Exception as exc:
        return _unavailable_result(
            scanner, version, cfg, corpus,
            f"freshness failed before scan: {type(exc).__name__}: {exc}",
        )
    try:
        detector_digest = _scanner_detector_corpus_sha256(scanner)
    except Exception as exc:
        return _unavailable_result(
            scanner, version, cfg, corpus,
            f"detector provenance failed: {type(exc).__name__}: {exc}",
        )
    if not scanner.available():
        return _unavailable_result(
            scanner, version, cfg, corpus, "scanner binary not found",
            detector_corpus_sha256=detector_digest,
        )
    try:
        executable_digest = _scanner_executable_sha256(scanner)
    except Exception as exc:
        return _unavailable_result(
            scanner, version, cfg, corpus,
            f"executable provenance failed: {type(exc).__name__}: {exc}",
            detector_corpus_sha256=detector_digest,
        )
    run_with_provenance = getattr(scanner, "run_with_provenance", None)
    execution_route = ""
    daemon_pid = 0
    daemon_requests = 0
    scan_manifest: dict[str, object] = {}
    if callable(run_with_provenance):
        try:
            findings, stats, provenance = run_with_provenance(corpus.scan_root, cfg)
            if not isinstance(provenance, MeasurementProvenance):
                raise TypeError(
                    "provenance-bound scanner returned no MeasurementProvenance record"
                )
            for label, digest in (
                ("executable", provenance.executable_sha256),
                ("detector corpus", provenance.detector_corpus_sha256),
            ):
                if not is_sha256(digest):
                    raise ValueError(
                        f"provenance-bound scanner returned an invalid {label} SHA-256"
                    )
            detector_digest = provenance.detector_corpus_sha256
            executable_digest = provenance.executable_sha256
            if not provenance.scanner_version:
                raise ValueError(
                    "provenance-bound scanner returned no snapshot version identity"
                )
            version = provenance.scanner_version
            execution_route = provenance.execution_route
            daemon_pid = provenance.daemon_pid
            daemon_requests = provenance.daemon_requests
            scan_manifest = dict(provenance.scan_manifest)
            if scanner.name == "keyhog":
                expected_route = "daemon" if cfg.daemon == "on" else "in_process"
                if execution_route != expected_route:
                    raise ValueError(
                        f"provenance execution route {execution_route!r} does not match "
                        f"requested {expected_route!r} route"
                    )
                if execution_route == "daemon":
                    if daemon_pid <= 0 or daemon_requests != 2:
                        raise ValueError(
                            "daemon provenance requires an owned positive PID and exactly "
                            "two served requests"
                        )
                elif daemon_pid != 0 or daemon_requests != 0:
                    raise ValueError(
                        "in-process provenance cannot contain daemon execution evidence"
                    )
        except Exception as exc:
            return _unavailable_result(
                scanner, version, cfg, corpus, f"{type(exc).__name__}: {exc}",
                executable_sha256=executable_digest,
                detector_corpus_sha256=detector_digest,
            )
    else:
        try:
            findings, stats = scanner.run(corpus.scan_root, cfg)
        except Exception as exc:
            return _unavailable_result(
                scanner, version, cfg, corpus, f"{type(exc).__name__}: {exc}",
                executable_sha256=executable_digest,
                detector_corpus_sha256=detector_digest,
            )
        try:
            detector_digest_after = _scanner_detector_corpus_sha256(scanner)
        except Exception as exc:
            return _unavailable_result(
                scanner, version, cfg, corpus,
                f"detector provenance failed after scan: {type(exc).__name__}: {exc}",
                executable_sha256=executable_digest,
                detector_corpus_sha256=detector_digest,
            )
        if detector_digest_after != detector_digest:
            return _unavailable_result(
                scanner, version, cfg, corpus,
                "detector corpus changed during the measured scan; rerun against stable detector bytes",
                executable_sha256=executable_digest,
                detector_corpus_sha256=detector_digest,
            )
    if not callable(run_with_provenance):
        try:
            final_version = _assert_scanner_freshness(scanner)
        except Exception as exc:
            return _unavailable_result(
                scanner, version, cfg, corpus,
                f"freshness failed after scan: {type(exc).__name__}: {exc}",
                executable_sha256=executable_digest,
                detector_corpus_sha256=detector_digest,
            )
        if final_version is not None and final_version != version:
            return _unavailable_result(
                scanner, version, cfg, corpus,
                "freshness failed after scan: scanner identity changed during measurement",
                executable_sha256=executable_digest,
                detector_corpus_sha256=detector_digest,
            )
    result = build_result(
        scanner_name=scanner.name,
        scanner_version=version,
        cfg=cfg,
        corpus=corpus,
        findings=findings,
        stats=stats,
        executable_sha256=executable_digest,
        detector_corpus_sha256=detector_digest,
        execution_route=execution_route,
        daemon_pid=daemon_pid,
        daemon_requests=daemon_requests,
        scan_manifest=scan_manifest,
    )
    if stats.timed_out:
        result.error = "scanner timed out"
        result.available = False
    elif not scanner.exit_success(stats.exit_code):
        # A scanner that crashed (nonzero, non-success exit) produced no usable
        # result; keeping available=True would rank a crashed competitor as a
        # legitimate low-recall entrant (the gate/leaderboard filter on
        # `available`). Fail it closed instead.
        result.error = f"scanner exited {stats.exit_code}"
        result.available = False
    return result


def run_once(
    *,
    scanner_name: str,
    corpus_name: str,
    scanner_binary: str | None = None,
    corpus_root: str | pathlib.Path | None = None,
) -> RunResult:
    scanner = resolve_scanner(scanner_name, binary=scanner_binary)
    corpus = resolve_corpus_with_root(corpus_name, corpus_root)
    return _run_resolved_scanner(
        scanner, scanner.version(), scanner.default_config(), corpus,
    )


def write_result(result: RunResult, output: str | pathlib.Path | None = None) -> None:
    payload = json.dumps(result.to_json(), indent=2, sort_keys=True)
    if output is None or str(output) == "-":
        print(payload)
        return
    path = pathlib.Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload + "\n", encoding="utf-8")


def _unavailable_result(
    scanner: _ScannerAdapter,
    version: str,
    cfg: ScannerConfig,
    corpus: Corpus,
    error: str,
    executable_sha256: str = "",
    detector_corpus_sha256: str = "",
) -> RunResult:
    return RunResult(
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        host=hardware.capture(),
        scanner=ScannerRecord(
            name=scanner.name,
            version=version,
            config=cfg,
            executable_sha256=executable_sha256,
            detector_corpus_sha256=detector_corpus_sha256,
        ),
        corpus=corpus.info(),
        # No scanner process ran. Keep this distinct from a successful scanner
        # exit so unavailable rows cannot masquerade as successful execution.
        exit_code=-1,
        available=False,
        error=error,
    )
