"""Measured benchmark runner."""

from __future__ import annotations

import json
import pathlib
# timezone.utc (not datetime.UTC, which is 3.11+) (macOS ships Python 3.9).
from datetime import datetime, timezone
from typing import Protocol

from . import hardware
from .corpora import resolve_corpus
from .corpora.base import Corpus
from .scanners import resolve_scanner
from .scanners.base import Finding, RunStats
from .schema import Detection, RunResult
from .schema import Scanner as ScannerRecord
from .schema import ScannerConfig, Speed
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
    detector_corpus_sha256: str = "",
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
            detector_corpus_sha256=detector_corpus_sha256,
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
    )


def _run_resolved_scanner(
    scanner: _ScannerAdapter,
    version: str,
    cfg: ScannerConfig,
    corpus: Corpus,
) -> RunResult:
    """Measure one resolved scanner/config with one provenance contract."""
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
    run_with_provenance = getattr(scanner, "run_with_provenance", None)
    if callable(run_with_provenance):
        try:
            findings, stats, detector_digest = run_with_provenance(corpus.scan_root, cfg)
        except Exception as exc:
            return _unavailable_result(
                scanner, version, cfg, corpus, f"{type(exc).__name__}: {exc}",
                detector_corpus_sha256=detector_digest,
            )
    else:
        try:
            findings, stats = scanner.run(corpus.scan_root, cfg)
        except Exception as exc:
            return _unavailable_result(
                scanner, version, cfg, corpus, f"{type(exc).__name__}: {exc}",
                detector_corpus_sha256=detector_digest,
            )
        try:
            detector_digest_after = _scanner_detector_corpus_sha256(scanner)
        except Exception as exc:
            return _unavailable_result(
                scanner, version, cfg, corpus,
                f"detector provenance failed after scan: {type(exc).__name__}: {exc}",
                detector_corpus_sha256=detector_digest,
            )
        if detector_digest_after != detector_digest:
            return _unavailable_result(
                scanner, version, cfg, corpus,
                "detector corpus changed during the measured scan; rerun against stable detector bytes",
                detector_corpus_sha256=detector_digest,
            )
    result = build_result(
        scanner_name=scanner.name,
        scanner_version=version,
        cfg=cfg,
        corpus=corpus,
        findings=findings,
        stats=stats,
        detector_corpus_sha256=detector_digest,
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
    detector_corpus_sha256: str = "",
) -> RunResult:
    return RunResult(
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        host=hardware.capture(),
        scanner=ScannerRecord(
            name=scanner.name,
            version=version,
            config=cfg,
            detector_corpus_sha256=detector_corpus_sha256,
        ),
        corpus=corpus.info(),
        available=False,
        error=error,
    )
