"""Measured benchmark runner."""

from __future__ import annotations

import json
import pathlib
# timezone.utc (not datetime.UTC, which is 3.11+) — macOS ships Python 3.9.
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


def resolve_corpus_with_root(name: str, root: str | pathlib.Path | None = None) -> Corpus:
    if root is None:
        return resolve_corpus(name)
    if name == "mirror" or name.startswith("homefield"):
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
        scanner=ScannerRecord(name=scanner_name, version=scanner_version, config=cfg),
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


def run_once(
    *,
    scanner_name: str,
    corpus_name: str,
    scanner_binary: str | None = None,
    corpus_root: str | pathlib.Path | None = None,
) -> RunResult:
    scanner = resolve_scanner(scanner_name, binary=scanner_binary)
    corpus = resolve_corpus_with_root(corpus_name, corpus_root)
    cfg = scanner.default_config()
    version = scanner.version()
    if not scanner.available():
        return _unavailable_result(scanner, version, cfg, corpus, "scanner binary not found")
    try:
        findings, stats = scanner.run(corpus.scan_root, cfg)
    except Exception as exc:
        return _unavailable_result(scanner, version, cfg, corpus, f"{type(exc).__name__}: {exc}")
    result = build_result(
        scanner_name=scanner.name,
        scanner_version=version,
        cfg=cfg,
        corpus=corpus,
        findings=findings,
        stats=stats,
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
) -> RunResult:
    return RunResult(
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        host=hardware.capture(),
        scanner=ScannerRecord(name=scanner.name, version=version, config=cfg),
        corpus=corpus.info(),
        available=False,
        error=error,
    )
