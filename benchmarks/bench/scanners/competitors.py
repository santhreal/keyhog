"""Competitor scanner adapters for the benchmark harness."""

from __future__ import annotations

import contextlib
import json
import pathlib
import sqlite3
import tempfile

from ..schema import ScannerConfig
from .base import Finding, RunStats, Scanner, _line, probe_version, run_measured


def _load_json(text: str) -> object:
    text = text.strip()
    if not text:
        return []
    return json.loads(text)


def _normalize_betterleaks(data: object) -> list[Finding]:
    out: list[Finding] = []
    for finding in data if isinstance(data, list) else []:
        if not isinstance(finding, dict):
            continue
        out.append(
            {
                "file": finding.get("File", ""),
                "line": _line(finding.get("StartLine")),
                "value": finding.get("Secret") or finding.get("Match") or "",
                "detector": finding.get("RuleID", ""),
            }
        )
    return out


def _normalize_kingfisher_jsonl(text: str) -> list[Finding]:
    out: list[Finding] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        finding = obj.get("finding") if isinstance(obj, dict) else None
        rule = obj.get("rule") if isinstance(obj, dict) else None
        if not isinstance(finding, dict) or not isinstance(rule, dict):
            continue
        out.append(
            {
                "file": finding.get("path") or "",
                "line": _line(finding.get("line")),
                "value": finding.get("snippet") or "",
                "detector": rule.get("id") or rule.get("name") or "",
            }
        )
    return out


def _normalize_nosey_report(data: object) -> list[Finding]:
    out: list[Finding] = []
    for finding in data if isinstance(data, list) else []:
        if not isinstance(finding, dict):
            continue
        detector = finding.get("rule_text_id") or finding.get("rule_name") or ""
        for match in finding.get("matches") or []:
            if not isinstance(match, dict):
                continue
            path = ""
            for item in match.get("provenance") or []:
                if isinstance(item, dict) and item.get("path"):
                    path = item["path"]
                    break
            snippet = match.get("snippet") if isinstance(match.get("snippet"), dict) else {}
            location = match.get("location") if isinstance(match.get("location"), dict) else {}
            span = location.get("source_span") if isinstance(location.get("source_span"), dict) else {}
            start = span.get("start") if isinstance(span.get("start"), dict) else {}
            out.append(
                {
                    "file": path,
                    "line": _line(start.get("line")),
                    "value": snippet.get("matching") or "",
                    "detector": detector,
                }
            )
    return out


def _normalize_titus_datastore(db_path: pathlib.Path) -> list[Finding]:
    query = """
        select
            coalesce(provenance.path, '') as path,
            coalesce(matches.start_line, 0) as line,
            coalesce(matches.snippet_matching, '') as value,
            coalesce(matches.rule_id, '') as detector
        from matches
        left join provenance on provenance.blob_id = matches.blob_id
    """
    out: list[Finding] = []
    # closing() actually closes the handle; the sqlite context manager only
    # commits/rolls back and would leak the connection into the rmtree below.
    with contextlib.closing(sqlite3.connect(db_path)) as con:
        for path, line, value, detector in con.execute(query):
            if isinstance(value, bytes):
                value = value.decode("utf-8", "replace")
            out.append(
                {
                    "file": path or "",
                    "line": _line(line),
                    "value": value or "",
                    "detector": detector or "",
                }
            )
    return out


def _normalize_trufflehog_jsonl(text: str) -> list[Finding]:
    out: list[Finding] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            finding = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(finding, dict):
            continue
        source = finding.get("SourceMetadata")
        source_data = source.get("Data") if isinstance(source, dict) else {}
        filesystem = (
            source_data.get("Filesystem")
            if isinstance(source_data, dict) and isinstance(source_data.get("Filesystem"), dict)
            else {}
        )
        out.append(
            {
                "file": filesystem.get("file") or finding.get("SourceName") or "",
                "line": _line(finding.get("Line")),
                "value": finding.get("Raw") or finding.get("Redacted") or "",
                "detector": finding.get("DetectorName") or finding.get("DetectorType") or "",
            }
        )
    return out


class BetterleaksScanner(Scanner):
    name = "betterleaks"
    binary_name = "betterleaks"
    binary_env = "BETTERLEAKS_BIN"

    def variants(self) -> list[ScannerConfig]:
        return [ScannerConfig(backend="default", cache="off", daemon="off", mode="no-validate")]

    def run(
        self,
        root: pathlib.Path,
        cfg: ScannerConfig,
        output: pathlib.Path | None = None,
    ) -> tuple[list[Finding], RunStats]:
        stdout, _stderr, stats = run_measured(
            [
                self.binary,
                "dir",
                "--no-banner",
                "--report-format",
                "json",
                "--report-path",
                "-",
                "--redact=0",
                "--validation=false",
                "--exit-code",
                "0",
                str(root),
            ],
            timeout=3600,
        )
        return _normalize_betterleaks(_load_json(stdout)), stats


class KingfisherScanner(Scanner):
    name = "kingfisher"
    binary_name = "kingfisher"
    binary_env = "KINGFISHER_BIN"
    success_exit_codes = (0, 200)

    def variants(self) -> list[ScannerConfig]:
        return [ScannerConfig(backend="default", cache="off", daemon="off", mode="low-no-validate")]

    def run(
        self,
        root: pathlib.Path,
        cfg: ScannerConfig,
        output: pathlib.Path | None = None,
    ) -> tuple[list[Finding], RunStats]:
        stdout, _stderr, stats = run_measured(
            [
                self.binary,
                "--no-update-check",
                "scan",
                "--format",
                "jsonl",
                "--no-validate",
                "--confidence",
                "low",
                str(root),
            ],
            timeout=3600,
        )
        return _normalize_kingfisher_jsonl(stdout), stats


class NoseyparkerScanner(Scanner):
    name = "noseyparker"
    binary_name = "noseyparker"
    binary_env = "NOSEYPARKER_BIN"

    def variants(self) -> list[ScannerConfig]:
        return [ScannerConfig(backend="default", cache="off", daemon="off", mode="no-git-history")]

    def run(
        self,
        root: pathlib.Path,
        cfg: ScannerConfig,
        output: pathlib.Path | None = None,
    ) -> tuple[list[Finding], RunStats]:
        with tempfile.TemporaryDirectory(prefix="keyhog-bench-np-") as tmp:
            datastore = pathlib.Path(tmp) / "datastore.np"
            _scan_stdout, _scan_stderr, scan_stats = run_measured(
                [
                    self.binary,
                    "--color",
                    "never",
                    "--progress",
                    "never",
                    "scan",
                    "--datastore",
                    str(datastore),
                    "--git-history",
                    "none",
                    str(root),
                ],
                timeout=3600,
            )
            report_stdout, _report_stderr, report_stats = run_measured(
                [
                    self.binary,
                    "--color",
                    "never",
                    "--progress",
                    "never",
                    "report",
                    "--datastore",
                    str(datastore),
                    "--format",
                    "json",
                    "--max-matches",
                    "0",
                    "--max-provenance",
                    "0",
                ],
                timeout=3600,
            )
        stats = _combine_stats(scan_stats, report_stats)
        return _normalize_nosey_report(_load_json(report_stdout)), stats


class TitusScanner(Scanner):
    name = "titus"
    binary_name = "titus"
    binary_env = "TITUS_BIN"

    def variants(self) -> list[ScannerConfig]:
        return [ScannerConfig(backend="default", cache="off", daemon="off", mode="no-validate")]

    def version(self) -> str:
        # titus uses a `version` subcommand, not `--version`.
        return probe_version(self.binary, ("version",))

    def run(
        self,
        root: pathlib.Path,
        cfg: ScannerConfig,
        output: pathlib.Path | None = None,
    ) -> tuple[list[Finding], RunStats]:
        with tempfile.TemporaryDirectory(prefix="keyhog-bench-titus-") as tmp:
            datastore = pathlib.Path(tmp) / "titus.ds"
            _stdout, _stderr, stats = run_measured(
                [
                    self.binary,
                    "scan",
                    str(root),
                    "--format",
                    "json",
                    "--output",
                    str(datastore),
                    "--validate=false",
                ],
                timeout=3600,
            )
            db_path = datastore / "datastore.db"
            findings = _normalize_titus_datastore(db_path) if db_path.exists() else []
        return findings, stats


class TrufflehogScanner(Scanner):
    name = "trufflehog"
    binary_name = "trufflehog"
    binary_env = "TRUFFLEHOG_BIN"

    def variants(self) -> list[ScannerConfig]:
        return [ScannerConfig(backend="default", cache="off", daemon="off", mode="no-verify")]

    def run(
        self,
        root: pathlib.Path,
        cfg: ScannerConfig,
        output: pathlib.Path | None = None,
    ) -> tuple[list[Finding], RunStats]:
        stdout, _stderr, stats = run_measured(
            [
                self.binary,
                "filesystem",
                "--json",
                "--no-update",
                "--no-verification",
                str(root),
            ],
            timeout=3600,
        )
        return _normalize_trufflehog_jsonl(stdout), stats


def _combine_stats(first: RunStats, second: RunStats) -> RunStats:
    return RunStats(
        wall_ms=first.wall_ms + second.wall_ms,
        peak_rss_kb=max(first.peak_rss_kb, second.peak_rss_kb),
        throughput_mb_s=0.0,
        exit_code=second.exit_code if second.exit_code != 0 else first.exit_code,
        timed_out=first.timed_out or second.timed_out,
    )
