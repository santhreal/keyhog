"""Render benchmark results to markdown and inject them into the README.

Reads every ``RunResult`` JSON under ``results/`` and produces three tables
the README cites, written between HTML-comment markers so re-running is
idempotent (``--check`` asserts the README is byte-stable on a second pass -
a CI gate against a stale, hand-edited table):

    <!-- BENCH:leaderboard:start -->  F1 / P / R / speed, ranked
    <!-- BENCH:perf:start -->         wall / throughput / peak RSS
    <!-- BENCH:gaps:start -->         per-category places a competitor wins

The committed README/reports consume an exact TOML run-set inventory. Ad-hoc
result directories remain usable only when each scanner has one unambiguous
eligible row, so archived measurements can never silently replace a headline
result.
"""

from __future__ import annotations

import argparse
import datetime as dt
from dataclasses import dataclass
import html
import json
import pathlib
import re
import sys
import tomllib

from .schema import Detection, Outcome, RunResult, is_sha256

_BENCH_ROOT = pathlib.Path(__file__).resolve().parents[1]
_REPO_ROOT = _BENCH_ROOT.parent
_DEFAULT_RUN_SET = _BENCH_ROOT / "run-sets" / "canonical.toml"


def default_run_set_path(results_dir: pathlib.Path) -> pathlib.Path | None:
    """Return the committed inventory only for the committed results directory."""
    if results_dir.resolve() == (_BENCH_ROOT / "results").resolve():
        return _DEFAULT_RUN_SET
    return None

# Scanner display order / friendly names for the tables.
_DISPLAY = {
    "keyhog": "KeyHog",
    "betterleaks": "Betterleaks",
    "kingfisher": "Kingfisher",
    "trufflehog": "TruffleHog",
    "titus": "Titus",
    "noseyparker": "Nosey Parker",
}

FULL_DIFFERENTIAL_SCANNERS = (
    "keyhog",
    "betterleaks",
    "kingfisher",
    "trufflehog",
    "titus",
    "noseyparker",
)


class ResultLoadError(ValueError):
    """A result-shaped artifact violates the current benchmark schema."""


class ReportEmptyError(ValueError):
    """A benchmark report would contain no measured rows for the corpus."""


class ResultSelectionError(ValueError):
    """A leaderboard run set is missing, ambiguous, or contradicts its inventory."""


@dataclass(frozen=True)
class RunDeclaration:
    """Declaration of one committed run artifact binding scanner identity and host provenance."""

    scanner: str
    config_id: str
    path: str
    generated_at: str
    executable_sha256: str
    hostname_hash: str
    fixture_count: int
    labeled_positives: int
    corpus_bytes: int


@dataclass(frozen=True)
class RunSet:
    """Set of declared run artifacts representing a canonical benchmark inventory."""

    corpus: str
    runs: tuple[RunDeclaration, ...]

_HOST_HASH_RE = re.compile(r"[0-9a-f]{12}")


def _cell(value: object) -> str:
    """Escape an observed result value for one Markdown table cell."""
    return html.escape(str(value), quote=True).replace("|", "&#124;").replace(
        "\r\n", "<br>"
    ).replace("\r", "<br>").replace("\n", "<br>")


def _run_date_error(value: str) -> str | None:
    """Validate ISO timestamp format and timezone specifier of a run date."""
    if not value:
        return "run date (`generated_at`) is missing"
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return f"run date (`generated_at`) is invalid: {value!r}"
    if parsed.tzinfo is None:
        return f"run date (`generated_at`) has no timezone: {value!r}"
    return None


def provenance_errors(rows: list[RunResult], corpus: str) -> list[str]:
    """Return missing, invalid, or contradictory selected-result provenance."""
    errors: list[str] = []
    corpus_fingerprints: set[tuple[str, int, int, int]] = set()
    for row in rows:
        scanner = row.scanner.name or "<missing scanner>"
        prefix = f"{scanner} result"
        version = row.scanner.version.strip()
        executable_digest = row.scanner.executable_sha256
        if executable_digest and not is_sha256(executable_digest):
            errors.append(f"{prefix} has an invalid executable SHA-256")
        if not version and not is_sha256(executable_digest):
            errors.append(f"{prefix} has neither scanner version nor executable SHA-256")

        corpus_fingerprints.add((
            row.corpus.name,
            row.corpus.fixture_count,
            row.corpus.labeled_positives,
            row.corpus.bytes,
        ))
        if not row.corpus.name:
            errors.append(f"{prefix} corpus name is missing")
        elif row.corpus.name != corpus:
            errors.append(
                f"{prefix} corpus name {row.corpus.name!r} conflicts with {corpus!r}"
            )
        for field, value in (
            ("fixture_count", row.corpus.fixture_count),
            ("labeled_positives", row.corpus.labeled_positives),
            ("bytes", row.corpus.bytes),
        ):
            if value <= 0:
                errors.append(f"{prefix} corpus {field} is missing")

        if not _HOST_HASH_RE.fullmatch(row.host.hostname_hash):
            errors.append(f"{prefix} host identity (`hostname_hash`) is missing or invalid")
        date_error = _run_date_error(row.generated_at)
        if date_error:
            errors.append(f"{prefix} {date_error}")

    if len(corpus_fingerprints) > 1:
        errors.append(
            f"selected results report conflicting identities for corpus {corpus!r}"
        )
    return errors


def _scanner_provenance(row: RunResult) -> str:
    """Format scanner binary and configuration provenance for report tables."""
    parts = []
    version = row.scanner.version.strip()
    digest = row.scanner.executable_sha256
    if version:
        parts.append(f"version: {_cell(version)}")
    else:
        parts.append("_version not recorded_")
    if digest:
        if is_sha256(digest):
            parts.append(f"executable SHA-256: `{digest}`")
        else:
            parts.append(f"_invalid executable SHA-256: {_cell(digest)}_")
    else:
        parts.append("_executable SHA-256 not recorded_")
    return "<br>".join(parts)


def _corpus_provenance(row: RunResult) -> str:
    """Format corpus and fixture count provenance for report tables."""
    corpus = _cell(row.corpus.name) if row.corpus.name else "_missing name_"

    def observed(value: int, label: str) -> str:
        """Format integer count with label or missing fallback."""
        return f"{value:,} {label}" if value > 0 else f"_missing {label}_"

    return "; ".join((
        corpus,
        observed(row.corpus.fixture_count, "fixtures"),
        observed(row.corpus.labeled_positives, "labeled positives"),
        observed(row.corpus.bytes, "bytes"),
    ))


def _host_provenance(row: RunResult) -> str:
    """Format execution host hardware and kernel provenance for report tables."""
    host_hash = row.host.hostname_hash
    parts = [
        f"hostname SHA-256/12: `{host_hash}`"
        if _HOST_HASH_RE.fullmatch(host_hash)
        else "_missing or invalid hostname hash_"
    ]
    if row.host.os:
        parts.append(_cell(row.host.os))
    if row.host.cpu:
        parts.append(_cell(row.host.cpu))
    return "<br>".join(parts)


def render_provenance(rows: list[RunResult]) -> str:
    """Render only provenance carried by each selected result record."""
    lines = [
        "### Result provenance",
        "",
        "| Scanner | Scanner version / executable digest | Corpus identity | Host identity | Run date |",
        "|---|---|---|---|---|",
    ]
    seen = set()
    for row in rows:
        key = (
            row.scanner.name,
            row.corpus.name,
            row.scanner.executable_sha256,
            row.generated_at,
        )
        if key in seen:
            continue
        seen.add(key)
        generated_at = (
            _cell(row.generated_at)
            if _run_date_error(row.generated_at) is None
            else "_missing or invalid_"
        )
        lines.append(
            f"| {_cell(_name(row.scanner.name))} | {_scanner_provenance(row)} | "
            f"{_corpus_provenance(row)} | {_host_provenance(row)} | {generated_at} |"
        )
    return "\n".join(lines)


def report_population_errors(results: list[RunResult], corpus: str) -> list[str]:
    """Return reasons the canonical reports for ``corpus`` would be empty.

    A report must fail closed rather than silently publish a placeholder such
    as ``_No results for corpus `mirror` yet_``.  This checks the same data
    axes the four markdown files render, so a missing or unavailable scanner
    cannot masquerade as a populated benchmark.
    """
    errors: list[str] = []
    try:
        leaderboard_rows = canonical_leaderboard(results, corpus)
    except ResultSelectionError as exc:
        return [str(exc)]
    if not leaderboard_rows:
        errors.append(f"leaderboard has no rows for corpus `{corpus}`")
    elif not any(row.available for row in leaderboard_rows):
        errors.append(f"leaderboard has no available scanner rows for corpus `{corpus}`")
    else:
        errors.extend(provenance_errors(leaderboard_rows, corpus))

    perf_rows = [row for row in results if row.available and row.corpus.name == corpus]
    if not perf_rows:
        errors.append(f"perf has no available timed runs for corpus `{corpus}`")

    keyhog = next((row for row in leaderboard_rows if row.scanner.name == "keyhog"), None)
    if keyhog is None:
        errors.append(f"keyhog row missing for corpus `{corpus}` (recall-gap and category-recall need it)")
    elif not keyhog.available:
        errors.append(f"keyhog row unavailable for corpus `{corpus}`: {keyhog.error}")
    elif not keyhog.detection.per_category:
        errors.append(f"keyhog row for corpus `{corpus}` has no per-category data")
    return errors


def assert_reports_populated(results: list[RunResult], corpus: str) -> None:
    """Raise :class:`ReportEmptyError` if any canonical report is unpopulated."""
    errors = report_population_errors(results, corpus)
    if errors:
        raise ReportEmptyError(
            f"cannot render reports for corpus {corpus!r}: " + "; ".join(errors)
        )


def load_results(results_dir: pathlib.Path) -> list[RunResult]:
    """Load every ``*.json`` under ``results_dir`` (recursively) as RunResult.

    Each row retains its relative source path as private report metadata so an
    external run-set inventory can bind a published row to one exact artifact.
    """
    out: list[RunResult] = []
    if not results_dir.exists():
        return out
    for p in sorted(results_dir.rglob("*.json")):
        try:
            data = json.loads(p.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(data, dict) or "scanner" not in data or "detection" not in data:
            continue
        try:
            result = RunResult.from_json(data, source=str(p))
        except ValueError as exc:
            raise ResultLoadError(str(exc)) from exc
        result._report_source = p.relative_to(results_dir).as_posix()
        out.append(result)
    return out


# -- selection ----------------------------------------------------------


def load_run_set(path: pathlib.Path) -> RunSet:
    """Load a run-set whose result paths resolve relative to ``--results``."""
    try:
        data = tomllib.loads(path.read_text())
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ResultSelectionError(f"cannot load run-set inventory {path}: {exc}") from exc
    if data.get("schema_version") != 1:
        raise ResultSelectionError(
            f"{path} has unsupported run-set schema_version={data.get('schema_version')!r}"
        )
    corpus = data.get("corpus")
    raw_runs = data.get("run")
    if not isinstance(corpus, str) or not corpus or not isinstance(raw_runs, list):
        raise ResultSelectionError(f"{path} must declare `corpus` and one or more `[[run]]` entries")

    runs: list[RunDeclaration] = []
    scanners: set[str] = set()
    paths: set[str] = set()
    fields = tuple(RunDeclaration.__dataclass_fields__)
    for index, raw in enumerate(raw_runs, 1):
        if not isinstance(raw, dict):
            raise ResultSelectionError(f"{path} [[run]] #{index} is not a table")
        missing = [field for field in fields if field not in raw]
        unknown = sorted(set(raw) - set(fields))
        if missing or unknown:
            raise ResultSelectionError(
                f"{path} [[run]] #{index} has missing={missing} unknown={unknown}"
            )
        try:
            run = RunDeclaration(**raw)
        except TypeError as exc:
            raise ResultSelectionError(f"{path} [[run]] #{index} is invalid: {exc}") from exc
        relative = pathlib.PurePosixPath(run.path)
        if relative.is_absolute() or ".." in relative.parts or run.path != relative.as_posix():
            raise ResultSelectionError(f"{path} declares unsafe/non-canonical result path {run.path!r}")
        if not all(isinstance(getattr(run, field), str) for field in (
            "scanner", "config_id", "path", "generated_at",
            "executable_sha256", "hostname_hash",
        )):
            raise ResultSelectionError(f"{path} [[run]] #{index} has a non-string identity field")
        if not is_sha256(run.executable_sha256):
            raise ResultSelectionError(f"{path} [[run]] #{index} has invalid executable_sha256")
        if _run_date_error(run.generated_at):
            raise ResultSelectionError(f"{path} [[run]] #{index} has invalid generated_at")
        if not _HOST_HASH_RE.fullmatch(run.hostname_hash):
            raise ResultSelectionError(f"{path} [[run]] #{index} has invalid hostname_hash")
        if not all(
            isinstance(getattr(run, field), int) and getattr(run, field) > 0
            for field in ("fixture_count", "labeled_positives", "corpus_bytes")
        ):
            raise ResultSelectionError(f"{path} [[run]] #{index} has invalid corpus identity counts")
        if run.scanner in scanners or run.path in paths:
            raise ResultSelectionError(
                f"{path} duplicates scanner {run.scanner!r} or result path {run.path!r}"
            )
        scanners.add(run.scanner)
        paths.add(run.path)
        runs.append(run)
    if not runs:
        raise ResultSelectionError(f"{path} declares no runs")
    return RunSet(corpus=corpus, runs=tuple(runs))


def refresh_run_set(
    results: list[RunResult],
    corpus: str,
    current: RunSet,
) -> RunSet:
    """Bind the declared result paths to their newly measured exact identities."""
    if current.corpus != corpus:
        raise ResultSelectionError(
            f"run-set corpus {current.corpus!r} conflicts with requested corpus {corpus!r}"
        )
    by_path: dict[str, list[RunResult]] = {}
    for result in results:
        source = getattr(result, "_report_source", None)
        if isinstance(source, str):
            by_path.setdefault(source, []).append(result)

    refreshed: list[RunDeclaration] = []
    errors: list[str] = []
    for declaration in current.runs:
        matches = by_path.get(declaration.path, [])
        if len(matches) != 1:
            errors.append(
                f"{declaration.path}: expected one current result, found {len(matches)}"
            )
            continue
        result = matches[0]
        if result.corpus.name != corpus:
            errors.append(
                f"{declaration.path}: corpus={result.corpus.name!r}, expected {corpus!r}"
            )
        if result.scanner.name != declaration.scanner:
            errors.append(
                f"{declaration.path}: scanner={result.scanner.name!r}, "
                f"expected {declaration.scanner!r}"
            )
        if result.scanner.config_id != declaration.config_id:
            errors.append(
                f"{declaration.path}: config_id={result.scanner.config_id!r}, "
                f"expected {declaration.config_id!r}"
            )
        if not result.available:
            errors.append(
                f"{declaration.path}: current result is unavailable: {result.error}"
            )
        identity = RunDeclaration(
            scanner=declaration.scanner,
            config_id=declaration.config_id,
            path=declaration.path,
            generated_at=result.generated_at,
            executable_sha256=result.scanner.executable_sha256,
            hostname_hash=result.host.hostname_hash,
            fixture_count=result.corpus.fixture_count,
            labeled_positives=result.corpus.labeled_positives,
            corpus_bytes=result.corpus.bytes,
        )
        if _run_date_error(identity.generated_at):
            errors.append(f"{declaration.path}: generated_at is invalid")
        if not is_sha256(identity.executable_sha256):
            errors.append(f"{declaration.path}: executable_sha256 is invalid")
        if not _HOST_HASH_RE.fullmatch(identity.hostname_hash):
            errors.append(f"{declaration.path}: hostname_hash is invalid")
        if not all(
            value > 0
            for value in (
                identity.fixture_count,
                identity.labeled_positives,
                identity.corpus_bytes,
            )
        ):
            errors.append(f"{declaration.path}: corpus identity counts are invalid")
        refreshed.append(identity)
    if errors:
        raise ResultSelectionError("cannot refresh run-set inventory: " + "; ".join(errors))
    return RunSet(corpus=corpus, runs=tuple(refreshed))


def render_run_set(run_set: RunSet) -> str:
    """Render one deterministic TOML inventory from validated run identities."""
    lines = ["schema_version = 1", f"corpus = {json.dumps(run_set.corpus)}", ""]
    for run in run_set.runs:
        lines.extend(
            [
                "[[run]]",
                f"scanner = {json.dumps(run.scanner)}",
                f"config_id = {json.dumps(run.config_id)}",
                f"path = {json.dumps(run.path)}",
                f"generated_at = {json.dumps(run.generated_at)}",
                f"executable_sha256 = {json.dumps(run.executable_sha256)}",
                f"hostname_hash = {json.dumps(run.hostname_hash)}",
                f"fixture_count = {run.fixture_count}",
                f"labeled_positives = {run.labeled_positives}",
                f"corpus_bytes = {run.corpus_bytes}",
                "",
            ]
        )
    return "\n".join(lines)


def select_declared_results(
    results: list[RunResult],
    corpus: str,
    run_set: RunSet,
) -> list[RunResult]:
    """Resolve every inventory entry to exactly one matching result artifact."""
    if run_set.corpus != corpus:
        raise ResultSelectionError(
            f"run-set corpus {run_set.corpus!r} conflicts with requested corpus {corpus!r}"
        )
    by_path: dict[str, list[RunResult]] = {}
    for result in results:
        source = getattr(result, "_report_source", None)
        if source is not None:
            by_path.setdefault(source, []).append(result)

    selected: list[RunResult] = []
    errors: list[str] = []
    for declaration in run_set.runs:
        matches = by_path.get(declaration.path, [])
        if len(matches) != 1:
            errors.append(
                f"{declaration.path}: expected exactly one result, found {len(matches)}"
            )
            continue
        result = matches[0]
        observed = {
            "corpus": result.corpus.name,
            "scanner": result.scanner.name,
            "config_id": result.scanner.config_id,
            "generated_at": result.generated_at,
            "executable_sha256": result.scanner.executable_sha256,
            "hostname_hash": result.host.hostname_hash,
            "fixture_count": result.corpus.fixture_count,
            "labeled_positives": result.corpus.labeled_positives,
            "corpus_bytes": result.corpus.bytes,
        }
        expected = {
            "corpus": corpus,
            "scanner": declaration.scanner,
            "config_id": declaration.config_id,
            "generated_at": declaration.generated_at,
            "executable_sha256": declaration.executable_sha256,
            "hostname_hash": declaration.hostname_hash,
            "fixture_count": declaration.fixture_count,
            "labeled_positives": declaration.labeled_positives,
            "corpus_bytes": declaration.corpus_bytes,
        }
        mismatches = [
            f"{field}={observed[field]!r} (expected {value!r})"
            for field, value in expected.items()
            if observed[field] != value
        ]
        if mismatches:
            errors.append(f"{declaration.path}: " + ", ".join(mismatches))
            continue
        selected.append(result)
    if errors:
        raise ResultSelectionError("invalid report run set: " + "; ".join(errors))
    hosts = {r.host.hostname_hash for r in selected}
    if len(hosts) > 1:
        raise ResultSelectionError(f"invalid report run set: mixed-host rows detected: {sorted(hosts)}")
    detectors = {getattr(r.scanner, "detector_corpus_sha256", None) for r in selected}
    if None in detectors:
        raise ResultSelectionError("invalid report run set: detector corpus identity is missing")
    valid_detectors = {d for d in detectors if isinstance(d, str) and is_sha256(d)}
    if not valid_detectors:
        raise ResultSelectionError("invalid report run set: detector corpus identity is missing")
    if len(valid_detectors) > 1:
        reprs = [repr(d) for d in sorted(valid_detectors)]
        raise ResultSelectionError(f"invalid report run set: mixed-detector rows detected: {reprs}")
    return selected

def _default_config_id(scanner_name: str) -> str | None:
    """Return default configuration ID for registered scanner adapter."""
    from .scanners import resolve_scanner

    # Only an UNKNOWN scanner (a result file for an adapter no longer
    # registered) legitimately has no resolvable default, tolerate that by
    # returning None. Any other failure (a real bug in default_config) must
    # propagate, never be swallowed into an arbitrary/tuned config pick.
    try:
        scanner = resolve_scanner(scanner_name)
    except SystemExit:
        return None
    return scanner.default_config().config_id


def canonical_leaderboard(results: list[RunResult], corpus: str) -> list[RunResult]:
    """Select one default or otherwise unique eligible row per scanner.

    Multiple default-config measurements are ambiguous by definition: their
    timestamps are evidence, not a selection policy. An explicit run-set must
    resolve such a directory before this function is called.
    """
    by_scanner: dict[str, list[RunResult]] = {}
    for result in results:
        if result.corpus.name == corpus:
            by_scanner.setdefault(result.scanner.name, []).append(result)
    chosen: list[RunResult] = []
    for name, runs in by_scanner.items():
        default_id = _default_config_id(name)
        defaults = [run for run in runs if run.scanner.config_id == default_id]
        if len(defaults) > 1:
            sources = ", ".join(
                getattr(run, "_report_source", "<in-memory result>")
                for run in defaults
            )
            raise ResultSelectionError(
                f"ambiguous {name} default-config results for corpus {corpus!r}: {sources}; "
                "declare an exact run-set inventory"
            )
        if defaults:
            chosen.append(defaults[0])
            continue
        eligible = [run for run in runs if run.available] or runs
        if len(eligible) != 1:
            sources = ", ".join(
                getattr(run, "_report_source", "<in-memory result>")
                for run in eligible
            )
            raise ResultSelectionError(
                f"ambiguous {name} non-default results for corpus {corpus!r}: {sources}; "
                "declare an exact run-set inventory"
            )
        chosen.append(eligible[0])
    chosen.sort(key=lambda row: row.detection.overall.f1(), reverse=True)
    return chosen


# -- rendering ----------------------------------------------------------


def _fmt_secs(ms: float) -> str:
    """Format millisecond wall time as seconds or minutes for display."""
    s = ms / 1000.0
    return f"{s:.2f}s" if s < 60 else f"{s/60:.1f}m"


def _name(scanner: str) -> str:
    """Return display name for scanner identifier."""
    return _DISPLAY.get(scanner, scanner)


def _is_daemon_corpus(name: str) -> bool:
    """Return True if the corpus is a daemon performance workload."""
    return not name or name.startswith("daemon")


def _corpus_heading(name: str) -> str:
    """Return the Markdown heading for a benchmark corpus section."""
    if name == "mirror":
        return "#### Synthetic SecretBench-shape mirror corpus"
    if name == "homefield":
        return "#### Competitor homefield / home-turf rule corpus"
    return f"#### Competitor {name} rule corpus"


def render_leaderboard(results: list[RunResult], corpus: str) -> str:
    """Render Markdown leaderboard table for corpus and companion corpora."""
    primary_corpus = "mirror" if corpus == "multi-corpus" else corpus
    rows = canonical_leaderboard(results, primary_corpus)
    if not rows:
        return f"_No results for corpus `{corpus}` yet - run `make leaderboard`._"
    fixtures = next((r.corpus.fixture_count for r in rows if r.corpus.fixture_count), 0)
    positives = next((r.corpus.labeled_positives for r in rows if r.corpus.labeled_positives), 0)
    primary_bytes = next((r.corpus.bytes for r in rows if r.corpus.bytes), 0)
    other_corpora = sorted(
        {r.corpus.name for r in results if r.corpus.name and r.corpus.name != primary_corpus and not _is_daemon_corpus(r.corpus.name)}
    )
    lines = []
    if other_corpora or corpus == "multi-corpus":
        lines.append(_corpus_heading(primary_corpus))
    bytes_str = f", {primary_bytes:,} bytes" if primary_bytes else ""
    lines.extend([
        f"Corpus: **{primary_corpus}** - {fixtures} fixtures, {positives} labeled positives{bytes_str}. "
        f"Every scanner scored identically (SecretBench overlap rule); the answer-key "
        f"manifest is excluded from the scan tree.",
        "",
        "| Rank | Scanner | F1 | Precision | Recall | Findings | Wall | Peak RSS |",
        "|---|---|---|---|---|---|---|---|",
    ])
    for i, r in enumerate(rows, 1):
        o = r.detection.overall
        if not r.available:
            lines.append(f"| {i} | {_name(r.scanner.name)} | - | - | - | - | "
                         f"_n/a_ | - |")
            continue
        bold = "**" if r.scanner.name == "keyhog" else ""
        lines.append(
            f"| {i} | {bold}{_name(r.scanner.name)}{bold} | "
            f"{bold}{o.f1():.4f}{bold} | {o.precision():.4f} | {o.recall():.4f} | "
            f"{r.finding_count} | {_fmt_secs(r.speed.wall_ms)} | "
            f"{r.speed.peak_rss_kb // 1024} MB |"
        )
    provenance_rows = list(rows)
    for other in other_corpora:
        other_rows = canonical_leaderboard(results, other)
        if not other_rows:
            continue
        o_fixtures = next((r.corpus.fixture_count for r in other_rows if r.corpus.fixture_count), 0)
        o_positives = next((r.corpus.labeled_positives for r in other_rows if r.corpus.labeled_positives), 0)
        o_bytes = next((r.corpus.bytes for r in other_rows if r.corpus.bytes), 0)
        heading = _corpus_heading(other)
        if other == "homefield":
            corpus_desc = (
                f"Corpus: **homefield** - {o_fixtures} fixtures harvested from competitor ground-truth "
                f"rule suites (Betterleaks and Kingfisher rules; {o_positives:,} labeled positives, "
                f"{o_fixtures - o_positives:,} negatives, {o_bytes:,} bytes). "
                "Cross-tool evaluation on competitor ground truth."
            )
        else:
            bytes_part = f", {o_bytes:,} bytes" if o_bytes else ""
            corpus_desc = (
                f"Corpus: **{other}** - {o_fixtures} fixtures, {o_positives} labeled positives{bytes_part}. "
                "Cross-tool evaluation on competitor ground truth."
            )
        lines.extend([
            "",
            heading,
            corpus_desc,
            "",
            "| Rank | Scanner | F1 | Precision | Recall | Findings | Wall | Peak RSS |",
            "|---|---|---|---|---|---|---|---|",
        ])
        for i, r in enumerate(other_rows, 1):
            o = r.detection.overall
            if not r.available:
                lines.append(f"| {i} | {_name(r.scanner.name)} | - | - | - | - | _n/a_ | - |")
                continue
            bold = "**" if r.scanner.name == "keyhog" else ""
            lines.append(
                f"| {i} | {bold}{_name(r.scanner.name)}{bold} | "
                f"{bold}{o.f1():.4f}{bold} | {o.precision():.4f} | {o.recall():.4f} | "
                f"{r.finding_count} | {_fmt_secs(r.speed.wall_ms)} | "
                f"{r.speed.peak_rss_kb // 1024} MB |"
            )
        provenance_rows.extend(other_rows)
    lines.extend(["", render_provenance(provenance_rows)])
    return "\n".join(lines)


def render_perf(results: list[RunResult], corpus: str | None = None) -> str:
    """Render Markdown throughput and latency performance table."""
    available_rows = [r for r in results if r.available]
    if not available_rows:
        return "_No timed runs yet._"
    if corpus is None or corpus == "multi-corpus":
        corpora_in_rows = sorted(
            {r.corpus.name for r in available_rows if r.corpus.name and not _is_daemon_corpus(r.corpus.name)}
        )
        if len(corpora_in_rows) > 1:
            lines = []
            for c in corpora_in_rows:
                c_rows = [r for r in available_rows if r.corpus.name == c]
                if not c_rows:
                    continue
                c_rows.sort(key=lambda r: r.speed.wall_ms)
                heading = _corpus_heading(c)
                lines.extend([
                    heading,
                    "",
                    "| Scanner | Config | Corpus | Wall | Throughput | Peak RSS |",
                    "|---|---|---|---|---|---|",
                ])
                for r in c_rows:
                    tp = f"{r.speed.throughput_mb_s:.1f} MB/s" if r.speed.throughput_mb_s else "-"
                    lines.append(
                        f"| {_name(r.scanner.name)} | `{r.scanner.config_id}` | {r.corpus.name} | "
                        f"{_fmt_secs(r.speed.wall_ms)} | {tp} | {r.speed.peak_rss_kb // 1024} MB |"
                    )
                lines.append("")
            return "\n".join(lines).rstrip()
        elif len(corpora_in_rows) == 1:
            corpus = corpora_in_rows[0]
        else:
            return "_No timed runs yet._"

    selected_rows = [r for r in available_rows if r.corpus.name == corpus]
    if not selected_rows:
        return "_No timed runs yet._"
    selected_rows.sort(key=lambda r: r.speed.wall_ms)
    lines = [
        "| Scanner | Config | Corpus | Wall | Throughput | Peak RSS |",
        "|---|---|---|---|---|---|",
    ]
    for r in selected_rows:
        tp = f"{r.speed.throughput_mb_s:.1f} MB/s" if r.speed.throughput_mb_s else "-"
        lines.append(
            f"| {_name(r.scanner.name)} | `{r.scanner.config_id}` | {r.corpus.name} | "
            f"{_fmt_secs(r.speed.wall_ms)} | {tp} | {r.speed.peak_rss_kb // 1024} MB |"
        )
    return "\n".join(lines)


def _outcome_metrics(outcome: Outcome) -> dict:
    """Convert Outcome object to dictionary of raw metric fields."""
    return {
        "tp": outcome.tp,
        "fp": outcome.fp,
        "fn": outcome.fn,
        "precision": round(outcome.precision(), 4),
        "recall": round(outcome.recall(), 4),
        "f1": round(outcome.f1(), 4),
    }


def class_recall_differential(
    results: list[RunResult],
    corpus: str,
    required_scanners: tuple[str, ...] | None = None,
) -> dict:
    """Structured per-category recall differential for benchmark and ML gates."""
    rows = canonical_leaderboard(results, corpus)
    by_scanner = {
        r.scanner.name: r
        for r in rows
        if r.available
    }
    if required_scanners:
        missing = [name for name in required_scanners if name not in by_scanner]
        if missing:
            raise ValueError(
                f"missing required scanner result(s) for `{corpus}`: "
                f"{', '.join(missing)}"
            )
        empty = [
            name
            for name in required_scanners
            if not by_scanner[name].detection.per_category
        ]
        if empty:
            raise ValueError(
                f"scanner result(s) for `{corpus}` lack per-category data: "
                f"{', '.join(empty)}"
            )

    kh = by_scanner.get("keyhog")
    if kh is None:
        raise ValueError(f"missing available keyhog result for `{corpus}`")
    cats = set(kh.detection.per_category)
    for r in by_scanner.values():
        cats |= set(r.detection.per_category)

    diff_rows = {}
    for cat in sorted(cats):
        kh_o = kh.detection.per_category.get(cat) or Outcome()
        competitors = {}
        for name, r in sorted(by_scanner.items()):
            if name == "keyhog":
                continue
            o = r.detection.per_category.get(cat)
            competitors[name] = _outcome_metrics(o or Outcome())

        best_name = None
        best_metrics = None
        for name, metrics in competitors.items():
            key = (metrics["recall"], metrics["f1"], metrics["precision"])
            if best_metrics is None:
                best_name, best_metrics = name, metrics
                continue
            best_key = (
                best_metrics["recall"],
                best_metrics["f1"],
                best_metrics["precision"],
            )
            if key > best_key:
                best_name, best_metrics = name, metrics

        kh_metrics = _outcome_metrics(kh_o)
        best_metrics = best_metrics or _outcome_metrics(Outcome())
        gap = best_metrics["recall"] - kh_metrics["recall"]
        diff_rows[cat] = {
            "keyhog": kh_metrics,
            "best_competitor": {
                "scanner": best_name or "",
                **best_metrics,
            },
            "recall_gap": round(gap, 4),
            "competitors": competitors,
        }

    return {
        "corpus": corpus,
        "required_scanners": list(required_scanners or []),
        "scanners": sorted(by_scanner),
        "scanner_count": len(by_scanner),
        "category_count": len(diff_rows),
        "rows": diff_rows,
    }


def render_recall_gap(results: list[RunResult], corpus: str) -> str:
    """Per-category recall comparison for the selected corpus.

    The table names categories where a competitor's recall exceeds keyhog's,
    the keyhog P/R/F1 and TP/FN, and the best competitor's same-category
    precision and recall.  When no competitor exceeds keyhog, or required
    scanner data is missing, the message states the measured fact or the
    missing inputs rather than declaring a winner.
    """
    try:
        diff = class_recall_differential(results, corpus)
    except ValueError:
        return f"_Per-category recall comparison unavailable for `{corpus}`: no keyhog result._"

    out_lines = []
    for cat, row in diff["rows"].items():
        kh_o = row["keyhog"]
        best_o = row["best_competitor"]
        if row["recall_gap"] > 1e-9:
            out_lines.append(
                f"| `{cat}` | {kh_o['precision']:.3f} / {kh_o['recall']:.3f} / "
                f"{kh_o['f1']:.3f} | {kh_o['tp']}/{kh_o['fn']} | "
                f"{_name(best_o['scanner'])} {best_o['precision']:.3f} / "
                f"{best_o['recall']:.3f} / {best_o['f1']:.3f} | "
                f"+{row['recall_gap']:.3f} |"
            )
    if not out_lines:
        scanners = diff["scanners"]
        if len(scanners) <= 1:
            return (
                f"_Per-category recall comparison unavailable for `{corpus}`: "
                f"no competitor results._"
            )
        return (
            f"_No measured competitor exceeds KeyHog recall in any category on "
            f"`{corpus}`._"
        )
    return "\n".join([
        "_Diagnostic recall slice only. Overall precision and F1 remain the comparison "
        "contract; false positives are counted in their scored categories._",
        "",
        "| Category | KeyHog P/R/F1 | KeyHog TP/FN | Best competitor P/R/F1 | Recall gap |",
        "|---|---|---|---|---|",
        *out_lines,
    ])


def render_gaps(results: list[RunResult], corpus: str) -> str:
    """Render per-category recall comparison gaps table."""
    return render_recall_gap(results, corpus)


# -- category recall (collapsed primary axis) ---------------------------


def primary_category(raw: str) -> str:
    """Collapse a CredData composite category label to its primary axis.

    CredData labels a positive with a colon-joined multi-label
    (``API:Anthropic API Key:Key``, ``Token:UUID``). Keying per_category on the
    full string fragments the taxonomy into ~190 near-empty cells that hide
    WHERE recall actually bleeds. The base credential class is the LAST atom by
    CredData convention (``…:Key`` is a key, ``…:UUID`` a uuid), so that is the
    single axis this dashboard groups on. One owner for the collapse so score,
    report, and the gate never disagree on what "the Key bucket" means.
    """
    atom = (raw or "unknown").split(":")[-1].strip()
    return atom or "unknown"


def collapse_per_category(per_category: dict) -> dict[str, Outcome]:
    """Sum every composite cell into its `primary_category` bucket."""
    out: dict[str, Outcome] = {}
    for raw, outcome in per_category.items():
        prim = primary_category(raw)
        acc = out.get(prim)
        if acc is None:
            out[prim] = Outcome(tp=outcome.tp, fp=outcome.fp, fn=outcome.fn)
        else:
            acc.tp += outcome.tp
            acc.fp += outcome.fp
            acc.fn += outcome.fn
    return out


def render_category_recall(results: list[RunResult], corpus: str) -> str:
    """KeyHog recall per collapsed primary category, ranked by misses (FN).

    The headline F1 hides that a few generic shapes carry almost all of the
    misses. This table names them: for every primary CredData category it shows
    KeyHog TP/FN and recall next to the best competitor's recall on the SAME
    category, ordered by KeyHog's raw miss count so the biggest recall holes sit
    at the top. This is the "where is recall actually lost" view.
    """
    rows = canonical_leaderboard(results, corpus)
    by_scanner = {r.scanner.name: r for r in rows if r.available}
    kh = by_scanner.get("keyhog")
    if kh is None or not kh.detection.per_category:
        return (
            f"_Category recall comparison unavailable for `{corpus}`: "
            f"keyhog per-category data missing._"
        )

    kh_cats = collapse_per_category(kh.detection.per_category)
    comp_cats = {
        name: collapse_per_category(r.detection.per_category)
        for name, r in by_scanner.items()
        if name != "keyhog"
    }

    def best_competitor_recall(cat: str) -> tuple[str, float]:
        """Find best competitor recall for a specific category."""
        best_name, best_rec = "", 0.0
        for name, cats in comp_cats.items():
            o = cats.get(cat)
            if o is None:
                continue
            rec = o.recall()
            if rec > best_rec:
                best_name, best_rec = name, rec
        return best_name, best_rec

    ordered = sorted(kh_cats.items(), key=lambda kv: kv[1].fn, reverse=True)
    out_lines = [
        "| Category | KeyHog TP/FN | KeyHog recall | Best competitor recall | Miss share |",
        "|---|---|---|---|---|",
    ]
    total_fn = sum(o.fn for o in kh_cats.values()) or 1
    for cat, o in ordered:
        if o.tp + o.fn == 0:
            continue
        bname, brec = best_competitor_recall(cat)
        best_cell = f"{_name(bname)} {brec:.3f}" if bname else "N/A"
        out_lines.append(
            f"| `{cat}` | {o.tp}/{o.fn} | {o.recall():.3f} | {best_cell} | "
            f"{o.fn / total_fn * 100:.1f}% |"
        )
    return "\n".join(out_lines)


# -- per-detector calibration -------------------------------------------


def render_per_detector(detection: Detection, corpus_positives: int,
                        top: int | None = None) -> str:
    """Per-detector precision/recall + the measured ``min_confidence`` floor.

    One row per detector that fired, FP-heavy first, the tuning worklist:
    a low-precision, high-FP detector with a non-zero lossless floor is a
    free precision win; a high ``unique_tp`` detector is recall-critical and
    must be tuned carefully. ``RecallShare`` is the fraction of the corpus's
    positives this detector *alone* accounts for.
    """
    from .calibrate import recommend_all

    recs = recommend_all(detection.per_detector)
    if not recs:
        return "_No keyhog detectors fired (per-detector stats require a " \
               "keyhog run that emits confidence)._"
    if top:
        recs = recs[:top]
    lines = [
        "| Detector | TP | FP | Precision | UniqueTP | RecallShare | "
        "Lossless floor | FP cut | F1 floor | F1 P |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for r in recs:
        share = (r.unique_tp / corpus_positives) if corpus_positives else 0.0
        lossless = f"**{r.lossless_floor:.2f}**" if r.actionable else f"{r.lossless_floor:.2f}"
        lines.append(
            f"| `{r.detector_id}` | {r.tp} | {r.fp} | {r.current_precision:.3f} | "
            f"{r.unique_tp} | {share:.3f} | {lossless} | "
            f"{r.lossless_fp_cut} | {r.f1_floor:.2f} | {r.f1_precision:.3f} |"
        )
    return "\n".join(lines)


def render_calibration(detection: Detection) -> str:
    """The actionable lossless floor bumps, as a summary table."""
    from .calibrate import actionable, recommend_all

    wins = actionable(recommend_all(detection.per_detector))
    if not wins:
        return "_No lossless `min_confidence` bumps available on this corpus._"
    total_fp_cut = sum(r.lossless_fp_cut for r in wins)
    lines = [
        f"{len(wins)} detector(s) can losslessly cut **{total_fp_cut}** false "
        f"positive(s), each floor below removes ≥1 FP and loses 0 TP on this corpus.",
        "",
        "| Detector | Current P | FP | Recommended floor | FP cut |",
        "|---|---|---|---|---|",
    ]
    for r in wins:
        lines.append(
            f"| `{r.detector_id}` | {r.current_precision:.3f} | {r.fp} | "
            f"**{r.lossless_floor:.2f}** | {r.lossless_fp_cut} |"
        )
    return "\n".join(lines)


def write_calibration_reports(detection: Detection, corpus: str,
                              corpus_positives: int,
                              reports_dir: pathlib.Path) -> dict[str, pathlib.Path]:
    """Write ``per_detector.md`` + ``calibration.md`` + ``calibration.toml``."""
    from .calibrate import recommend_all, to_toml_overlay

    reports_dir.mkdir(parents=True, exist_ok=True)
    per_det = f"# Per-detector scoring: {corpus}\n\n" \
              f"{render_per_detector(detection, corpus_positives)}\n"
    calib = f"# min_confidence calibration: {corpus}\n\n" \
            f"{render_calibration(detection)}\n"
    overlay = to_toml_overlay(recommend_all(detection.per_detector))
    written = {
        "per_detector.md": reports_dir / "per_detector.md",
        "calibration.md": reports_dir / "calibration.md",
        "calibration.toml": reports_dir / "calibration.toml",
    }
    written["per_detector.md"].write_text(per_det)
    written["calibration.md"].write_text(calib)
    written["calibration.toml"].write_text(overlay)
    return written


# -- injection ----------------------------------------------------------


def _markers(section: str) -> tuple[str, str]:
    """Return HTML start and end comments for README injection section."""
    return (f"<!-- BENCH:{section}:start -->", f"<!-- BENCH:{section}:end -->")


def has_markers(text: str, section: str) -> bool:
    """True iff both markers for ``section`` are present and well-ordered."""
    start, end = _markers(section)
    si = text.find(start)
    ei = text.find(end)
    return si != -1 and ei != -1 and ei >= si


def missing_marker_sections(text: str, sections: list[str]) -> list[str]:
    """Sections whose BENCH markers are absent from ``text`` (a README that
    lost them). Under ``--check`` this is a hard error, not a silent pass: an
    injection whose markers vanished would otherwise leave the text unchanged
    and be reported as "already current"."""
    return [s for s in sections if not has_markers(text, s)]


def inject(text: str, section: str, body: str) -> str:
    """Replace content between the section's markers. If the markers are
    absent, returns the text unchanged (caller must use
    :func:`missing_marker_sections` to detect and reject that). Idempotent:
    same body -> identical output."""
    start, end = _markers(section)
    si = text.find(start)
    ei = text.find(end)
    if si == -1 or ei == -1 or ei < si:
        return text
    replacement = f"{start}\n{body}\n{end}"
    return text[:si] + replacement + text[ei + len(end):]

def render_static_recovery(results: list[RunResult], corpus: str) -> str:
    """Render exact bounded static-recovery metrics for the selected KeyHog run."""
    rows = canonical_leaderboard(results, corpus)
    keyhog = next((row for row in rows if row.scanner.name == "keyhog"), None)
    if keyhog is None:
        return f"_No KeyHog result selected for corpus `{_cell(corpus)}`._"
    source = _cell(getattr(keyhog, "_report_source", "<in-memory result>"))
    identity = (
        f"Selected run: scanner **KeyHog** `{_cell(keyhog.scanner.version)}`; "
        f"corpus **{_cell(keyhog.corpus.name)}** "
        f"({keyhog.corpus.fixture_count:,} fixtures, {keyhog.corpus.bytes:,} bytes); "
        f"generated `{_cell(keyhog.generated_at)}`; artifact `{source}`."
    )
    metrics = keyhog.static_recovery
    if metrics is None:
        return (
            f"{identity}\n\n"
            f"_Static recovery telemetry not recorded: artifact schema "
            f"`{_cell(keyhog.schema_version)}` predates `static-recovery-v1`. "
            "Rerun this exact scanner/corpus/config selection with the current "
            "benchmark harness; no zero values are inferred._"
        )
    lines = [
        identity,
        "",
        f"Telemetry schema: `{metrics.schema_version}`.",
        "",
        "| Disposition | Exact count |",
        "|---|---:|",
        f"| Supported | {metrics.supported} |",
        f"| Unsupported | {metrics.unsupported} |",
        f"| Erroneous | {metrics.erroneous} |",
        "",
        "| Rejection reason | Exact count |",
        "|---|---:|",
    ]
    if metrics.reasons:
        for reason in sorted(metrics.reasons):
            lines.append(f"| `{_cell(reason)}` | {metrics.reasons[reason]} |")
    else:
        lines.append("| _none_ | 0 |")
    return "\n".join(lines)


def render_bloom_evidence(results: list[RunResult], corpus: str) -> str:
    """Render real-corpus Bloom effectiveness and exact bypass parity."""
    rows = canonical_leaderboard(results, corpus)
    keyhog = next((row for row in rows if row.scanner.name == "keyhog"), None)
    if keyhog is None:
        return f"_No KeyHog result selected for corpus `{_cell(corpus)}`._"
    evidence = keyhog.bloom
    if evidence is None:
        return (
            "_Bloom corpus evidence was not recorded for the selected artifact. "
            "Run `make bloom KEYHOG_BIN=/absolute/path/to/keyhog` and attach the "
            "result; no synthetic or zero-valued fallback is inferred._"
        )
    rejection = (
        f"{evidence.rejection_basis_points // 100}."
        f"{evidence.rejection_basis_points % 100:02d}%"
    )
    parity = "IDENTICAL" if evidence.findings_identical else "MISMATCH"
    unavailable_reasons = ", ".join(
        f"{reason}={count}"
        for reason, count in evidence.unavailable_reason_counts.items()
    )
    return "\n".join([
        f"Evidence schema: `{evidence.schema_version}`.",
        "",
        "| Field | Exact result |",
        "|---|---|",
        f"| Corpus | `{_cell(evidence.corpus_name)}` |",
        f"| Corpus revision | `{_cell(evidence.corpus_revision)}` |",
        f"| Corpus SHA-256 | `{evidence.corpus_sha256}` |",
        f"| Fixture SHA-256 | `{evidence.fixture_sha256}` |",
        f"| Executable SHA-256 | `{evidence.executable_sha256}` |",
        (
            "| Workspace detector corpus SHA-256 | "
            f"`{evidence.workspace_detector_corpus_sha256}` |"
        ),
        f"| Scanner detector digest | `{evidence.scanner_detector_digest}` |",
        f"| Detector corpus SHA-256 | `{evidence.detector_corpus_sha256}` |",
        (
            "| Bloom rejection | "
            f"**{evidence.rejected_input_count}/{evidence.input_count} "
            f"({rejection})**; {evidence.admitted_input_count} admitted |"
        ),
        (
            "| External availability | "
            f"{evidence.input_count} measured; "
            f"{evidence.unavailable_input_count} explicitly unavailable "
            f"of {evidence.declared_input_count} declared; "
            f"reasons: {unavailable_reasons} |"
        ),
        (
            "| Enabled vs bypassed findings | "
            f"**{parity}**; {evidence.enabled_finding_count}/"
            f"{evidence.bypass_finding_count} findings |"
        ),
        (
            "| Finding identity SHA-256 | "
            f"`{evidence.enabled_findings_sha256}` / "
            f"`{evidence.bypass_findings_sha256}` |"
        ),
        (
            "| Bloom density/state | "
            f"{evidence.populated_slots}/{evidence.total_slots} slots; "
            f"`{evidence.state}`; saturation at "
            f"{evidence.saturation_threshold_slots} |"
        ),
        "",
        (
            "Finding identity binds detector, file, line, byte span, and "
            "credential SHA-256; plaintext credentials are never recorded."
        ),
    ])


def build_sections(results: list[RunResult], corpus: str) -> dict[str, str]:
    """Build all Markdown sections for README markers."""
    primary_corpus = "mirror" if corpus == "multi-corpus" else corpus
    return {
        "leaderboard": render_leaderboard(results, corpus),
        "perf": render_perf(results, corpus),
        "gaps": render_gaps(results, primary_corpus),
        "recovery": render_static_recovery(results, primary_corpus),
        "bloom": render_bloom_evidence(results, primary_corpus),
    }


def report_files(results: list[RunResult], corpus: str) -> dict[str, str]:
    """The canonical {filename: full markdown body} set the bench renders under
    `reports/`. Single owner: `write_reports` (which writes them) and
    `stale_report_paths` (the `--check` gate that asserts they're current) both
    consume THIS, so the on-disk rollups and the staleness check can never
    diverge.
    """
    is_multi = any(r.corpus.name and r.corpus.name != corpus and not r.corpus.name.startswith("daemon") for r in results)
    sections = build_sections(results, "multi-corpus" if is_multi else corpus)
    return {
        "leaderboard.md": f"# Leaderboard - {'multi-corpus' if is_multi else corpus}\n\n{sections['leaderboard']}\n",
        "perf.md": f"# Performance\n\n{sections['perf']}\n",
        "recall-gap.md": f"# Per-category recall comparison - {corpus}\n\n{sections['gaps']}\n",
        "category-recall.md": f"# Category recall dashboard - {corpus}\n\n"
        f"{render_category_recall(results, corpus)}\n",
        "static-recovery.md": f"# Bounded static recovery - {corpus}\n\n"
        f"{sections['recovery']}\n",
        "bloom.md": f"# Bigram Bloom evidence\n\n{sections['bloom']}\n",
    }
def write_reports(results: list[RunResult], corpus: str,
                  reports_dir: pathlib.Path) -> None:
    """Write the canonical report set for ``corpus`` under ``reports_dir``.

    Fails closed if any report would contain no measured rows, so placeholder
    markdown can never be committed as a real benchmark.
    """
    assert_reports_populated(results, corpus)
    reports_dir.mkdir(parents=True, exist_ok=True)
    for name, body in report_files(results, corpus).items():
        (reports_dir / name).write_text(body)


def stale_report_paths(
    results: list[RunResult],
    corpus: str,
    reports_dir: pathlib.Path,
) -> list[pathlib.Path]:
    """Return list of report file paths that differ from current result outputs."""
    expected = report_files(results, corpus)
    stale = []
    for name, body in expected.items():
        path = reports_dir / name
        try:
            current = path.read_text()
        except OSError:
            stale.append(path)
            continue
        if current != body:
            stale.append(path)
    return stale


def _main(argv: list[str] | None = None) -> int:
    """Main CLI entry point for report rendering and injection."""
    ap = argparse.ArgumentParser(description="Render bench results to markdown / README.")
    ap.add_argument("--results", default=str(_BENCH_ROOT / "results"))
    ap.add_argument("--reports", default=str(_BENCH_ROOT / "reports"))
    ap.add_argument("--readme", default=str(_REPO_ROOT / "README.md"))
    ap.add_argument("--corpus", default="mirror")
    ap.add_argument(
        "--run-set",
        help=(
            "TOML inventory binding rows to paths relative to --results and exact identities. "
            "The committed results directory uses run-sets/canonical.toml by default."
        ),
    )
    ap.add_argument(
        "--refresh-run-set",
        action="store_true",
        help="Rewrite the exact inventory from its declared current result paths and exit.",
    )
    ap.add_argument("--inject", action="store_true", help="Rewrite README between markers.")
    ap.add_argument("--check", action="store_true",
                    help="Exit 1 if reports or the README would change (idempotence gate).")
    args = ap.parse_args(argv)

    results_path = pathlib.Path(args.results)
    try:
        results = load_results(results_path)
        run_set_path = pathlib.Path(args.run_set) if args.run_set else None
        if run_set_path is None:
            run_set_path = default_run_set_path(results_path)
        if args.refresh_run_set and run_set_path is None:
            raise ResultSelectionError(
                "--refresh-run-set requires --run-set outside the committed results directory"
            )
        if run_set_path is not None:
            run_set = load_run_set(run_set_path)
            if args.refresh_run_set:
                run_set = refresh_run_set(results, args.corpus, run_set)
                run_set_path.write_text(render_run_set(run_set), encoding="utf-8")
                print(f"refreshed exact run-set inventory: {run_set_path}", file=sys.stderr)
                return 0
            results = select_declared_results(results, args.corpus, run_set)
        assert_reports_populated(results, args.corpus)
    except (OSError, ReportEmptyError, ResultLoadError, ResultSelectionError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    sections = build_sections(results, args.corpus)

    print(sections["leaderboard"])
    if args.inject or args.check:
        readme = pathlib.Path(args.readme)
        original = readme.read_text() if readme.exists() else ""
        if args.check:
            absent = missing_marker_sections(original, list(sections))
            if absent:
                print(
                    f"README is missing BENCH markers for: {', '.join(absent)} "
                    f"(injection cannot run, restore the <!-- BENCH:*:start/end --> markers).",
                    file=sys.stderr,
                )
                return 1
        updated = original
        for name, body in sections.items():
            updated = inject(updated, name, body)
        if args.check:
            stale_reports = stale_report_paths(
                results,
                args.corpus,
                pathlib.Path(args.reports),
            )
            if stale_reports:
                joined = ", ".join(str(path) for path in stale_reports)
                print(
                    f"Benchmark reports are stale: `make report` would change {joined}.",
                    file=sys.stderr,
                )
                return 1
            if updated != original:
                print("README is stale: `make report` would change it.", file=sys.stderr)
                return 1
            print("README bench tables are up to date.", file=sys.stderr)
            return 0
        if updated != original:
            readme.write_text(updated)
            print(f"injected bench tables into {readme}", file=sys.stderr)
        else:
            print("README unchanged (no markers found or already current).",
                  file=sys.stderr)
    write_reports(results, args.corpus, pathlib.Path(args.reports))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
