"""Render benchmark results to markdown and inject them into the README.

Reads every ``RunResult`` JSON under ``results/`` and produces three tables
the README cites, written between HTML-comment markers so re-running is
idempotent (``--check`` asserts the README is byte-stable on a second pass -
a CI gate against a stale, hand-edited table):

    <!-- BENCH:leaderboard:start -->  F1 / P / R / speed, ranked
    <!-- BENCH:perf:start -->         wall / throughput / peak RSS
    <!-- BENCH:gaps:start -->         per-category places a competitor wins

The full detail (every config, every host) is also written to
``reports/*.md``. Selection for the README leaderboard is deterministic: per
(corpus, scanner) the run at the scanner's DEFAULT config on the reference
host, so the headline never silently swaps in a tuned variant.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

from .schema import Detection, Outcome, RunResult

_BENCH_ROOT = pathlib.Path(__file__).resolve().parents[1]
_REPO_ROOT = _BENCH_ROOT.parent

# Scanner display order / friendly names for the tables.
_DISPLAY = {
    "keyhog": "KeyHog",
    "betterleaks": "BetterLeaks",
    "kingfisher": "Kingfisher",
    "trufflehog": "TruffleHog",
    "titus": "Titus",
    "noseyparker": "Nosey Parker",
}


def load_results(results_dir: pathlib.Path) -> list[RunResult]:
    """Load every ``*.json`` under ``results_dir`` (recursively) as RunResult.
    Skips files that aren't RunResult-shaped (e.g. an index)."""
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
        out.append(RunResult.from_json(data))
    return out


# -- selection ----------------------------------------------------------


def _default_config_id(scanner_name: str) -> str | None:
    try:
        from .scanners import resolve_scanner
        return resolve_scanner(scanner_name).default_config().config_id
    except Exception:
        return None


def canonical_leaderboard(results: list[RunResult], corpus: str) -> list[RunResult]:
    """One row per scanner for ``corpus``: the default-config run, else the
    first available run. Deterministic, default-config-only."""
    by_scanner: dict[str, list[RunResult]] = {}
    for r in results:
        if r.corpus.name != corpus:
            continue
        by_scanner.setdefault(r.scanner.name, []).append(r)
    chosen: list[RunResult] = []
    for name, runs in by_scanner.items():
        default_id = _default_config_id(name)
        # Prefer the default-config runs; fall back to any available run, then
        # to all runs. Among the candidates, the MOST RECENT measurement wins
        # (by generated_at): an archived `results/<commit>/` snapshot must never
        # shadow the current run just because its path sorts first. This keeps a
        # regenerated leaderboard authoritative and the README in sync with HEAD.
        candidates = [r for r in runs if r.scanner.config_id == default_id]
        candidates = candidates or [r for r in runs if r.available] or runs
        pick = max(candidates, key=lambda r: r.generated_at or "")
        chosen.append(pick)
    chosen.sort(key=lambda r: r.detection.overall.f1(), reverse=True)
    return chosen


# -- rendering ----------------------------------------------------------


def _fmt_secs(ms: float) -> str:
    s = ms / 1000.0
    return f"{s:.2f}s" if s < 60 else f"{s/60:.1f}m"


def _name(scanner: str) -> str:
    return _DISPLAY.get(scanner, scanner)


def render_leaderboard(results: list[RunResult], corpus: str) -> str:
    rows = canonical_leaderboard(results, corpus)
    if not rows:
        return f"_No results for corpus `{corpus}` yet - run `make leaderboard`._"
    fixtures = next((r.corpus.fixture_count for r in rows if r.corpus.fixture_count), 0)
    positives = next((r.corpus.labeled_positives for r in rows if r.corpus.labeled_positives), 0)
    lines = [
        f"Corpus: **{corpus}** - {fixtures} fixtures, {positives} labeled positives. "
        f"Every scanner scored identically (SecretBench overlap rule); the answer-key "
        f"manifest is excluded from the scan tree.",
        "",
        "| Rank | Scanner | F1 | Precision | Recall | Findings | Wall | Peak RSS |",
        "|---|---|---|---|---|---|---|---|",
    ]
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
    return "\n".join(lines)


def render_perf(results: list[RunResult], corpus: str | None = None) -> str:
    rows = [r for r in results if r.available and (corpus is None or r.corpus.name == corpus)]
    rows.sort(key=lambda r: r.speed.wall_ms)
    if not rows:
        return "_No timed runs yet._"
    lines = [
        "| Scanner | Config | Corpus | Wall | Throughput | Peak RSS |",
        "|---|---|---|---|---|---|",
    ]
    for r in rows:
        tp = f"{r.speed.throughput_mb_s:.1f} MB/s" if r.speed.throughput_mb_s else "-"
        lines.append(
            f"| {_name(r.scanner.name)} | `{r.scanner.config_id}` | {r.corpus.name} | "
            f"{_fmt_secs(r.speed.wall_ms)} | {tp} | {r.speed.peak_rss_kb // 1024} MB |"
        )
    return "\n".join(lines)


def render_recall_gap(results: list[RunResult], corpus: str) -> str:
    """Per-category recall cells where any competitor beats keyhog.

    This is the benchmark-side companion to the ML per-class retrain gate:
    aggregate F1 can hide tail misses, so the report names the exact category,
    keyhog P/R/F1, TP/FN, and the best competitor's same-category precision and
    recall.
    """
    rows = canonical_leaderboard(results, corpus)
    kh = next((r for r in rows if r.scanner.name == "keyhog" and r.available), None)
    if kh is None:
        return "_No keyhog result for this corpus yet._"
    cats = set(kh.detection.per_category)
    for r in rows:
        cats |= set(r.detection.per_category)
    out_lines = []
    for cat in sorted(cats):
        kh_o = kh.detection.per_category.get(cat) or Outcome()
        kh_recall = kh_o.recall()
        best = None
        for r in rows:
            if r.scanner.name == "keyhog" or not r.available:
                continue
            o = r.detection.per_category.get(cat)
            if (
                o
                and o.recall() > kh_recall + 1e-9
                and (
                    best is None
                    or o.recall() > best[1].recall() + 1e-9
                    or (
                        abs(o.recall() - best[1].recall()) <= 1e-9
                        and o.f1() > best[1].f1()
                    )
                )
            ):
                best = (r.scanner.name, o)
        if best:
            best_o = best[1]
            out_lines.append(
                f"| `{cat}` | {kh_o.precision():.3f} / {kh_recall:.3f} / "
                f"{kh_o.f1():.3f} | {kh_o.tp}/{kh_o.fn} | "
                f"{_name(best[0])} {best_o.precision():.3f} / "
                f"{best_o.recall():.3f} / {best_o.f1():.3f} | "
                f"+{best_o.recall()-kh_recall:.3f} |"
            )
    if not out_lines:
        return "_keyhog matches or beats every competitor's recall in every category on " \
               f"`{corpus}`._"
    return "\n".join([
        "| Category | KeyHog P/R/F1 | KeyHog TP/FN | Best competitor P/R/F1 | Recall gap |",
        "|---|---|---|---|---|",
        *out_lines,
    ])


def render_gaps(results: list[RunResult], corpus: str) -> str:
    return render_recall_gap(results, corpus)


# -- per-detector calibration -------------------------------------------


def render_per_detector(detection: Detection, corpus_positives: int,
                        top: int | None = None) -> str:
    """Per-detector precision/recall + the measured ``min_confidence`` floor.

    One row per detector that fired, FP-heavy first — the tuning worklist:
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
        f"positive(s) — each floor below removes ≥1 FP and loses 0 TP on this corpus.",
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
    per_det = f"# Per-detector scoring — {corpus}\n\n" \
              f"{render_per_detector(detection, corpus_positives)}\n"
    calib = f"# min_confidence calibration — {corpus}\n\n" \
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
    return (f"<!-- BENCH:{section}:start -->", f"<!-- BENCH:{section}:end -->")


def inject(text: str, section: str, body: str) -> str:
    """Replace content between the section's markers. If the markers are
    absent, returns the text unchanged (caller decides whether that's an
    error). Idempotent: same body -> identical output."""
    start, end = _markers(section)
    si = text.find(start)
    ei = text.find(end)
    if si == -1 or ei == -1 or ei < si:
        return text
    replacement = f"{start}\n{body}\n{end}"
    return text[:si] + replacement + text[ei + len(end):]


def build_sections(results: list[RunResult], corpus: str) -> dict[str, str]:
    return {
        "leaderboard": render_leaderboard(results, corpus),
        "perf": render_perf(results),
        "gaps": render_gaps(results, corpus),
    }


def write_reports(results: list[RunResult], corpus: str,
                  reports_dir: pathlib.Path) -> None:
    sections = build_sections(results, corpus)
    reports = {
        "leaderboard.md": f"# Leaderboard - {corpus}\n\n{sections['leaderboard']}\n",
        "perf.md": f"# Performance\n\n{sections['perf']}\n",
        "recall-gap.md": f"# Recall gap dashboard - {corpus}\n\n{sections['gaps']}\n",
    }
    reports_dir.mkdir(parents=True, exist_ok=True)
    for name, body in reports.items():
        (reports_dir / name).write_text(body)


def stale_report_paths(
    results: list[RunResult],
    corpus: str,
    reports_dir: pathlib.Path,
) -> list[pathlib.Path]:
    sections = build_sections(results, corpus)
    expected = {
        "leaderboard.md": f"# Leaderboard - {corpus}\n\n{sections['leaderboard']}\n",
        "perf.md": f"# Performance\n\n{sections['perf']}\n",
        "recall-gap.md": f"# Recall gap dashboard - {corpus}\n\n{sections['gaps']}\n",
    }
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
    ap = argparse.ArgumentParser(description="Render bench results to markdown / README.")
    ap.add_argument("--results", default=str(_BENCH_ROOT / "results"))
    ap.add_argument("--reports", default=str(_BENCH_ROOT / "reports"))
    ap.add_argument("--readme", default=str(_REPO_ROOT / "README.md"))
    ap.add_argument("--corpus", default="mirror")
    ap.add_argument("--inject", action="store_true", help="Rewrite README between markers.")
    ap.add_argument("--check", action="store_true",
                    help="Exit 1 if --inject would change the README (idempotence gate).")
    args = ap.parse_args(argv)

    results = load_results(pathlib.Path(args.results))
    sections = build_sections(results, args.corpus)

    print(sections["leaderboard"])

    if args.inject or args.check:
        readme = pathlib.Path(args.readme)
        original = readme.read_text() if readme.exists() else ""
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
