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

from .schema import RunResult

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
        pick = next((r for r in runs if r.scanner.config_id == default_id), None)
        pick = pick or next((r for r in runs if r.available), runs[0])
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


def render_gaps(results: list[RunResult], corpus: str) -> str:
    """Per-category cells where any competitor's F1 beats keyhog's - the
    detection gaps left to close."""
    rows = canonical_leaderboard(results, corpus)
    kh = next((r for r in rows if r.scanner.name == "keyhog" and r.available), None)
    if kh is None:
        return "_No keyhog result for this corpus yet._"
    cats = set(kh.detection.per_category)
    for r in rows:
        cats |= set(r.detection.per_category)
    out_lines = []
    for cat in sorted(cats):
        kh_f1 = kh.detection.per_category.get(cat)
        kh_f1v = kh_f1.f1() if kh_f1 else 0.0
        best = None
        for r in rows:
            if r.scanner.name == "keyhog" or not r.available:
                continue
            o = r.detection.per_category.get(cat)
            if o and o.f1() > kh_f1v + 1e-9 and (best is None or o.f1() > best[1]):
                best = (r.scanner.name, o.f1())
        if best:
            out_lines.append(
                f"| `{cat}` | {kh_f1v:.3f} | {_name(best[0])} {best[1]:.3f} | "
                f"+{best[1]-kh_f1v:.3f} |"
            )
    if not out_lines:
        return "_keyhog matches or beats every competitor in every category on " \
               f"`{corpus}`._"
    return "\n".join([
        "| Category | KeyHog F1 | Best competitor | Gap |",
        "|---|---|---|---|",
        *out_lines,
    ])


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
    reports_dir.mkdir(parents=True, exist_ok=True)
    sections = build_sections(results, corpus)
    (reports_dir / "leaderboard.md").write_text(
        f"# Leaderboard - {corpus}\n\n{sections['leaderboard']}\n")
    (reports_dir / "perf.md").write_text(
        f"# Performance\n\n{sections['perf']}\n")
    (reports_dir / "gaps.md").write_text(
        f"# Per-category gaps - {corpus}\n\n{sections['gaps']}\n")


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
    write_reports(results, args.corpus, pathlib.Path(args.reports))
    sections = build_sections(results, args.corpus)

    print(sections["leaderboard"])

    if args.inject or args.check:
        readme = pathlib.Path(args.readme)
        original = readme.read_text() if readme.exists() else ""
        updated = original
        for name, body in sections.items():
            updated = inject(updated, name, body)
        if args.check:
            if updated != original:
                print("README is stale: `make report` would change it.", file=__import__("sys").stderr)
                return 1
            print("README bench tables are up to date.", file=__import__("sys").stderr)
            return 0
        if updated != original:
            readme.write_text(updated)
            print(f"injected bench tables into {readme}", file=__import__("sys").stderr)
        else:
            print("README unchanged (no markers found or already current).",
                  file=__import__("sys").stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
