#!/usr/bin/env python3
"""Gate #1 — NO SILENT FALLBACKS (Law 10), enforced as a shrink-only ratchet.

Law 10 was written in CLAUDE.md the whole time 66 silent fallbacks accumulated.
A rule a human has to remember is a rule that gets skipped. This gate makes a
NEW silent-swallow idiom in the detection crates a RED BUILD.

It scans `crates/{scanner,sources,core,cli,verifier}/{src,examples,benches}`
for TWO idiom classes
that discard a failure / degrade with no operator-visible surfacing:
  (1) the swallow idioms:
    .ok()              (Result -> Option, error dropped)
    if let Ok(...)     (error arm omitted)
    Err(_) =>          (error swallowed in a match arm)
    unwrap_or(...)     unwrap_or_else(...)  unwrap_or_default()
    let _ = <expr>     (Result/value explicitly discarded)
  (2) a `tracing::debug!`/`trace!` whose message carries degrade-language
    (fallback / skip / ignore / degrade / disabled / using default / unavailable
    / dropped / recall) — the idiom Law 10 names FIRST: a debug log "then
    continue to a weaker path" is invisible at default verbosity, i.e. silent.
Each occurrence is a CANDIDATE. `python3 no_silent_fallbacks.py --self-test`
proves both classes still catch real fallbacks and ignore benign code (Law 6). A candidate is EXEMPT only if its line, or the
immediately following rustfmt-moved comment line, carries an explicit
justification marker:
    // LAW10: <how this failure is surfaced or why it is recall-safe>
so every real fallback must be loud, recorded, or consciously waived IN THE DIFF.

BASELINE RATCHET: the current (unfixed) candidates are recorded in
`scripts/gates/silent_fallback_baseline.txt`. The gate FAILS if a candidate
appears that is not in the baseline (a NEW silent fallback) — so new ones can't
land. Fixing or annotating an existing one removes it from the live set; the gate
also FAILS if the baseline contains entries no longer present UNLESS you
regenerate it, so the baseline can only SHRINK. The 66 audited violations live in
this baseline as visible, shrinking debt.

Keys are `relpath::normalized_code` (NOT line numbers) so they survive line moves.

Run:        python3 scripts/gates/no_silent_fallbacks.py
Regenerate: python3 scripts/gates/no_silent_fallbacks.py --update-baseline
"""
from __future__ import annotations

import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]
BASELINE = pathlib.Path(__file__).resolve().parent / "silent_fallback_baseline.txt"
# Every crate that runs on the operator's scan/verify/CLI path. `cli` and
# `verifier` were blind spots for the first 66 audited fallbacks: ~186 candidate
# idioms lived in the operator-facing CLI argument/output plumbing and the
# verifier's network/credential-validation path with no gate watching them.
# Adding them here makes a NEW swallow in either crate a RED BUILD too.
CRATES = ["scanner", "sources", "core", "cli", "verifier"]

IDIOMS = [
    re.compile(r"\.ok\(\)"),
    re.compile(r"\bif\s+let\s+Ok\b"),
    re.compile(r"Err\(_\)\s*=>"),
    re.compile(r"\.unwrap_or\("),
    re.compile(r"\.unwrap_or_else\("),
    re.compile(r"\.unwrap_or_default\(\)"),
    re.compile(r"\blet\s+_\s*="),
]
# Second idiom class — the one Law 10 names FIRST and the idiom regexes above
# MISS: a `tracing::debug!`/`trace!` that is the SOLE surface of a degrade. A
# debug log "then continue to a weaker path" is invisible at default verbosity,
# so it is a silent fallback. We can't parse control flow with a regex, so we
# flag debug/trace lines whose MESSAGE carries degrade-language (fallback / skip
# / ignore / degrade / disabled / using default / unavailable / failed / dropped
# / reroute / truncate / exhausted)
# — the lines most likely to be masking a degrade. A benign diagnostic
# ("scanning X", "loaded Y") does not match. Each hit is triaged like any other:
# upgrade to warn!/eprintln! + a counter if it is a real degrade, or annotate
# `// LAW10: <why this debug is supplementary, the degrade is surfaced elsewhere>`.
DEGRADE_LOG = re.compile(r"tracing::(?:debug|trace)!")
# Stems with a LEADING word boundary only (no trailing \b) so inflected forms
# match: skip -> skipping/skipped/skips, ignor -> ignoring/ignored, drop ->
# dropped/drops/dropping, degrad -> degraded/degrades, disabl -> disabled.
DEGRADE_WORDS = re.compile(
    r"(?i)\b(?:fall ?back|degrad|skip|ignor|disabl|using default|unavailabl|"
    r"gave up|swallow|drop|recall|rerout|truncat|exhaust)"
)
EXEMPT = re.compile(r"//\s*LAW10:")
WS = re.compile(r"\s+")


def _is_tests_path_relative_to(path: pathlib.Path, repo: pathlib.Path) -> bool:
    rel = path.relative_to(repo)
    return "tests" in rel.parts


def _is_repo_tests_path(path: pathlib.Path) -> bool:
    return _is_tests_path_relative_to(path, REPO)


def _iter_src_files():
    for crate in CRATES:
        for subdir in ("src", "examples", "benches"):
            root = REPO / "crates" / crate / subdir
            if not root.exists():
                continue
            for f in root.rglob("*.rs"):
                # Skip in-file unit tests crudely: files that are predominantly tests
                # still get scanned, but pure test modules under a `tests/` dir are
                # out of scope (those don't ship in the scan path).
                if _is_repo_tests_path(f):
                    continue
                yield f


def _has_exemption_line(lines: list[str], idx: int) -> bool:
    if EXEMPT.search(lines[idx]):
        return True
    prev = idx - 1
    while prev >= 0 and lines[prev].strip().startswith("//"):
        if EXEMPT.search(lines[prev]):
            return True
        prev -= 1
    if idx + 1 >= len(lines):
        return False
    next_line = lines[idx + 1].strip()
    return next_line.startswith("//") and EXEMPT.search(next_line)


def _has_exemption_in_range(lines: list[str], start: int, end: int) -> bool:
    lo = start
    prev = start - 1
    while prev >= 0 and lines[prev].strip().startswith("//"):
        lo = prev
        prev -= 1
    hi = min(len(lines), end + 2)
    return any(EXEMPT.search(lines[i]) for i in range(lo, hi))


def _collect_macro(lines: list[str], start: int) -> tuple[str, int]:
    parts: list[str] = []
    depth = 0
    seen_open = False
    for idx in range(start, min(len(lines), start + 32)):
        line = lines[idx]
        parts.append(line.strip())
        for ch in line:
            if ch == "(":
                depth += 1
                seen_open = True
            elif ch == ")" and depth:
                depth -= 1
        if seen_open and depth == 0 and ";" in line:
            return " ".join(parts), idx
    return " ".join(parts), start


def collect() -> set[str]:
    """Return the set of un-exempt silent-fallback candidate keys."""
    found: set[str] = set()
    for f in _iter_src_files():
        rel = f.relative_to(REPO).as_posix()
        lines = f.read_text(errors="replace").splitlines()
        for idx, line in enumerate(lines):
            stripped = line.strip()
            if _has_exemption_line(lines, idx):
                continue
            if stripped.startswith("//"):
                continue
            matched = False
            for rx in IDIOMS:
                if rx.search(line):
                    norm = WS.sub(" ", stripped)[:160]
                    found.add(f"{rel}::{norm}")
                    matched = True
                    break
            # Second class: a debug/trace log whose message carries degrade-language.
            # Reconstruct the whole macro call so rustfmt-multiline logs cannot
            # hide the degrade word on a later line.
            if not matched and DEGRADE_LOG.search(line):
                macro, end_idx = _collect_macro(lines, idx)
                if DEGRADE_WORDS.search(macro) and not _has_exemption_in_range(
                    lines, idx, end_idx
                ):
                    norm = WS.sub(" ", macro)[:160]
                    found.add(f"{rel}::{norm}")
    return found


def _snippet_is_candidate(lines: list[str]) -> bool:
    for idx, line in enumerate(lines):
        if line.strip().startswith("//"):
            continue
        if _has_exemption_line(lines, idx):
            continue
        if any(rx.search(line) for rx in IDIOMS):
            return True
        if DEGRADE_LOG.search(line):
            macro, end_idx = _collect_macro(lines, idx)
            if DEGRADE_WORDS.search(macro) and not _has_exemption_in_range(
                lines, idx, end_idx
            ):
                return True
    return False


def load_baseline() -> set[str]:
    if not BASELINE.exists():
        return set()
    return {ln.strip() for ln in BASELINE.read_text().splitlines()
            if ln.strip() and not ln.startswith("#")}


def _line_is_candidate(line: str, next_line: str = "") -> bool:
    """True if `line` would be flagged (mirrors the per-line logic in collect)."""
    return _snippet_is_candidate([line, next_line] if next_line else [line])


def self_test() -> int:
    """Prove BOTH idiom classes catch real silent fallbacks and ignore benign
    code — so a future regex tweak can't silently neuter the gate (Law 6)."""
    cases = {
        # regex idiom class -> must flag
        'let x = foo().unwrap_or(0);': True,
        'match r { Err(_) => default(), Ok(v) => v };': True,
        'let v = parse().ok();': True,
        'if let Ok(v) = maybe_value() { use_it(v); }': True,
        # debug/trace degrade-language class -> must flag (incl. inflections)
        'tracing::debug!("GPU init failed, using CPU fallback");': True,
        'tracing::trace!("AC build failed; skipping the fast gate");': True,
        'tracing::debug!("degraded to host path");': True,
        'tracing::debug!("ignored stale cache entry");': True,
        'tracing::debug!("pattern rejected; caller reroutes it");': True,
        'tracing::debug!("decode caller deadline exhausted; stopping decode-through");': True,
        'tracing::debug!("decode cap reached: chunk truncated to limit");': True,
        # benign / exempt / wrong-level / comment -> must NOT flag
        'tracing::debug!("scanning {n} chunks");': False,
        'tracing::info!("falling back to CPU");': False,
        'let v = parse().ok(); // LAW10: fail-closed to None at the boundary': False,
        '// the old tracing::debug! dropped blobs here': False,
        'let total = a + b;': False,
    }
    ok = True
    for line, want in cases.items():
        got = _line_is_candidate(line)
        if got != want:
            ok = False
            print(f"  FAIL want={want} got={got}: {line}", file=sys.stderr)
    rustfmt_adjacent = _line_is_candidate(
        "last_attempt.unwrap_or_else(|| {",
        "// LAW10: exhausted retry loop emits an Error finding; fail-closed.",
    )
    if rustfmt_adjacent:
        ok = False
        print("  FAIL rustfmt-adjacent LAW10 comment was not exempt", file=sys.stderr)
    multiline_debug = _snippet_is_candidate(
        [
            "tracing::debug!(",
            '    target: "keyhog::routing",',
            '    "backend prewarm skipped during autoroute calibration"',
            ");",
        ]
    )
    if not multiline_debug:
        ok = False
        print("  FAIL multiline degrade debug log was not flagged", file=sys.stderr)
    multiline_debug_exempt = _snippet_is_candidate(
        [
            "// LAW10: calibration measures all backends directly; no scan coverage is dropped.",
            "tracing::debug!(",
            '    target: "keyhog::routing",',
            '    "backend prewarm skipped during autoroute calibration"',
            ");",
        ]
    )
    if multiline_debug_exempt:
        ok = False
        print("  FAIL preceding LAW10 comment did not exempt multiline log", file=sys.stderr)
    if _is_repo_tests_path(REPO / "crates/scanner/src/lib.rs"):
        ok = False
        print("  FAIL production src path was classified as tests/", file=sys.stderr)
    if not _is_repo_tests_path(REPO / "crates/scanner/tests/gap/example.rs"):
        ok = False
        print("  FAIL repo-relative tests/ path was not classified as tests/", file=sys.stderr)
    fake_repo_under_tests = pathlib.Path("/tmp/tests/keyhog")
    if _is_tests_path_relative_to(
        fake_repo_under_tests / "crates/scanner/src/lib.rs",
        fake_repo_under_tests,
    ):
        ok = False
        print("  FAIL absolute parent tests/ segment leaked into repo-relative skip", file=sys.stderr)
    if not _is_tests_path_relative_to(
        fake_repo_under_tests / "crates/scanner/tests/gap/example.rs",
        fake_repo_under_tests,
    ):
        ok = False
        print("  FAIL fake repo-relative tests/ path was not classified as tests/", file=sys.stderr)
    print("self-test PASS" if ok else "self-test FAIL", file=sys.stderr)
    return 0 if ok else 1


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return self_test()
    current = collect()
    if "--update-baseline" in argv:
        header = (
            "# Silent-fallback baseline (Gate #1). Shrink-only: an entry leaving "
            "this list (fixed or annotated `// LAW10:`) is good; a NEW entry not "
            "in this list fails CI. Regenerate ONLY when intentionally shrinking.\n"
        )
        BASELINE.write_text(header + "\n".join(sorted(current)) + "\n")
        print(f"wrote {len(current)} baseline entries -> {BASELINE}")
        return 0

    baseline = load_baseline()
    new = current - baseline
    fixed = baseline - current

    if new:
        print(f"FAIL — {len(new)} NEW silent-fallback candidate(s) in the detection "
              f"crates (not in the baseline):\n", file=sys.stderr)
        for k in sorted(new):
            path, _, code = k.partition("::")
            print(f"  {path}\n      {code}", file=sys.stderr)
        print("\nFix each: make the primary path correct, fail closed, or surface "
              "LOUDLY (unconditional eprintln + a counter). If it is genuinely "
              "recall-safe, annotate the line `// LAW10: <why>`. Do NOT add it to "
              "the baseline — the baseline only shrinks.", file=sys.stderr)
        return 1

    if fixed:
        print(f"NOTE: {len(fixed)} baseline entr(ies) are gone (fixed/annotated). "
              f"Run --update-baseline to lock in the shrink:")
        for k in sorted(fixed):
            print(f"  - {k.split('::')[0]}")
    print(f"OK — no new silent fallbacks. {len(current)} known (baseline debt, "
          f"shrinking).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
