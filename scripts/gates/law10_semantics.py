#!/usr/bin/env python3
"""Gate #1b - semantic Law 10 exemption contract.

`no_silent_fallbacks.py` catches new swallow/degrade idioms and allows a
same-line `// LAW10:` marker. This gate makes that marker carry a checkable
meaning instead of acting as a blank waiver.

Each Law 10 block must prove one of the conservation claims:
  * no runtime effect / unreachable / initialization-only
  * reporting or display only; finding/work is still emitted
  * recall-preserving default; bytes/findings still flow through another path
  * fail-closed / fail-open-for-suppression at a security boundary
  * loud and counted/surfaced when work is intentionally not scanned

Risky language such as "drop", "skip", "not scanned", "fallback", or
"unreadable" must be paired with one of the safety claims above. A cosmetic
comment cannot hide a real coverage loss.
"""
from __future__ import annotations

import argparse
import pathlib
import re
import sys
from collections import Counter
from dataclasses import dataclass

REPO = pathlib.Path(__file__).resolve().parents[2]
CRATES = ["scanner", "sources", "core", "cli", "verifier"]

CATEGORIES: dict[str, re.Pattern[str]] = {
    "no_runtime_effect": re.compile(
        r"(?i)\b(?:unused-binding|no runtime effect|warm-up|compile-time|"
        r"borrowck|signature|cfg|unreachable|never-taken|infallible|"
        r"valid pattern|idempotent init|same value|not a fallback|not a swallow|"
        r"constructs? .*reporting|map-async callback|receiver-dropped|"
        r"recover the inner guard|data still valid|never blocks)\b"
    ),
    "reporting_only": re.compile(
        r"(?i)\b(?:reporting-only|display-only|display |display default|"
        r"display placeholder|formatter|formatting|label|csv cell|sarif|junit|"
        r"finding still (?:emitted|printed)|optional field|optional confidence|"
        r"dedup-key|sort default|ordering only|telemetry event|diagnostic accessor|"
        r"health/diagnostic|error-message string|output|result metadata)\b"
    ),
    "recall_preserving": re.compile(
        r"(?i)\b(?:recall-safe|recall safe|recall-irrelevant|recall preserved|"
        r"recall-preserving|recall-invariant|findings? (?:are )?unchanged|"
        r"no recall impact|perf-only|shard/size knob|nonzerousize::min floor|"
        r"scan findings are unchanged|full detector regex|whole-chunk|whole-file|"
        r"analyze the whole url|authority is whole remainder|"
        r"recovered prefix|same patterns|un-truncated|caller (?:scans|runs|reuses)|"
        r"returned to the caller|rerout|recompile|reparses source|not scanning|"
        r"not scanned.*count|scan path involved|not dropped|never dropped|"
        r"preserves deterministic|preserved|primary path|scan reparses)\b"
    ),
    "fail_closed_or_security_safe": re.compile(
        r"(?i)\b(?:fail-closed|fail closed|fail-open for suppression|"
        r"fail-open|fail-open to domain|never an allow|never misses|conservative|"
        r"treated as (?:private/blocked|present error)|disallowed host|blocked|"
        r"not a valid value|malformed input|unparseable url|function's honest|"
        r"propagated via \?|security-safe|arg injection|post-resolution veto|"
        r"no recall/security effect|fail-toward-visible|not a parseable hex|"
        r"dns-resolved|re-screened|aborts to `?none`|field-parse aborts)\b"
    ),
    "loud_counted_or_surfaced": re.compile(
        r"(?i)\b(?:loud|surface|surfaced|visible|operator must see|warn|warning|"
        r"eprintln|reported|recorded|records|count|counted|counter|fetch_add|tracked|"
        r"bump|bumped|report\.failures|failures entry|metadata|status|emit|"
        r"emitted|reads as full .* coverage|coverage reflects)\b"
    ),
    "intentional_default": re.compile(
        r"(?i)\b(?:documented (?:numeric |compile-shard |)?default|"
        r"documented .* sentinel|intended default|intended path default|"
        r"canonical default|canonical .* default|correct https default|deterministic default|"
        r"caller defaults|default prefix|optional|unset|absent|"
        r"empty/absent|missing/non-string|path-less|none is valid|"
        r"anonymous s3|infer from url|base64 zero-pad|hashes as none|"
        r"distinct cache-key state|empty names|source_\{i\})\b"
    ),
}

RISKY = re.compile(
    r"(?i)\b(?:drop|dropped|skip|skips|skipping|not scanned|fallback|degrad|"
    r"unreadable|failed|failure|error|could not|unable|over-cap|poison|"
    r"corrupt|truncat|ignored|ignore|disabled)\b"
)

RISKY_SAFE_CATEGORIES = {
    "no_runtime_effect",
    "reporting_only",
    "recall_preserving",
    "fail_closed_or_security_safe",
    "loud_counted_or_surfaced",
    "intentional_default",
}

RAW_SOURCE_SKIP_COUNTER = re.compile(
    r"(?:SKIPPED_(?:OVER_MAX_SIZE|BINARY|EXCLUDED|UNREADABLE|ARCHIVE_TRUNCATED)|"
    r"BINARY_SECTION_NAME_UNRESOLVED|SOURCE_TRUNCATED)\s*(?:\n\s*)?\.(?:fetch_add|store)"
)

RAW_SCANNER_COVERAGE_COUNTER = re.compile(
    r"(?:STRUCTURED_PARSE_FAILURES|DECODE_TRUNCATIONS)\s*(?:\n\s*)?\.(?:fetch_add|store)"
)

RAW_CLI_SCAN_FAILURE_COUNTER = re.compile(
    r"(?:(?:SOURCE_ERRORS|FAILED_SOURCES)\s*(?:\n\s*)?\.fetch_add|"
    r"SCANNER_PANICKED\s*(?:\n\s*)?\.(?:store|swap))"
)


@dataclass(frozen=True)
class Law10Block:
    path: pathlib.Path
    line: int
    text: str

    @property
    def rel(self) -> str:
        return self.path.relative_to(REPO).as_posix()


def iter_src_files() -> list[pathlib.Path]:
    files: list[pathlib.Path] = []
    for crate in CRATES:
        root = REPO / "crates" / crate / "src"
        files.extend(sorted(root.rglob("*.rs")))
    return files


def strip_comment_text(line: str) -> str | None:
    stripped = line.strip()
    for prefix in ("//!", "///", "//"):
        if stripped.startswith(prefix):
            return stripped[len(prefix) :].strip()
    return None


def collect_blocks() -> list[Law10Block]:
    blocks: list[Law10Block] = []
    for path in iter_src_files():
        lines = path.read_text(errors="replace").splitlines()
        idx = 0
        while idx < len(lines):
            line = lines[idx]
            if "LAW10:" not in line:
                idx += 1
                continue
            before, _, after = line.partition("LAW10:")
            text_parts = [after.strip()]
            cursor = idx + 1
            while cursor < len(lines):
                continuation = strip_comment_text(lines[cursor])
                if continuation is None:
                    break
                text_parts.append(continuation)
                cursor += 1
            blocks.append(
                Law10Block(path=path, line=idx + 1, text=" ".join(text_parts).strip())
            )
            idx += 1
    return blocks


def classify(text: str) -> set[str]:
    return {name for name, pattern in CATEGORIES.items() if pattern.search(text)}


def check(blocks: list[Law10Block]) -> tuple[Counter[str], list[Law10Block], list[Law10Block]]:
    counts: Counter[str] = Counter()
    unclassified: list[Law10Block] = []
    risky_unproven: list[Law10Block] = []
    for block in blocks:
        cats = classify(block.text)
        if not cats:
            unclassified.append(block)
        for cat in cats:
            counts[cat] += 1
        if RISKY.search(block.text) and not (cats & RISKY_SAFE_CATEGORIES):
            risky_unproven.append(block)
    return counts, unclassified, risky_unproven


def raw_source_skip_counter_mutations() -> list[tuple[str, int, str]]:
    offenders: list[tuple[str, int, str]] = []
    allowed_owner_paths = {
        "crates/sources/src/skip.rs",
    }
    root = REPO / "crates" / "sources" / "src"
    for path in sorted(root.rglob("*.rs")):
        rel = path.relative_to(REPO).as_posix()
        if rel in allowed_owner_paths:
            continue
        text = path.read_text(errors="replace")
        for match in RAW_SOURCE_SKIP_COUNTER.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            snippet = " ".join(text[match.start() : match.end()].split())
            offenders.append((rel, line, snippet))
    return offenders


def raw_scanner_coverage_counter_mutations() -> list[tuple[str, int, str]]:
    offenders: list[tuple[str, int, str]] = []
    root = REPO / "crates" / "scanner" / "src"
    for path in sorted(root.rglob("*.rs")):
        rel = path.relative_to(REPO).as_posix()
        if rel == "crates/scanner/src/telemetry.rs":
            continue
        text = path.read_text(errors="replace")
        for match in RAW_SCANNER_COVERAGE_COUNTER.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            snippet = " ".join(text[match.start() : match.end()].split())
            offenders.append((rel, line, snippet))
    return offenders


def raw_cli_scan_failure_counter_mutations() -> list[tuple[str, int, str]]:
    offenders: list[tuple[str, int, str]] = []
    root = REPO / "crates" / "cli" / "src"
    for path in sorted(root.rglob("*.rs")):
        rel = path.relative_to(REPO).as_posix()
        if rel == "crates/cli/src/lib.rs":
            continue
        text = path.read_text(errors="replace")
        for match in RAW_CLI_SCAN_FAILURE_COUNTER.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            snippet = " ".join(text[match.start() : match.end()].split())
            offenders.append((rel, line, snippet))
    return offenders


def self_test() -> int:
    samples = [
        (
            "a zip-bomb abort truncates extraction, so remaining entries are NOT scanned. "
            "Surface loudly + count it.",
            {"loud_counted_or_surfaced"},
            False,
        ),
        (
            "unsupported pattern is returned to the caller and rerouted through keyword fallback",
            {"recall_preserving"},
            False,
        ),
        (
            "optional field -> empty, finding still emitted",
            {"reporting_only"},
            False,
        ),
        (
            "unused-binding marker; no runtime effect, not a fallback",
            {"no_runtime_effect"},
            False,
        ),
        (
            "malformed input => None (fail-closed at the boundary; not a valid value)",
            {"fail_closed_or_security_safe"},
            False,
        ),
        ("skipping object because parse failed", set(), True),
    ]
    ok = True
    for text, expected_any, expect_risky_failure in samples:
        cats = classify(text)
        risky_failure = bool(RISKY.search(text) and not (cats & RISKY_SAFE_CATEGORIES))
        if expected_any and not (cats & expected_any):
            ok = False
            print(f"FAIL missing category {expected_any}: {text} => {cats}", file=sys.stderr)
        if risky_failure != expect_risky_failure:
            ok = False
            print(
                f"FAIL risky={risky_failure} want={expect_risky_failure}: {text} => {cats}",
                file=sys.stderr,
            )
    raw_good = "let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);"
    raw_bad = "crate::SKIPPED_UNREADABLE.fetch_add(1, Ordering::Relaxed);"
    raw_store_bad = "crate::SKIPPED_UNREADABLE.store(0, Ordering::Relaxed);"
    raw_scanner_good = (
        "let _event = crate::telemetry::record_scanner_coverage_gap("
        "crate::telemetry::ScannerCoverageGapEvent::DecodeTruncation);"
    )
    raw_scanner_bad = "crate::telemetry::DECODE_TRUNCATIONS.fetch_add(1, Ordering::Relaxed);"
    raw_cli_good = "let _event = crate::record_failed_source();"
    raw_cli_bad = "crate::FAILED_SOURCES.fetch_add(1, Ordering::Relaxed);"
    raw_cli_panic_bad = "crate::SCANNER_PANICKED.store(true, Ordering::Relaxed);"
    if RAW_SOURCE_SKIP_COUNTER.search(raw_good):
        ok = False
        print(f"FAIL raw-skip false positive: {raw_good}", file=sys.stderr)
    if not RAW_SOURCE_SKIP_COUNTER.search(raw_bad):
        ok = False
        print(f"FAIL raw-skip missed: {raw_bad}", file=sys.stderr)
    if not RAW_SOURCE_SKIP_COUNTER.search(raw_store_bad):
        ok = False
        print(f"FAIL raw-skip store missed: {raw_store_bad}", file=sys.stderr)
    if RAW_SCANNER_COVERAGE_COUNTER.search(raw_scanner_good):
        ok = False
        print(f"FAIL raw-scanner false positive: {raw_scanner_good}", file=sys.stderr)
    if not RAW_SCANNER_COVERAGE_COUNTER.search(raw_scanner_bad):
        ok = False
        print(f"FAIL raw-scanner missed: {raw_scanner_bad}", file=sys.stderr)
    if RAW_CLI_SCAN_FAILURE_COUNTER.search(raw_cli_good):
        ok = False
        print(f"FAIL raw-cli false positive: {raw_cli_good}", file=sys.stderr)
    if not RAW_CLI_SCAN_FAILURE_COUNTER.search(raw_cli_bad):
        ok = False
        print(f"FAIL raw-cli missed: {raw_cli_bad}", file=sys.stderr)
    if not RAW_CLI_SCAN_FAILURE_COUNTER.search(raw_cli_panic_bad):
        ok = False
        print(f"FAIL raw-cli panic missed: {raw_cli_panic_bad}", file=sys.stderr)
    print("self-test PASS" if ok else "self-test FAIL", file=sys.stderr)
    return 0 if ok else 1


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()

    blocks = collect_blocks()
    counts, unclassified, risky_unproven = check(blocks)
    raw_skip_mutations = raw_source_skip_counter_mutations()
    raw_scanner_mutations = raw_scanner_coverage_counter_mutations()
    raw_cli_mutations = raw_cli_scan_failure_counter_mutations()
    if (
        unclassified
        or risky_unproven
        or raw_skip_mutations
        or raw_scanner_mutations
        or raw_cli_mutations
    ):
        if unclassified:
            print(
                f"FAIL - {len(unclassified)} LAW10 annotation(s) have no recognized conservation claim:",
                file=sys.stderr,
            )
            for block in unclassified:
                print(f"  {block.rel}:{block.line}\n      {block.text}", file=sys.stderr)
        if risky_unproven:
            print(
                f"FAIL - {len(risky_unproven)} risky LAW10 annotation(s) lack loud/closed/recall-preserving proof:",
                file=sys.stderr,
            )
            for block in risky_unproven:
                print(f"  {block.rel}:{block.line}\n      {block.text}", file=sys.stderr)
        if raw_skip_mutations:
            print(
                f"FAIL - {len(raw_skip_mutations)} raw source skip-counter mutation(s); use record_skip_event(...):",
                file=sys.stderr,
            )
            for rel, line, snippet in raw_skip_mutations:
                print(f"  {rel}:{line}\n      {snippet}", file=sys.stderr)
        if raw_scanner_mutations:
            print(
                f"FAIL - {len(raw_scanner_mutations)} raw scanner coverage-counter mutation(s); use record_scanner_coverage_gap(...):",
                file=sys.stderr,
            )
            for rel, line, snippet in raw_scanner_mutations:
                print(f"  {rel}:{line}\n      {snippet}", file=sys.stderr)
        if raw_cli_mutations:
            print(
                f"FAIL - {len(raw_cli_mutations)} raw CLI scan-failure counter mutation(s); use record_scan_failure(...):",
                file=sys.stderr,
            )
            for rel, line, snippet in raw_cli_mutations:
                print(f"  {rel}:{line}\n      {snippet}", file=sys.stderr)
        return 1

    summary = ", ".join(f"{name}={counts[name]}" for name in sorted(CATEGORIES))
    print(
        f"OK - {len(blocks)} LAW10 annotations classified; source skip counters typed; scanner coverage counters typed; CLI scan-failure counters typed: {summary}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
