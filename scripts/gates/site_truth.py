#!/usr/bin/env python3
"""Reject stale website product claims and detector catalog drift."""

from __future__ import annotations

import pathlib
import re
import sys
import tomllib

REPO = pathlib.Path(__file__).resolve().parents[2]
sys.dont_write_bytecode = True
sys.path.insert(0, str(REPO / "scripts"))

from site_detector_catalog import detector_catalog_drift  # noqa: E402

STALE_PATTERNS = [
    ("unsupported recall claim", re.compile(r"\b96\s*%")),
    ("unsupported recall delta", re.compile(r"\b33\s*%\s+more\b")),
    ("unsupported superlative title", re.compile(r"fastest, most accurate")),
    ("startup hardware guess wording", re.compile(r"Auto-detects your hardware")),
    ("startup fastest-backend wording", re.compile(r"picks the fastest backend")),
    ("router fastest-backend wording", re.compile(r"routes scans to the fastest backend")),
    ("retired benchmark harness path", re.compile(r"benchmark-harness/")),
    ("retired routing matrix output", re.compile(r"routing matrix:")),
]

DETECTOR_COUNT_PATTERN = re.compile(
    r"\b(?P<count>\d{2,5})\s+(?:"
    r"(?:embedded|service)\s+detectors?\b|detector\s+TOMLs?\b|"
    r"TOML\s+files?\b|service-specific\s+patterns?\b)",
    re.IGNORECASE,
)
VERIFIER_COUNT_PATTERN = re.compile(
    r"\b(?P<count>\d{2,5})\s+detectors?\s+with\s+a\s+vendor\s+verifier\s+endpoint\b",
    re.IGNORECASE,
)

TEXT_FILES = {".css", ".html", ".js", ".json", ".md", ".py", ".svg", ".toml", ".txt"}


def current_version() -> str:
    cargo = tomllib.loads((REPO / "Cargo.toml").read_text())
    return f"v{cargo['workspace']['package']['version']}"


def current_detector_count() -> int:
    return sum(1 for path in (REPO / "detectors").glob("*.toml") if path.is_file())


def current_verifier_count() -> int:
    count = 0
    for path in (REPO / "detectors").glob("*.toml"):
        if not path.is_file():
            continue
        detector = tomllib.loads(path.read_text()).get("detector", {})
        if detector.get("verify") is not None:
            count += 1
    return count


def product_claim_paths() -> list[pathlib.Path]:
    paths: list[pathlib.Path] = []
    for path in (REPO / "site").rglob("*"):
        if path.is_file() and path.suffix in TEXT_FILES:
            paths.append(path)
    paths.extend(
        [
            REPO / "docs/book.toml",
            REPO / "docs/assets/keyhog-banner.svg",
        ]
    )
    return sorted(paths)


def stale_claim_hits() -> list[tuple[str, int, str, str]]:
    hits: list[tuple[str, int, str, str]] = []
    expected_version = current_version()
    expected_detectors = current_detector_count()
    expected_verifiers = current_verifier_count()
    build_py = (REPO / "site/build.py").read_text()
    if re.search(r'(?m)^VERSION\s*=\s*"v\d+\.\d+\.\d+"', build_py):
        hits.append(("site/build.py", 0, "site generator version", "VERSION must derive from Cargo.toml"))
    for path in product_claim_paths():
        rel = path.relative_to(REPO).as_posix()
        text = path.read_text(errors="replace")
        for lineno, line in enumerate(text.splitlines(), start=1):
            for version in re.findall(r"\bv0\.\d+\.\d+\b", line):
                if version != expected_version:
                    hits.append((rel, lineno, "old release tag", line.strip()))
            for match in DETECTOR_COUNT_PATTERN.finditer(line):
                found = int(match.group("count"))
                if found != expected_detectors:
                    hits.append(
                        (
                            rel,
                            lineno,
                            "stale detector count",
                            f"found {found}, expected {expected_detectors}: {line.strip()}",
                        )
                    )
            for match in VERIFIER_COUNT_PATTERN.finditer(line):
                found = int(match.group("count"))
                if found != expected_verifiers:
                    hits.append(
                        (
                            rel,
                            lineno,
                            "stale verifier count",
                            f"found {found}, expected {expected_verifiers}: {line.strip()}",
                        )
                    )
            for label, pattern in STALE_PATTERNS:
                if pattern.search(line):
                    hits.append((rel, lineno, label, line.strip()))
    return hits


def self_test() -> int:
    expected = current_version()
    expected_detectors = current_detector_count()
    expected_verifiers = current_verifier_count()
    stale_version = "v0.0.0" if expected != "v0.0.0" else "v9.9.9"
    stale_detectors = expected_detectors - 1
    bad = (
        f"keyhog {stale_version} | {stale_detectors} service detectors | "
        f"{expected_verifiers - 1} detectors with a vendor verifier endpoint | "
        "96 % recall | picks the fastest backend"
    )
    good = (
        f"keyhog {expected} | {expected_detectors} service detectors | "
        f"{expected_verifiers} detectors with a vendor verifier endpoint | "
        "persisted autoroute calibration"
    )
    bad_hits = [label for label, pattern in STALE_PATTERNS if pattern.search(bad)]
    good_hits = [label for label, pattern in STALE_PATTERNS if pattern.search(good)]
    bad_hits.extend(
        "stale detector count"
        for match in DETECTOR_COUNT_PATTERN.finditer(bad)
        if int(match.group("count")) != expected_detectors
    )
    good_hits.extend(
        "stale detector count"
        for match in DETECTOR_COUNT_PATTERN.finditer(good)
        if int(match.group("count")) != expected_detectors
    )
    bad_hits.extend(
        "stale verifier count"
        for match in VERIFIER_COUNT_PATTERN.finditer(bad)
        if int(match.group("count")) != expected_verifiers
    )
    good_hits.extend(
        "stale verifier count"
        for match in VERIFIER_COUNT_PATTERN.finditer(good)
        if int(match.group("count")) != expected_verifiers
    )
    bad_hits.extend(
        "old release tag"
        for version in re.findall(r"\bv0\.\d+\.\d+\b", bad)
        if version != expected
    )
    good_hits.extend(
        "old release tag"
        for version in re.findall(r"\bv0\.\d+\.\d+\b", good)
        if version != expected
    )
    ok = bool(bad_hits) and not good_hits
    print("self-test PASS" if ok else "self-test FAIL", file=sys.stderr)
    if not ok:
        print(f"bad_hits={bad_hits} good_hits={good_hits}", file=sys.stderr)
    return 0 if ok else 1


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return self_test()

    hits = stale_claim_hits()
    drift = detector_catalog_drift()
    if hits or drift:
        if hits:
            print(f"FAIL - {len(hits)} stale website product claim(s):", file=sys.stderr)
            for rel, lineno, label, line in hits:
                loc = f"{rel}:{lineno}" if lineno else rel
                print(f"  {loc}: {label}: {line}", file=sys.stderr)
        if drift:
            print("FAIL - detector catalog JSON drift:", file=sys.stderr)
            for issue in drift:
                print(f"  {issue}", file=sys.stderr)
        print(
            "\nUpdate site/page sources, run `cd site && python3 build.py`, and run `scripts/site_detector_catalog.py --write`.",
            file=sys.stderr,
        )
        return 1
    print("OK - website product claims and detector catalog match source truth.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
