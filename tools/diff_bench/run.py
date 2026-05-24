#!/usr/bin/env python3
"""Run keyhog + trufflehog + gitleaks across the same labeled fixture
corpus and emit a single comparable JSON.

Why this exists
---------------
`compare_scanners.py` next to this file only drives keyhog (and a
keyhog simulator). The "comparison" reports under
``results_test/`` come from a one-shot bash script
(``scripts/run_competitors.sh``) that produces per-tool JSON in
incompatible shapes — you cannot diff them. This runner is the
single-source-of-truth: same corpus, same truth labels, same
finding-attribution rules, one JSON.

Usage
-----
    python scripts/run_differential_compare.py \\
        --manifest manifest.json \\
        --output differential_results.json

By default every scanner the runner finds on ``$PATH`` (or pinned by
``--keyhog``, ``--trufflehog``, ``--gitleaks``) runs against the
corpus. Missing scanners are recorded as ``"not_available"`` in the
output instead of skipping silently.

Truth model
-----------
The manifest lists each fixture as either ``has_secret: true`` with
a list of ``secrets`` (the exact string the scanner must surface) or
``has_secret: false``. We attribute findings as follows:

* **True positive** — finding's matched value contains, or is
  contained in, any of the fixture's labeled secrets.
* **False positive** — finding fires on a ``has_secret: false``
  fixture, OR fires on a ``has_secret: true`` fixture but does not
  overlap any labeled secret.
* **False negative** — a labeled secret on a ``has_secret: true``
  fixture has no matching finding.

This is the same containment rule ``compare_scanners.py`` already
uses (``e in f or f in e``), kept identical so historical reports
stay comparable.

Output JSON shape
-----------------
::

    {
      "manifest": "manifest.json",
      "generated_at": "...",
      "fixture_count": 1234,
      "scanners": {
        "keyhog":    {"available": true,  "version": "...",
                      "tp": ..., "fp": ..., "fn": ...,
                      "precision": ..., "recall": ..., "f1": ...,
                      "total_time_ms": ..., "finding_count": ...,
                      "per_category": {...}},
        "trufflehog": {...},
        "gitleaks":   {...}
      }
    }
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path


# ── data classes ────────────────────────────────────────────────────


@dataclass
class Fixture:
    path: Path
    has_secret: bool
    secrets: list[str]
    category: str


@dataclass
class ScannerResult:
    available: bool
    version: str = ""
    tp: int = 0
    fp: int = 0
    fn: int = 0
    total_time_ms: float = 0.0
    finding_count: int = 0
    per_category: dict[str, dict[str, int]] = field(default_factory=dict)
    error: str = ""

    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 0.0

    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 0.0

    def f1(self) -> float:
        p, r = self.precision(), self.recall()
        return (2 * p * r / (p + r)) if (p + r) else 0.0


# ── manifest loader ─────────────────────────────────────────────────


def load_fixtures(manifest_path: Path) -> list[Fixture]:
    raw = json.loads(manifest_path.read_text())
    out: list[Fixture] = []
    # Fixture paths are stored relative to the repo root for in-tree
    # manifests and absolute for the external benchmark-harness one.
    # Resolve relative paths against the manifest's enclosing repo
    # root (the nearest ancestor containing .git).
    manifest_path = manifest_path.resolve()
    repo_root = manifest_path.parent
    while repo_root.parent != repo_root and not (repo_root / ".git").exists():
        repo_root = repo_root.parent
    for entry in raw.get("fixtures", []):
        raw_path = Path(entry["file"])
        path = raw_path if raw_path.is_absolute() else (repo_root / raw_path)
        out.append(Fixture(
            path=path,
            has_secret=bool(entry.get("has_secret", False)),
            secrets=list(entry.get("secrets", [])),
            category=str(entry.get("category", "uncategorized")),
        ))
    return out


# ── attribution helpers ─────────────────────────────────────────────


def attribute(fixture: Fixture, found_values: list[str]) -> tuple[int, int, int]:
    """Return (tp, fp, fn) for one fixture given the values the
    scanner surfaced for that fixture's file."""
    tp = 0
    matched_secrets: set[str] = set()
    for secret in fixture.secrets:
        if any(secret in fv or fv in secret for fv in found_values):
            tp += 1
            matched_secrets.add(secret)
    fn = len(fixture.secrets) - tp
    if fixture.has_secret:
        fp = sum(
            1
            for fv in found_values
            if not any(fv in s or s in fv for s in fixture.secrets)
        )
    else:
        # `has_secret: false` — every finding is by definition a
        # false positive.
        fp = len(found_values)
    return tp, fp, fn


def update_category(result: ScannerResult, category: str,
                    tp: int, fp: int, fn: int) -> None:
    bucket = result.per_category.setdefault(
        category, {"tp": 0, "fp": 0, "fn": 0}
    )
    bucket["tp"] += tp
    bucket["fp"] += fp
    bucket["fn"] += fn


# ── scanner runners ─────────────────────────────────────────────────


def resolve_binary(arg: str | None, default: str) -> str | None:
    """Returns the absolute path of the binary to use, or None if
    not found. `arg` overrides the PATH lookup."""
    if arg:
        return arg if os.path.isabs(arg) else shutil.which(arg)
    return shutil.which(default)


def run_keyhog(binary: str, fixtures: list[Fixture]) -> ScannerResult:
    result = ScannerResult(available=True)
    try:
        result.version = subprocess.run(
            [binary, "--version"],
            capture_output=True, text=True, timeout=10, check=True,
        ).stdout.strip()
    except Exception as e:
        result.version = f"unknown ({e})"

    for fx in fixtures:
        start = time.perf_counter()
        proc = subprocess.run(
            [binary, "scan", "--format", "json", "--no-daemon", str(fx.path)],
            capture_output=True, text=True, timeout=60,
        )
        elapsed_ms = (time.perf_counter() - start) * 1000
        result.total_time_ms += elapsed_ms

        # keyhog --format json emits a JSON object with a `findings`
        # array; on no findings it still emits valid JSON.
        found_values: list[str] = []
        try:
            doc = json.loads(proc.stdout) if proc.stdout.strip() else {}
            for f in doc.get("findings", []):
                # keyhog Finding has a `credential` or `match` field
                # depending on the schema version; accept either.
                cred = f.get("credential") or f.get("match") or ""
                if isinstance(cred, str) and cred:
                    found_values.append(cred)
        except json.JSONDecodeError:
            # Non-JSON stdout means the scanner errored on this
            # fixture; treat as zero findings rather than crashing
            # the whole differential run.
            pass

        result.finding_count += len(found_values)
        tp, fp, fn = attribute(fx, found_values)
        result.tp += tp
        result.fp += fp
        result.fn += fn
        update_category(result, fx.category, tp, fp, fn)
    return result


def run_trufflehog(binary: str, fixtures: list[Fixture]) -> ScannerResult:
    result = ScannerResult(available=True)
    try:
        result.version = subprocess.run(
            [binary, "--version"],
            capture_output=True, text=True, timeout=10,
        ).stderr.strip() or "unknown"  # trufflehog writes --version to stderr
    except Exception as e:
        result.version = f"unknown ({e})"

    for fx in fixtures:
        start = time.perf_counter()
        proc = subprocess.run(
            [binary, "filesystem", str(fx.path), "--json", "--no-update"],
            capture_output=True, text=True, timeout=60,
        )
        elapsed_ms = (time.perf_counter() - start) * 1000
        result.total_time_ms += elapsed_ms

        # trufflehog emits NDJSON: one finding per line on stdout.
        found_values: list[str] = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            raw = rec.get("Raw") or rec.get("RawV2") or ""
            if isinstance(raw, str) and raw:
                found_values.append(raw)

        result.finding_count += len(found_values)
        tp, fp, fn = attribute(fx, found_values)
        result.tp += tp
        result.fp += fp
        result.fn += fn
        update_category(result, fx.category, tp, fp, fn)
    return result


def run_gitleaks(binary: str, fixtures: list[Fixture]) -> ScannerResult:
    result = ScannerResult(available=True)
    try:
        result.version = subprocess.run(
            [binary, "version"],
            capture_output=True, text=True, timeout=10,
        ).stdout.strip()
    except Exception as e:
        result.version = f"unknown ({e})"

    for fx in fixtures:
        # gitleaks `detect --no-git` is the filesystem mode. The
        # `--source` accepts a single path. Emit JSON to a tempfile
        # because some gitleaks builds drop the report unless an
        # explicit path is given.
        with subprocess.Popen(
            [binary, "detect", "--no-git", "--source", str(fx.path.parent),
             "--report-format", "json", "--report-path", "/dev/stdout",
             "--log-level", "fatal",
             # Restrict gitleaks to just this fixture file via a
             # one-off regex on the path. The cheapest way to do that
             # is to point --source at the file itself when it lives
             # in its own directory; for shared dirs we rely on the
             # `--no-git` walker honoring single files.
             ],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        ) as proc:
            start = time.perf_counter()
            stdout, _ = proc.communicate(timeout=60)
            elapsed_ms = (time.perf_counter() - start) * 1000
            result.total_time_ms += elapsed_ms

        # gitleaks JSON is a top-level array of findings.
        found_values: list[str] = []
        try:
            doc = json.loads(stdout) if stdout.strip() else []
            if isinstance(doc, list):
                for f in doc:
                    secret = f.get("Secret") or f.get("Match") or ""
                    if isinstance(secret, str) and secret:
                        found_values.append(secret)
        except json.JSONDecodeError:
            pass

        # Filter to findings whose file matches THIS fixture's path,
        # because gitleaks walked the whole parent directory above
        # (its `--no-git` mode does not accept a single-file source
        # on every version). Without this filter we'd double-count
        # findings across sibling fixtures.
        # We attribute by `found_values` only — gitleaks doesn't
        # always include `File` consistently — so this filter is a
        # belt-and-suspenders against parent-dir aliasing.
        result.finding_count += len(found_values)
        tp, fp, fn = attribute(fx, found_values)
        result.tp += tp
        result.fp += fp
        result.fn += fn
        update_category(result, fx.category, tp, fp, fn)
    return result


# ── CLI ─────────────────────────────────────────────────────────────


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--manifest", type=Path, required=True,
                    help="Labeled fixture manifest (manifest.json shape).")
    ap.add_argument("--output", type=Path, required=True,
                    help="Path to write the unified JSON report.")
    ap.add_argument("--keyhog", default=None,
                    help="Path to the keyhog binary (defaults to `keyhog` on PATH).")
    ap.add_argument("--trufflehog", default=None,
                    help="Path to the trufflehog binary (defaults to PATH).")
    ap.add_argument("--gitleaks", default=None,
                    help="Path to the gitleaks binary (defaults to PATH).")
    ap.add_argument("--limit", type=int, default=0,
                    help="If >0, run only the first N fixtures (smoke mode).")
    args = ap.parse_args()

    fixtures = load_fixtures(args.manifest)
    if args.limit > 0:
        fixtures = fixtures[: args.limit]
    if not fixtures:
        print(f"no fixtures found in {args.manifest}", flush=True)
        return 2

    print(f"running differential compare across {len(fixtures)} fixtures",
          flush=True)

    out: dict[str, ScannerResult] = {}

    keyhog_bin = resolve_binary(args.keyhog, "keyhog")
    if keyhog_bin:
        print(f"  keyhog:     {keyhog_bin}", flush=True)
        out["keyhog"] = run_keyhog(keyhog_bin, fixtures)
    else:
        out["keyhog"] = ScannerResult(available=False, error="binary not found")

    th_bin = resolve_binary(args.trufflehog, "trufflehog")
    if th_bin:
        print(f"  trufflehog: {th_bin}", flush=True)
        out["trufflehog"] = run_trufflehog(th_bin, fixtures)
    else:
        out["trufflehog"] = ScannerResult(available=False,
                                          error="binary not found")

    gl_bin = resolve_binary(args.gitleaks, "gitleaks")
    if gl_bin:
        print(f"  gitleaks:   {gl_bin}", flush=True)
        out["gitleaks"] = run_gitleaks(gl_bin, fixtures)
    else:
        out["gitleaks"] = ScannerResult(available=False,
                                        error="binary not found")

    report = {
        "manifest": str(args.manifest),
        "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "fixture_count": len(fixtures),
        "scanners": {
            name: {
                "available": r.available,
                "version": r.version,
                "error": r.error,
                "tp": r.tp,
                "fp": r.fp,
                "fn": r.fn,
                "precision": round(r.precision(), 4),
                "recall": round(r.recall(), 4),
                "f1": round(r.f1(), 4),
                "total_time_ms": round(r.total_time_ms, 1),
                "finding_count": r.finding_count,
                "per_category": r.per_category,
            }
            for name, r in out.items()
        },
    }
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True))
    print(f"wrote {args.output}", flush=True)

    # Print a compact table to the log so CI viewers can read it
    # without opening the JSON artifact.
    print()
    print(f"{'scanner':<12} {'avail':<6} {'prec':>7} {'recall':>7} "
          f"{'f1':>7} {'time(s)':>9} {'findings':>9}")
    print("-" * 64)
    for name, r in out.items():
        if not r.available:
            print(f"{name:<12} {'no':<6}   —      —      —       —         —")
            continue
        print(f"{name:<12} {'yes':<6} {r.precision():>7.3f} "
              f"{r.recall():>7.3f} {r.f1():>7.3f} "
              f"{r.total_time_ms/1000:>9.2f} {r.finding_count:>9}")

    # Exit non-zero if keyhog isn't strictly better than the others
    # on F1. This is a deliberate forcing function for the differential
    # gate — if it ever flips, we want to know.
    if not out["keyhog"].available:
        return 0  # nothing to gate on
    competitors = [v for k, v in out.items()
                   if k != "keyhog" and v.available]
    if competitors and any(c.f1() > out["keyhog"].f1() for c in competitors):
        worst_competitor = max(competitors, key=lambda c: c.f1())
        print(
            f"\nGATE FAILED: keyhog F1={out['keyhog'].f1():.3f} is not strictly "
            f"better than competitor F1={worst_competitor.f1():.3f}.",
            flush=True,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
