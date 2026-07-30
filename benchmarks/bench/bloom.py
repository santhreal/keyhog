"""CredData Bloom effectiveness fixture and exact differential runner."""

from __future__ import annotations

import argparse
import csv
import json
import os
import pathlib
import subprocess
import sys
from typing import Any

from .corpora.creddata import CREDDATA_PIN, CredDataCorpus
from .executable_snapshot import sibling_executable_snapshot
from .keyhog_version import workspace_detector_corpus_sha256

FIXTURE_SCHEMA = "keyhog-bloom-corpus-v1"
RESULT_SCHEMA = "bloom-evidence-v1"
UNAVAILABLE_SOURCE_FILE_MISSING = "source-file-missing"
DEFAULT_FIXTURE = pathlib.Path("corpora/creddata/bloom-fx-record-spans-v1.json")
DEFAULT_RESULT = pathlib.Path("results/bloom-creddata-fx-record-spans-v1.json")
DEFAULT_REPORT = pathlib.Path("reports/bloom-creddata-fx-record-spans-v1.md")


def _git_revision(root: pathlib.Path) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def build_fixture(
    root: str | pathlib.Path | None = None,
    output: str | pathlib.Path = DEFAULT_FIXTURE,
) -> dict[str, Any]:
    """Build canonical source spans for every CredData F/X record."""
    corpus = CredDataCorpus(root=root)
    clone_root = corpus.file_root.resolve()
    if not corpus.is_downloaded(require_complete=False):
        raise SystemExit(
            f"CredData is unavailable at {clone_root}; run `make creddata` (no mirror fallback)"
        )
    revision = _git_revision(clone_root)
    if revision != CREDDATA_PIN:
        raise SystemExit(
            f"CredData revision mismatch at {clone_root}: got {revision}, expected {CREDDATA_PIN}"
        )

    records: list[dict[str, Any]] = []
    for csv_path in sorted(corpus.meta_dir().glob("*.csv")):
        with csv_path.open(newline="") as handle:
            for row_number, row in enumerate(csv.DictReader(handle), start=1):
                relative = (row.get("FilePath") or "").strip()
                label = (row.get("GroundTruth") or "").strip().upper()
                if label not in {"F", "X"}:
                    continue
                try:
                    line_start = int(row.get("LineStart") or 0)
                    line_end = int(row.get("LineEnd") or 0)
                except ValueError as error:
                    raise SystemExit(
                        f"CredData F/X record has invalid line metadata in {csv_path}:{row_number}"
                    ) from error
                if not relative or line_start < 1 or line_end < line_start:
                    raise SystemExit(
                        f"CredData F/X record is incomplete in {csv_path}:{row_number}"
                    )
                identity = (
                    f"creddata-record:{csv_path.name}:{row_number}:"
                    f"{relative}:{line_start}:{line_end}"
                )
                records.append(
                    {
                        "id": identity,
                        "path": relative,
                        "labels": [label],
                        "line_start": line_start,
                        "line_end": line_end,
                    }
                )
    records.sort(
        key=lambda record: (
            record["path"],
            record["line_start"],
            record["line_end"],
            record["id"],
        )
    )
    if not records:
        raise SystemExit("CredData metadata contains no F/X negative records")

    inputs: list[dict[str, Any]] = []
    unavailable: list[dict[str, str]] = []
    for record in records:
        if (clone_root / record["path"]).is_file():
            inputs.append(record)
        else:
            unavailable.append(
                {
                    "id": record["id"],
                    "path": record["path"],
                    "category": UNAVAILABLE_SOURCE_FILE_MISSING,
                    "reason": "source file absent from configured pinned CredData checkout",
                }
            )

    fixture = {
        "schema_version": FIXTURE_SCHEMA,
        "corpus_name": "samsung-creddata-fx-record-spans-v1",
        "corpus_revision": revision,
        "declared_input_count": len(records),
        "unavailable_inputs": unavailable,
        "inputs": inputs,
    }
    output_path = pathlib.Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(fixture, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        f"Bloom fixture: {len(inputs)} measured F/X record spans, "
        f"{len(unavailable)} explicitly unavailable, revision {revision}",
        file=sys.stderr,
    )
    return fixture

def render_report(result: dict[str, Any]) -> str:
    """Render the redacted, digest-bound Bloom effectiveness receipt."""
    basis_points = int(result["rejection_basis_points"])
    rejection = f"{basis_points // 100}.{basis_points % 100:02d}%"
    parity = "IDENTICAL" if result["findings_identical"] else "MISMATCH"
    unavailable_reasons = ", ".join(
        f"{category}={count}"
        for category, count in sorted(result["unavailable_reason_counts"].items())
    )
    return "\n".join(
        [
            "# Bigram Bloom corpus evidence",
            "",
            "| Field | Exact result |",
            "|---|---|",
            f"| Corpus | `{result['corpus_name']}` |",
            f"| Corpus revision | `{result['corpus_revision']}` |",
            f"| Corpus SHA-256 | `{result['corpus_sha256']}` |",
            f"| Fixture SHA-256 | `{result['fixture_sha256']}` |",
            f"| Executable SHA-256 | `{result['executable_sha256']}` |",
            (
                "| Workspace detector corpus SHA-256 | "
                f"`{result['workspace_detector_corpus_sha256']}` |"
            ),
            f"| Scanner detector digest | `{result['scanner_detector_digest']}` |",
            f"| Detector corpus SHA-256 | `{result['detector_corpus_sha256']}` |",
            (
                "| Bloom rejection | "
                f"**{result['rejected_input_count']}/{result['input_count']} "
                f"({rejection})**; {result['admitted_input_count']} admitted |"
            ),
            (
                "| External availability | "
                f"{result['input_count']} measured; "
                f"{result['unavailable_input_count']} explicitly unavailable "
                f"of {result['declared_input_count']} declared; "
                f"reasons: {unavailable_reasons} |"
            ),
            (
                "| Enabled vs bypassed findings | "
                f"**{parity}**; {result['enabled_finding_count']}/"
                f"{result['bypass_finding_count']} findings |"
            ),
            (
                "| Finding identity SHA-256 | "
                f"`{result['enabled_findings_sha256']}` / "
                f"`{result['bypass_findings_sha256']}` |"
            ),
            (
                "| Bloom density/state | "
                f"{result['populated_slots']}/{result['total_slots']} slots; "
                f"`{result['state']}`; saturation at "
                f"{result['saturation_threshold_slots']} |"
            ),
            "",
            "Finding digests cover the sorted detector ID, source path, line, byte "
            "span, and credential SHA-256 for every downstream finding. Credential "
            "values are never written.",
            "",
        ]
    )


def measure(
    keyhog: str | pathlib.Path,
    fixture: str | pathlib.Path = DEFAULT_FIXTURE,
    corpus_root: str | pathlib.Path | None = None,
    output: str | pathlib.Path = DEFAULT_RESULT,
    report: str | pathlib.Path | None = None,
) -> dict[str, Any]:
    """Run the scanner-owned enabled/bypass differential and persist its receipt."""
    corpus = CredDataCorpus(root=corpus_root)
    clone_root = corpus.file_root.resolve()
    fixture_path = pathlib.Path(fixture).resolve()
    workspace_digest_before = workspace_detector_corpus_sha256()
    with sibling_executable_snapshot(str(keyhog)) as snapshot:
        run_options: dict[str, object] = {}
        if snapshot.pass_fds:
            run_options["pass_fds"] = snapshot.pass_fds
        completed = subprocess.run(
            [
                str(snapshot.launch_path),
                "bloom-diagnostic",
                "--fixture",
                str(fixture_path),
                "--corpus-root",
                str(clone_root),
            ],
            check=False,
            capture_output=True,
            text=True,
            **run_options,
        )
        executable_sha256 = snapshot.sha256
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise SystemExit(
            f"Bloom diagnostic failed with exit {completed.returncode}: {detail}"
        )
    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise SystemExit(f"Bloom diagnostic emitted invalid JSON: {error}") from error
    workspace_digest_after = workspace_detector_corpus_sha256()
    if workspace_digest_after != workspace_digest_before:
        raise SystemExit(
            "workspace detector corpus changed during the Bloom differential"
        )
    result["executable_sha256"] = executable_sha256
    result["workspace_detector_corpus_sha256"] = workspace_digest_before
    if result.get("schema_version") != RESULT_SCHEMA:
        raise SystemExit(
            f"Bloom result schema mismatch: {result.get('schema_version')!r}"
        )
    reason_counts = result.get("unavailable_reason_counts")
    if (
        not isinstance(reason_counts, dict)
        or set(reason_counts) - {UNAVAILABLE_SOURCE_FILE_MISSING}
        or any(
            isinstance(count, bool) or not isinstance(count, int) or count < 0
            for count in reason_counts.values()
        )
        or sum(reason_counts.values()) != result.get("unavailable_input_count")
    ):
        raise SystemExit("Bloom result unavailable reason accounting is invalid")
    if result.get("rejected_input_count", 0) <= 0:
        raise SystemExit("Bloom result rejected zero inputs; refusing ineffective evidence")
    if not result.get("findings_identical"):
        raise SystemExit("Bloom result does not prove enabled/bypass finding parity")
    if result.get("enabled_finding_count") != result.get("bypass_finding_count"):
        raise SystemExit("Bloom differential finding counts differ")
    if result.get("enabled_findings_sha256") != result.get("bypass_findings_sha256"):
        raise SystemExit("Bloom differential finding identity/location digests differ")

    output_path = pathlib.Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if report is not None:
        report_path = pathlib.Path(report)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(render_report(result), encoding="utf-8")
    print(
        "Bloom result: "
        f"{result['rejected_input_count']}/{result['input_count']} rejected; "
        f"{result['enabled_finding_count']} findings identical with bypass; "
        f"corpus={result['corpus_sha256']}; "
        f"detectors={result['scanner_detector_digest']}",
        file=sys.stderr,
    )
    return result


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Measure production Bloom rejection on pinned CredData negatives."
    )
    parser.add_argument(
        "--root",
        default=os.environ.get("KEYHOG_BENCH_CREDDATA"),
        help="CredData clone root (defaults to benchmark adapter configuration)",
    )
    parser.add_argument("--fixture", default=str(DEFAULT_FIXTURE))
    parser.add_argument("--output", default=str(DEFAULT_RESULT))
    parser.add_argument("--report", default=str(DEFAULT_REPORT))
    parser.add_argument(
        "--keyhog",
        default=os.environ.get("KEYHOG_BIN"),
        help="KeyHog binary for the differential measurement",
    )
    parser.add_argument(
        "--fixture-only",
        action="store_true",
        help="Generate and validate the fixture without scanning",
    )
    args = parser.parse_args(argv)

    build_fixture(root=args.root, output=args.fixture)
    if args.fixture_only:
        return 0
    if not args.keyhog:
        raise SystemExit("--keyhog or KEYHOG_BIN is required; no alternate scanner fallback")
    measure(
        keyhog=args.keyhog,
        fixture=args.fixture,
        corpus_root=args.root,
        output=args.output,
        report=args.report,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
