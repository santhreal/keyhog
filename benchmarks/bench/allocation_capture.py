"""Provenance-bound whole-process allocation capture with Valgrind Massif."""

from __future__ import annotations

import hashlib
import json
import math
import pathlib
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Sequence

from .baseline_capture import BaselineCaptureError, SUCCESS_EXIT_CODES, sha256_file
from .scanners.base import run_measured


@dataclass(frozen=True)
class MassifSummary:
    """Peak mapped bytes and the exact snapshot that established the peak."""

    peak_mapped_bytes: int
    peak_snapshot: int
    snapshots: int


def parse_massif(text: str) -> MassifSummary:
    """Parse a pages-as-heap Massif stream without trusting report prose."""
    lines = text.splitlines()
    if not lines or "--pages-as-heap=yes" not in lines[0]:
        raise BaselineCaptureError("Massif evidence must use --pages-as-heap=yes")
    snapshot: int | None = None
    rows: list[tuple[int, int]] = []
    for line in lines:
        if line.startswith("snapshot="):
            try:
                snapshot = int(line.removeprefix("snapshot="))
            except ValueError as exc:
                raise BaselineCaptureError("Massif snapshot id is not an integer") from exc
        elif line.startswith("mem_heap_B="):
            if snapshot is None:
                raise BaselineCaptureError("Massif heap measurement precedes its snapshot")
            try:
                value = int(line.removeprefix("mem_heap_B="))
            except ValueError as exc:
                raise BaselineCaptureError("Massif heap measurement is not an integer") from exc
            if value < 0:
                raise BaselineCaptureError("Massif heap measurement is negative")
            rows.append((snapshot, value))
            snapshot = None
    if not rows:
        raise BaselineCaptureError("Massif evidence contains no heap snapshots")
    ids = [row[0] for row in rows]
    if ids != list(range(len(rows))):
        raise BaselineCaptureError(f"Massif snapshots are incomplete or reordered: {ids}")
    peak_snapshot, peak_bytes = max(rows, key=lambda row: row[1])
    return MassifSummary(peak_bytes, peak_snapshot, len(rows))


def capture_massif_baseline(
    *,
    binary: pathlib.Path,
    command: Sequence[str],
    workload_id: str,
    backend: str,
    fixture_input_sha256: str,
    fixture_answer_sha256: str,
    output: pathlib.Path,
) -> dict[str, object]:
    """Run one exact production command under Massif and publish its allocation receipt."""
    binary = binary.resolve(strict=True)
    if not command or pathlib.Path(command[0]).resolve(strict=True) != binary:
        raise BaselineCaptureError("Massif command executable differs from the bound binary")
    version = subprocess.run(
        ["valgrind", "--version"], capture_output=True, text=True, check=False, timeout=30,
    )
    if version.returncode != 0 or not version.stdout.strip():
        raise BaselineCaptureError(f"Valgrind version unavailable: {version.stderr.strip()}")
    with tempfile.TemporaryDirectory(prefix="keyhog-massif-") as raw:
        massif_path = pathlib.Path(raw) / "massif.out"
        argv = [
            "valgrind", "--tool=massif", "--pages-as-heap=yes", "--time-unit=ms",
            f"--massif-out-file={massif_path}", *command,
        ]
        _stdout, stderr, stats = run_measured(argv, timeout=600)
        if stats.timed_out or stats.exit_code not in SUCCESS_EXIT_CODES:
            raise BaselineCaptureError(
                f"Massif workload exited {stats.exit_code}, timed_out={stats.timed_out}: {stderr.strip()}"
            )
        try:
            raw_evidence = massif_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise BaselineCaptureError(f"Massif did not publish evidence: {exc}") from exc
        summary = parse_massif(raw_evidence)
        evidence_sha256 = hashlib.sha256(raw_evidence.encode()).hexdigest()
    artifact = {
        "schema_version": 1,
        "workload_id": workload_id,
        "backend": backend,
        "binary_sha256": sha256_file(binary),
        "fixture_input_sha256": fixture_input_sha256,
        "fixture_answer_sha256": fixture_answer_sha256,
        "profiler": "valgrind-massif",
        "profiler_version": version.stdout.strip(),
        "pages_as_heap": True,
        "command": list(command),
        "peak_mapped_bytes": summary.peak_mapped_bytes,
        "peak_snapshot": summary.peak_snapshot,
        "snapshots": summary.snapshots,
        "evidence_sha256": evidence_sha256,
        "measured_wall_ms": stats.wall_ms,
        "measured_peak_rss_kb": stats.peak_rss_kb,
        "minor_page_faults": stats.minor_page_faults,
        "major_page_faults": stats.major_page_faults,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.tmp")
    temporary.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(output)
    return artifact
DEFAULT_MAX_RECONCILIATION_RATIO = 0.10


@dataclass(frozen=True)
class DeviceAllocationReconciliation:
    """Device VRAM allocation high-water mark reconciliation between VYRE receipts and driver observation."""

    workload_id: str
    vyre_vram_bytes: int
    driver_vram_bytes: int
    difference_bytes: int
    ratio_difference: float
    reconciled: bool

    def to_json(self) -> dict[str, object]:
        """Return a JSON-serializable dictionary representation of reconciliation result."""
        return {
            "workload_id": self.workload_id,
            "vyre_vram_bytes": self.vyre_vram_bytes,
            "driver_vram_bytes": self.driver_vram_bytes,
            "difference_bytes": self.difference_bytes,
            "ratio_difference": self.ratio_difference,
            "reconciled": self.reconciled,
        }


def reconcile_device_allocations(
    *,
    workload_id: str,
    vyre_vram_bytes: int,
    driver_vram_bytes: int,
    max_ratio_difference: float = DEFAULT_MAX_RECONCILIATION_RATIO,
) -> DeviceAllocationReconciliation:
    """Reconcile VYRE receipt VRAM high-water marks against independent driver observations.

    Raises BaselineCaptureError if either measurement is non-positive or if the two
    measurements diverge beyond the declared bound.
    """
    if not isinstance(workload_id, str) or not workload_id.strip():
        raise BaselineCaptureError("workload_id must be a non-empty string")
    if (
        isinstance(max_ratio_difference, bool)
        or not isinstance(max_ratio_difference, (int, float))
        or math.isnan(max_ratio_difference)
        or math.isinf(max_ratio_difference)
        or max_ratio_difference <= 0
    ):
        raise BaselineCaptureError(f"{workload_id}: max_ratio_difference must be a finite positive number, got {max_ratio_difference!r}")
    if isinstance(vyre_vram_bytes, bool) or not isinstance(vyre_vram_bytes, int) or vyre_vram_bytes <= 0:
        raise BaselineCaptureError(f"{workload_id}: VYRE VRAM measurement must be a positive integer, got {vyre_vram_bytes!r}")
    if isinstance(driver_vram_bytes, bool) or not isinstance(driver_vram_bytes, int) or driver_vram_bytes <= 0:
        raise BaselineCaptureError(f"{workload_id}: driver VRAM measurement must be a positive integer, got {driver_vram_bytes!r}")

    diff = abs(vyre_vram_bytes - driver_vram_bytes)
    baseline = max(vyre_vram_bytes, driver_vram_bytes)
    ratio = diff / baseline

    reconciled = ratio <= max_ratio_difference
    if not reconciled:
        raise BaselineCaptureError(
            f"{workload_id}: device allocation high-water marks failed reconciliation: "
            f"VYRE={vyre_vram_bytes} B, driver={driver_vram_bytes} B, "
            f"difference ratio {ratio:.4f} exceeds max bound {max_ratio_difference:.4f}"
        )

    return DeviceAllocationReconciliation(
        workload_id=workload_id,
        vyre_vram_bytes=vyre_vram_bytes,
        driver_vram_bytes=driver_vram_bytes,
        difference_bytes=diff,
        ratio_difference=ratio,
        reconciled=reconciled,
    )
