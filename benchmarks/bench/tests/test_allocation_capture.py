"""Whole-process allocation evidence contracts."""

from __future__ import annotations

import pytest

from bench.allocation_capture import parse_massif, reconcile_device_allocations
from bench.baseline_capture import BaselineCaptureError


def test_massif_parser_selects_exact_peak_mapped_snapshot() -> None:
    """WHY: the quarter-memory redesign needs the mapped high-water mark; using the final snapshot or heap-tree prose misses transient startup mappings."""
    evidence = """desc: --pages-as-heap=yes --time-unit=ms
cmd: /keyhog scan fixture
snapshot=0
time=0
mem_heap_B=4096
mem_heap_extra_B=0
snapshot=1
time=2
mem_heap_B=16384
mem_heap_extra_B=0
snapshot=2
time=3
mem_heap_B=8192
mem_heap_extra_B=0
"""
    summary = parse_massif(evidence)
    assert summary.peak_mapped_bytes == 16_384
    assert summary.peak_snapshot == 1
    assert summary.snapshots == 3


def test_massif_parser_rejects_heap_only_measurement() -> None:
    """WHY: allocator heap is not process memory; accepting a run without pages-as-heap would hide mmap-backed detector plans and thread stacks."""
    with pytest.raises(BaselineCaptureError, match="pages-as-heap"):
        parse_massif("desc: --pages-as-heap=no\nsnapshot=0\nmem_heap_B=1\n")


def test_massif_parser_rejects_missing_snapshot() -> None:
    """WHY: dropped or reordered snapshots make the reported peak unverifiable and can silently remove the actual high-water event."""
    evidence = """desc: --pages-as-heap=yes
snapshot=0
mem_heap_B=1
snapshot=2
mem_heap_B=4
"""
    with pytest.raises(BaselineCaptureError, match="incomplete or reordered"):
        parse_massif(evidence)


def test_massif_parser_rejects_negative_mapped_bytes() -> None:
    """WHY: malformed profiler output must fail closed rather than yielding an impossible low allocation baseline that weakens the memory gate."""
    with pytest.raises(BaselineCaptureError, match="negative"):
        parse_massif("desc: --pages-as-heap=yes\nsnapshot=0\nmem_heap_B=-1\n")
def test_reconcile_device_allocations_reconciles_within_bound() -> None:
    """WHY: KH-2005 requires VYRE receipts and driver observations to reconcile within a declared bound."""
    res = reconcile_device_allocations(
        workload_id="filesystem-single-large-file",
        vyre_vram_bytes=100_000_000,
        driver_vram_bytes=102_000_000,
        max_ratio_difference=0.10,
    )
    assert res.reconciled is True
    assert res.difference_bytes == 2_000_000
    assert res.to_json()["workload_id"] == "filesystem-single-large-file"


def test_reconcile_device_allocations_rejects_out_of_bound_divergence() -> None:
    """WHY: KH-2005 fails closed when VYRE receipt and driver observation diverge beyond the bound."""
    with pytest.raises(BaselineCaptureError, match="failed reconciliation"):
        reconcile_device_allocations(
            workload_id="filesystem-single-large-file",
            vyre_vram_bytes=100_000_000,
            driver_vram_bytes=150_000_000,
            max_ratio_difference=0.10,
        )
def test_reconcile_device_allocations_rejects_invalid_inputs() -> None:
    """WHY: invalid workload_id or max_ratio_difference (NaN, bool, negative) fails closed."""
    import math
    with pytest.raises(BaselineCaptureError, match="non-empty string"):
        reconcile_device_allocations(
            workload_id="",
            vyre_vram_bytes=100_000_000,
            driver_vram_bytes=102_000_000,
        )
    with pytest.raises(BaselineCaptureError, match="finite positive number"):
        reconcile_device_allocations(
            workload_id="filesystem-single-large-file",
            vyre_vram_bytes=100_000_000,
            driver_vram_bytes=102_000_000,
            max_ratio_difference=math.nan,
        )
    with pytest.raises(BaselineCaptureError, match="finite positive number"):
        reconcile_device_allocations(
            workload_id="filesystem-single-large-file",
            vyre_vram_bytes=100_000_000,
            driver_vram_bytes=102_000_000,
            max_ratio_difference=True, # type: ignore
        )
