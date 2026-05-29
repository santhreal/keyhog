# Bench release plan  -  vyre-bench upgrades

**Owner**: main release engineering.
**Target crate**: `vyre-bench/` only. Do NOT touch other crates.
**Deadline**: before the Vyre `0.4.1` release-candidate tag.
**Coordination**: optimizer work in `vyre-foundation`, `vyre-driver`, and `vyre-core` must land with benchmark evidence that this crate can report without hand transcription.

## Why these five upgrades

Today `vyre-bench` is criterion harnesses that print microseconds. The public release bench output is evidence, not a dev-only tool. These five upgrades convert the bench from "prints latency" to "tells the moat story per dispatch, per device, per substrate, with regression gates."

## Task list (each is one PR)

### B-UPG-1  -  release-axes harness

**File**: `vyre-bench/benches/release.rs` (new) and `vyre-bench/src/release/` (new module).
**Spec**: One `#[bench]` per axis below. Driver: `cargo bench -p vyre-bench --bench release` runs them all, prints one number per axis as the final output (suitable for copying into release notes).

| Axis | Number printed | Source |
| --- | --- | --- |
| warm μs/file | μs (mean of 1k iterations after 100 warm-up) | repeated dispatch of standard corpus |
| cold pipeline-build ms | ms (single cold run, no disk cache) | nuke `~/.cache/vyre/`, dispatch once |
| GB/s scan throughput | GB/s (workload bytes / wall-clock seconds) | scan a 1GB synthetic input |
| ULP drift max | u32 (max ULP across all output bytes) | diff against CPU reference |
| max-VRAM ceiling | MiB (peak from cudaMemGetInfo / wgpu adapter limits) | sample mid-dispatch |

**Acceptance**:
- Harness runs end-to-end on the box with RTX 5090 in `<5min`.
- Output is parseable: one line per axis as `axis_name=value units`.
- Five tests prove each axis number is computed correctly on a known fixture.

### B-UPG-2  -  substrate-attribution dashboard

**File**: `vyre-bench/src/attribution/` (new module).
**Spec**: After every bench run, parse committed `VYRE_TRACE=1` events. The trace schema is release-owned evidence; if the schema is absent or malformed, the bench reports an actionable blocker instead of inventing synthetic trace data. Emit a markdown table to stdout:

```
| Substrate            | Fired | Total saved | Avg saved |
|----------------------|-------|-------------|-----------|
| trace_jit_speculate  | 142   | 458ms       | 3.2ms     |
| vec_pack             | 89    | 267ms       | 3.0ms     |
| ...                  |       |             |           |
```

**Acceptance**:
- Reads from `VYRE_BENCH_TRACE_PATH` env var (default `/tmp/vyre-bench-trace.jsonl`).
- Sorts by total saved descending.
- One test that feeds a hand-built event log and asserts the table layout.
- If trace capture produces no events, prints `Fix: no trace events found; set VYRE_TRACE=1 and re-run the benchmark workload`.

### B-UPG-3  -  cross-device parity table

**File**: `vyre-bench/src/parity/` (new module).
**Spec**: Run the same Program on every probed device (5090, 4090, Metal via `wgpu::Backend::Metal` when the host actually exposes Metal, CPU reference as an oracle only). Output:

| Workload | 5090 ULP | 4090 ULP | Metal ULP | 5090 μs | 4090 μs | Metal μs |
| --- | --- | --- | --- | --- | --- | --- |
| layer_norm | 0 | 0 | 2 | 142 | 198 | n/a |
| ...        |   |   |   |     |     |     |

Generates an SVG sparkline per row using `tinyplot` or a hand-written SVG writer (no heavy deps).

**Acceptance**:
- Runs every probed device; marks unavailable devices as `n/a` only with the adapter-probe diagnostic recorded beside the table.
- Output written to `vyre-bench/target/parity-table.{md,svg}`.
- Test: with a single mocked device, the table renders with one column.

### B-UPG-4  -  baselines tracked in git

**File**: `vyre-bench/baselines/` (new directory) + `vyre-bench/src/baseline/` (new module).
**Spec**: One TOML per `(workload, device, version)`:

```toml
# vyre-bench/baselines/v0.6/layer_norm/rtx5090.toml
warm_us_per_file = 142.3
cold_pipeline_build_ms = 89.7
gbs_throughput = 412.5
ulp_drift_max = 0
max_vram_mib = 1834
recorded_at = "2026-05-02T22:30:00Z"
recorded_by = "main-cc"
```

After every release-axes run (B-UPG-1), compare against the matching baseline; fail with non-zero exit if any axis regresses more than 2σ (configurable threshold per axis).

**Acceptance**:
- `cargo bench -p vyre-bench --bench release -- --regression-gate` returns non-zero on any axis > 2σ regression.
- `--update-baseline` flag overwrites the baseline TOML for the current device.
- One initial baseline TOML per workload checked in for v0.6 numbers.

### B-UPG-5  -  cold-machine repro script

**File**: `vyre-bench/scripts/cold-warm-split.sh` (new).
**Spec**: Bash script that:

1. Nukes `~/.cache/vyre/`.
2. Runs cold benches (one dispatch per workload).
3. Records cold numbers to `vyre-bench/target/cold.toml`.
4. Runs the same workloads 100 times in a tight loop.
5. Records warm numbers to `vyre-bench/target/warm.toml`.
6. Diffs cold vs warm; prints the saved-by-cache-per-axis number.

Proves the disk + module cache is doing what we say it is.

**Acceptance**:
- Runs end-to-end without manual intervention.
- Output is exactly two TOML files plus a printed delta table.
- Idempotent (running twice produces same warm numbers within ULP).

## Hard rules for the agent

- Do NOT touch crates outside `vyre-bench/`. Specifically: do not modify vyre-foundation, vyre-lower, vyre-driver, vyre-emit-naga, vyre-runtime.
- Do NOT introduce new crate dependencies beyond what `vyre-bench/Cargo.toml` already has, except: `serde_json` (events), `tinyplot` or a 100-LOC hand-written SVG (parity), `chrono` (baseline timestamps). Confirm with main-cc before adding any other dep.
- Each task gets its own commit + own PR scope; do not bundle.
- Tests must use real fixtures from `vyre-bench/fixtures/`, not mocked Programs.
- If a task needs an upstream change (e.g., R4 substrate trace event format), open a separate ticket and ship the bench-side scaffolding that reads the format, with `gracefully prints "no events"` until R4 lands.
- Regression-gate (B-UPG-4) must NOT block the v0.6 release if it's the first time a baseline is recorded  -  only block on subsequent regressions.

## Order

Recommended: B-UPG-1 first (gives every other upgrade a number to consume) → B-UPG-4 (locks v0.6 numbers) → B-UPG-3 (cross-device confidence) → B-UPG-5 (cold/warm proof) → B-UPG-2 (last; depends on R4 trace events).

## Out of scope for this plan

- Upgrading other crates' bench harnesses (vyre-driver-cuda, vyre-driver-wgpu have their own crit benches; leave them alone for v0.6).
- Adding new optimization substrates (main-cc owns N6/N7/N9; do not duplicate).
- Touching ROADMAP.md (main-cc owns roadmap edits).
