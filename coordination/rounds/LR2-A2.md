# LR2-A2

LOCK: `crates/scanner/src/engine/**`, `hw_probe.rs`, `crates/scanner/tests/unit/engine_a2_cases/**`, `crates/scanner/tests/gap/gpu_forced_backend_no_silent_degrade.rs`

## Hunt

- KH-GAP-040 (LR1 KH-GAP-002 lineage): `KEYHOG_BACKEND=gpu` silently fell back to CPU via `scan_coalesced_non_gpu` / `scan_chunks_with_backend_internal`
- `engine/mod.rs` 1237 LOC god file; `scan_gpu.rs` 1153 LOC god file
- Inline `#[cfg(test)]` in former `scan_gpu.rs` (3 coalesce tests)

## Splits

| Module | LOC (post) | Extracted from |
|--------|------------|----------------|
| `engine/mod.rs` | 237 | struct + scan API + re-exports |
| `engine/compile.rs` | 159 | `CompiledScanner::compile` |
| `engine/gpu_lazy.rs` | 167 | lazy GPU matcher / AC / rule pipeline |
| `engine/rule_pipeline.rs` | 129 | MegaScan compile + cache |
| `engine/gpu_cache.rs` | 57 | cache dir/key + const packs |
| `engine/scan_postprocess.rs` | 405 | post-process + fragments + ML batch |
| `engine/gpu_coalesce.rs` | 35 | chunk coalescing |
| `engine/gpu_dispatch.rs` | 85 | shard dispatch |
| `engine/gpu_megascan.rs` | 169 | MegaScan coalesced path |
| `engine/gpu_literal_phase1.rs` | 425 | literal-set GPU phase 1 |
| `engine/gpu_ac_phase1.rs` | 285 | AC-kernel GPU phase 1 |
| `engine/gpu_phase2.rs` | 66 | GPU phase 2 extract |
| `engine/gpu_scan_wrappers.rs` | 55 | `GpuPhase1Output` + wrappers |
| `engine/gpu_forced.rs` | 44 | KH-GAP-040 explicit error path |

`scan_gpu.rs` monolith **removed** (gate: `engine_a2_cases/scan_gpu_monolith_removed.rs`).

## Fix KH-GAP-040

- `hw_probe::forced_backend_from_env()` — public parse of `KEYHOG_BACKEND`
- `engine/gpu_forced.rs` — `deny_silent_gpu_degrade()` panics with explicit message when env forces Gpu/MegaScan but stack unavailable
- Wired into: `warm_backend`, `scan_chunks_with_backend`, `scan_with_deadline_and_backend`, `backend::scan_chunks_with_backend_internal`, GPU degrade paths via `gpu_degrade_done()`

## Tests added

- count: **41** hand-written files (`engine_a2_cases/`, one `#[test]` per file)
- wired in `crates/scanner/tests/unit/mod.rs` → `all_tests.rs`
- includes file-size gates, coalesce oracles, forced-backend env oracles, monolith-removal gate

## Commands

```bash
env -u CC cargo test -p keyhog-scanner --test all_tests --profile release-fast 'engine_a2_cases::'
env -u CC cargo test -p keyhog-scanner --test all_tests --profile release-fast gap::gpu_forced_backend_no_silent_degrade
```

## GAP

- KH-GAP-040 → **fixed** (explicit panic on forced GPU unavailable)
- KH-GAP-001 MegaScan parity — unchanged (open)

## Notes

- NFS workspace: verify `scan_gpu.rs` monolith does not reappear; split modules live as `engine/gpu_*.rs` siblings declared from `mod.rs`.
- `keyhog-core` SARIF split in flux during LR2; scanner tests require core green.
