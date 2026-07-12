# keyhog × Vyre: Maximal Adoption Plan (targeted)

Goal: make keyhog consume everything vyre 0.6.4 already ships, so the GPU route
beats simd-regex on every byte-tier it should win — with autoroute parity proof,
never a preferred-backend shortcut.

Grounding facts (measured / read from source, 2026-07-02):
- keyhog's GPU route loses to Hyperscan today: gpu-nocache 5.12 s / 3.5 GB RSS vs
  simd-nocache ~3.3 s / 1.8 GB on creddata (README bench tables).
- vyre 0.6.4 changelog: region-presence kernel ~41 µs for 8 MiB × 900 detectors on
  an RTX 5090 — "the borrowed path's cost is per-scan table re-upload, not the kernel."
- keyhog still calls the borrowed paths only (engine/gpu_literal_scratch.rs):
  `scan_presence_by_region_with_scratch` + a separate `scan_into_with_scratch` for
  positioned literals. None of the 0.6.4 resident/fused/async APIs are used.
- Known vyre bug: region-presence under-fire, caught by keyhog's optional
  gpu_recall_floor (gpu_region_dispatch.rs "fix the vyre literal-set path before
  treating GPU-only as parity-safe"). Tracked W1-1 in 02-vyre-upgrade-master.md.

Rules of engagement: autoroute contract unchanged (no fallback hierarchy, no
preferred backend); every phase lands with parity tests; recall-identical by
construction or by differential gate; crates/scanner/CHANGELOG.md updated per
behavior-affecting phase.

## Phase 0 — Attribution baseline (do first)
- Wire TimedDispatchResult via ResidentPresencePipeline::scan_into_timed into a
  diagnostic-only probe behind engine/profile.rs, or extend the perf-trace
  gpu-region-presence line with kernel-vs-staging split once Phase 1 lands.
- Record baseline: `keyhog scan --backend gpu --profile` + `make -C benchmarks bench`
  GPU configs on mirror + creddata. Save under
  planning/vyre-acceleration/bench-results/baseline/.
- Acceptance: written table attributing GPU route time to {matcher build, host
  fold+coalesce, table upload, kernel, readback, CPU phase-2 tail}. Every later
  phase must move a named row.

## Phase 1 — Adopt the 0.6.4 resident + fused + async APIs (the big one)
### 1a. Resident presence pipeline
- Files: engine/gpu_literal_scratch.rs, engine/gpu_region_dispatch.rs, engine/mod.rs
  (new CompiledScanner field), engine/gpu_lazy*.rs.
- Hold OnceLock<Option<ResidentPresencePipeline>> per scanner via
  GpuLiteralSet::prepare_resident_presence with capacity = gpu_batch_input_limit()
  (VRAM-tiered, owned by engine/gpu_input_budget.rs).
- prepare_resident_presence fails closed on undersized capacity — loud degrade with
  reason (existing record_gpu_degrade path).
- Batches larger than resident capacity: split at region boundaries (also fixes the
  u32-ABI cliff, Phase 2b).
- Acceptance: perf-trace shows table upload paid ONCE per scan, not per batch;
  parity vs borrowed path byte-identical on the differential suite.
### 1b. Fused presence + positions — REFUTED as a perf lever (2026-07-02, read from vyre source)
- vyre-libs/tests/literal_set_presence_and_positions_gpu.rs header (MEASURED, RTX 5090,
  wgpu release): the fused one-pass is **~20× SLOWER** than the two separate passes —
  the fused kernel is ~3× larger (suffix3 prefilter inlines the replay 3×) so occupancy
  loss dwarfs the saved haystack walk. vyre ships the fold as a CORRECTNESS-equivalent
  primitive only; timing is reported, not asserted. **Do NOT adopt fusion for perf.**
  The real GPU-8MiB lever is segmentation / dispatch-overhead → prioritize 1a (resident,
  pay table-upload once) + 1c (async overlap) + 2b (segmentation), skip 1b's perf goal.
- (original 1b, kept for record) Replace the two dispatch families with
  scan_presence_and_positions_by_region[_with_scratch] — one pass.
- Keep the adaptive window-split pager (split_positioned_window) only as the
  over-cap escape hatch; primary path is fused.
- Files: gpu_region_dispatch.rs::positioned_literal_evidence_from_gpu folds into the
  main dispatch closure in scan_coalesced_gpu_region_presence.
- Acceptance: dispatch count per batch 2→1 in perf-trace; positioned rows
  byte-identical to two-pass on the parity corpus.
### 1c. Async overlap
- Use scan_presence_by_region_async (PendingDispatch / await_words) to submit
  batch N+1 while the CPU phase-2 tail processes batch N. Integration point: batch
  loop above scan_coalesced_phase2_with_admission.
- Double-buffer host fold scratch (two RegionPresenceScratch slots) so fold(N+1)
  overlaps kernel(N).
- Acceptance: end-to-end GPU wall time on a multi-batch corpus improves by ≥ the
  measured kernel+readback serialization from Phase 0; determinism gate green.

## Phase 2 — Kill host-side prep overhead
### 2a. Parallel case-fold
- File: engine/gpu_region_batch.rs::build_region_presence_batch. Parallelize
  write_ascii_lowercase_into over disjoint chunk ranges with rayon.
- Longer-term: delete the fold entirely when vyre lands in-kernel case-insensitive
  matching (W2-1). Tracking note, not a compat shim.
### 2b. u32-ABI batch splitting
- build_region_presence_batch currently errors (→ full CPU degrade) when a coalesced
  batch exceeds u32::MAX bytes. Split at region boundaries instead; sub-batch results
  concatenate trivially (per-region rows). This is the scan-system multi-TB shape.
- Acceptance: synthetic >4 GiB batch scans on GPU with zero degrade events;
  adversarial test pins the split boundary.
### 2c. RSS
- After 1a–2b, re-measure peak RSS on creddata. Target: GPU route within ~1.2× SIMD
  (baseline 3.5 GB vs 1.8 GB). Sub-batching removes the all-at-once double corpus copy.

## Phase 3 — Widen what the GPU decides
### 3a. Positions everywhere
- Today positioned evidence covers only confirmed-anchor rows + generic keyword
  stems; other triggered patterns re-walk whole chunks on CPU.
- Extend gpu_position_literals to every ac_map trigger literal whose pattern has a
  bounded match width (ac_match_upper_bounds exists). Phase-2 validates ±window
  slices via validate_detector_match instead of whole-chunk regex walks.
- Unbounded-width patterns keep the whole-chunk path (recall-identical by
  construction — same contract as confirmed_anchor_index).
- Gate behind a tuning route flag with a differential parity test before default-on.
- Acceptance: phase2:confirmed + extraction leaf time drops on GPU-routed profile
  dumps; parity gate green.
### 3b. Phase-2 GPU DFA catalog: precompile + persist + raise caps
- File: engine/phase2_gpu_dfa.rs (PHASE2_GPU_DFA_MAX_SHARDS=4, TARGET_SHARD_PATTERNS=16
  → only 64 of ~2,700 always-active patterns).
- Compile the catalog at `keyhog calibrate-autoroute` / install time; persist via the
  GPU artifact cache (gpu_cache.rs to_bytes/from_bytes), keyed by detector digest +
  backend id + vyre version.
- When loaded from cache, lift the shard cap (VRAM-tiered, same table as
  gpu_batch_input_limit_for_vram_mb). Lazy-build path keeps tight caps.
- Acceptance: covered-pattern count (report_phase2_gpu_catalog_loss) rises from ≤64
  toward full coverage on cached hosts; CPU no-hit admission time drops.

## Phase 4 — Re-route and prove
- Fix-or-gate the vyre under-fire bug (W1-1). Until fixed, gpu_recall_floor stays the
  differential oracle; GPU-only buckets ineligible for autoroute wins where under-fire
  reproduces.
- `keyhog calibrate-autoroute` full re-prime on the bench fleet; regenerate
  `make -C benchmarks report`.
- MoE consts single-owner: codegen the WGSL MOE_SHADER header from
  ml_scorer/ml_weights.rs consts (CONSOLIDATION_TODO.md); prerequisite hygiene before
  any GPU-MoE tuning.

Exit criteria:
- GPU route wins its large-chunk byte-tier buckets in persisted autoroute decisions
  with parity proof (not forced --backend gpu).
- README bench tables regenerate with GPU ≤ SIMD on creddata full config.
- Zero silent-degrade events across the dogfood corpus (keyhog backend --autoroute
  --json clean).

Ordering: 0 → 1a → 1b → (2a,2b parallel) → 1c → 3a → 3b → 4.
Phases 1a–2b are pure integration, no vyre changes. Phase 3a is the largest
keyhog-side change; 4 depends partly on vyre W1-1.
