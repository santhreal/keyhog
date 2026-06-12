# 40 — GPU / megakernel / vyre utilization

The biggest innovation surface. keyhog rides vyre for regex-DFA lowering and GPU
matching (presence bitmap + megakernel firings + CUDA AC kernel). Known priors:
GPU is output-bound, not scan-bound; the CPU pipeline is the real throughput
ceiling; the megakernel only replaces phase-1. The legendary bar: GPU is a
*categorical* win on the workloads where it can win, with every host_detector
gap surfaced, and zero silent degrade. Hardest-first: the megakernel finalization
+ host-detector coverage are RESEARCH lanes and lead.

Numbers: KH-L-0380 … KH-L-0499.

## Flagship: finalize the 78046450 consolidation (RESEARCH)

- KH-L-0380 [L4,AV8][GPU][RESEARCH] Finalize the GPU consolidation architecture: one documented contract for phase-1 trigger production across CPU-Hyperscan / SIMD / GPU-presence / megakernel, swappable through one boundary. Proof: an `engine/mod.rs`-level contract doc + a trait/enum that all four implement.
- KH-L-0381 [L8,AV2][GPU][RESEARCH] Prove the megakernel firing union is a sound SUPERSET of the CPU Hyperscan net (the perf win — dropping the CPU net — only lands once parity is proven). Proof: a `megakernel_superset_parity` gate over the full corpus.
- KH-L-0382 [SCR,AV3][GPU][RESEARCH] Close the GPU coverage gap: the `host_detectors` that don't lower to a GPU DFA (state explosion, backreferences) run only on the CPU net — quantify the set, then lower as many as possible (alternate DFA construction, splitting). Proof: host_detector count down, surfaced in `KH_PERF`.
- KH-L-0383 [L8,AV4][GPU][RESEARCH] Megakernel positions on GPU: today positions come from CPU regex in phase-2. Investigate emitting validated match spans on-GPU (the bounded-ranges triple path in `gpu_lazy.rs`) to cut the CPU confirm cost — with the degenerate-triple integrity guard wired into the live path (currently only in tests). Proof: on-GPU spans behind a parity gate + wired integrity check.
- KH-L-0384 [L10,AV9][GPU][L] Wire `segment_attribution::map_offsets_to_segments` (the degenerate-triple guard) into the live GPU path if/when GPU emits positions — today it's test-only (a latent Law-10 gap if positions ever go live). Proof: a production call site + a fault-injection test.

## CUDA + wgpu: two backends, both proven

- KH-L-0385 [L8,L10][GPU][L] Make the CUDA-vs-wgpu backend choice explicit + documented: doctor self-test ran on CUDA; the wgpu integration test had no adapter headless. Both must be selectable, probed, and proven. Proof: doctor reports which backend each path used; both have a passing self-test.
- KH-L-0386 [L8][GPU][M] wgpu adapter acquisition headless: fix the empty-`vulkaninfo` environment so the wgpu path runs in CI/dogfood, or document CUDA-primary + wgpu-fallback explicitly. Proof: `gpu_batch_preserves_cross_chunk_reassembly` runs (not env-skipped) on a GPU runner.
- KH-L-0387 [L8,AV1][GPU][RESEARCH] CUDA driver perf: is the CUDA AC kernel faster than wgpu on the 5090? Bench both, pick the default per host, document. Proof: a per-backend throughput table.
- KH-L-0388 [L10][GPU][M] Every GPU→CPU degrade is loud + records a concrete reason (done: `gpu_last_degrade_reason`); add metrics so repeated degrades are visible to operators, not just one warn. Proof: a degrade-counter in `--self-test`/JSON.
- KH-L-0389 [VR1,AV15][GPU][L] Fault-inject GPU dispatch failures (corrupt catalog, OOM, adapter loss) and prove each degrades loudly + correctly, never a silent empty result. Proof: a GPU fault-injection test matrix.

## vyre utilization (deepen the substrate)

- KH-L-0390 [AV3,AV5][VYRE][RESEARCH] Audit which vyre capabilities keyhog UNDER-uses (region-presence scan, multi-pattern DFA batching, the rule engine, intern) and which would lift keyhog if adopted. Proof: a utilization gap-map with adopt/skip decisions.
- KH-L-0391 [AV1,L7][VYRE][L] `scan_presence_by_region` (unreleased) — use it to window the GPU prefilter to active regions, cutting dispatch cost on sparse files. Proof: a region-windowed bench win.
- KH-L-0392 [DEDUP,AV7][VYRE][M] keyhog's `StaticInterner` replaces vyre's CHD on the per-match hot path — confirm one interner story, no double-interning. Proof: an intern-path audit + a single-source gate.
- KH-L-0393 [AV4,L8][VYRE][RESEARCH] Megakernel innovations (the parked #10): GPU-resident multi-stage (presence→confirm→extract) to move more of phase-2 onto the GPU where output-bandwidth allows. Proof: a staged-GPU prototype behind a parity gate.
- KH-L-0394 [SCR,L1][VYRE][M] Every keyhog→vyre call is against a published, stable API once 0.6.2 lands (no reliance on internal unreleased symbols beyond the documented set). Proof: a `vyre_api_surface` gate listing exactly the symbols used.
- KH-L-0395 [AV2][VYRE][RESEARCH] Track vyre's frontier (megakernel/GPU work happens in the vyre source repo) and upstream keyhog-driven improvements as vyre releases, not keyhog forks. Proof: vyre changelog entries driven by keyhog needs.

## GPU correctness + parity (the gate wall)

- KH-L-0396 [L8,TC][GPU][L] CPU/GPU decoder parity (~30 known WGSL-vs-CPU divergences) — drive to zero with per-decoder differential tests. Proof: `megakernel_cpu_parity` + decoder parity at zero diffs.
- KH-L-0397 [TC,AV12][GPU][L] Backend parity matrix: CPU / SimdCpu / Gpu / megakernel produce identical RawMatch sets on the corpus (chunk-boundary, empty, edge, large). Proof: `backend_parity_*` suite green on a GPU runner.
- KH-L-0398 [L11][GPU][M] The bounded-ranges triple program in `gpu_lazy.rs` — confirm it's live (not dead code guarded only by a passing test); if dead, remove or wire. Proof: a utilization check on `ac_gpu_program`.
- KH-L-0399 [AV1][GPU][RESEARCH] GPU is output-bound (prior): attack the output bottleneck (presence-bitmap compaction, firing-buffer layout) to raise the ceiling where GPU can win. Proof: a measured output-bandwidth improvement.
- KH-L-0400 [SCR,L8][GPU][M] `keyhog backend` subcommand reflects the real routing per host (not a hardcoded matrix) and `--backend gpu/cuda/wgpu/cpu` all work + are tested. Proof: per-backend e2e on a GPU host.
- KH-L-0401 [L8][GPU][M] The megakernel catalog cache (`~/.cache/keyhog/programs/`) is correct under detector-set changes (digest-keyed) and concurrent access. Proof: a cache-invalidation + concurrent-build test.
- KH-L-0402 [L5,AV8][GPU][M] `megakernel.rs` (573 L) split by responsibility (catalog build / wire / dispatch) once the architecture is final — keep `MegakernelCatalog` `pub(crate)` (the allowlist stands). Proof: ≤500 L files + the inline tests migrated or allowlist updated.
- KH-L-0403 [AV13,L8][GPU][L] Cross-OS GPU: prove the GPU path (or its loud degrade) on macOS (Metal via wgpu) and document Windows. Proof: dogfood-all-os GPU row PASS/loud-SKIP per OS.
- KH-L-0404 [VR1,AV15][GPU][RESEARCH] Fuzz the megakernel catalog wire format (`to_bytes`/`from_bytes`) for malformed-cache handling. Proof: a wire-format fuzz harness, fail-closed on corruption.
- KH-L-0405 [AV1,SCALE][GPU][RESEARCH] The real question (prior: "GPU cannot win keyhog detection" / "scan throughput bottleneck is CPU pipeline"): quantify the precise workload envelope where GPU wins, ship it as the auto-routing policy, and make the CPU pipeline faster everywhere else. Proof: an auto-route policy + the envelope documented with measurements.
