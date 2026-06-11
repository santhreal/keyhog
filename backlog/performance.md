# Performance backlog

Perf is a co-equal vector with detection. The target is the Linux kernel
tree (`/mnt/FlareTraining/santh-corpus/repos/linux`, ~2 GB, 94k files), not
the tiny SecretBench mirror (15k small files) — the mirror's per-file
overhead is real but the decisive scale behaviour only shows on a large
real tree. Items carry the data that proves them.

## CRITICAL

- **PERF-01 · SHIP-BLOCKER · keyhog DEADLOCKS on large trees (root-caused + fixed)** —
  scanning the 2 GB / 94k-file Linux kernel tree hangs forever. gdb on the
  live process: all 64–75 threads parked in futex at ~0.6 % CPU after only
  ~1–3 s of CPU work (a true deadlock, not slow compute). Isolation:
  `kernel/mm` (202 files), `Documentation` (11k files) and `.git` (273 MB
  pack) each scan fine; only the full 94k tree hangs, under BOTH the SIMD
  (`KEYHOG_NO_GPU=1`) and GPU backends. So the root cause is scale-triggered
  and backend-independent.
  ROOT CAUSE: shared global rayon pool. `FilesystemSource::chunks()`
  (`crates/sources/src/filesystem.rs`) runs a `par_bridge()` file-reader on
  the GLOBAL rayon pool, and each task BLOCKS on `sync_channel(64).send`
  under backpressure. The downstream scanner thread runs `scan_coalesced`
  (`crates/scanner/src/engine/scan.rs:84` `chunks.par_iter()`) on the SAME
  global pool. On a large tree every global worker ends up parked in `send`
  (channel full) while the scanner's `par_iter` can never acquire a worker to
  do the scanning that would drain the channel and release the readers —
  reader-blocks-on-send ↔ scanner-needs-worker is a cycle. Small trees drain
  before full saturation, so the SecretBench mirror never exposed it.
  FIX (landed + VERIFIED): run the file-reader on a DEDICATED rayon
  `ThreadPool` so it cannot starve the scanner's global-pool `par_iter`;
  readers may all park in `send`, but the scanner stays schedulable, drains
  the channel and unblocks them. Falls back to the global pool if the
  dedicated pool can't be built.
  VERIFIED 2026-05-30: release binary now scans the full kernel in **93.5 s
  wall** (was: infinite hang), peak RSS 2.2 GB, 22 findings, SIMD backend.
  → testing gap CLOSED: a generated wide-tree e2e now exists —
  `crates/cli/tests/e2e/scan_bigtree_completes_and_recalls.rs` (T-perf-bigtree)
  builds a synthetic wide tree, asserts the scan COMPLETES under a wall-clock
  deadline (the deadlock would hang it forever), and asserts a planted secret
  is still recalled (completion alone could be a no-op). The whole large-tree
  class is no longer invisible to CI.

- **PERF-02 · HIGH · GPU (Vulkan) path has unbounded host waits** — independent
  of PERF-01, the GPU backend can block the scan forever:
  `crates/scanner/src/gpu_moe_backend.rs:328` `device.poll(wgpu::PollType::Wait)`
  waits with no timeout for GPU completion, and `:343` `receiver.recv()` waits
  with no timeout for the map-async callback. If a submission never completes
  (driver stall, lost completion) the calling rayon worker parks forever.
  Observed on the first kernel run: NVIDIA Vulkan driver threads
  (`[vkrt]/[vkcf]/[vkps]`, `libnvidia-glcore.so`) idle in cond_wait while a
  keyhog worker was parked — work submitted, completion never observed.
  Violates the "never wait for something" rule.
  FIX LANDED 2026-05-31: GPU MoE readback now uses a bounded
  `PollType::Poll` loop plus nonblocking channel checks. The default
  deadline is 30 s and `KEYHOG_GPU_MOE_TIMEOUT_MS=<MS>` tunes it. A timeout,
  device-poll error, callback disconnect, or `map_async` error falls back to
  CPU MoE for that batch instead of parking a rayon worker forever. Static
  gate: `gpu_moe_readback_bounded`.

- **PERF-07 · SHIP-BLOCKER · GPU path produces a DIFFERENT finding set than
  SIMD on identical input (gpu_parity violated in production)** — confirmed
  2026-05-30 on the kernel, release-fast, warm cache:
    default (auto-route)  129.66 s  264 % CPU  19 findings
    simd-forced           119.15 s  173 % CPU  22 findings
  The two finding sets are NOT equal. Diff: 4 `codesandbox-api-token` hits in
  `drivers/gpu/drm/amd/include/soc21_enum.h` (lines 20267-20272) present under
  SIMD, ABSENT under the auto-routed (GPU) default; and 1 `github-oauth-access-
  token` in `tools/perf/arch/arm/entry/syscalls/syscall.tbl:1` present under
  default, absent under SIMD. So a scan's result depends on which backend a
  batch happened to route to — non-reproducible, and hardware/batch-order
  dependent. dispatch.rs itself flags this as a release blocker
  ("SIMD and GPU MUST produce identical findings ... That equivalence is not
  self-evident") — it is now PROVEN false. For a secret scanner this is
  fail-OPEN: a GPU recall gap silently drops real secrets by default. (Here the
  dropped 4 are codesandbox-on-`CSB_`-enum FALSE positives, so GPU looked
  "better" by luck — but the divergence is the bug, and the next file it could
  drop a real credential.) Also a coherence break: benchmarks pin
  `KEYHOG_BACKEND=simd` (F1 measured on SIMD), so the SHIPPED default diverges
  from the BENCHED accuracy — tuned != shipped.
  ROOT-CAUSED + FIXED 2026-05-30 (user chose: keep fastest-wins autorouting,
  fix parity). Two compounding GPU-path bugs, both proven on soc21_enum.h
  (SIMD 4 codesandbox matches, GPU 0):
    1. CASE. Hyperscan is compiled `PatternFlags::CASELESS` for EVERY pattern
       (simd.rs), but the GPU AC literal automaton matched bytes exactly, so a
       lowercase literal `csb_` never fired on `CSB_…`. FIX: ASCII-lowercase the
       GPU literal set (build_gpu_literals) AND the coalesced haystack
       (gpu_ac_phase1 / gpu_literal_phase1) before AC matching; phase-2 still
       confirms on the ORIGINAL bytes with the caseless regex. Raised AC matches
       31384 -> 47928 (the uppercase CSB_ enums now hit).
    2. POSITIONS. The classic_ac_bounded_ranges GPU kernel reports degenerate
       match positions (observed (0,0)); fold_overlapping_same_pid_inplace then
       collapsed a pid's 46 hits into one (0,0) span, and the phase-2
       cheap-filter derived a ~1 KiB window [0,1024] from it -> is_match(window)
       false even though is_match(whole)=true, so codesandbox was dropped. FIX:
       the cheap-filter now confirms each hit pid against the WHOLE chunk
       (position-independent, identical to SIMD's triggered->extract), bounded
       by distinct-pid count since fold dedups to ~one-per-pid.
  VERIFIED: soc21_enum.h GPU now 4 == SIMD 4; broader file check PARITY PASS;
  new release-gate test `crates/cli/tests/gpu_simd_parity.rs` (GPU vs SIMD
  byte-exact finding sets on a fixture with tokens past 4 KiB padding + an
  uppercase caseless occurrence) passes. SIMD path untouched (changes are
  GPU-only: build_gpu_literals + gpu_*_phase1 + GPU phase-2 cheap-filter), so
  the simd-pinned bench F1 is unaffected. Full-kernel default-vs-simd
  re-confirmation in progress. Underlying vyre AC position-reporting bug logged
  separately (the keyhog-side whole-chunk confirm makes it non-blocking).
  Separately: the `codesandbox-api-token` detector firing on `CSB_`/`csb_`
  enum identifiers is a precision bug (logged to detection.md).

- **PERF-07b · DET-11 · FIXED+VERIFIED 2026-05-31 · GPU MoE used a DIFFERENT
  activation function than the CPU MoE** — the WGSL shader (`gpu_shader.rs`)
  applied the true logistic `1/(1+exp(-x))` while the CPU MoE
  (`ml_scorer::sigmoid`) uses a rational approximation
  `0.5+0.5*x/(1+|x|)` clamped at ±6. These diverge by up to ~0.05 in the
  mid-range — far wider than the near-floor band — so the GPU MoE produced
  systematically different confidences than the benched CPU MoE. Impact: the
  auto-route default flipped ~80 near-floor findings on the SecretBench mirror
  vs the SIMD-pinned bench (the swing that forced `KEYHOG_NO_GPU=1` to be
  pinned for reproducibility), and forced `--backend gpu` on the kernel scored
  14 vs SIMD's 18. This is the MoE-CONFIDENCE layer, distinct from PERF-07's
  AC-LITERAL layer. FIX: shader now mirrors the CPU rational sigmoid + clamps
  (GPU-only change; SIMD/CPU path untouched). GUARDS: `gpu_shader::tests`
  (asserts the shader uses the rational form, not the logistic; documents the
  ~0.05 divergence); `score.py` now honors a caller-provided `KEYHOG_NO_GPU`
  (defaults to deterministic) so the SAME scorer can dogfood the GPU path.
  VERIFIED: mirror `KEYHOG_NO_GPU=1` and `KEYHOG_NO_GPU=0` now byte-identical
  (P=0.9207 R=0.8167 F1=0.8656, TP=2450 FP=211 FN=550 both) — the GPU MoE no
  longer diverges, so "tuned==benched==shipped" holds whichever backend a GPU
  user's batch routes to. The pin is now determinism-only, not a hidden bug.

- **PERF-07c · FIXED+VERIFIED 2026-05-31 · GPU AC literal automaton produced a
  DIFFERENT trigger set than the Hyperscan DB (PERF-07 residual)** —
  discovered by the all-backend kernel dogfood 2026-05-31. With the DET-11
  sigmoid fixed, forced `--backend gpu` on the kernel still diverged: 14
  findings vs SIMD 18. Root causes were split across three layers: (1) GPU
  no-hit chunks skipped active fallback patterns; (2) source/config files such
  as `Kconfig` and `syscall.tbl` still ran Caesar decode and produced
  GPU-only decoded false positives once fallback admission was fixed; (3) the
  CUDA literal-set path can emit impossible `end <= start` triples, which
  corrupt chunk attribution before phase 2.

  Fixes: GPU no-hit phase 2 now admits chunks with a real active fallback set;
  GPU phase 2 unions the canonical CPU AC roots before extraction so admitted
  chunks fail closed against literal-set drift; corrupt GPU AC triples degrade
  the batch to the SIMD/CPU literal path before attribution; Caesar decode now
  skips source/config paths lacking ordinary code extensions; decoded-source
  aliases no longer displace original file locations during dedup.

  Verified: the targeted Linux subset that reproduced PERF-07c now emits
  byte-identical sorted JSON for forced SIMD and forced GPU:
  `devcycle-api-credentials` x2, `generic-secret` x1, and
  `saltstack-credentials` x2. The former `azure-container-registry-token`
  miss was a SIMD false positive fixed by the ACR hex-constant suppression;
  the former `fireworks-ai-api-key` and `github-oauth-access-token` GPU extras
  were Caesar decode false positives on source/config paths.
  UPDATE 2026-05-31: the remaining RTX 5090 red gate was split in two and
  closed. Vyre's plain AC append builder cloned `atomic_add` into the guard
  and each store, so pattern/start/end could land in different output slots;
  KeyHog's production AC builder now binds the atomic result once and reuses
  that slot for all three fields. Separately, `KEYHOG_REQUIRE_GPU=1`
  preflight was killing healthy GPU scans before dispatch; the strict guard is
  now a no-op for an already usable GPU stack and still hard-fails on concrete
  runtime degradation. Verified on the live RTX 5090:
  `keyhog backend --self-test --json` returns `status=pass`,
  `recommended_backend=gpu`, and `vyre_ac_kernel=pass`; required-GPU
  `gpu_and_simd_produce_identical_findings_on_same_corpus` reaches assertions
  and passes.

- **PERF-07d · FIXED+VERIFIED 2026-05-31 · Forced GPU on CredData spent the
  run confirming dense literal-prefix floods on CPU** — CredData's 11,393-file
  corpus produced GPU AC batches with 1.2M, 11.0M, and 10.4M literal-prefix
  hits. Phase 1 itself was fast, but phase 2 then confirmed broad prefixes
  across thousands of chunks; the pre-fix forced-GPU run did not complete in
  45 s and peaked around 5.1 GB RSS. FIX: the AC readback cap is now aligned
  to the measured dense-prefix loss point (32,768 triples per shard), cap
  overflow reroutes the batch through the SIMD coalesced scanner, and the
  existing whole-batch density guard catches dense outputs that fit under the
  cap. This is a backend execution guard, not detector policy. VERIFIED on
  the live RTX 5090: forced GPU CredData completes in **5.04 s wall, 3.89 GB
  RSS** on the first cap-guard run and **6.16 s wall, 4.04 GB RSS** warm, down
  from the 45 s timeout; current SIMD is **4.43 s wall, 2.65 GB RSS**. The
  forced-GPU and SIMD outputs both emit 2263 findings and match exactly by
  detector id, credential hash, file, and offset.

## Parallelism

- **PERF-08 · HIGH · kernel scan is matching-bound + only ~4 of 16 cores hot
  (flat perf profile, release-fast, 2026-05-30)** — supersedes the earlier
  "serial funnel" guess in PERF-05. A flat (no-call-graph) `perf record -F 999`
  over a SIMD kernel scan shows where the CPU actually goes:
    PER-THREAD: keyhog-worker-6 37%, worker-1 29%, worker-0 15%, worker-8 14%,
                all others < 2%. readers ~0%, producer ("keyhog") 0.77%.
    TOP SELF SYMBOLS: aho_corasick Teddy `find` 43%+8.5%+4.4%+1.7%+0.9% ~= 58%,
                regex_automata hybrid `find_fwd` 15% + meta strategy ~3%,
                memchr ~5%, keyhog extract/preprocess ~1%.
  Findings:
  - NOT I/O-bound, NOT a producer/reader funnel (readers+producer < 1%), NOT
    allocation (jemalloc A/B was flat, PERF-05 refinement). It is CPU-bound in
    LITERAL+REGEX matching.
  - Hyperscan IS live (`HS ready compiled=1629 unsupported=0`), so phase-1 is
    fine. The 58% aho_corasick is the SECOND full-content pass: the fallback
    keyword-AC sweep (`scan_fallback_patterns`, runs on EVERY chunk per Task
    #69) + generic-assignment scan - additive to hyperscan phase-1.
    `KEYHOG_BACKEND=simd` (6.86 s) was actually SLOWER than `=cpu` (5.56 s) on
    the 467 MB amd/include dir: Hyperscan adds coalesce/dispatch overhead with
    no net matching-throughput win because aho_corasick already does the work.
  - Only ~4 workers hot because DEFAULT_WINDOW_SIZE was 64 MiB
    (crates/sources/src/filesystem.rs:21) and the kernel's LARGEST file is
    22 MiB, so NO file is windowed - every file is a single chunk pinned to one
    rayon worker. A batch's heavy work lives in its few large single-chunk
    files, so per-batch `par_iter` lights ~4 workers and parks the other 12.
  FIX LANDED 2026-05-31 (L1): source-level default windows are now 1 MiB with
  128 KiB overlap, matching the scanner's chunk/overlap contract. Multi-MB
  source files now enter the scanner as independent chunks that `par_iter` can
  spread across workers instead of one worker serially re-windowing the file.
  Regression gate: `default_windowing_splits_multimegabyte_source_files`.
  REMEASURED 2026-05-31 after L1/current-thread runtime/reader-pool sizing on
  `/mnt/FlareTraining/santh-corpus/repos/linux/drivers/gpu/drm/amd/include`
  (467 MB, 543 files, release-fast, `KEYHOG_NO_GPU=1`): SIMD 1.26 s wall,
  4.93 s user, 460% CPU, 1.52 GB RSS; CPU fallback 1.30 s wall, 4.88 s user,
  443% CPU, 1.55 GB RSS; both emit zero findings and byte-identical sorted
  JSON. The old 5.56-6.86 s amd/include numbers are no longer representative.
  Remaining measured levers:
    L2 (biggest single cost): gate/shrink the fallback keyword-AC sweep - it
       re-scans full content on every chunk. Tighten its bloom/keyword gate, or
       fold fallback-detector keywords into the hyperscan DB so there is ONE
       literal pass, not two. Recall-sensitive (Task #69) - guard with the
       differential + mirror F1.
    L3: don't batch-barrier the scanner - a single global `par_iter` over all
       chunks (instead of per-batch) would let heavy chunks from different
       batches overlap, but conflicts with the GPU coalesce/memory model.
  The 100x kernel target needs L1 x L2 together (parallelism x halving the
  per-chunk matching work), not any single lever.
  UPDATE 2026-05-31 (current full-kernel baseline + a refuted reader-side
  hypothesis): release binary, full `/mnt/FlareTraining/santh-corpus/repos/linux`
  (94825 files, 2.0 GB), `KEYHOG_NO_GPU=1 --backend simd --no-daemon`:
  **84.2 s wall, 213 % CPU (≈2 of 32 cores), 17 findings, 2.29 GB RSS.**
  Confirms the scan is pipeline-serialised, NOT matching-bound, on the full
  tree (so the L2 fallback-AC fold is the wrong lever here — it only helps the
  big-file subdir profile).
  TESTED + REVERTED: replaced the reader `par_bridge()` with a bounded-batch
  `into_par_iter` (512/batch) on the theory the bridge's single-mutex cursor
  serialised the 94k tiny-file pull. It **regressed** to 102.7 s / 175 % CPU —
  LESS parallel, not more. So the readers are NOT pull-bound; they block on the
  inner `sync_channel(64)` SEND (downstream-limited, matching PERF-05's off-CPU
  profile), and a per-batch barrier only cut the bridge's continuous
  read↔send overlap. Reader pull contention is a DEAD END; do not retry it.
  NARROWED LEVER: the consumer side. ≈2 effective cores live in the single
  main-thread chunk drain (`dispatch.rs` `for chunk_result in source.chunks()`)
  + the single scanner thread; `scan_coalesced`'s per-chunk preprocessing
  (line offsets / code-line / doc-comment / unicode) par_iters per batch but
  STARVES between batches because the per-chunk channel handoffs (94k ×
  send/recv across two single-thread funnels) can't refill it. REQUIRED
  MEASUREMENT: profile `scan_coalesced` preprocessing parallelism + the
  per-chunk funnel with a symbolised build; the fix is to stop routing every tiny chunk
  through one drain thread (e.g. per-file end-to-end scan on the SIMD/CPU path,
  reserving coalescing for genuinely large files — L3, constrained by the GPU
  coalesce model). Verify finding-set parity (17) + wall on the kernel.

- **PERF-05 · HIGH · kernel scan uses ~1.6 cores of 32 (pipeline serialization)** —
  after the PERF-01 fix the kernel scan COMPLETES but runs at ~162 % CPU with
  only ~2 of 58 worker threads in R state and 0 in D (so it is neither
  CPU-saturated nor I/O-bound — most threads are parked in futex waiting for
  work). A pipeline imbalance, not a deadlock (CPU climbs steadily). Suspect
  the single-consumer producer loop (`dispatch.rs` main thread drains the
  64-deep reader channel one chunk at a time and batches) and/or the
  `par_bridge` reader gated by codewalk's single-cursor enumeration. This is
  the headline lever for the 100x speed target: ~30 idle cores. Profile which
  stage starves (reader vs batcher vs scanner) and rebalance — likely widen
  the producer→scanner channel depth and/or parallelise batch assembly so the
  scanner's global-pool `par_iter` is continuously fed. Measure on the kernel
  before/after.
  REFINEMENT (2026-05-30): `scan_coalesced` IS parallel within a batch
  (`scan.rs` phase1+phase2 both `par_iter`), but on the kernel most files are
  cheap-rejected by the alphabet/bigram-bloom prefilter, so the scanner
  drains each batch in microseconds and STARVES waiting for the reader. The
  real bottleneck is the read path: 104.8 s for 2 GB ≈ 19 MB/s, far below
  nvme bandwidth — per-file overhead (open/stat/read/decode/window/chunk-
  assembly/channel-send) × 94k files dominates, gated further by codewalk's
  single-cursor enumeration that `par_bridge` pulls through a shared mutex.
  Lever: cut per-file read overhead and parallelise enumeration; ~30 cores
  sit idle waiting for the reader.
  REFINEMENT 2026-05-30 (SIMD path, off-CPU profile + allocator A/B):
  • ALLOCATOR RULED OUT. Three back-to-back kernel scans — default glibc
    malloc, jemalloc via LD_PRELOAD, and glibc tuned (MALLOC_ARENA_MAX etc.)
    — all land at 108–111 s @ ~165 % CPU. If malloc arena/mmap_lock
    contention were the limiter, jemalloc would have unlocked cores; it moved
    the needle <3 %. The earlier `__mprotect`/`osq_lock` kernel-time was a
    symptom, not the cause. Do NOT add a `#[global_allocator]` for this.
  • OFF-CPU PROFILE (per-thread kernel-stack sampling, 16-phys/32-logical
    Ryzen 9950X): in the SIMD path essentially ONE worker is in R at any
    instant; ~87 threads parked in `futex_do_wait`. Reader threads
    (`keyhog-reader-N`) are blocked on the inner `sync_channel(64)` SEND
    (futex) — NOT in `vfs_read`/D-state — so the scan is NOT I/O-bound; raw
    parallel read of all 94k files is 0.7 s. 32 idle `tokio-rt-worker`
    threads confirm PERF-03 (async runtime spun up for a pure fs scan).
  • ARITHMETIC: 86–96 s for ~1.4 GB at ~1.8 effective cores ⇒ ~156
    core-seconds of real work ⇒ ~1.66 ms/file of CPU somewhere, funnelled to
    <2 cores. Pure single-stream Hyperscan would do this in seconds, so the
    cost is per-file FIXED overhead in a serial stage, not match throughput.
    Pinning the exact frame needs a symbolized build (release strips; built
    release-fast for the flamegraph). Prime suspects: the SINGLE dispatch
    producer thread draining the 64-deep inner channel one chunk at a time
    and the SINGLE scanner thread, both `std::thread` (process-named
    `keyhog`), each a funnel every one of 94k chunks crosses. Candidate fix:
    fold read+scan into one rayon parallel pipeline (worker reads AND scans a
    file end-to-end, no central funnel) and reserve the coalesce/GPU model
    for genuinely large files. Measure on the kernel before/after.

- **PERF-06 · HIGH · GPU auto-routing (the DEFAULT) is catastrophically slow on
  large trees** — the default (GPU) backend did NOT finish the kernel in 300 s
  (timed out at 5:00 wall, 1401 % CPU = ~14 cores busy throughout, RSS
  3.27 GB) vs SIMD's 104.8 s. It was computing the whole time (not hung), so
  the cause is wasted CPU, not a stall: `gpu_phase2.rs` runs `prepare_chunk` +
  `scan_prepared_with_pattern_hits` + `post_process_matches` + boundary rescan
  for EVERY chunk in `par_iter`, while SIMD `scan_coalesced` phase2 takes the
  cheap `triggered_opt == None` path for the ~99 % of kernel files with no HS
  hit. So a default `keyhog scan <big-repo>` is >3x slower than it should be
  and may not complete. FIX LANDED: GPU phase2 now uses the same no-hit
  plausibility gate as SIMD coalesced scans, skipping `prepare_chunk` /
  `scan_prepared_with_pattern_hits` / `post_process_matches` for empty-hit
  chunks unless the chunk has multiline split-secret indicators, secret
  assignment keywords, known secret prefixes, or a long entropy run. Static
  regression gate added. UPDATE 2026-05-31: the forced-GPU correctness gate
  no longer hard-fails during preflight, and the RTX 5090 JSON self-test now
  reports `vyre_ac_kernel=pass`; GPU-default large-tree speed remains a
  routing/architecture problem rather than a corrupt-readback problem.
  UPDATE 2026-05-30 (head-to-head, current binary, RTX 5090 host): the
  phase2 no-hit gate helped (300 s → 204 s) but GPU-default is STILL the
  worst path on the kernel on every axis:
    gpu-default  204.05 s  523 % CPU  4.08 GB RSS
    simd-forced   96.24 s  179 % CPU  2.34 GB RSS
    simd+no-gpu   86.65 s  190 % CPU  2.20 GB RSS
  GPU-default is 2.1x SLOWER, 3x CPU, ~1.8x RSS than SIMD, and one run hit
  the PERF-02 unbounded-wait stall (110 s "lucky" → 204 s → near-hang across
  three runs = non-deterministic). ROOT CAUSE (deeper than phase2): routing
  decided on the COALESCED batch total. The kernel's ~94k ~12 KiB files
  coalesce into 256 MiB batches that clear the 16 MiB high-tier solo floor,
  so EVERY batch routed to GPU even though no single file is GPU-sized. The
  GPU then re-scans every byte, surfaces a literal hit for every detector
  prefix across 256 MiB, and hands the CPU the same per-chunk phase-2 it
  would have run anyway — plus coalesce/PCIe/readback the SIMD path skips.
  FIX LANDED 2026-05-30: `select_backend_for_batch(caps, total, patterns,
  large_chunk_bytes)` (crates/scanner/src/hw_probe/select.rs) gates GPU on
  large-chunk DOMINANCE — large-file bytes (chunks >= the tier per-file floor)
  must be >= half the coalesced batch. A largest-single-chunk guard was tried
  first and FAILED in verification: the kernel's 55 files >= 2 MiB are
  sprinkled through the walk, so nearly every 4096-file batch caught one and
  still routed to GPU (default measured 158 s, 326 % CPU — mixed path). The
  dominance bar a tiny-file swarm can never clear no matter how the large
  files cluster, while a big-file-dominated batch still gets the device.
  `KEYHOG_BACKEND=gpu` override and the simd-pinned benchmarks are unchanged.
  dispatch.rs sums per-batch large-chunk bytes (chunks >= gpu_min_bytes floor)
  and passes them. 7 new routing_matrix tests lock the contract (pure-swarm →
  SIMD, few-large-riding-along → SIMD, large-dominated → GPU, 50%% boundary
  inclusive, env-override, single-large-file equivalence, no-GPU). 29/29
  routing tests green. Verifying default-path wall-clock on release-fast next.

## Resource / overhead

- **PERF-03 · MED · 32 tokio worker threads spawned for a filesystem scan** —
  the kernel-scan process carried 32 `tokio-rt-worker` threads (one per core)
  even with verification off and no network source. The async runtime is for
  the verifier/HTTP; a plain `scan <dir>` shouldn't pay a full multi-thread
  runtime. Size the runtime to demand (lazy / current-thread until a network
  source or verification is actually used), or cap workers. Pure overhead at
  scale.
  FIX LANDED 2026-05-31: the CLI entrypoint now uses
  `#[tokio::main(flavor = "current_thread")]`, keeping async signal handling,
  daemon, update, repair, and verifier futures on a single runtime thread while
  scan parallelism remains in Rayon. Regression gate:
  `main_uses_current_thread_tokio_runtime`.

- **PERF-04 · LOW · dedicated reader pool doubles rayon thread count** — the
  PERF-01 fix adds a reader pool sized to the global pool, so a 32-core box
  runs ~64 rayon threads (+ codewalk + tokio). Intentional (read/scan
  overlap is the point) and OS-scheduled, but reader work is I/O/decode-bound
  and needs fewer threads than CPU-bound scanning. FIX LANDED 2026-05-31:
  `FilesystemSource` now sizes the dedicated reader pool to half the scanner
  pool with a 16-thread cap and a two-thread minimum. A 32-core host now runs
  16 reader workers instead of 32, preserving the deadlock fix while reducing
  scheduler pressure on large-tree scans. Gate:
  `filesystem_reader_pool_is_smaller_than_scan_pool_on_large_hosts`.

## Throughput (mirror, for reference — not the scale target)

- Mirror corpus: ~0.71 ms/file overhead measured pre-deadlock-investigation.
  The real lever is large files/repos via GPU coalescing + per-file overhead;
  re-measure once PERF-01/02 land and the kernel scan completes, then chase
  the 100x absolute-speed target against a kernel-scan wall-clock baseline.

## PERF-08 — kernel scan is COMPUTE-bound + ~65% SERIAL, not IO, not matching (2026-05-31)

Fresh baseline (current binary): full kernel 90.4s wall / 185% CPU / 2.4GB RSS.
Thread-scaling sweep on a 6772-file / 160MB kernel subset (drivers/net):

  | --threads | wall   | CPU  |
  |-----------|--------|------|
  | 1         | 24.8s  | 101% |
  | 4         | 15.6s  | 163% |
  | 16        | 16.1s  | 184% |
  | 32        | 16.2s  | 192% |

Speedup saturates at ~4 threads, max 1.55x over single-thread → Amdahl serial
fraction ~0.65. CPU plateaus at ~1.9 cores on a 32-thread box.

NOT IO-bound: corpus is local NVMe ext4 and fully page-cached — raw
`cat $(subset)` reads 160MB in 0.06s (File system inputs: 0). So the 16s is
keyhog CPU, and ~65% of it runs single-threaded.

NOT the matching: `scan_coalesced` (scan.rs) already `par_iter`s chunks on the
global pool; phase-1 HS prefilter rejects ~95% cheaply, phase-2 extracts ~5%.
The parallel matching is a SMALL fraction of wall. The serial 65% is the
pipeline FRAMING: single dispatch consumer draining `sync_channel(64)` one chunk
at a time → batching → `scan_chunk_boundaries` post-pass (serial, O(chunks)) →
result aggregation, plus per-file UTF-8 decode on the reader pool. These run
regardless of --threads, so more cores don't help.

Tooling BLOCKED for a symbolised profile: `perf_event_paranoid=4` (needs sudo to
lower) and the release binary is `strip="symbols"` (0 nm symbols). A proper next
step needs either (a) sudo to drop paranoid + a `debug=line-tables` profiling
build, or (b) valgrind/callgrind on a tiny subset (no perf_event needed) to name
the exact serial frame. Do NOT ship a speculative hot-path change first — the
prior reader-pull rewrite (PERF-05) regressed 84→103s doing exactly that.

Candidate levers once profiled: (1) parallelise `scan_chunk_boundaries`;
(2) batch-pull from the reader channel instead of one chunk at a time;
(3) move UTF-8 decode off the critical path / scan bytes directly;
(4) the 58% fallback-AC-sweep finding (PERF earlier) — verify under a real profile.

### PERF-08 addendum — wall-clock profiling is BLOCKED in this sandbox (2026-05-31)
All three profilers are unavailable here: `perf` (perf_event_paranoid=4, needs
sudo), `valgrind` (not installed), `gdb` attach (ptrace blocked by the sandbox:
"ptrace: Inappropriate ioctl for device"; ptrace_scope=1 also forbids sibling
attach). A symbolised build exists (CARGO_PROFILE_RELEASE_DEBUG=line-tables-only,
29483 syms) but cannot be sampled in-place. To profile, run on the host outside
the sandbox: `sudo sysctl kernel.perf_event_paranoid=1` then
`perf record -g --call-graph dwarf <symbolised keyhog> scan <subset>` /
`perf report`, OR install valgrind and `valgrind --tool=callgrind`. Until then
the serial frame is INFERRED (framing: single-consumer drain + scan_chunk_boundaries
+ utf8 decode), not measured. No speculative hot-path change shipped (PERF-05
regressed doing that).

### PERF-08 resolution — decode recursion, not serial framing, was the dominant kernel wall (2026-05-31)

The symbolised-profile hypothesis above was superseded by `KH_PERF` phase
timing plus directory isolation. The hot file was:

`/mnt/FlareTraining/santh-corpus/repos/linux/drivers/net/wireless/broadcom/b43/main.c`

It is a 156 KB C source file with zero findings. Before the fix it cost
15.7 s wall by entering the no-Hyperscan-hit multiline branch, which called
full `scan(chunk)`. That re-entered postprocess decode on ordinary source,
spliced thousands of decoded candidates back into parent-sized chunks, and
rescanned them.

Fixes landed:

- The SIMD coalesced no-hit multiline path now scans changed multiline
  preprocessed text directly and does not re-enter full scan/postprocess
  decode.
- Decoded splice-back keeps a bounded context window around the encoded
  payload instead of cloning the whole parent file per candidate.
- `--no-decode` now really sets `max_decode_depth = 0`; `--fast` now prints
  and runs with decode, entropy, and ML disabled.
- `KH_PERF=1` now reports coalesced p1/p2/boundary and orchestrator
  scan/receive-wait timing.

Measured warm-cache results on the RTX 5090 host, SIMD forced:

| workload | before | after |
|----------|--------|-------|
| `b43/main.c` | 15.7 s wall, p2 15.6 s, 0 findings | 0.27 s wall, p2 0.093 s, 0 findings |
| `drivers/net` | 15.6 s wall, p2 batch 15.15 s, 1 finding | 0.62 s wall, p2 batches 0.194 s + 0.084 s, 1 finding |
| full Linux kernel | 90.4 s wall / 2.4 GB RSS | 3.43 s wall / 2.1 GB RSS |
| CredData warm SIMD | 4.19 s wall / 2.64 GB RSS baseline | 4.59 s wall / 2.67 GB RSS |

The full-kernel finding count changed from the older 22-finding artifact to
15; the seven removed findings are stale source-code false positives
(`0x000...` register constants and `CSB_*COUNT/RESULT` enum-style symbols),
not planted credentials. Live GPU evidence remains green:
`backend --self-test --json` reports RTX 5090 `status=pass`,
`recommended_backend=gpu`, and `vyre_ac_kernel=pass`.

### PERF-05 / PERF-08 resolution — the consumer-side serial funnel is GONE (fused parallel read+scan, 2026-06-10)

PERF-05's NARROWED LEVER (the single main-thread chunk drain + single scanner
thread giving ~2 effective cores of 32, "stop routing every tiny chunk through
one drain thread") is RESOLVED. The fix is the **fused parallel read+scan
pipeline** `scan_sources_fused` (`crates/cli/src/orchestrator/dispatch.rs`),
now the default for CPU/SIMD filesystem scans (`should_use_fused_pipeline`).
It batches chunks off the reader channel and runs every batch through
`scan_coalesced` on the global rayon pool via `par_bridge` — no single-thread
drain, no single scanner thread. The legacy single-drain batch pipeline
(`scan_sources`) is kept only for the GPU/MegaScan coalesce model and is
selected by `backend_requires_legacy_gpu_pipeline` (explicit `--backend gpu`)
or `KEYHOG_LEGACY_PIPELINE=1`; auto/default stays fused even on GPU hosts.

Remeasured warm-cache on the full Linux kernel (94825 files, 2.0 GB at
`/mnt/FlareTraining/santh-corpus/repos/linux`), 32-core / 91 GB box, release:

  | path                         | wall   | CPU    | effective cores |
  |------------------------------|--------|--------|-----------------|
  | fused (default)              | 4.25 s | 1833 % | ~18 of 32       |
  | legacy (`KEYHOG_LEGACY_PIPELINE=1`) | 7.12 s | 749 % | ~7              |

Thread scaling 1→32 on the fused path: 40.78 s → 4.25 s = **9.6× → Amdahl
serial fraction ~0.075** (was ~0.65 / ~2 cores in the PERF-08 framing above).
Finding set is BYTE-IDENTICAL across default / `--backend simd` / legacy:
27 findings (21 generic-secret, 3 cloudsmith, 2 devcycle, 1
github-app-private-key). Guarded by `pipeline_fused_and_legacy_agree`
(fused == legacy finding set), `pipeline_auto_filesystem_uses_fused` (routing),
and `scan_bigtree_completes_and_recalls`.

Tier-A throughput knobs added (compiled default → env override, no CLI/TOML
surface yet): `KEYHOG_FUSED_BATCH` (default 32 chunks/batch — amortises
`scan_coalesced`'s own two-phase `par_iter` fork-join barrier) and
`KEYHOG_FUSED_DEPTH` (reader→scanner `sync_channel` depth, default
`clamp(threads*¾, 2, 8)`). The 256-default sweep was inconclusive and the
default stays at the proven 32; the knobs let the optimum be retuned per host
without a rebuild. Always MEASURE on the kernel before shipping a hot-path
default — the prior reader-pull `into_par_iter` rewrite regressed 84→103 s.

CAVEAT — absolute kernel wall-clock is in flux: an in-progress scanner refactor
(GPU subcrate removal + `megakernel.rs`/`scan.rs` rewrite, uncommitted as of
2026-06-10) is actively changing `scan_coalesced` phase-2 cost, so a binary
built from the working tree mid-refactor does NOT reflect the 4.25 s number
above. Re-measure the fused-vs-legacy wall on the kernel once that refactor
lands. The serial-funnel ARCHITECTURE fix (this section) is independent of it
and is locked by the three parity/routing tests.
