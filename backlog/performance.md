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
  → testing gap: no large-tree (50k+ file) scan test exists; the whole class
  was invisible. Add a generated wide-tree e2e that asserts completion under
  a wall-clock deadline (T-perf-bigtree).

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
  - Only ~4 workers hot because DEFAULT_WINDOW_SIZE = 64 MiB
    (crates/sources/src/filesystem.rs:21) and the kernel's LARGEST file is
    22 MiB, so NO file is windowed - every file is a single chunk pinned to one
    rayon worker. A batch's heavy work lives in its few large single-chunk
    files, so per-batch `par_iter` lights ~4 workers and parks the other 12.
  LEVERS (measure each on the kernel before/after; do NOT hand-tune blind):
    L1 (parallelism, ~4x ceiling): window files at ~1-4 MiB so multi-MB files
       split into CPU-count sub-chunks that spread across workers. Watch the
       4 KiB overlap for boundary-spanning secrets and extra per-chunk cost.
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
  regression gate added; forced `gpu_parity` remains a separate red gate
  because the runtime GPU dispatch currently hard-fails under
  `KEYHOG_REQUIRE_GPU=1` even though `keyhog backend --self-test` passes.
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

- **PERF-04 · LOW · dedicated reader pool doubles rayon thread count** — the
  PERF-01 fix adds a reader pool sized to the global pool, so a 32-core box
  runs ~64 rayon threads (+ codewalk + tokio). Intentional (read/scan
  overlap is the point) and OS-scheduled, but revisit sizing once PERF-01 is
  verified — readers are I/O/decode-bound and may need fewer threads than the
  CPU-bound scanner. Measure read-vs-scan balance on the kernel and right-size
  (candidate: readers = max(2, cores/2)).

## Throughput (mirror, for reference — not the scale target)

- Mirror corpus: ~0.71 ms/file overhead measured pre-deadlock-investigation.
  The real lever is large files/repos via GPU coalescing + per-file overhead;
  re-measure once PERF-01/02 land and the kernel scan completes, then chase
  the 100x absolute-speed target against a kernel-scan wall-clock baseline.
