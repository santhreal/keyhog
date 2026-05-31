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
  FIX (planned): bound every GPU wait. Replace `PollType::Wait` with a
  `PollType::Poll` deadline loop + CPU fallback, and `recv()` with
  `recv_timeout()`. Belt-and-suspenders: a dispatch-level watchdog
  (`crates/cli/src/orchestrator/dispatch.rs`) that abandons a GPU batch
  exceeding a deadline, falls back to SIMD, and disables GPU for the rest of
  the run so one stall can't poison the whole scan.

## Parallelism

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
