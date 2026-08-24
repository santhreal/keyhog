# Changelog

All notable changes to `keyhog-profile` are documented here. Versions follow [Semantic Versioning](https://semver.org/).

## 0.5.83 - 2026-08-24

- fix(ci): decouple action-e2e version pin from auto-release contract.

## 0.5.82 - 2026-08-24

- fix(cli): gate git-staged ScanArgs fields in hook run; enable futures-util sink.

## 0.5.81 - 2026-08-20

- feat(profile): instrument runtime compile surface counters and phases across `CompileSurfaceId` and `CompilePhase` with deterministic `CausalProfileV2` export (Row 125).
- feat(profile): directional queue attribution distinguishing producer backpressure from consumer starvation (Row 133).
- feat(profile): canonical owner of host parallelism width and provenance resolution (Row 110).
- feat(profile): render tabular Markdown profile and comparison reports with blocked wait time, worker concurrency, and queue depths (Row 108).
- fix(profile): calculate worker occupancy and stage self-time from exclusive span durations without nested container double-counting (Row 104, Row 109).
- feat(gpu): add GPU region dispatch phase decomposition metrics (`GpuMatcherNs`, `GpuCoalesceNs`, `GpuDispatchNs`, `GpuDeriveNs`, `GpuRecallFloorNs`, `Phase2GpuAdmissionNs`) and dispatch detail counters to `keyhog_profile`.

## 0.5.80 - 2026-08-17

- style: format guard massive diff test and git sources modules.

## 0.5.79 - 2026-08-16

- ci(release): fallback token and sync floating major tag on release.

## 0.5.78 - 2026-08-16

- fix(scanner): gate expand_triggered_patterns independently of decode feature.

## 0.5.77 - 2026-08-16

- fix(ci): format scan_postprocess, update dogfood hashes for doc fixtures, and bump action version.

## 0.5.76 - 2026-08-16

- Add `ProfileConfig`, `ProfileName`, `KnownProfile`, and environment lookup routines for zero-allocation profile resolution and secure credential memory zeroization.
- fix(core): rerun build script on GITHUB_SHA changes to prevent stale git hash in CI cache.

## 0.5.75 - 2026-08-14

- Merge remote-tracking branch 'origin/main'.

## 0.5.74 - 2026-08-14

- fix(release): ignore Marketplace-only tags.

## 0.5.73 - 2026-08-14

- fix(release): preflight registry dependencies.

## 0.5.72 - 2026-08-13

- release: publish the tag the bump job creates.

## 0.5.71 - 2026-08-13

- fix(release): consume legacy unreleased notes.

## 0.5.70 - 2026-08-10

- Fail-closed overlapping allocation sessions instead of misattributing process-global peaks

## 0.5.69 - 2026-08-10

- Make `--profile` answer the questions a slow scan raises instead of reporting spans and leaving the conclusion to the reader. Six families are measured now. Memory: peak resident from the kernel high water, the engine-init floor taken on entry to scanning, input-driven resident as peak minus floor, amplification, per-scanner-thread resident, and allocation volume owned per stage. Parallelism: per-worker busy and blocked time from outermost spans only so nesting never double-counts, idle against pool capacity, achieved speedup as process CPU over wall, an Amdahl ceiling from measured serial work, and time inside instrumented regions while not on CPU, which is where a large pool loses speedup without going idle. Serial phases: per-stage wall windows giving average concurrency, plus an exclusivity measure separating a real barrier from an inclusive wrapper whose children are the parallel work. Throughput: MiB/s and files/s overall, per phase and per micro-function. Attribution: cost per call, per file, per byte, per detector family and per backend. Cache and reuse: hit rates for autoroute decisions, calibration reuse, incremental unchanged-skips, matcher artifacts and verifier results, through one CacheId vocabulary. Retry attempts are counted by cause and named as a finding, because a retry that fires is a failure that was not designed out. The first line of the summary is the conclusion, for example `bottleneck memory-floor 62.9 MiB of the 68.0 MiB peak (92.5%) is standing the engine up, not the input`. Verified on the mirror corpus, `crates/`, and a 300 MiB file: the profiler independently reproduces the engine-init floor, the per-scanner-thread scratch slope over a thread sweep, and resident amplification on a large file, all of which previously took `/usr/bin/time` and shell loops. This changes `--profile` stderr, which gains the summary above the existing span table, and the `--profile-out` document, which gains stage_concurrency, worker_occupancy, queue_depths, blocked_waits, caches, indexed_counters, retries and insight. Every new field carries a serde default so older records still decode, and the profile schema minor moves 2.7 to 2.8. Default scan output, findings and exit codes are unchanged. Every derived value is an integer in thousandths or parts per million, so two records diff exactly and an unchanged run cannot look changed. Recording stays free when profiling is off: the disabled path is one relaxed atomic load with no clock read.

- BufferedStdinSource now records the same SourceAcquire and SourceRead profile spans as spooling stdin, so pre-owned stdin payloads no longer appear unprofiled while still charging input totals.
- Cap retained batch-route records and count drops like other profile event streams
- Deallocate Mach thread ports after task_threads sampling so utilization samples do not leak send rights
- Clear the per-worker shards in `keyhog_profile::reset()`. It cleared the runtime-level stores and the legacy mirrors and never touched the shards, so stage times, call counts, latency buckets, stage windows, typed counters, input bytes, cache counts and indexed counters all survived it. Benchmarks call `profile_reset()` between measured rounds precisely to discard warm-up, so round two reported round one's numbers as its own. Nothing failed and no output looked wrong; the second measurement was simply the first plus the second. A test now asserts each family is empty after a reset. Separately, the fixed-memory finding no longer keys on an absolute byte threshold: it was calibrated against a 483 MiB engine-init floor, and once that floor dropped to 63 MiB the finding sat four MiB from going silent while its diagnosis stayed true. It now keys on the share of peak that is fixed cost, which is the actual claim and holds at any scale.
- Gap system IO evidence when no start sample exists instead of publishing absolute /proc counters

- Fail-closed TrackingAllocator dealloc validates header magic/stage/bytes before SLOT indexing

## 0.5.68 - 2026-08-05

- Scanner source files freed of large co-located test suites.

## 0.5.67 - 2026-08-05

- Filesystem enumeration-order contract.

## 0.5.66 - 2026-08-04

- Whole-tree GPU guidance in the backends guide.

## 0.5.65 - 2026-08-04

- Actionable GPU refusal diagnostics.

## 0.5.64 - 2026-08-04

- README evidence panels remeasured against the current detector corpus.

## 0.5.63 - 2026-08-04

- Mailchimp datacenter key routing.

## 0.5.62 - 2026-08-04

- Routing literals for every prefixless detector pattern.

## 0.5.61 - 2026-08-04

- Character-class token anchoring for short vendor prefixes.

## 0.5.60 - 2026-08-04

- Token-boundary anchoring for short vendor prefixes.

## 0.5.59 - 2026-08-04

- Token-boundary anchoring and an actionable autoroute parity rejection.

## 0.5.58 - 2026-08-04

- README evidence panels remeasured against the current binary.

## 0.5.57 - 2026-08-04

- Repeatable autoroute calibration.

## 0.5.56 - 2026-08-04

- Overlapping coalesced batches and autoroute classification for any batch size.

## 0.5.55 - 2026-08-04

- Idempotent source contract-test generator and a warning-free workspace build.

## 0.5.54 - 2026-08-04

- Skip homoglyph variants on chunks that provably contain no confusable glyph.

## 0.5.53 - 2026-08-04

- Make the coalesced batch pipeline eleven times faster and stop starving the accelerator.

## 0.5.52 - 2026-08-04

- Refuse configuration fields the scanner cannot honour and check every documented command against the real CLI.

## 0.5.51 - 2026-08-04

- Make the portable phase-two prefilter two to three times faster and repair ten red gates.

## 0.5.50 - 2026-08-02

- Add low-overhead causal run profiling with fixed scanner stages, state transitions, process resource measurements, and explicit source and backend identity while keeping per-pattern diagnostics behind --perf-trace.
- Add nested causal events, fixed-memory latency distributions, typed counters, gauges, events, annotations, bounded sampling, async context propagation, and explicit point-event, annotation, and span loss counts.
- Enforce optimized hot-path budgets in CI for disabled checks, aggregate spans, and complete causal span recording.
- Add cross-thread causal parent tokens, producer-consumer queue links, queue depth high-water marks, blocked-wait accounting, typed work origins, task and worker identities, deterministic shard merging, and worker imbalance measurements.
- Record legacy-mode typed counters and distributions so `--perf-trace` diagnostics flow through one runtime-owned drain.

## 0.5.49 - 2026-07-31

- Added fixed-stage timing, causal run identity, explicit state transitions, process resource sampling, and portable JSON and text reports.
