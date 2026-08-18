# Backends and routing

KeyHog has several execution engines for the same compiled detector policy.
Changing a backend may change performance, startup cost, and hardware use; it
must not change findings, locations, internal confidence, evidence verdicts,
suppression, verification, or output ordering.

For the repository map, dependency direction, and bytes-to-finding pipeline,
see [Architecture](./architecture.md).

## The backend choices

| Backend | What it does | Typical cost profile |
|---|---|---|
| `cpu` (`cpu-fallback`) | Pure-Rust literal and regex execution | Portable and cheap to start; useful when native accelerators are unavailable. |
| `simd` (`simd-regex`) | Hyperscan/Vectorscan trigger matching plus the shared extraction and policy pipeline | Fast CPU throughput after compiled databases are loaded; the calibration reference for accelerated builds. |
| `gpu-cuda` (`gpu-cuda-region-presence`) | VYRE CUDA region-presence matching feeding the shared confirmation pipeline | Measured as its own autoroute candidate. |
| `gpu-metal` (`gpu-metal-region-presence`) | VYRE native Metal region-presence matching feeding the shared confirmation pipeline | Measured as its own autoroute candidate on macOS. |
| `gpu-wgpu` (`gpu-wgpu-region-presence`) | VYRE WGPU region-presence matching feeding the shared confirmation pipeline | Measured as its own autoroute candidate. |
| `auto` | Exact lookup in a persisted, parity-checked calibration table | Default. It is a selector over all eligible engines, not a fallback order. |

## Use automatic routing for normal scans

Start with a calibrated automatic route:

```sh
keyhog calibrate-autoroute
keyhog backend --autoroute
keyhog scan .
```

The last command is equivalent to `keyhog scan . --backend auto`. Cargo
cannot execute a binary after `cargo install`, so run the first command once
after installing a multi-backend Cargo build and again after any binary, driver,
hardware, or routing-relevant configuration change. A scalar-only build needs no
calibration and reports `health: direct`. `auto` performs an exact cache lookup.
It does not try backends in order and does not benchmark during the scan.

For a healthy multi-backend installation, `keyhog backend --autoroute` reports
`health: ready`. A scalar-only build reports `health: direct` because it has no
backend choice to calibrate.


`--backend` is an explicit diagnostic or benchmark override. It bypasses
autoroute and its calibration cache:

```sh
keyhog scan . --backend cpu
keyhog scan . --backend simd
keyhog scan . --backend gpu-cuda
keyhog scan . --backend gpu-metal
keyhog scan . --backend gpu-wgpu
```

Use these commands to compare engines or isolate a driver problem. Do not put an
explicit backend in a routine scan configuration. It does not prove that the
chosen engine is fastest for the input, repair autoroute evidence, or publish a
route decision.

An explicit backend is a hard execution contract. If it was not compiled, its
runtime is unavailable, initialization fails, or dispatch fails, the scan
returns an error. KeyHog does not substitute CPU, SIMD, or another GPU peer.
`gpu-cuda`, `gpu-metal`, or `gpu-wgpu` are separate choices. There is no
generic `gpu` override.

## Check SIMD and GPU availability

Inspect discovery before forcing an accelerator:

```sh
keyhog --version --full
keyhog backend --self-test
keyhog backend --self-test --require-gpu
```

`--version --full` reports whether the running binary can see
Hyperscan/Vectorscan and a physical GPU. This is a discovery report, not an
execution test. `backend --self-test` executes the GPU diagnostic and production
dispatch paths. It reports `SKIP` and exits successfully when no physical GPU is
available. Add `--require-gpu` to make that condition fail. After calibration,
`keyhog backend --autoroute --json` records the exact `eligible_backends` set
that was measured.

The scalar `cpu-fallback` backend is always the portable reference. The
`simd-regex` backend requires a build with scanner SIMD support and a usable,
identifiable Hyperscan/Vectorscan runtime. A CPU with AVX2 or AVX-512 alone does
not provide that runtime. GPU candidates require scanner GPU support, a
physical device, and a usable driver path. CUDA, native Metal, and WGPU are
acquired and measured independently, so one available peer does not imply that
another is available. Diagnose exact engines with `--backend simd`
(`simd-regex`), `gpu-cuda` (`gpu-cuda-region-presence`), `gpu-metal`
(`gpu-metal-region-presence`), or `gpu-wgpu`
(`gpu-wgpu-region-presence`).

## Library backend contract

The Rust library deliberately has a different default contract. Calling
`CompiledScanner::scan` or `scan_coalesced` without a backend uses the portable
`cpu-fallback` reference, so identical library code does not change execution
with host hardware or local calibration files. Library callers that want
acceleration choose `scan_with_backend`/`scan_coalesced_with_backend`; the CLI
is the owner of persisted automatic routing.

Those explicit-backend methods return typed `Result` values. Unavailable
selected SIMD or GPU backends and later runtime failures return `ScanError`;
they never terminate an embedding process and never return findings from
another backend. `warm_backend` probes startup eligibility in-band. The
`keyhog` CLI separately maps terminal scanner errors to its documented exit
statuses. The no-backend portable CPU methods do not acquire an accelerator.

The GPU literal matcher keeps its immutable VYRE tables resident after the
first successful batch. One dispatch returns both region presence and complete
positions for the shared confirmed-anchor and generic-keyword localizers.
Backend-shaped phase-two DFA catalogs are also immutable
for the compiled detector set and are reused across scans. Haystack and region
capacity grow in bounded bands from the actual workload. KeyHog serializes each
resident session so concurrent
requests cannot interleave uploads against the same device buffers. Preparation,
growth, match-output overflow, dispatch, and readback errors remain selected-GPU failures. Teardown
cleanup errors are logged. There is no per-batch pipeline or CPU substitution.
Each physical dispatch accepts at most 65,536 positioned literal matches, which
bounds resident readback to 768 KiB. Exceeding that cap returns no partial
evidence: automatic routing visibly replays the stable bytes, while an explicit
or required GPU route fails its backend contract.

A coalesced request above the smaller of the live VRAM/config budget and the
selected backend's hard ceiling is split between source chunks. An individually
oversized chunk is scanned through physical windows whose overlap covers the
longest compiled GPU literal. Window presence rows are OR-reduced and position
rows are offset-adjusted and deduplicated into one logical source row before
phase-two evidence is consumed. A complete region-presence
request above 4,096 physical dispatches fails visibly before execution instead
of amplifying chunk count or custom-detector overlap without bound.
Prefixless phase-two GPU regex admission stays on whole chunks because regex
width may be unbounded. Oversized rows retain the authoritative CPU no-hit
admission path instead of accepting an unsafe GPU negative. Readback words are
consumed through a scoped borrow while the resident session is locked, then
zeroized without discarding the warmed host allocation.

## What “same results” means

Calibration compares the complete `RawMatch` identity: chunk index; detector
id, name, service, and severity; exact credential, stored-hash, and companion
identity; source, file, line, offset, commit, author, and date; entropy,
internal confidence, evidence tier, and evidence reason. A candidate is rejected
if any field or finding multiplicity differs from the Hyperscan reference, if
repeated reference trials are inconsistent, or if required GPU timing evidence
is invalid. Diagnostics name
only the differing fields and occurrence counts. They never emit raw
values or deterministic value fingerprints. Normal automatic scans do not
benchmark or silently replace a rejected backend.

Each backend is measured with phase-two plain-pattern localization disabled and
enabled. The persisted route owns both choices, so concurrent scans never mutate
scanner-global tuning and decode or recovery replays retain the selected route.

Among parity-correct candidates, routing uses complete trial distributions,
never a lucky fastest trial. The selected route's 95% confidence interval must
lie below every other eligible execution route. Phase-two localization plans
are distinct routes even when they use the same backend, so overlapping
same-backend timings are inconclusive rather than permission to choose the
lowest median. Overlap that separates nothing at all resolves to the
lowest-complexity backend inside the fastest route's own 95% upper bound,
reported as a dead heat rather than as a proved win. Autoroute inspection
prints this selection basis.

`scan_coalesced_with_backend` already includes extraction, decode, built-in
suppression, confidence, and scanner postprocessing. Autoroute parity therefore
compares the complete `RawMatch` values returned by that production scanner
path. CLI allowlists and rules, severity and confidence floors, cross-source
deduplication, optional verification, and reporting run after backend selection.
The same detector TOML corpus and resolved configuration digest identify every
backend and localization plan.

## Why size alone is insufficient

Two inputs with the same byte count can have different winners. Autoroute also
keys evidence by logarithmic buckets for bytes, chunk count, largest source
size, and detector pattern count, plus one boolean recording whether any
decoder was admitted. Source family, resolved configuration, build features,
and host identity also participate.

A measured key covers only the values grouped into that key. A size band nobody
measured is served only when at least two measured bands of the same source
class and decode state reconcile to one route: a backend measured at every one
of them and proved slower at none, on the compiled default plan when they split
on the plan. Never for a GPU route. See
[Autoroute calibration](./reference/autoroute-calibration.md).

Runtime lifetime matters too. A one-shot process includes GPU first-dispatch
cost. A ready daemon has already initialized accelerator state and uses the warm
GPU trials from the same calibration evidence. See
[Daemon and warm scans](./workflows/daemon.md).

## The 8 MiB Hyperscan crossover

The July 10 RTX 5090 artifact is retained for regression history, but it is not
release or routing evidence. Its SIMD timing used the generic per-chunk entry
point instead of the faster production coalesced Hyperscan path. The artifact is
marked `production_comparable = false` and must not support a crossover claim.

The checked benchmark now sends identical 1 MiB windows with 128 KiB overlap
through the explicit production execution-route entry point for Hyperscan and
every acquired CUDA, Metal, or WGPU peer. It measures all four combinations of
plain-pattern and keyword-anchor localization and every resident pipeline depth
the peer declares eligible. Synchronous peers expose depth one. Asynchronous
peers expose depths one through four.
It requires sorted full-match parity from every route, rejects GPU degradation,
and rotates candidate order during selection. Selection-only samples choose one
measured-correct GPU route and one measured-correct Hyperscan route. Both routes
then run in 300 fresh rotating held-out trials. Every other parity-correct
Hyperscan route also runs in those trials and remains visible in the artifact,
but no held-out observation can change either selected route.

The gate passes only when the selected GPU to selected Hyperscan paired ratio's
95% confidence upper bound is below 1.0 at 8 MiB. A slower CPU tuning choice
cannot make the GPU result look favorable because independent selection compares
all eligible localization plans before the held-out phase. A per-trial minimum
across several CPU plans is not an eligible backend and is not used as a
hindsight oracle. A forced plain or keyword localizer filter, profiling, or perf
tracing retains parity and degradation checks but cannot pass the release speed
gate.

Schema 10 records both selected backends, localization choices, and the GPU
pipeline depth, every route-selection sample, and a separate held-out confidence
interval for each Hyperscan plan. `crossover_passed` is based only on the
independently selected GPU and Hyperscan routes.
Use `--diagnostic` for an unprofiled 8 MiB measurement from a dirty development
tree. That mode retains exact parity and degradation checks but records
`diagnostic = true`, `production_comparable = false`, and cannot pass the
release gate.

Diagnostic runs may isolate either localization dimension with
`KH_BENCH_PHASE2_PLAIN_LOCALIZER=0|1` or
`KH_BENCH_PHASE2_KEYWORD_LOCALIZER=0|1`. Setting either variable makes the run
ineligible for release evidence; an unrestricted run measures all four plans.

Use `--profile` to attribute scanner stages to exact routes. Candidate selection
and held-out trials remain unprofiled; after timing, the benchmark runs one
isolated scan for each Hyperscan localization plan and the selected GPU route.
Profile labels include the backend, both localization values, and the resident
pipeline depth, so costs from different execution plans are never merged into
one report. Profile runs cannot pass the release gate.

The checked artifact at
`benchmarks/baselines/gpu_8mib_crossover_rtx5090.toml` retains the last measured
timing and parity distribution, but it is historical rather than release
evidence because that run did not attest a clean source tree. It recorded 143
identical findings with no degradation, a 24.5886 ms VYRE CUDA median versus
69.5641 ms for Hyperscan, and a paired ratio confidence interval of 0.3482 to
0.3579 across 100 held-out pairs. Those measurements cannot prove the current
release binary is reproducible from the recorded commit. A new crossover claim
requires `build_source_tree_state = "clean"`, `source_tree_state = "clean"`, and
`production_comparable = true` from the corrected route with exact binary,
detector, configuration, host, runtime, workload, result count, peer, and trial
identity. The build script watches the tracked and non-ignored source inventory,
so cleaning a tree after compiling dirty source forces a rebuild before the
artifact can qualify.

Run the crossover benchmark when you change backend performance or routing.
Release automation does not run it. The benchmark remains the evidence for
route comparisons: it records the candidate commit, detector digests, feature
set, GPU identity, finding parity, held-out pairs, and confidence interval.
Autoroute still requires calibration on the deployment host for the exact
workload class.

## What the GPU does for a whole-tree scan

The crossover above measures one 8 MiB window through the matching kernel. A
repository scan is a different workload, and the answer there is different, so
measure before you choose a backend for one.

Scan a tree with each backend and compare. These are median wall times over five
runs on an RTX 5090 with a Ryzen 9 9950X, scanning copies of this repository:

| Input | Pure-Rust CPU | CUDA | Difference |
|---|---:|---:|---:|
| 63 MiB | 4.22 s | 4.64 s | +9.9% |
| 251 MiB | 10.43 s | 11.34 s | +8.7% |

The GPU route is slower, by roughly the same percentage at both sizes, so this
is not a startup cost that a larger tree amortizes away.

The reason is which stage the GPU accelerates. A scan runs phase one, which
finds candidate regions, and phase two, which confirms them against the full
detector patterns. The GPU runs phase one. Phase two runs on the CPU in both
cases, and phase two is the larger cost: a `--perf-trace` of one 4,096 chunk
batch shows `dispatch=0.04s` for the GPU kernel against `phase2=0.39s` for
confirmation. The GPU shortens the smaller half and adds its own dispatch and
transfer on top of an unchanged larger half.

You can see the same thing in the trace field `phase2_gpu_ascii_patterns`. It
reads `0` on this detector corpus, meaning no pattern is eligible for the GPU
phase-two path, so none of the confirmation work moves off the CPU.

What to do with that:

- For a repository, container, or history scan, leave routing automatic. The
  calibrated router measures both and will pick the CPU route when it is faster.
- Use an explicit `--backend gpu-cuda` for diagnostics, parity checks, and
  kernel-level benchmarking, not because you expect a whole-tree scan to finish
  sooner.
- Findings do not depend on the choice. Every route reports the same secrets,
  which is what the parity contract above guarantees.

## Memory footprint and zero-allocation execution

KeyHog is designed to scan multi-gigabyte repositories and large disk images with
a bounded memory footprint.

### Streaming windowing and rendezvous channels

Files larger than 1 MiB are divided into overlapping 1 MiB windows with 128 KiB
overlap. The filesystem reader uses a rendezvous queue (`fused_depth = 0`), so
windows are handed directly to the scanner workers without accumulating resident
memory in crossbeam channels.

### Zero-allocation source semantic indexing

Structured configuration and source AST indexing in `StructuredSourceIndex` uses
compact byte offsets (`SourceSpan`) and fixed-size stack arrays
(`[SourceSpan; 12]`) rather than allocating heap strings or nested hash maps.
Tokens are referenced as borrowed slices of the original window.

### Bounded GPU scratch and readback buffers

The GPU execution engine bounds device allocations and host transfers:

- Resident literal tables are compiled once and reused across dispatches.
- Match readback buffers are capped at 65,536 entries (768 KiB), preventing
  high-candidate inputs from triggering host memory allocation spikes.
- Oversized chunks are sliced into physical windows, uploaded within the
  configured `--gpu-batch-input-limit`, and reduced on-device before transfer.

### Memory tuning controls

| Setting | Default | Flag | Description |
|---|---|---|---|
| Fused batch size | `1024` | `--fused-batch <N>` | Maximum chunks grouped into one scanner batch. |
| Fused queue depth | `0` | `--fused-depth <N>` | Maximum completed chunk batches queued in RAM. Default `0` (rendezvous) minimizes resident heap. |
| GPU batch input limit | Adaptive (128M-1G) | `--gpu-batch-input-limit <SIZE>` | Byte budget for GPU coalesced batch buffers. |
| Scanner threads | CPU count | `--threads <N>` | Number of parallel worker threads. |
| Reader threads | `1` | `--reader-threads <N>` | Number of dedicated filesystem reader workers. |

## Automatic routing failures and recovery

Automatic routing has two visible failure states. Neither one changes an
explicit backend contract.

### The route state is invalid

Missing, stale, malformed, disabled, incomplete, or quarantined evidence cannot
authorize an automatic route. KeyHog prints the missing workload identity and a
repair command. No backend is selected. The affected batch remains unscanned,
metadata-bearing output records partial coverage, and the process exits
non-success.

Run `keyhog backend --autoroute` to distinguish `calibration_required`, `stale`,
`invalid`, `disabled`, and `quarantined`. Run `keyhog calibrate-autoroute` for
the core ladder. For Git, Docker, or web workloads, run the exact
`scan --autoroute-calibrate --autoroute-gpu` repair command printed in the
routing diagnostic.

Use an explicit backend only when you intentionally want a diagnostic override.
It bypasses the invalid route state but does not repair it.

### A selected automatic backend faults

During a normal automatic scan, an accelerated backend fault is warned and the
same stable bytes are replayed through the confidence-separated fastest
remaining peer. GPU recovery replays only exact unprocessed intervals. A
backend that fails before scanning replays the full stable batch. Completed
dispatches remain owned by their original backend.

This recovery is not silent. KeyHog reports the failed and recovery backends,
recovered ranges, chunks, and bytes, and records `complete_after_recovery`. The
exact workload route is quarantined in a bounded runtime-health artifact. That
artifact is separate from immutable timing evidence, survives restart, and
clears the repaired workload only after successful recalibration. If recovery
cannot prove full coverage, the result is incomplete rather than clean.

Calibration candidates, explicit backend overrides, and `--require-gpu` remain
hard execution contracts. They fail instead of recovering through another
backend.


For cache identity, inspection commands, calibration coverage, and recovery,
see [Autoroute calibration](./reference/autoroute-calibration.md).
