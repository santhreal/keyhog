# Backends and routing

KeyHog has several execution engines for the same compiled detector policy.
Changing a backend may change performance, startup cost, and hardware use; it
must not change findings, locations, confidence, suppression, verification, or
output ordering.

## The backend choices

| Backend | What it does | Typical cost profile |
|---|---|---|
| `cpu` (`cpu-fallback`) | Pure-Rust literal and regex execution | Portable and cheap to start; useful when native accelerators are unavailable. |
| `simd` (`simd-regex`) | Hyperscan/Vectorscan trigger matching plus the shared extraction and policy pipeline | Fast CPU throughput after compiled databases are loaded; the calibration reference for accelerated builds. |
| `gpu-cuda` (`gpu-cuda-region-presence`) | VYRE CUDA region-presence matching feeding the shared confirmation pipeline | Measured as its own autoroute candidate. |
| `gpu-wgpu` (`gpu-wgpu-region-presence`) | VYRE WGPU region-presence matching feeding the shared confirmation pipeline | Measured as its own autoroute candidate. |
| `auto` | Exact lookup in a persisted, parity-checked calibration table | Default. It is a selector over all eligible engines, not a fallback order. |

`--backend` is an explicit diagnostic or benchmark override. It bypasses
autoroute; it does not prove that the chosen engine is fastest for the input.

The Rust library deliberately has a different default contract. Calling
`CompiledScanner::scan` or `scan_coalesced` without a backend uses the portable
`cpu-fallback` reference, so identical library code does not change execution
with host hardware or local calibration files. Library callers that want
acceleration choose `scan_with_backend`/`scan_coalesced_with_backend`; the CLI
is the owner of persisted automatic routing.

Those explicit-backend methods have infallible finding-vector return types, so
selection is a hard process contract. Unavailable selected SIMD terminates with
exit `3`; unavailable or failed selected GPU execution terminates with exit
`12`. They never return findings from another backend. `warm_backend` probes
startup eligibility in-band, but a process that must contain a later driver or
dispatch failure should run the CLI as a subprocess. The no-backend portable
CPU methods do not acquire an accelerator.

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
identity; source, file, line, offset, commit, author, and date; entropy and
confidence. A candidate is rejected if any field or finding multiplicity
differs from the Hyperscan reference, if repeated reference trials are
inconsistent, or if required GPU timing evidence is invalid. Diagnostics name
only the differing fields and occurrence counts. They never emit raw
values or deterministic value fingerprints. Normal automatic scans do not
benchmark or silently replace a rejected backend.

Among parity-correct candidates, routing uses representative measured medians,
never a lucky fastest trial. A fully separated 95% confidence interval is the
strongest result. Overlapping intervals are disclosed as inconclusive rather
than mislabeled as proof of equal performance; KeyHog then selects the lowest
measured median among the non-dominated candidates, using engagement overhead
only for an exact median tie. Autoroute inspection prints this selection basis.

`scan_coalesced_with_backend` already includes extraction, decode, built-in
suppression, confidence, and scanner postprocessing. Autoroute parity therefore
compares the complete `RawMatch` values returned by that production scanner
path. CLI allowlists and rules, severity and confidence floors, cross-source
deduplication, optional verification, and reporting run after backend selection.
The same detector TOML corpus and resolved configuration digest identify every
route.

## Why size alone is insufficient

Two inputs with the same byte count can have different winners. Autoroute also
keys evidence by logarithmic buckets for bytes, chunk count, largest source
size, and detector pattern count. Decoder work is identified by the observed
decoder-kind mask, candidate-count bucket, candidate-byte bucket, and an
explicit unknown-state bit. Source family, resolved configuration, build
features, and host identity also participate. It does not interpolate from a
neighbouring key; a measured key covers only the values grouped into that key.

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
through `scan_coalesced_with_backend` for Hyperscan and every acquired CUDA or
WGPU peer. It requires sorted full-match parity from each peer, rejects GPU
degradation, and rotates candidate order during peer selection. The selected
exact GPU peer then runs in fresh alternating held-out pairs against Hyperscan.
The gate passes only when the paired GPU/Hyperscan ratio's 95% confidence upper
bound is below 1.0 at 8 MiB. Profiling and perf tracing retain parity and
degradation checks but cannot pass the speed gate.

The canonical checked result is
`benchmarks/baselines/gpu_8mib_crossover_rtx5090.toml`. On its recorded RTX
5090 host, VYRE 0.6.5 CUDA produced the same 143 findings with no degradation,
then measured a 45.6209 ms held-out median against Hyperscan's 47.6683 ms. The
paired GPU/Hyperscan geometric-mean ratio was 0.9542 with a 95% confidence
interval of 0.9383 to 0.9703 across 100 held-out pairs. This is evidence for the
recorded host and workload, not a portable route decision. A new crossover claim
requires a `production_comparable = true` artifact from the corrected route with
exact binary, detector, configuration, host, runtime, workload, peer, and trial
identity. Autoroute still requires calibration on the deployment host for the exact
workload class.

## When automatic routing refuses to scan

Missing, stale, malformed, or incomplete evidence is an invalid automatic
route. KeyHog exits with a configuration error and prints the missing workload
identity plus the calibration command. Run `keyhog calibrate-autoroute` for the
core ladder or the installer calibration for source-specific probes. Use an
explicit backend only when you intentionally want a diagnostic override.

Calibration candidates and explicit backend overrides remain hard execution
contracts. During a normal automatic scan, a runtime GPU fault is warned and
the same stable batch is replayed through the CPU reference path. Recovered
chunks and bytes are reported and do not count as GPU work. If recovery cannot
prove full coverage, the result is incomplete rather than clean.

For cache identity, inspection commands, calibration coverage, and recovery,
see [Autoroute calibration](./reference/autoroute-calibration.md).
