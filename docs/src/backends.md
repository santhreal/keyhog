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
| `gpu` (`gpu-region-presence`) | VYRE GPU region-presence matching feeding the shared confirmation pipeline | Higher initialization/dispatch cost; can win on large or persistent workloads. |
| `auto` | Exact lookup in a persisted, parity-checked calibration table | Default. It is a selector over all eligible engines, not a fallback order. |

`--backend` is an explicit diagnostic or benchmark override. It bypasses
autoroute; it does not prove that the chosen engine is fastest for the input.

The Rust library deliberately has a different default contract. Calling
`CompiledScanner::scan` or `scan_coalesced` without a backend uses the portable
`cpu-fallback` reference, so identical library code does not change execution
with host hardware or local calibration files. Library callers that want
acceleration choose `scan_with_backend`/`scan_coalesced_with_backend`; the CLI
is the owner of persisted automatic routing.

## What “same results” means

Calibration compares canonical match identity: chunk index, detector id,
credential hash, file path, line, and byte offset. A candidate is rejected if
that identity differs from the Hyperscan reference, if repeated reference trials
are inconsistent, or if required GPU timing evidence is invalid. Normal
automatic scans do not benchmark or silently replace a rejected backend.

This parity contract covers match bytes and offsets before the common
suppression, confidence, verification, deduplication, and reporter stages. The
same detector TOML corpus and resolved configuration digest identify every
route. Report confidence is canonicalized to three decimal places at the shared
policy boundary; this removes meaningless CPU-f64/GPU-f32 accumulator ULPs
before both the reporting-floor decision and serialized output.

## Why size alone is insufficient

Two inputs with the same byte count can have different winners. Autoroute also
keys evidence by stable logarithmic ranges for bytes, chunk count, largest
source size, and decode density, plus detector/pattern shape, source family,
resolved configuration, build features, and host identity. It does not
interpolate from a neighbouring range key; a measured key nevertheless covers
the values grouped into that range.

Runtime lifetime matters too. A one-shot process includes GPU first-dispatch
cost. A ready daemon has already initialized accelerator state and uses the warm
GPU trials from the same calibration evidence. See
[Daemon and warm scans](./workflows/daemon.md).

## The 8 MiB Hyperscan crossover

The checked RTX 5090 production-window baseline compares the GPU path with the
real parallel Hyperscan path over one 8 MiB source split into 1 MiB windows with
128 KiB overlap. It verifies sorted full-match parity, rejects GPU degradation,
excludes one warmup, and aggregates five process medians. The recorded medians
are 31.4524 ms for GPU and 35.0860 ms for Hyperscan: GPU is about 1.12× faster
in that warm workload.

That evidence proves the warm 8 MiB crossover on the recorded host; it does not
claim that a cold one-shot process, another GPU/driver, dense-match corpus, or
different detector/config digest has the same winner. Autoroute calibration is
what converts hardware- and workload-specific measurements into an exact local
decision. The reproducible metadata lives at
`benchmarks/baselines/gpu_8mib_crossover_rtx5090_2026-07-10.toml` in the source tree.

## When automatic routing refuses to scan

Missing, stale, malformed, or incomplete evidence is an invalid automatic
route. KeyHog exits with a configuration error and prints the missing workload
identity plus the calibration command. Run `keyhog calibrate-autoroute` for the
core ladder or the installer calibration for source-specific probes. Use an
explicit backend only when you intentionally want a diagnostic override.

For cache identity, inspection commands, calibration coverage, and recovery,
see [Autoroute calibration](./reference/autoroute-calibration.md).
