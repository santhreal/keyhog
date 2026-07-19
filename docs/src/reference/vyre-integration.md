# VYRE integration

KeyHog pins the five VYRE runtime crates to exact crates.io version `=0.6.5`
(VYRE v0.6.5). The pin is shared by every workspace crate and recorded in
`Cargo.lock`; KeyHog does not carry a vendored VYRE tree or resolve VYRE through
machine-local paths.

## Production ownership

VYRE supplies accelerated primitives. KeyHog still owns detector compilation,
backend eligibility, persisted autoroute evidence, extraction, suppression,
confidence, verification, and reporting. A VYRE result is therefore never a
second interpretation of a detector and never bypasses the shared finding
pipeline.

| VYRE capability | KeyHog owner | Production use |
|---|---|---|
| GPU fused literal evidence | `keyhog-scanner::engine::{gpu_region_dispatch,gpu_resident_evidence}` | One resident dispatch produces the candidate-detector bitmap and complete positions for detector-derived confirmed anchors and generic assignment stems. Dispatches honor the smaller of the live VRAM/config budget and the backend ceiling. Oversized batches shard between chunks. Oversized individual chunks use overlap-preserving physical windows whose presence and position rows reduce into one logical row on the selected WGPU or CUDA peer. The common path starts with a 65,536-record, 768 KiB position buffer. A dense batch is counted exactly and replayed once with a bounded larger buffer. No partial position set is accepted. |
| GPU literal artifacts and cache | `keyhog-scanner::engine::{gpu_artifacts,gpu_cache}` | Compiles one ordered detector-derived matcher containing trigger and positioned-evidence segments. The local key combines a program-kind prefix with a SHA-256 hash of KeyHog's cache-format version and the exact length-delimited rows. VYRE rejects incompatible wire envelopes when loading. |
| GPU regex-DFA admission | `keyhog-scanner::engine::phase2_gpu_dfa` | Narrows eligible prefixless phase-two work; host extraction remains authoritative. KeyHog first compiles one catalog shard, then recursively splits only when VYRE proves that the DFA exceeds its state cap. Each resulting shard requires one full-batch dispatch. |
| Declarative rule evaluation | `keyhog-core::rule_filter` | Evaluates `.keyhogignore.toml` rules through the shared rule representation. |

The portable build retains the CPU-side VYRE support libraries used by these
shared primitives while omitting WGPU/CUDA drivers and their startup probes.
Those libraries are not a separate scan backend: `cpu-fallback` remains
KeyHog's Aho-Corasick trigger path plus Rust-regex extraction.

## Backend and parity contract

The GPU path produces phase-one candidate triggers, optional phase-two
admission rows, and complete literal positions that replace equivalent host
localization passes. Host regex extraction remains authoritative. GPU and CPU routes use
the same decode, built-in suppression, confidence, and scanner postprocessing.
Release parity canonicalizes results before comparing the chunk-indexed match
multiset, including every finding field and multiplicity. It does not compare
backend emission order. Canonical report ordering is a separate postprocessing
contract. An empty or structurally different GPU result is a failure, not a
successful scan.

VYRE does not choose the scan backend. `--backend auto` accepts only a current
persisted KeyHog calibration record that proves correctness and measures every
eligible backend for the exact binary, detector/config digests, host, runtime,
device, and workload bucket. Missing, stale, or incomplete proof is an invalid
autoroute state. See [Autoroute calibration](./autoroute-calibration.md).

## Diagnostics

Use these operator surfaces instead of implementation-specific environment
variables:

```console
keyhog backend
keyhog backend --self-test --json
keyhog calibrate-autoroute
keyhog scan PATH --backend gpu-wgpu --profile
```

`--backend gpu-wgpu` is a diagnostic/benchmark override. It proves neither automatic
selection nor a valid calibration record. GPU initialization, runtime, parity,
and calibration failures remain visible in the command result and exit status.
An explicit or required GPU route that fails dispatch exits `12`. A normal
automatic scan visibly scans exact unprocessed ranges from the same stable
snapshot through the scalar recovery path, records those ranges, retains
completed GPU work, and quarantines the affected autoroute workload identity.

## Feature boundaries

| Build feature | VYRE surface |
|---|---|
| `portable` | CPU-side VYRE support primitives only; no VYRE scan backend, WGPU, or CUDA driver |
| `gpu` | Runtime-probed WGPU and CUDA drivers behind the shared GPU contract |

The retired per-rule megakernel catalog and environment-selected GPU side routes
are not production KeyHog backends. Backend names and runtime policy are the
canonical CLI/TOML values documented in [Backends and routing](../backends.md)
and [Configuration](./configuration.md).
