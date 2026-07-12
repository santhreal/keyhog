# VYRE integration

KeyHog pins the five VYRE runtime crates to exact crates.io version `=0.6.4`
(vyre v0.6.4). The pin is shared by every workspace crate and recorded in
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
| GPU literal-set region presence | `keyhog-scanner::engine::gpu_region_dispatch` | Produces one candidate-detector bitmap per input region. WGPU and optional CUDA implementations share this boundary. |
| GPU literal artifacts and cache | `keyhog-scanner::engine::{gpu_artifacts,gpu_cache}` | Compiles and caches detector-derived literal programs under detector, binary, backend, and runtime identity. |
| GPU regex-DFA admission | `keyhog-scanner::engine::phase2_gpu_dfa` | Narrows eligible prefixless phase-two work; host extraction remains authoritative. |
| Metadata interning | `keyhog-scanner::static_intern` | Freezes detector metadata for allocation-light scan state. |
| Declarative rule evaluation | `keyhog-core::allowlist` | Evaluates `.keyhogignore.toml` rules through the shared rule representation. |

The portable build retains the VYRE CPU libraries used by these shared data
structures while omitting WGPU/CUDA drivers and their startup probes.

## Backend and parity contract

The GPU path performs trigger production only. Every candidate then passes
through the same KeyHog phase-two extraction, decode, suppression, confidence,
deduplication, and reporting code used by CPU routes. Release parity compares
detector id, credential, file, line, byte offset, confidence, and ordering; an
empty or structurally different GPU result is a failure, not a successful scan.

VYRE does not choose the scan backend. `--backend auto` accepts only a current
persisted KeyHog calibration record that proves correctness and measures every
eligible backend for the exact binary, detector/config digests, host, runtime,
device, and workload bucket. Missing, stale, or incomplete proof is an invalid
autoroute state. See [Autoroute calibration](./autoroute-calibration.md).

## Diagnostics

Use these operator surfaces instead of implementation-specific environment
variables:

```console
keyhog backend --json
keyhog backend --self-test --json
keyhog calibrate-autoroute
keyhog scan PATH --backend gpu --profile
```

`--backend gpu` is a diagnostic/benchmark override. It proves neither automatic
selection nor a valid calibration record. GPU initialization, runtime, parity,
and calibration failures remain visible in the command result and exit status;
KeyHog does not silently substitute a CPU backend.

## Feature boundaries

| Build feature | VYRE surface |
|---|---|
| `portable` | CPU-side VYRE libraries only; no WGPU or CUDA driver |
| `gpu` | Runtime-probed WGPU and CUDA drivers behind the shared GPU contract |

The retired per-rule megakernel catalog and environment-selected GPU side routes
are not production KeyHog backends. Backend names and runtime policy are the
canonical CLI/TOML values documented in [Backends and routing](../backends.md)
and [Configuration](./configuration.md).
