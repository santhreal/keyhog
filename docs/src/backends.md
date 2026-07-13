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

Those explicit-backend methods have infallible finding-vector return types, so
selection is a hard process contract. Unavailable selected SIMD terminates with
exit `3`; unavailable or failed selected GPU execution terminates with exit
`12`. They never return findings from another backend. `warm_backend` probes
startup eligibility in-band, but a process that must contain a later driver or
dispatch failure should run the CLI as a subprocess. The no-backend portable
CPU methods do not acquire an accelerator.

The GPU trigger matcher keeps its immutable VYRE tables resident after the
first successful batch. Haystack and region capacity grow in bounded bands from
the actual workload. KeyHog serializes each resident session so concurrent
requests cannot interleave uploads against the same device buffers. Preparation,
growth, dispatch, and readback errors remain selected-GPU failures. Teardown
cleanup errors are logged. There is no borrowed or CPU substitution.

## What “same results” means

Calibration compares the complete redacted `RawMatch` identity: chunk index;
detector id, name, service, and severity; hashes of the actual credential,
stored credential hash, and companion names/values; source, file, line, offset,
commit, author, and date; entropy and confidence. A candidate is rejected if
any field or finding multiplicity differs from the Hyperscan reference, if
repeated reference trials are inconsistent, or if required GPU timing evidence
is invalid. Plain credentials and companion values never enter parity logs.
Normal automatic scans do not benchmark or silently replace a rejected backend.

Among parity-correct candidates, routing uses representative measured medians,
never a lucky fastest trial. A fully separated 95% confidence interval is the
strongest result. Overlapping intervals are disclosed as inconclusive rather
than mislabeled as proof of equal performance; KeyHog then selects the lowest
measured median among the non-dominated candidates, using engagement overhead
only for an exact median tie. Autoroute inspection prints this selection basis.

This parity contract runs before the common suppression, verification,
deduplication, and reporter stages, but already proves every raw field those
stages consume. The same detector TOML corpus and resolved configuration digest
identify every route.

## Why size alone is insufficient

Two inputs with the same byte count can have different winners. Autoroute also
keys evidence by one-power-of-two logarithmic ranges for bytes, chunk count,
and largest source size, plus a jitter-resistant decode-density range,
detector/pattern shape, source family,
resolved configuration, build features, and host identity. It does not
interpolate from a neighbouring range key; a measured key nevertheless covers
the values grouped into that range.

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
through `scan_coalesced_with_backend` for both GPU and Hyperscan. It requires
sorted full-match parity, rejects GPU degradation, excludes the first complete
warmup, and fails unless GPU is faster at 8 MiB. A new crossover claim requires
a `production_comparable = true` artifact from that corrected route with exact
binary, detector, configuration, host, runtime, workload, and trial identity.
Autoroute still requires calibration on the deployment host for the exact
workload class.

## When automatic routing refuses to scan

Missing, stale, malformed, or incomplete evidence is an invalid automatic
route. KeyHog exits with a configuration error and prints the missing workload
identity plus the calibration command. Run `keyhog calibrate-autoroute` for the
core ladder or the installer calibration for source-specific probes. Use an
explicit backend only when you intentionally want a diagnostic override.

After selection, the backend remains a hard execution contract. If a selected
GPU route fails during runtime dispatch, KeyHog exits `12`; it does not complete
that scan through an unselected CPU or SIMD backend.

For cache identity, inspection commands, calibration coverage, and recovery,
see [Autoroute calibration](./reference/autoroute-calibration.md).
