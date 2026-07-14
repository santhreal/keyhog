# Autoroute calibration

> **Not the same as confidence calibration.** This page is about *backend
> selection*: measuring which engine (SIMD, scalar CPU, GPU) is fastest and
> proven-correct for your workload. For the per-detector Bayesian confidence
> counters (`keyhog calibrate --tp/--fp`), see
> [Confidence calibration](./confidence-calibration.md).

KeyHog uses measured evidence to select a backend for a calibrated workload key:
Hyperscan/SIMD, scalar CPU, CUDA, or WGPU. It does
not guess from a device name or a hard-coded size threshold. Autoroute is *not*
a fallback hierarchy: during calibration KeyHog measures every eligible
execution class exposed by that scanner, rejects candidates whose complete
redacted raw-match identity differs from the reference, and records the fastest
survivor for the measured representative. Every executable CUDA and WGPU path
is acquired and measured independently. One driver never substitutes for the
other. The parity identity
covers chunk membership; detector id/name/service/severity; hashes of the actual
credential, stored hash, and companion names/values; full source/history
location; entropy; confidence; and finding multiplicity. Plain credentials and
companions never enter calibration logs. Normal scans then do a direct table
lookup; they never benchmark mid-scan.

Calibration, in-process batches, and daemon requests call the same explicit
backend-dispatch boundary. Hyperscan uses its coalesced multi-chunk path. Scalar
CPU and GPU use their normal batch paths. A timing row therefore measures the
implementation that the persisted route authorizes.

The workload key preserves the canonical source mixture, not only the set of
source families. Each sorted, raw-family-free BLAKE3 identity and size-provenance
entry records exact reduced chunk and payload proportions plus the maximum
source-span band. Reordering chunks keeps the same complete workload key.
Scaling every class equally keeps only the source-mixture component stable;
size, admission, and decoder bands can still change. Any different reduced
mixture, including 31:1 versus 1:31, requires its own measured route.
Noncanonical, duplicate, inconsistent, or oversized persisted mixtures
invalidate the cache instead of being normalized silently.
Each persisted decision also carries a digest of the complete workload key.
Changing or relabeling any keyed field invalidates the row before routing.

Performance selection uses the median of the recorded trials, not the single
fastest sample. If one route's 95% Student-t confidence interval is entirely
below every competitor, it is the separated winner. If intervals overlap,
KeyHog reports that evidence as inconclusive and chooses the lowest measured
median among the statistically non-dominated routes; it does not pretend that
overlap proves equivalence or apply a CPU/GPU preference hierarchy. Engagement
overhead breaks only an exact median tie. `keyhog backend --autoroute` exposes
the representative times and a `selection_basis` for every decision, so this
distinction is visible in both text and JSON inspection output.

Because the decision is *measured*, it must be recorded before `--backend auto`
(the default) can run. A fresh install has no recorded decisions yet, so until
you calibrate, an auto scan fails closed with
[exit code `2`](./exit-codes.md), `autoroute calibration required`, rather
than silently substituting a slower or unverified backend.

## Operator workflow

1. Install normally or run calibration for the workload families you use.
2. Inspect the cache with `keyhog backend --autoroute`.
3. Run with the default `--backend auto`; normal scans never benchmark.
4. If a real scan names an uncovered key, calibrate that workload family or use
   an explicit backend only as a deliberate diagnostic override.

## Calibrate core and source-specific workloads

**A normal install calibrates automatically.** Plain `./install.sh` /
`./install.ps1` runs the visible calibration phase after the binary is verified,
and the install *fails* rather than leave you with an uncalibrated default auto
route. You do not need to pass any flag to get calibrated.

To re-run calibration later without reinstalling (after hardware changes, or to
cover source routes that were unavailable at install time):

```sh
# Unix: full sweep, including the git / docker / web source probes
./install.sh --calibrate
# Windows
./install.ps1 -Calibrate
```

The binary can also recalibrate its own core workloads in place:

```sh
keyhog calibrate-autoroute
```

This drives the core stdin + filesystem workload ladder across every scan
preset. Plain single-file probes cover every power-of-two size band from 1 byte
through 32 MiB. File-tree probes cover every chunk-count band through the
default 32-chunk fused batch, plus decode-heavy and many-file shapes. It does **not**
cover the git / docker / web source probes; those need environment orchestration
(a repo, a running daemon, a served URL) that only the installer's
`--calibrate` mode performs. The installers construct those fixtures and invoke
the low-level `scan --autoroute-calibrate` probe mode; that scan flag records one
caller-supplied workload but does not build or sweep the external fixtures. If
you scan those sources and hit
`autoroute calibration required`, re-run `install.sh --calibrate` /
`install.ps1 -Calibrate` rather than the subcommand. Decisions are written,
parity-checked, to the autoroute cache
(`$XDG_CACHE_HOME/keyhog/autoroute.json` by default; override with
`--autoroute-cache <path>` or `[system].autoroute_cache`).

Canonical calibration admits every eligible execution class. The low-level
`scan --no-autoroute-gpu --autoroute-calibrate` diagnostic deliberately writes
under a noncanonical config identity; its CPU-only evidence cannot overwrite a
normal all-candidate decision.

Startup reports every acquired GPU peer and each acquisition failure. The
autoroute cache stores separate CUDA and WGPU cold and warm timing vectors, and
`keyhog backend --autoroute` prints both. A failed driver is ineligible until it
is repaired and calibration is rerun.

Calibration saves take an exclusive sibling-file lock across the complete
read/merge/atomic-write cycle. Separate calibration processes therefore
accumulate compatible config and workload decisions without a
last-writer-wins loss; the operating system releases the lock if a writer exits
or crashes. Only identity-compatible, structurally valid rows are preserved. If
an existing cache is unreadable, incompatible, or invalid, calibration emits an
unconditional stderr warning with the cache path and replacement reason, then
starts a fresh cache; unrelated preset rows in that old file are not merged.

## What a decision covers

A decision is tied to its recorded build identity, host profile, detector
corpus, **and routing-relevant resolved scan configuration**. Options that
change that identity get their own calibration, even when they do not change
which backend is fastest:

- Build identity records the exact running executable SHA-256, package version,
  Git hash, and the CLI and dependency feature sets. GPU and SIMD support are
  read from the scanner library that
  actually owns and compiled those backends, not inferred from similarly named
  CLI features. Source capability identity separately records each compiled
  filesystem, archive, forge, cloud, container, and web source feature
  (including GitHub, GitLab, and Bitbucket), while verifier identity records
  whether live verification is compiled. A different artifact or recorded
  capability set cannot reuse the evidence, including dirty/profile/native-link
  builds that happen to share a package version and Git hash.
- Host identity includes OS/architecture, CPU model and topology, memory, CPU
  instruction support and, when the scanner can use a physical GPU, the GPU
  device, every acquired runtime backend and version, and driver/runtime identity. A missing or changed
  required field invalidates the evidence and requires recalibration.
- Each scan preset (default, `--fast`, `--deep`, `--precision`) is calibrated
  separately.
- Flags hashed into the scan config (for example `--threads` or
  `--min-confidence`) fork the decision; `keyhog calibrate-autoroute` sweeps the
  documented presets so the common combinations are covered.
- Candidate-shape knobs (`--min-secret-len`, `--entropy-threshold`, decode depth,
  entropy/ML/keyword floors) fork the decision, because they change what reaches
  scan-phase output and can therefore change backend crossover.
- Pipeline knobs (`--threads`, `--reader-threads`, `--fused-batch`,
  `--fused-depth`) and `[tuning]` settings fork the decision because they change
  work partitioning and backend warm-up behavior.
- Source policy (`--limit-*`, `--max-file-size`, `--no-default-excludes`) and detector
  floors fork the decision for real `stdin`/directory buckets that feed different cache/chunk
  geometry.
- Workload **shape** matters: a single file, a directory, and a piped `stdin`
  stream are distinct buckets, and `stdin` is content-sensitive.

The host profile is deliberately checked, but it is not a complete performance-
environment fingerprint: for example, CPU governor, system load, and every
accelerator limit are not all identity fields. Inspection reports each decision's
persisted calibration timestamp and current age. Decisions do not expire by age.
A timestamp later than the inspecting system clock is invalid evidence, so cache
loading and inspection fail closed with clock and recalibration guidance.
Recalibrate after driver, firmware, power-policy, or material workload changes
even when the stored identity still parses as compatible.

`keyhog config --effective` prints the resolved scan settings. Pair it with
`keyhog backend --autoroute --json` to verify that a routing-relevant setting
change produced a new `config_digest` row.

Every lookup is exact at the complete workload-key level. Size, chunk-count,
and maximum-file dimensions use one-power-of-two logarithmic ranges; decode
density uses paired logarithmic ranges to resist content-sample jitter. The
key also records how many chunks and bytes the detector-specific phase-one
alphabet and bigram screens reject or admit. A phase-one rejection suppresses
only the direct-literal pass. It does not skip normalization, decoding,
fragment, boundary, or phase-two work, so these classes describe measured cost
without changing detection semantics. The decision proves correctness and
timing for the representative that was
measured under that key. It does **not** prove that the same backend is fastest
for every individual byte length inside the numeric range. A neighbouring range
is not evidence for this one. Uncalibrated keys fail closed; KeyHog never
interpolates or clamps them to a CPU/GPU substitute.

Large directory and multi-source scans run in process and produce multiple real
batches. Each batch needs an exact key in the cache; one calibrated single-file
key does not authorize every later tree shape. The core calibration command
includes file-tree probes, while Git, Docker, and web fixtures require installer
calibration.

## One-shot scans and the daemon

Runtime lifetime changes GPU cost, so it is part of routing semantics.
Calibration records warm CPU/Hyperscan medians and, for GPU, the real first
dispatch followed by warm trials:

- An in-process one-shot scan includes cold GPU cost when choosing a backend.
- A ready daemon initializes accelerator state before accepting requests and
  chooses from the warm GPU trials. Startup derives its required warm peer set
  from the validated decision table. It does not warm unrelated acquired peers,
  and it refuses readiness if any selected peer cannot be warmed.

The current in-process router applies that cold-aware decision to each workload
lookup. It does not infer request-wide GPU startup amortization across a large
number of batches. This is why the cache and inspection output describe a
measured workload key and runtime class rather than promising one universal
crossover size.

Both routes consume the same parity-checked primary evidence; they derive the
appropriate decision for their runtime instead of sharing one misleading
"GPU time." `keyhog backend --autoroute` prints both routes. CPU,
Hyperscan/SIMD, and GPU remain peers in both cases. See
[Daemon and warm scans](../workflows/daemon.md) for request eligibility,
in-process retry policy, socket, and timeout semantics.

## When an auto scan reports `calibration required`

The error names the missing workload bucket. Resolve it by either:

- Re-running calibration (`keyhog calibrate-autoroute`, or `install.sh
  --calibrate` / `install.ps1 -Calibrate`) so the bucket gets a measured
  decision, or
- Passing an explicit backend for a one-off diagnostic scan:
  `keyhog scan --backend simd` (or `gpu-cuda`, `gpu-wgpu`, `cpu`). An explicit `--backend`
  bypasses autoroute entirely; it is a diagnostic/benchmark override and does
  not prove autoroute correctness.

A `STALE` status means the cache was written for a different build; auto scans
reject it, so recalibrate after upgrading KeyHog.

## Inspect what is calibrated

```sh
keyhog backend --autoroute          # human-readable cache contents
keyhog backend --autoroute --json   # machine-readable
keyhog backend --autoroute --autoroute-cache /absolute/custom/autoroute.json
keyhog doctor                       # reports calibrated / not calibrated / STALE
```

Pass `--autoroute-cache` when the scan uses a non-default cache path through
the matching scan flag or `[system].autoroute_cache`.

These show every persisted config, its workload buckets, representative median
route times, whether confidence was separated, the selection basis, and the
resolved one-shot and daemon backends. When a scan hits `exit 2`, you can
therefore see exactly what *is* covered and how each existing decision was
made. An invalid decision makes the inspection report the cache as unusable;
inspection never omits a malformed row and presents the remainder as healthy.

Inspection validates build compatibility and the complete persisted cache
structure. It does not have the live scan's host, detector, rule, and resolved
config inputs; those identities are checked when a real scan loads its decision.
Therefore a readable, build-matched inspection is evidence that the cache can be
examined, not a guarantee that the next workload has a usable row.

The top-level `calibration_required` field is true only when this build has
multiple compiled scan backends. When false, `direct_backend` names the only
possible route and a disabled or absent cache does not make automatic scans
unhealthy. `inspected_at_unix_ms` is the clock value used for timestamp
validation and age derivation. The per-decision JSON fields have these exact
meanings:

| Field | Meaning |
|---|---|
| `calibrated_at_unix_ms` | Persisted Unix timestamp from the calibration run. A future value invalidates the complete cache. |
| `calibration_age_ms` | Age derived at inspection time from `inspected_at_unix_ms`; it is visible evidence, not an expiry policy. |
| `backend` | Cold-aware backend for an in-process one-shot scan. |
| `simd_ms`, `cpu_ms` | Median trial time for that CPU route; `cpu_ms` is `null` when scalar CPU was not measured separately. |
| `gpu_cuda_ms`, `gpu_wgpu_ms` | Per-driver one-shot representative: the greater of the real first dispatch and that driver's warm-trial median. |
| `gpu_cuda_warm_ms`, `gpu_wgpu_warm_ms` | Per-driver warm median used by a ready daemon; `null` when that driver was not eligible. |
| `confidence_separated` | Whether the one-shot winner's 95% interval is entirely below every competitor. |
| `selection_basis` | `separated-95pct-confidence`, or `lowest-measured-median-among-overlapping-confidence`. |
| `selected_margin_ns` | One-shot representative-time margin to the next candidate; `null` when there is no competitor. |
| `daemon_backend` | Backend derived for a ready persistent daemon from warm GPU evidence. |
| `daemon_confidence_separated`, `daemon_selection_basis`, `daemon_selected_margin_ns` | Daemon-route counterparts of the one-shot confidence, basis, and margin fields. |
| `candidate_receipts` | One receipt per measured backend, containing its canonical backend identity, secret-safe correctness digest, complete trial count, and evidence digest over those fields plus the exact timing vector. Every result digest must equal the SIMD reference and every evidence digest must recompute exactly or the cache is rejected. |

## Single-backend builds

A build that compiled only one backend has nothing to route. The `portable`
build, for example, ships only the scalar CPU backend, so it skips autoroute
entirely and never reports `calibration required`. Calibration applies only to
builds that compiled a real backend choice (Hyperscan/SIMD and/or GPU).
