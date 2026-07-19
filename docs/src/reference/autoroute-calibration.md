# Autoroute calibration

> **Not the same as confidence calibration.** This page is about *backend
> selection*: measuring which engine (SIMD, scalar CPU, GPU) is fastest and
> proven-correct for your workload. For the per-detector Bayesian confidence
> counters (`keyhog calibrate --tp/--fp`), see
> [Confidence calibration](./confidence-calibration.md).

KeyHog uses measured evidence to select an execution route for a calibrated
workload key: Hyperscan/SIMD, scalar CPU, CUDA, or WGPU, each measured with all
four combinations of phase-two plain-pattern and keyword-anchor localization.
It does
not guess from a device name or a hard-coded size threshold. Autoroute is *not*
a fallback hierarchy: during calibration KeyHog measures every eligible
execution class exposed by that scanner, rejects candidates whose complete
redacted raw-match identity differs from the independent scalar reference, and
records the fastest survivor for the measured representative. Optional SIMD,
CUDA, and WGPU engines are candidates, never correctness oracles. Every
executable CUDA and WGPU path is acquired and measured independently during
calibration. One driver never substitutes for the other. The parity identity
covers chunk membership; detector
id/name/service/severity; exact credential, stored-hash, and companion identity;
full source/history location; entropy; confidence; and finding multiplicity.
Mismatch diagnostics expose only field names and occurrence counts.
They never expose credentials, companions, history values, or deterministic
value fingerprints. Normal scans then do a direct table lookup; they never
benchmark mid-scan.

Calibration, in-process batches, and daemon requests call the same explicit
backend-dispatch boundary. Hyperscan uses its coalesced multi-chunk path. Scalar
CPU and GPU use their normal batch paths. A timing row therefore measures the
implementation that the persisted route authorizes.

The workload key preserves the canonical source execution mixture, not only the
top-level source families. Each sorted, raw-label-free BLAKE3 identity and size-provenance
entry records exact reduced chunk and payload proportions plus the maximum
source-span band. Reordering chunks keeps the same complete workload key.
Scaling every class equally keeps only the source-mixture component stable;
size, admission, and decoder bands can still change. Any different reduced
mixture, including 31:1 versus 1:31, requires its own measured route.
Noncanonical, duplicate, inconsistent, or oversized persisted mixtures
invalidate the cache instead of being normalized silently.
Each persisted decision also carries a digest of the complete workload key.
Changing or relabeling any keyed field invalidates the row before routing.

Filesystem producers keep each path's chunks contiguous. KeyHog uses that
contract to end a batch when the source execution class or full-size provenance
changes, unless the next chunk belongs to the same path dependency. Ordinary,
windowed, PDF, archive, web-script, source-map, and other preprocessing classes
therefore use independently measured homogeneous routes. Dynamic ELF, PE, and
Mach-O section names collapse to their binary-format class because the label
does not change execution. Sources without a contiguous-path contract retain
their exact mixed key instead of being split on an unsafe assumption.

Git diff producers make the same ordering guarantee. Tracked diff hunks and
full-size untracked files therefore calibrate as separate route classes during
installer calibration, even when one `--git-diff` scan contains both.

Performance selection uses the complete recorded distribution, not the single
fastest sample. A route is eligible for persistence only when its 95% Student-t
confidence interval is entirely below every other eligible execution route.
Localization variants on the same backend remain distinct candidates;
same-backend overlap is as inconclusive as cross-backend overlap. KeyHog never
turns an overlapping median, backend rank, or CPU/GPU preference into a claim
that a route is fastest. `keyhog backend
--autoroute` exposes the representative times and `selection_basis` for every
valid decision.

Calibration records 7 trials per route. Accelerator evidence retains its real
cold dispatch; steady and warm rounds rotate route order so host drift is shared
across peers. If cross-backend confidence still overlaps, calibration stops with
host-load guidance plus every route's median and 95% interval instead of
spending unbounded install time or guessing.

Because the decision is *measured*, it must be recorded before `--backend auto`
(the default) can claim a fastest route. A fresh install has no decisions yet,
so an auto scan warns, scans every byte through the scalar correctness oracle,
and reports `complete_after_recovery` plus `autoroute calibration required`.
That recovery is deliberately not labelled autoroute.

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
through 32 MiB, with additional 4 MiB + 1, 8 MiB - 1, 8 MiB + 1, and
16 MiB - 1 probes retaining raw evidence on both sides of the required 8 MiB
crossover. A coarse size class is reusable only when every retained point
selects the same fastest-correct one-shot and daemon backends; disagreement
rejects calibration and requires the class to be split. File-tree probes cover
every chunk-count band through the default 32-chunk fused batch. Tar-member
probes cover the same count ladder for payload-derived extracted filesystem
chunks. Decode-heavy probes cover the decoder path. Empty input has no routing
work and is not counted as a calibrated workload; daemon and watch paths return
the exact empty result without consulting the cache. Each preset uses one
compiled production scanner. Immutable detector, GPU literal, and GPU phase-two
program artifacts are reused. Workload-shaped resident GPU state is reset before
each representative. The measured shared literal and backend-shaped phase-two
preparation costs are added to every matching one-shot GPU observation. Candidate
order rotates across workload bands rather than giving one backend the same
thermal position in every probe. The final count is the number of probes run,
not the number of unique persisted route classes. Multiple representatives can
share one logarithmic workload key. The summary separately reports unique route
classes measured by this sweep and the total route decisions in the cache after a
required readback check. The cache total can include valid decisions from prior
calibration runs. The command also prints a cache route summary showing how many
one-shot and daemon rows select a VYRE GPU route, plus the number of GPU candidate
receipts measured. The command does **not**
cover the git / docker / web source probes; those need environment orchestration
(a repo, a running daemon, a served URL) that only the installer's
`--calibrate` mode performs. Current installers delegate the complete core sweep
to this command, then construct external fixtures and invoke the low-level
`scan --autoroute-calibrate` probe mode. Older binaries without the command use
the installers' compatibility sweep. Capability inspection must succeed before
that choice, so broken help output cannot silently select the older matrix. The
installers also accept the earlier unified command's migration summary
(`calibrated N workload buckets`). The low-level scan flag records one
caller-supplied workload but does not build or sweep external fixtures. If
you scan those sources and receive an
`autoroute calibration required` recovery receipt, re-run `install.sh --calibrate` /
`install.ps1 -Calibrate` rather than the subcommand. Decisions are written,
parity-checked, to the autoroute cache
(`$XDG_CACHE_HOME/keyhog/autoroute.json` by default; override with
`--autoroute-cache <path>` or `[system].autoroute_cache`).

Canonical calibration admits every eligible execution class. The low-level
`scan --no-autoroute-gpu --autoroute-calibrate` diagnostic deliberately writes
under a noncanonical config identity; its CPU-only evidence cannot overwrite a
normal all-candidate decision.

Startup reports every available GPU peer without creating execution devices or
pipelines. Calibration acquires each peer when its candidate is measured and
reports the exact acquisition failure. The
autoroute cache stores separate CUDA and WGPU cold and warm timing vectors, and
`keyhog backend --autoroute` prints both. A failed driver is ineligible until it
is repaired and calibration is rerun.

Low-level calibration saves take an exclusive sibling-file lock across the
complete read/merge/atomic-write cycle. The canonical `calibrate-autoroute`
command adds a generation transaction around the full workload and preset
sweep: every probe writes to an isolated cache, completed evidence is read back
and validated there, and the live cache is replaced once only after the full
sweep succeeds. A failed probe leaves the live cache byte-identical. Publication
also compares both the live cache and its runtime-health artifact captured at
sweep start while holding their canonical locks. If another process changed
either one, KeyHog preserves the concurrent update and asks the operator to
rerun instead of overwriting evidence or clearing a new route fault. A
successful publication clears only the exact route faults remeasured by this
sweep. The operating system releases a held lock if a writer exits or crashes.

Only identity-compatible, structurally valid rows are preserved. A storage or
permission error while reading an existing cache aborts without replacing it.
A readable cache with an incompatible schema, invalid JSON, invalid structure,
or a different build/corpus identity emits an unconditional stderr warning with
the cache path and replacement reason, then starts a fresh staged generation;
unrelated rows from that invalid artifact are not merged.

One cache can be shared across hosts. Each route generation is keyed by the
exact resolved config digest and host profile. Calibrating the same config on a
second host preserves the first host's evidence, and recalibrating either host
merges only that host's workload rows. A scan replays only the generation whose
complete host identity matches the live machine. JSON inspection exposes the
stable `host_identity` digest used to distinguish those generations.

### Cache schema compatibility

The cache has one strict schema version. KeyHog reads the small `version` field
before decoding any version-specific payload, so an older or newer cache cannot
be mistaken for a partially valid one. There is no silent in-place migration:
an unsupported version is reported as `unsupported autoroute cache version`
with the version found, the version expected by the binary, and the command to
regenerate it. The scan loader, calibration merge path, and `backend --autoroute`
inspection use this same diagnostic. Re-run calibration after upgrading KeyHog
or changing the cache format; a replacement save never merges rows from an
incompatible schema.

Each timing point stores a content-addressed measurement receipt: the canonical
receipt generator, a digest of the complete payload multiset, and a digest of
the exact source, offset, and decode shape. It stores no source text or paths.
Same-sized representatives with different candidate density therefore remain
distinct points, while the same chunks in a different producer order reuse one
receipt. `keyhog backend --autoroute --json` exposes all three fields so a
crossover can be tied to its exact probe.

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
  instruction support, the live linked Hyperscan/Vectorscan runtime version
  when SIMD is eligible and, when the scanner can use a physical GPU, the GPU
  device, every available runtime backend and version, driver/runtime identity,
  resolved batch-input byte cap, and the exact sorted eligible-backend census
  for that resolved config. A missing or changed required field invalidates the
  evidence and requires recalibration.
- SIMD is admitted when the scanner produced a nonempty backend-neutral plan
  and the linked Hyperscan/Vectorscan runtime has a reproducible identity.
  Scanner construction does not build its databases. Calibration or a selected
  SIMD route materializes the plan exactly once; failure aborts calibration or
  the selected scan with the initialization reason instead of removing SIMD
  from the census or substituting scalar CPU.
- Backend identity covers the complete scan tail, not only phase one. The
  always-active phase-two Hyperscan prefilter executes only for the SIMD
  candidate. Scalar and GPU candidates use their own measured trigger path and
  the portable host residual, so their timing cannot borrow hidden SIMD work.
- Each scan preset (default, `--fast`, `--deep`, `--precision`) is calibrated
  separately.
- Flags hashed into the scan config (for example `--threads`,
  `--min-confidence`, `--profile`, or `--perf-trace`) fork the decision;
  instrumentation cannot reuse timings measured without its hot-path overhead.
  `keyhog calibrate-autoroute` sweeps the documented presets so the common
  combinations are covered.
- Candidate-shape knobs (`--min-secret-len`, `--entropy-threshold`, decode depth,
  entropy/ML/keyword floors) fork the decision, because they change what reaches
  scan-phase output and can therefore change backend crossover.
- Pipeline knobs (`--threads`, `--reader-threads`, `--fused-batch`,
  `--fused-depth`) and `[tuning]` settings fork the decision because they change
  work partitioning and backend warm-up behavior.
- One calibration process may reuse a KeyHog-owned Rayon pool only at the same
  worker width. An external pool is rejected because its stack, naming, and
  ownership settings cannot be attested. An incompatible preset or live width
  fails before measurement, and the actual count is part of the resolved config
  identity.
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
is not evidence for this one. Uncalibrated keys never interpolate or clamp to
a guessed route. A normal scan warns, completes that exact input through scalar
correctness recovery, and reports the invalid autoroute state; calibration and
explicit backend contracts still fail when their requested evidence or route
cannot be produced.

Large directory and multi-source scans run in process and produce multiple real
batches. Each batch needs an exact key in the cache; one calibrated single-file
key does not authorize every later tree shape. The core calibration command
includes file-tree probes, while Git, Docker, and web fixtures require installer
calibration.

## One-shot scans and the daemon

Runtime lifetime changes accelerator cost, so it is part of routing semantics.
Calibration records the scalar CPU distribution directly. For SIMD and each
GPU peer it records the real first materialization/dispatch followed by warm
trials:

- An in-process one-shot scan includes cold Hyperscan or GPU cost when choosing
  a backend.
- A ready daemon initializes accelerator state before accepting requests and
  chooses from warm accelerator trials. Startup derives its required peer set
  from the validated decision table. It does not warm unrelated eligible peers,
  and it refuses readiness if any selected peer cannot be warmed.
- `keyhog watch` is also a compile-once persistent runtime. It warms every
  selected route before announcing readiness and uses warm evidence for later
  file events; it does not repeatedly price the same cold backend startup.

Decoded derived buffers are part of the measured route rather than a hidden
runtime choice. Scalar and SIMD candidates keep their own backend for decoded
rescans. GPU candidates explicitly compose with scalar for those small buffers,
so neither scalar nor GPU timing can silently borrow Hyperscan work.

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

Calibration never accepts a candidate that needs recovery. During an ordinary
automatic scan, an accelerated-backend fault warns and replays the same stable
snapshot through the fastest remaining measured-correct peer. GPU recovery
replays only exact unprocessed ranges and retains completed GPU shards.
Recovered work is counted separately, the affected workload route is quarantined, and the backend fault
is written to a bounded `<cache>.runtime-health.json` artifact. Runtime health
is separate from immutable timing evidence and survives restart. A successful
calibration commit clears only the workload identities remeasured in that
command. Missing health state means no runtime fault has been observed;
malformed, oversized, unknown-backend, or calibration-inconsistent health state
invalidates automatic routing and triggers visible scalar recovery with repair
guidance. An explicit GPU override or
`--require-gpu` remains a hard backend contract and is not substituted.
`keyhog backend --autoroute` reports `quarantined` readiness, aggregate and
per-config fault counts, and the failed backend/reason on each affected workload;
`keyhog doctor` reports the same repair state.

## When an auto scan recovers with `calibration required`

The warning and report receipt name the missing workload bucket and which
dimensions differ from the nearest calibrated class. Scan coverage remains
complete, but routing proof is unhealthy. Resolve it by either:

- Re-running the same scan once with `--autoroute-calibrate --autoroute-gpu`.
  This measures the actual source, resolved config, and workload class that
  failed. Use `keyhog calibrate-autoroute` for the standard core ladder, or
  `install.sh --calibrate` / `install.ps1 -Calibrate` during installation, or
- Passing an explicit backend for a one-off diagnostic scan:
  `keyhog scan --backend simd` (or `gpu-cuda`, `gpu-wgpu`, `cpu`). An explicit `--backend`
  bypasses autoroute entirely; it is a diagnostic/benchmark override and does
  not prove autoroute correctness.

A `STALE` status means the cache was written for a different build; auto scans
recover through the scalar oracle, so recalibrate after upgrading KeyHog.

## Inspect what is calibrated

```sh
keyhog backend --autoroute          # concise human-readable summary
keyhog backend --autoroute --verbose # every workload receipt
keyhog backend --autoroute --json    # machine-readable
keyhog backend --autoroute --autoroute-cache /absolute/custom/autoroute.json
keyhog doctor                       # reports the same readiness and repair action
```

The inspection command is also a health gate. A single-backend build reports
`health: direct` and exits `0` even when its unused cache is absent or stale.
For a multi-backend build, `health: ready` exits `0`; `quarantined`,
`calibration_required`, `disabled`, `stale`, and `invalid` exit `4` so
automation cannot mistake an unusable autoroute state for a healthy host. JSON includes the same `health`
value plus `repair_command`: `null` for `direct` or `ready`, the canonical
calibration command for quarantined, absent, stale, or invalid evidence, and an explicit
cache-path command when persistence is disabled. Scan reports expose recovered
chunks and bytes plus `complete_after_recovery`; inspection remains unhealthy
until calibration produces confidence-separated evidence.

Pass `--autoroute-cache` when the scan uses a non-default cache path through
the matching scan flag or `[system].autoroute_cache`.

These show every persisted config and host generation, its workload buckets,
representative route times, whether confidence was separated, the selection
basis, and the resolved one-shot and daemon backends. The JSON view is lossless:
each route includes its ordered nanosecond trials, cold observation, exact
one-shot and warm projections, and 95 percent confidence bounds, so the result
can be reproduced without parsing the private cache file. Each
generation's `eligible_backends` array defines the complete backend set. Every
decision must contain all four localization plans for every eligible backend and
prove each plan correct. Removing a candidate timing and its receipt together
still invalidates the cache because validation compares the full Cartesian route
set with this live config identity.
The inspection shows exactly what *is* covered and how each existing decision
was made. An invalid decision makes the inspection report the cache as unusable;
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
| `calibrated_at_unix_ms` | Oldest persisted Unix timestamp among the decision's measured points. A future value on any point invalidates the complete cache. |
| `calibration_age_ms` | Age of that oldest point, derived at inspection time from `inspected_at_unix_ms`; it is visible evidence, not an expiry policy. |
| `backend`, `phase2_plain_localizer`, `phase2_keyword_localizer` | Cold-aware backend and both phase-two localization choices for an in-process one-shot scan. |
| `calibration_points` | Number of exact content-and-source-shape representatives retained for this workload class. Equal byte/chunk counts can contribute more than one point. |
| `sample_bytes_min`, `sample_bytes_max`, `sample_chunks_min`, `sample_chunks_max` | Exact measured envelope covered by the class. |
| `measured_points` | Complete point-by-point projection: exact sample size, `measurement_generator`, `payload_digest`, `measurement_shape_digest`, timestamp, one-shot and daemon execution-plan winners, confidence status, every route timing, and every parity receipt. Use this array to distinguish same-sized probes and diagnose crossover behavior. |
| `sample_bytes`, `sample_chunks`, `route_timings` | Concise size projection plus the complete generic route-timing array for the first point after sorting by bytes, chunks, then measurement-shape digest. Each timing identifies the backend, both localization choices, one-shot time, and warm time when applicable. `measured_points` is authoritative. |
| `confidence_separated` | Whether the one-shot winner's 95% interval is entirely below every other eligible execution route at every measured point. |
| `selection_basis` | `separated-95pct-confidence`. Inconclusive evidence is rejected instead of appearing as a routable decision. |
| `selected_margin_ns` | Smallest one-shot representative-time margin to the next eligible route across all measured points; `null` when there is no peer route. |
| `daemon_backend`, `daemon_phase2_plain_localizer`, `daemon_phase2_keyword_localizer` | Backend and both phase-two localization choices derived for a ready persistent daemon from warm evidence. |
| `daemon_confidence_separated`, `daemon_selection_basis`, `daemon_selected_margin_ns` | Daemon-route counterparts, also aggregated conservatively across every measured point. |
| `source_mixture` | Structured source-class components used by the workload identity: privacy-safe `source_class` for KeyHog-owned classes (`null` for unknown library-provided values), canonical execution-class digest, full-size versus payload provenance, reduced chunk/payload ratios, and maximum source-span bucket. The human-readable `workload` uses `<source_class>@<digest>` for known classes and `custom@<digest>` otherwise, so arbitrary source metadata is never echoed. JSON consumers should use these fields instead of parsing that string. |
| `candidate_receipts` | Concise summary of the first measured point's receipts. Every receipt identifies the backend plus both localization choices. Every point carries the complete four-plans-per-backend set; every result digest must equal its point's scalar/both-off reference, and every evidence digest must recompute exactly or the cache is rejected. |

## Single-backend builds

A build that compiled only one backend has nothing to route. The `portable`
build, for example, ships only the scalar CPU backend, so it skips autoroute
entirely and never reports `calibration required`. Calibration applies only to
builds that compiled a real backend choice (Hyperscan/SIMD and/or GPU).
