# Autoroute calibration

> **Not the same as confidence calibration.** This page is about *backend
> selection*: measuring which engine (SIMD, scalar CPU, GPU) is fastest and
> proven-correct for your workload. For the per-detector Bayesian confidence
> counters (`keyhog calibrate --tp/--fp`), see
> [Confidence calibration](./confidence-calibration.md).

KeyHog uses measured evidence to select an execution route for a calibrated
workload key: Hyperscan/SIMD, scalar CPU, CUDA, native Metal, or WGPU, each
measured with all four combinations of phase-two plain-pattern and
keyword-anchor localization. GPU routes also measure every resident pipeline
depth the acquired peer declares eligible. Synchronous peers expose depth one;
asynchronous peers expose depths one through four. It does not guess from a
device name or a hard-coded size threshold. Autoroute is not a fallback
hierarchy. During calibration KeyHog measures every eligible execution class
exposed by that scanner, rejects candidates whose complete redacted raw-match
identity differs from the independent scalar reference, and records the fastest
survivor for the measured representative. Optional SIMD, CUDA, Metal, and WGPU
engines are candidates, never correctness oracles. Every executable GPU path is
acquired and measured independently. One driver never substitutes for another.
The parity identity covers chunk membership; detector
id/name/service/severity; exact credential, stored-hash, and companion identity;
full source/history location; entropy; confidence; and finding multiplicity.
Mismatch diagnostics expose only field names and occurrence counts.
They never expose credentials, companions, history values, or deterministic
value fingerprints. Normal scans then do a direct table lookup; they never
benchmark mid-scan.

Calibration, in-process batches, and daemon requests call the same explicit
backend-dispatch boundary. Hyperscan uses its coalesced multi-chunk path. Scalar
CPU and GPU use their normal batch paths, including the measured GPU resident
pipeline depth. A timing row therefore measures the implementation that the
persisted route authorizes.

## Ordered multi-device GPU routes

When one GPU API exposes two or more distinct physical adapters, calibration
also measures the complete ordered device set as a peer route. The route binds
each adapter's stable topology, driver/runtime identity, capacity, and measured
integer throughput weight. Cross-API aliases for one physical adapter are
deduplicated before the set is formed.

Acquisition is all-or-nothing. A missing, reordered, reset, or identity-changed
member invalidates the complete route before any batch is scanned. KeyHog
allocates each member's bounded resident slots before dispatch, checks the
aggregate process ceiling, assigns one contiguous weighted source range to each
member, dispatches concurrently, and retires results in source order. An error,
panic, incomplete receipt, or missing shard on any required member invalidates
the whole route; sibling results are not reported as complete.

The device-set identity is stable across workload-specific throughput weights.
One scanner therefore acquires one resident set for that physical topology,
while each workload decision retains its own authenticated weights, budgets,
pipeline depths, detector/config digests, and correctness receipt. Normal scans
never retime or rebalance the set.

A route class must be something calibration can enumerate ahead of any scan.
The workload key is therefore the shape of the work, not a measurement of the
bytes: logarithmic byte, chunk, maximum-file, and pattern bands, one boolean
recording whether any decoder was admitted, and the canonical set of source
execution classes with each class's size provenance. Reordering chunks keeps
the same key. Changing the proportion between two source classes, which
decoder families ran, the phase-one admission outcome, the phase-two keyword
density, or the number of decode candidates does not: those are properties of
the input, and a key that contained them made every scan an uncalibrated class.

Calibration still observes those statistics. It logs the phase-2 keyword
trigger counts for each measured decision on the `keyhog::routing` tracing
target, and every persisted point records its exact sample byte count, chunk
count, and measurement shape digest. They describe a measurement; they do not
select one.

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
fastest sample. All candidates are measured in the same rotated rounds, so
KeyHog compares paired per-round differences at 95% Student-t confidence. If
those differences prove one exact plan faster than every peer plan,
`selection_basis` is `exact-plan-paired-95pct-confidence`. If same-backend plans
remain tied, KeyHog chooses the compiled default when it is among the tied
leaders. Otherwise, it chooses a stable typed plan from that tied set. The
chosen plan's interval must remain below every plan on each peer backend.
Inspection reports `peer-separated-compiled-default-plan` or
`peer-separated-statistically-tied-plan`.

When nothing separates, the measurement is resolved rather than discarded. A
route stays in contention unless some peer is proved faster, meaning that
peer's whole 95% interval lies below the route's own. Among the routes still in
contention, only those whose median falls inside the fastest route's own 95%
upper bound are eligible, so a route can never win on a wide error bar while
its central tendency is measurably worse. The eligible set is then ordered by
backend complexity, `cpu-fallback` before `simd-regex` before the GPU peers,
because when nothing is proved faster the backend that needs no accelerator
bring-up and always runs is the honest choice, and it is the same choice on
every rerun of the same evidence. Inspection reports
`unseparated-dead-heat-lowest-complexity-backend` and `confidence_separated`
stays `false`, so a permitted decision is never presented as a proved one.

This matters on real trees. Calibrating `benchmarks/corpora/homefield` measured
`cpu-fallback` at 4.507 s [3.08, 11.49] against `gpu-wgpu` at 4.462 s
[4.40, 4.92], with every interval overlapping every other. Refusing to decide
left the workload with no persisted route, so every later automatic scan failed
closed without scanning even though the measurement showed the backends were
indistinguishable.

Calibration records 7 normalized timing trials per route. A warm trial repeats
short candidate executions until their combined timing reaches 10 ms. It stops
after 1,024 executions and records the per-execution average. This keeps
scheduler resolution from dominating small workloads without extending large
workloads. Accelerator evidence retains one real cold dispatch. Steady and warm
rounds rotate route order so host drift is shared across peers. Overlap that
survives the rotation is resolved as a dead heat rather than spending unbounded
install time or guessing.

Because the decision is *measured*, it must be recorded before `--backend auto`
(the default) can claim a fastest route. A fresh install has no decisions yet,
so an automatic scan selects no backend for each unproved batch, records
incomplete coverage, and reports `autoroute calibration required` with a repair
command.

## Calibrate, inspect, then scan

For a multi-backend build, use this sequence:

```sh
keyhog calibrate-autoroute
keyhog backend --autoroute
keyhog scan .
```

The scan uses `auto` by default. It reads the persisted table and never
benchmarks during the scan. Use an explicit backend only for a deliberate
diagnostic or benchmark.

Before calibration:

- Run the same KeyHog binary that will perform the scans. Build identity and
  scanner feature identity are part of every decision.
- Use a writable persistent cache path. `--autoroute-cache off` is rejected
  because calibration must publish durable evidence.
- Keep the host reasonably idle. Route trials are interleaved across peers so
  common drift is shared. Overlapping intervals resolve deterministically to a
  non-inferior low-complexity route; unusable evidence or backend disagreement
  across retained points exits without publication.
- Make every source prerequisite available. The subcommand covers the core
  stdin and filesystem ladder. Git, Docker, and web fixtures use the low-level
  `scan --autoroute-calibrate` probe on the exact source.

A build with only `cpu-fallback` reports `health: direct` and does not require
calibration.

## Calibrate core and source-specific workloads

Cargo installation does not benchmark your host. Calibrate the installed
binary before its first automatic scan:

```sh
keyhog calibrate-autoroute
```

Run the command again after a binary, detector, configuration, driver, or
hardware change. The command calibrates the core stdin and filesystem workload
ladder. A routing diagnostic for an unproved Git, Docker, or web workload prints
the exact low-level `scan --autoroute-calibrate --autoroute-gpu` command.

The default command calibrates the ordinary policy and every documented preset:

```sh
keyhog calibrate-autoroute                 # all policies
keyhog calibrate-autoroute --policy default
keyhog calibrate-autoroute --policy fast
keyhog calibrate-autoroute --policy deep
keyhog calibrate-autoroute --policy precision
```

The policy names correspond to no preset flag, `--fast`, `--deep`, and
`--precision`. Each policy has its own resolved configuration digest and route
decisions. A focused run keeps valid evidence for other configurations. It
publishes only after every workload in the selected policy succeeds. Use the
default all-policy sweep for a new installation. Use a focused policy to repair
or refresh only the preset you run.


This drives the core stdin + filesystem workload ladder across every scan
preset. Plain single-file probes cover every power-of-two size band from 1 byte
through 32 MiB, with additional 4 MiB + 1, 8 MiB - 1, 8 MiB + 1, and
16 MiB - 1 probes retaining raw evidence on both sides of the required 8 MiB
crossover. A coarse size class holds its points together when they agree, and
also when they disagree without proving anything: the class keeps the
lowest-complexity backend that is measured at every point and measurably
slower at none. A disagreement that measurement does prove, where one point's
whole 95% interval for the selected backend sits above a peer's, is a real
crossover; it rejects calibration and requires the class to be split. Such a
class reports `confidence_separated: false`, because the route is permitted by
the evidence rather than proved by it. File-tree probes cover
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
classes, exact measurement points retained by this sweep, and the total route
decisions in the cache. The required readback checks every measured shape digest,
not only the shared workload key. A missing representative prevents publication.
The cache total can include valid decisions from prior calibration runs. The
command also prints a cache route summary showing how many one-shot and daemon
rows select a VYRE GPU route, plus the number of GPU candidate receipts measured.
The command does **not** cover Git, Docker, or web source probes. Those
workloads need a real external fixture such as a repository, running daemon, or
served URL. The low-level `scan --autoroute-calibrate` probe measures one
caller-supplied workload. It does not synthesize or sweep external fixtures. If
one of these sources reports `autoroute calibration required`, run the
reported `repair_command`. Decisions are written, parity-checked, to the
autoroute cache (`$XDG_CACHE_HOME/keyhog/autoroute.json`
by default; override with `--autoroute-cache <path>` or
`[system].autoroute_cache`).

Canonical calibration admits every eligible execution class. The low-level
`scan --no-autoroute-gpu --autoroute-calibrate` diagnostic measures a CPU-only
candidate set, and that evidence cannot overwrite or be replayed by a normal
all-candidate decision. The isolation lives in the persisted host generation,
not in the config digest. A host generation records the eligible backend census
plus the complete GPU device, runtime, driver, and batch-limit identity, and a
scan replays a row only when that whole profile compares equal, so a CPU-only
measurement is invisible to a scan that admits a GPU.

The resolved config digest deliberately does not record whether a calibration
excluded a GPU. Recording it there was a guaranteed miss on every host and
build with no GPU candidate, because the exclusion is vacuous but the digest
still differed: calibration wrote decisions under a key no scan would ever
request, and the immediately following identical scan reported a config
mismatch and left the batch unscanned.

Startup reports every available GPU peer without creating execution devices or
pipelines. Calibration acquires each peer when its candidate is measured and
reports the exact acquisition failure. The
autoroute cache stores separate CUDA, Metal, and WGPU cold and warm timing
vectors, and `keyhog backend --autoroute` prints each eligible peer. A failed driver is ineligible until it
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

### Reading the cache hit rate

Every automatic scan prints one line on stderr saying what the cache did:

```text
INFO autoroute cache: 100.0% hit (2 hit / 2 lookup(s))
```

One lookup is one batch asking the cache for its route. A hit means the batch
ran on a persisted, measured-correct backend without benchmarking anything. A
miss means no backend was selected, the batch remained unscanned, and the run
records incomplete coverage.

The line prints in every output mode, including `--format json -o <file>`. That
is the shape CI and calibration harnesses use, and it used to suppress the whole
routing summary.

A scan with any miss names the cause and the repair:

```text
WARN autoroute cache: 0.0% hit (0 hit / 2 lookup(s)); every byte was still
scanned, this costs speed not coverage; miss causes: cache-rejected=2;
2 distinct uncalibrated bucket(s); repair: the cache belongs to a different
build, host, detector corpus or scan config; recalibrate this exact
configuration (recalibrating one bucket will not help)
```

Read the miss cause before you recalibrate. The causes call for different
actions:

| cause | meaning |
|---|---|
| `no-cache-configured` | no autoroute cache path resolved for this scan |
| `cache-rejected` | the cache belongs to a different build, host, corpus, or config; recalibrating one bucket will not help |
| `workload-unclassified` | the batch could not be bucketed, so no calibration can cover it |
| `bucket-absent` | the cache is valid and does not cover this workload yet |
| `runtime-class-unproved` | the bucket exists without a route proved for this runtime class |
| `route-quarantined` | a persisted route faulted at runtime and was quarantined |
| `route-health-unavailable` | route-health state could not be read, so no persisted route is trusted |
| `gpu-peer-identity-changed` | the GPU peer changed since calibration |

A miss costs speed, never coverage. Every byte is still scanned. This line is
not a coverage gap, and a 0% hit rate does not mean the scan was incomplete;
see [Coverage truth](coverage-truth.md) for the signals that do mean that.

Run with `-v` to list every distinct uncalibrated bucket under the
`keyhog::routing` target, most expensive first. One recalibration can then be
planned to cover all of them, rather than learning about one bucket per run.

Under `--profile`, the same outcomes appear in the standard cache family as
`autoroute-decision` (a scan reusing a persisted route) and
`autoroute-calibration` (a calibration reusing evidence instead of measuring
again), with hits, misses, and `hit_rate_ppm` in the `--profile-out` JSON.

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

Any decision containing a GPU one-shot route, persistent route, parity receipt,
or measured candidate also binds the installer-owned GPU matcher manifest.
KeyHog verifies every named `.bin` member against its SHA-256 digest before
accepting the cache. Missing, malformed, duplicate, symlinked, oversized, or
changed members reject the cache. Unrelated lazy runtime-cache files do not
change this identity.

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

A lookup first tries the complete workload key. Size, chunk-count, and
maximum-file dimensions use one-power-of-two logarithmic ranges. A decision
proves correctness and timing for the representative measured under that key.
It does **not** prove that the same backend is fastest for every individual
byte length inside the numeric range.

A size band nobody measured is served only by measured invariance. KeyHog
collects every calibrated decision that shares this workload's pattern band,
decode state, and source-class set. Two such bands are the minimum: one band
says nothing about whether the winner depends on size. Their measurements are
then reconciled by the rule that reconciles the repeated points inside a single
band. The served backend is the lowest-complexity backend measured at every one
of those bands and proved slower at none. Bands that agree on the backend and
disagree on the phase-2 localizer plan resolve to the compiled default plan,
which each of them must have measured. A band whose own evidence resolves no
route, a backend crossover where one band proves a peer faster and another
proves the reverse, and any GPU route all withdraw the reuse. Nothing is
benchmarked, guessed, or substituted at scan time; the served route is one
calibration measured, repeatedly, for this exact class.

GPU routes are never reused for an unmeasured band. GPU correctness, not only
GPU speed, varies with input size: batch input caps and per-slot capacities
bind to the measured shape, and a parity receipt proves that shape and no
other.

When neither an exact key nor an invariant family covers the batch, a normal
scan selects no backend for it, leaves it unscanned, records incomplete
coverage, and exits nonzero with recalibration guidance. Calibration and
explicit backend contracts also fail when their requested evidence or route
cannot be produced.

Large directory and multi-source scans run in process and produce multiple real
batches. The core calibration command includes file-tree probes, while Git,
Docker, and web fixtures require installer calibration.

## One-shot scans and the daemon

Runtime lifetime changes accelerator cost, so it is part of routing semantics.
Calibration records the scalar CPU distribution directly. For SIMD and each
GPU peer it records the real first materialization/dispatch followed by warm
trials:

Every candidate contributes exactly seven positive trial durations. Route
comparisons pair the same rounds. Missing, extra, zero, or unpaired trials
invalidate the decision instead of being trimmed or substituted.

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
invalidates automatic routing. No backend is selected for an affected batch; it
remains unscanned and receives repair guidance. An explicit GPU override or
`--require-gpu` remains a hard backend contract and is not substituted.
`keyhog backend --autoroute` reports `quarantined` readiness, aggregate and
per-config fault counts, and the failed backend/reason on each affected workload;
`keyhog doctor` reports the same repair state.

## Diagnose invalid state and authenticated recovery receipts

Capture a metadata-bearing report, then inspect routing health:

```sh
keyhog scan . --format json-envelope --output keyhog.json
jq '{scan_status, backend_recoveries: (.metadata.backend_recoveries // [])}' keyhog.json
keyhog backend --autoroute
keyhog doctor
```

When automatic route state is unusable, the scan warning names the missing
workload bucket and the dimensions that differ from the nearest measured class.
No backend is selected, the affected batch remains unscanned, and the report
uses `scan_status: "partial"` with a coverage gap. `metadata.backend_recoveries`
contains only completed recovery from a faulting authenticated backend; invalid
route state never creates a scalar recovery receipt.

Use the reported state to choose the repair:

- For one uncovered core workload, rerun the same scan once with
  `--autoroute-calibrate --autoroute-gpu`. This measures its actual source,
  resolved configuration, and workload class.
- For a standard preset ladder, run `keyhog calibrate-autoroute`. Add
  `--policy default`, `fast`, `deep`, or `precision` for a focused repair.
- For Git, Docker, or web source classes, run the exact `repair_command`
  reported for that source.
- For `stale`, recalibrate with the new binary after an upgrade.
- For `quarantined`, repair the named SIMD or GPU runtime first. Use
  `keyhog backend --self-test --require-gpu` for a GPU path, then recalibrate so
  the exact route fault can clear.
- For `disabled` or a storage error, fix the cache path or permissions and run
  the `repair_command` shown by JSON inspection.

An explicit diagnostic such as `keyhog scan . --backend simd` bypasses
autoroute. It does not clear an invalid state. It is a hard contract and fails
if that backend cannot initialize or execute. It is never substituted with
another backend.

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
chunks, ranges, and bytes only after a fault in an authenticated selected
backend. Invalid route state records an unscanned coverage gap; inspection
remains unhealthy until calibration produces confidence-separated evidence.

Pass `--autoroute-cache` when the scan uses a non-default cache path through
the matching scan flag or `[system].autoroute_cache`.

These show every persisted config and host generation, its workload buckets,
representative route times, whether confidence was separated, the selection
basis, and the resolved one-shot and daemon backends. The JSON view is lossless:
each route includes its ordered nanosecond trials, cold observation, exact
one-shot and warm projections, and 95 percent confidence bounds, so the result
can be reproduced without parsing the private cache file. Each generation's
`eligible_backends` array defines the complete backend set. Every decision must
contain all four localization plans for every eligible backend and every
eligible resident depth for each GPU peer, and prove each route correct.
Removing a candidate timing and its receipt together still invalidates the
cache because validation compares the full Cartesian route set with this live
config identity.
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
| `backend`, `phase2_plain_localizer`, `phase2_keyword_localizer`, `gpu_pipeline_depth` | Cold-aware backend, both phase-two localization choices, and resident GPU pipeline depth for an in-process one-shot scan. Host and synchronous GPU routes use depth one. |
| `calibration_points` | Number of exact content-and-source-shape representatives retained for this workload class. Equal byte/chunk counts can contribute more than one point. |
| `sample_bytes_min`, `sample_bytes_max`, `sample_chunks_min`, `sample_chunks_max` | Exact measured envelope covered by the class. |
| `measured_points` | Complete point-by-point projection: exact sample size, `measurement_generator`, `payload_digest`, `measurement_shape_digest`, timestamp, one-shot and daemon execution-plan winners, confidence status, every route timing, and every parity receipt. Use this array to distinguish same-sized probes and diagnose crossover behavior. |
| `sample_bytes`, `sample_chunks`, `route_timings` | Concise size projection plus the complete generic route-timing array for the first point after sorting by bytes, chunks, then measurement-shape digest. Each timing identifies the backend, both localization choices, GPU pipeline depth and capability, per-slot input and match capacities, one-shot time, and warm time when applicable. `measured_points` is authoritative. |
| `confidence_separated` | Whether one-shot evidence proves the route at every measured point, either as an exact paired-plan winner or as a statistically tied plan separated from every peer backend plan. `false` means the route is the dead-heat resolution of a measurement that separated nothing. |
| `selection_basis` | `exact-plan-paired-95pct-confidence`, `peer-separated-compiled-default-plan`, `peer-separated-statistically-tied-plan`, or `unseparated-dead-heat-lowest-complexity-backend`. The last one names a decision the evidence permits rather than one it proves, and always pairs with `confidence_separated: false`. |
| `selected_margin_ns` | Smallest one-shot representative-time margin to the next eligible route across all measured points; `null` when there is no peer route. |
| `daemon_backend`, `daemon_phase2_plain_localizer`, `daemon_phase2_keyword_localizer`, `daemon_gpu_pipeline_depth` | Backend, both phase-two localization choices, and resident GPU pipeline depth derived for a ready persistent daemon from warm evidence. |
| `daemon_confidence_separated`, `daemon_selection_basis`, `daemon_selected_margin_ns` | Daemon-route counterparts, also aggregated conservatively across every measured point. |
| `source_mixture` | Structured source-class components used by the workload identity: privacy-safe `source_class` for KeyHog-owned classes (`null` for unknown library-provided values), canonical execution-class digest, full-size versus payload provenance, reduced chunk/payload ratios, and maximum source-span bucket. The human-readable `workload` uses `<source_class>@<digest>` for known classes and `custom@<digest>` otherwise, so arbitrary source metadata is never echoed. JSON consumers should use these fields instead of parsing that string. |
| `candidate_receipts` | Concise summary of the first measured point's receipts. Every receipt identifies the backend, both localization choices, GPU pipeline depth, dispatch capability, and per-slot input and match capacities. Every point carries the complete eligible route set; every result digest must equal its point's scalar/both-off reference, and every evidence digest must recompute exactly or the cache is rejected. |

## Single-backend builds

A build that compiled only one backend has nothing to route. The `portable`
build, for example, ships only the scalar CPU backend, so it skips autoroute
entirely and never reports `calibration required`. Calibration applies only to
builds that compiled a real backend choice (Hyperscan/SIMD and/or GPU).
