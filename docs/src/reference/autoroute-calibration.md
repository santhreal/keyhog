# Autoroute calibration

> **Not the same as confidence calibration.** This page is about *backend
> selection*: measuring which engine (SIMD, scalar CPU, GPU) is fastest and
> proven-correct for your workload. For the per-detector Bayesian confidence
> counters (`keyhog calibrate --tp/--fp`), see
> [Confidence calibration](./confidence-calibration.md).

KeyHog scans with the **fastest backend that is proven correct** for your
hardware and workload: Hyperscan/SIMD, scalar CPU, or GPU. It does not guess.
Autoroute is *not* a fallback hierarchy: at install time KeyHog measures every
eligible backend, rejects candidates whose canonical match identity differs
from the reference (chunk, detector id, credential hash, file, line, and byte
offset), and records the fastest survivor. Normal scans then do a zero-cost
table lookup; they never benchmark mid-scan. Report metadata outside that
identity is produced by the shared post-processing/reporting tail rather than
by backend-specific extraction.

Because the decision is *measured*, it must be recorded before `--backend auto`
(the default) can run. A fresh install has no recorded decisions yet, so until
you calibrate, an auto scan fails closed with
[exit code `2`](./exit-codes.md), `autoroute calibration required`, rather
than silently substituting a slower or unverified backend.

## Calibrate

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
preset. Plain single-file probes cover every power-of-two size band from 512 bytes
through 32 MiB (512 B, then every power of two from 1 KiB through 32 MiB), plus
decode-heavy and many-file shapes. It does **not**
cover the git / docker / web source probes; those need environment orchestration
(a repo, a running daemon, a served URL) that only the installer's
`--calibrate` mode performs. If you scan those sources and hit
`autoroute calibration required`, re-run `install.sh --calibrate` /
`install.ps1 -Calibrate` rather than the subcommand. Decisions are written,
parity-checked, to the autoroute cache
(`$XDG_CACHE_HOME/keyhog/autoroute.json` by default; override with
`--autoroute-cache <path>` or `[system].autoroute_cache`).

Calibration saves take an exclusive sibling-file lock across the complete
read/merge/atomic-write cycle. Separate calibration processes therefore
accumulate their config and workload decisions without a last-writer-wins
loss; the operating system releases the lock if a writer exits or crashes.

## What a decision covers

A decision is tied to your exact binary, host, detector corpus, **and resolved
scan configuration**. Options that change the resolved config get their own
calibration, even when they do not change which backend is fastest:

- Build identity records the CLI and dependency feature sets. GPU and SIMD
  support are read from the scanner library that actually owns and compiled
  those backends, not inferred from similarly named CLI features.
- Host identity includes OS/architecture, CPU model and topology, memory, CPU
  instruction support and, when the scanner can use a physical GPU, the GPU
  device, runtime backend, and driver/runtime identity. A missing or changed
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

`keyhog config --effective` prints the exact resolved settings that are hashed into
this identity; pair it with `keyhog backend --autoroute --json` to verify that a single
setting change in `ScanConfig` produced a new `config_digest` row.

Every lookup is exact at the complete workload-key level. Size, chunk-count,
maximum-file dimensions use one-power-of-two logarithmic ranges; decode density
uses paired logarithmic ranges to resist content-sample jitter. The
decision proves the measured representative for that full range key, not every
individual byte length inside it. A neighbouring range is not evidence for this
one. Uncalibrated keys fail closed; KeyHog never interpolates or clamps them to
a CPU/GPU substitute.

## One-shot scans and the daemon

Runtime lifetime changes GPU cost, so it is part of routing semantics. Each GPU
measurement contains the real first dispatch plus warm trials:

- An in-process one-shot scan includes cold GPU cost when choosing a backend.
- A ready daemon initializes accelerator state before accepting requests and
  chooses from the warm GPU trials.

Both routes consume the same parity-checked primary evidence; they derive the
appropriate decision for their runtime instead of sharing one misleading
"GPU time." CPU, Hyperscan/SIMD, and GPU remain peers in both cases. See
[Daemon and warm scans](../workflows/daemon.md) for request eligibility,
fallback, policy, socket, and timeout semantics.

## When an auto scan reports `calibration required`

The error names the missing workload bucket. Resolve it by either:

- Re-running calibration (`keyhog calibrate-autoroute`, or `install.sh
  --calibrate` / `install.ps1 -Calibrate`) so the bucket gets a measured
  decision, or
- Passing an explicit backend for a one-off diagnostic scan:
  `keyhog scan --backend simd` (or `gpu`, `cpu`, …). An explicit `--backend`
  bypasses autoroute entirely; it is a diagnostic/benchmark override and does
  not prove autoroute correctness.

A `STALE` status means the cache was written for a different build; auto scans
reject it, so recalibrate after upgrading KeyHog.

## Inspect what is calibrated

```sh
keyhog backend --autoroute          # human-readable cache contents
keyhog backend --autoroute --json   # machine-readable
keyhog doctor                       # reports calibrated / not calibrated / STALE
```

These show every persisted config, its workload buckets, and the resolved
backend, so when a scan hits `exit 2` you can see exactly what *is* covered.

## Single-backend builds

A build that compiled only one backend has nothing to route. The `portable`
build, for example, ships only the scalar CPU backend, so it skips autoroute
entirely and never reports `calibration required`. Calibration applies only to
builds that compiled a real backend choice (Hyperscan/SIMD and/or GPU).
