# Autoroute Calibration Completeness & Tuning — Phase Design

## The bug (empirically confirmed on the ci-lean build)

After a clean `install.sh --calibrate`, **every** auto scan can fail closed with
**exit 2 "autoroute calibration required"** — not only the documented presets
(`--fast`/`--deep`/`--precision`), but the dominant `keyhog scan .` itself, and
the Docker integration matrix's `default` profile. Reproduced directly against
the `release-fast --features ci-lean` binary (Hyperscan present).

There are **two compounding root causes**, both proven by reproduction:

### Cause 1 — install calibrates a digest no real scan ever requests

`autoroute_config_digest` (`orchestrator_config/effective.rs:312`) hashes the
**resolved** scan config that reaches the engine, which includes routing/perf
knobs: `batch_pipeline` (effective.rs:384) and `autoroute_gpu` (effective.rs:393)
among them. `install.sh prime_autoroute_cache` runs every probe with
`--batch-pipeline --autoroute-gpu` (install.sh:1648–1666), so it calibrates
digest **A**. A plain `keyhog scan .` uses neither flag (a filesystem auto scan
cannot route GPU — `filesystem_auto_scan_cannot_route_gpu` returns true — and
does not force the coalesced batch pipeline), so it requests digest **B ≠ A** →
fail closed.

Proof:
- Calibrate with plain flags → plain scan **exit 1** (works).
- Calibrate with `--batch-pipeline --autoroute-gpu` → scan with the **same**
  flags **exit 1** (works). The digest is internally consistent; the installer
  simply calibrated the wrong flag combination for the dominant scan path.

### Cause 2 — sequential calibration probes clobber each other

`MeasuredBackendRouter::save_cache` (backend.rs) filters to `measured_this_run`,
and the old `save_autoroute_cache` **overwrote** the whole file. install.sh runs
each workload probe as a **separate process** (one bucket each), so probe N
overwrote probe N-1's bucket. Only the **last** probe's workload bucket survived
per digest; every other-sized scan failed closed even for the calibrated digest.

Proof: calibrate a small file (process 1) then a large file (process 2),
separate processes, same digest → cache holds **1** decision, not 2; the small
bucket is evicted (small scan exit 2, large scan exit 1).

These two stack: the wrong digest is calibrated, and even that digest keeps only
one workload bucket.

## The fix

### Keystone — merge-on-save multi-config cache (`backend/store.rs`) ✅

Schema **v20**: shared binary/host/corpus/rule identity lives once at the top;
per-resolved-config decisions live under `configs[]`, keyed by `config_digest`.

- `load_autoroute_cache(config_digest)` returns that config's decisions, fail
  closed (exit 2) if the config entry is absent — the fail-closed contract
  (#17/#18) is preserved per-config.
- `save_autoroute_cache(config_digest, decisions)` **merges**: it reads any
  compatible on-disk cache, **unions** this config's freshly measured buckets
  over those it already had (fixing Cause 2), and **preserves every other
  config** entry (letting default + presets coexist). An incompatible/corrupt
  file is superseded wholesale and **loudly** (`read_mergeable_configs` logs why
  — Law 10), because a binary/host/corpus change invalidates all configs.
- `load`/`save` signatures are unchanged, so the router (`backend.rs`) and every
  caller are untouched; the multi-config logic is fully internal to the store.
- Version gate bumped 19→20, so old single-config caches are rejected with a
  clear "unsupported autoroute cache version" verdict and recalibrated.

Regression tests (durable proof): `multi_config_cache_accumulates_buckets_across_
sequential_saves` (Cause 2), `multi_config_cache_keeps_distinct_presets_side_by_
side` (preset coexistence), `multi_config_cache_upserts_same_bucket_without_
duplicating` (merge upsert, no duplicate-key rejection).

### install-time calibration calibrates the real flag combinations

Calibration must produce the digests real scans request, with writer/reader
parity guaranteed rather than hand-matched in shell. Default scans use no
pipeline flags; the documented presets each change scan-policy fields. The
`--batch-pipeline --autoroute-gpu` digest stays as the GPU/coalesced opt-in path.

## Phase tasks (see task list #31–#43)

- **#32 calibrate-autoroute subcommand** — de-shell probe-sweep orchestration
  into the binary; resolve each (workload class × preset) digest the SAME way a
  real scan does, so parity is structural, not hand-matched. Generate each probe
  once, calibrate every preset on it (bounded install time). install.sh calls it.
- **#33 preset calibration** — sweep `default,fast,deep,precision` (and the
  Docker-matrix profiles: no-ml, no-entropy, no-gpu, threads-1). They coexist in
  the v20 multi-config cache.
- **#34 bucket generalization** — SHIPPED as sound CPU-class bracket
  interpolation (`store::resolve_bucket`): a near-miss bucket resolves to a
  backend only when it lies between two calibrated buckets that agree along ONE
  size axis AND are both CPU-class (exact-match → recall-uniform across size; GPU
  never interpolates, cf. #18). Loud once-per-process notice, never silent. A
  disagreeing/un-bracketed miss still fails closed.
  - **#44 below-floor clamp** — a single file SMALLER than every calibrated
    single-file rung on BOTH size axes (the everyday `keyhog scan small.env`)
    clamps to setup-free CpuFallback (an input too small to amortize any
    backend's setup cannot be beaten by one that pays it; CpuFallback is
    reference-correct). Strict on both axes; an uncalibrated class still fails
    closed. Loud `ClampedBelowFloor` notice.
  - **#46 diagonal interpolation** — a single file BETWEEN two calibrated
    single-file rungs (its `bytes`/`max_file` buckets move together, so #34's
    per-axis bracket can't see it) resolves along the size diagonal when the two
    rungs agree on a CPU backend. Same monotonicity soundness as #34 applied to
    the one-degree-of-freedom single-file size axis; GPU never anchors;
    disagreeing/one-sided brackets still fail closed.
- **#35 measurement rigor** — already multi-trial + SIMD-parity-checked
  (`backend/calibration.rs`); audit warmup/reps/margin and record margins.
- **#36 Docker matrix** — bake the preset calibration into the image so the auto
  profiles pass (cache lives in the image; each check is `docker run --rm`).
- **#37 doctor coverage** — report which presets/configs are calibrated; warn
  before a scan would hit exit 2.
- **#38 inspectable decisions** — `keyhog backend`/`--show-autoroute` lists
  persisted configs + buckets + margins.
- **#39 e2e** — after `install.sh --calibrate`, every documented preset resolves
  a decision (never exit 2); writer/reader config-digest parity per preset.
- **#40 coherence** — README Autoroute Contract + `--fast`/`--deep` examples +
  the exit-2 error message must state real coverage.
- **#41 elegance** — co-locate decision/bucket/digest/cache-schema/fail-closed
  policy behind one documented boundary; one re-export.

## Session findings (2026-06-27) — empirical, drive #34/#36/#38

**#36 root cause was two-layered, not just "uncalibrated."**
1. The ci-lean image carries Hyperscan/SIMD *and* scalar CPU, so every auto
   scan fails closed (exit 2) without a baked decision — fixed by the in-image
   `--autoroute-calibrate` bake (`tests/docker/Dockerfile.glibc`).
2. Even after baking, `--precision /test/corpus/aws_leak.env` returned **0
   findings** (rc 0, empty array), failing `inv:precision/aws-found`. Cause:
   `high_precision()` keeps `penalize_test_paths` ON, and `test` is a penalized
   path component (`crates/scanner/data/test-path-rules.toml`), so the planted
   AKIA was dropped below the 0.85 floor. The corpus was relocated `/test/corpus`
   → `/data/corpus` (a neutral path), restoring the "found under every profile"
   invariant. This is **correct** detector behavior surfaced by a bad fixture
   path — not a recall bug.

**Bucket/digest fragility — the concrete case for #34.** The matrix exercises
more autoroute (workload, config) pairs than the policy×file grid, and EACH that
the bake omitted failed closed at exit 2 until calibrated explicitly:
- a **directory** target is a different `WorkloadKey` than a single file;
- `--min-confidence 0.0` and `--threads 64` each fork the `autoroute_config_digest`
  (both are hashed in `effective.rs::autoroute_config_digest`), so each needs its
  own calibration even though neither changes which backend is *fastest*;
- **stdin** buckets are CONTENT-sensitive: calibrating stdin with `clean.txt`
  did NOT cover a stdin scan of the AKIA line — the bake and scenario must feed
  byte-identical input (now both pipe `/data/corpus/aws_leak.env`).

The image now bakes all of these explicitly (a drift = a loud exit 2 in run.sh,
never a silent miscalibration). But the broader lesson for **#34** is that the
exact-bucket-or-fail-closed model forces N calibrations for N near-identical
workloads. `min_confidence` is a pure post-scan *filter* — it cannot change
backend throughput — yet it forks the digest; that fragmentation (and the file
vs dir vs stdin bucket split) is what #34 must generalize WITHOUT guessing a
backend (Law 10): a decision may cover a neighbor only when the backend choice
is provably stable across that range, never by silent substitution.

**#38 shipped:** `keyhog backend --autoroute` (`+ --json`) renders the persisted
cache — configs, workload buckets, resolved backend, and build-staleness — so an
operator who hits the exit-2 message can see what *is* calibrated. Reuses one
`inspect_autoroute_cache` primitive (store.rs), re-exported once up the chain.

## Session findings (2026-06-27, cont.) — #36 musl green + single-backend bypass

**#36 fully closed (glibc AND musl).** The glibc image was greened earlier by the
in-image calibration bake + neutral corpus path. The **musl** image had been red
for 12+ runs for a *different* reason: it is built `--features portable` (no
Hyperscan/`simd`, no `gpu`), so it compiles only `ScanBackend::CpuFallback` — yet
both routers still demanded a cached decision and **failed closed (exit 2)** on
every auto scan. There was no single-backend bypass.

Fix: `sole_compiled_backend()` (`dispatch/backend.rs`) resolves the lone
`CpuFallback` directly when no backend *choice* was compiled, checked AFTER the
explicit `--backend` override (so it never silently substitutes for a requested
backend — Law 10). A multi-backend build returns `None` and routes as before. The
`--backend simd` Docker scenarios are skipped on single-backend images (that
backend genuinely does not exist there — a loud, recorded skip, not test-weakening).
Result: musl integration **green**. This also closes the doctor.rs/portable
coherence claim (#40) that single-backend builds never fail closed — now true.

**The cfg discriminator must live in the scanner, not the CLI.** First cut gated on
`cfg!(feature="simd") || cfg!(feature="gpu")` *inside the CLI crate* — WRONG, because
cli `ci-lean = ["keyhog-scanner/ci-lean"]` enables `keyhog-scanner/simd` WITHOUT the
CLI's own `simd` feature, so the CLI `cfg!` reads false while SimdCpu is compiled →
the bypass wrongly skipped calibration and reddened the e2e
`backend_autoroute_shows_calibrated_decisions_after_calibration`. Correct:
`keyhog_scanner::hw_probe::multiple_backends_compiled()` (`pub const fn`), where the
`simd`/`gpu` gates actually live.

**#40 install.ps1 Windows parity.** install.ps1 calibrated every probe with
`--autoroute-calibrate --batch-pipeline --autoroute-gpu`, keying a digest a plain
`keyhog scan .` never requests → every default Windows scan failed closed. Now it
calibrates the plain default + each supported preset (core stdin/filesystem
workloads once per preset; external sources at default only), mirroring install.sh's
`for autoroute_scan_flags in "" $autoroute_presets` loop. README documents the
single-backend bypass.
