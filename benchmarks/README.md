# keyhog benchmarks

A reproducible, multi-corpus, multi-config evaluation harness. One importable
Python package (`bench/`) replaces the scattered scripts that used to live
under `tools/secretbench/scoring/`: every run produces one `RunResult` JSON on
a single schema, so one scorer, one report generator, and one test suite serve
every **scanner × config × corpus × host** combination.

The competitor tables in the top-level [`../README.md`](../README.md) are
**generated** by `make report` (between `<!-- BENCH:* -->` markers) - never
hand-edited.

## Quick start

```bash
make mirror     # generate the 15k synthetic SecretBench-mirror corpus (off-git, neutral layout)
make bench      # run every scanner on the mirror -> results/<host>/
make ioc-recovery-corpus # generate the deterministic P0-P12 recovery corpus
make ioc-recovery # compare all four keyhog presets on exact recovery
make report     # render reports/ + inject the leaderboard into ../README.md
make analyze    # print top FP/FN examples for detector tuning
make test       # pytest the package (scorer truth, loaders, injection idempotence)
make targets    # execute aspirational recall/competitor target specs (expected worklist)
```

The release keyhog binary is resolved from `$KEYHOG_BIN`, else the cargo
target-dir in `$CARGO_TARGET_DIR`, else `~/.cargo/config.toml`, else the repo
target dir, else `keyhog` on `PATH`. Build it first:
`make keyhog` or `cargo build --release -p keyhog`.
The benchmark needs create and delete access beside that binary to protect its
execution snapshot. For a managed read-only install, copy the verified artifact
into a private writable runtime directory and set `$KEYHOG_BIN` to that copy.
The default test/release gate excludes tests marked `target_spec`; those are
executable product targets, not claims that the current release already meets.
Run them explicitly with `make targets`.

## What it measures

- **Detection:** TP / FP / FN → precision / recall / F1, overall and
  per-category. General secret corpora use the SecretBench containment rule.
  Recovery records require the scanner to surface the exact recovered
  plaintext, so an encoded value or a larger containing string earns no
  recovery credit.
- **Speed:** wall time + throughput (MB/s) + peak RSS per run. In-process rows
  use `/usr/bin/time -v`. Daemon rows time the warm client request and read the
  owned server's `VmHWM`, since the server owns scanner memory.
- **Host:** OS / kernel / CPU / cores / RAM / GPU + VRAM, captured per run so
  desktop / santhserver / Windows-ThinkPad / macOS results aggregate into one
  matrix.
- **Config:** keyhog's `backend × cache × daemon × mode` axes; each competitor
  carries its own knob (kingfisher confidence, etc.) in the same `config_id`.
- **Execution route:** each KeyHog result records whether execution was
  in-process or daemon-served. A daemon result also records the owned server
  PID and exactly two served requests (one warmup, one timed scan).
- **Detector provenance:** every KeyHog run scans a private immutable snapshot
  and records the SHA-256 of its exact detector TOML filenames and bytes. The
  gate rejects results whose digest does not match the workspace corpus.
- **Executable provenance:** every warmup and measured KeyHog command runs the
  same held-inode byte snapshot beside the resolved runtime. Linux launches use
  the inherited descriptor, so path replacement cannot change executed bytes.
  Windows holds the snapshot handle through measurement. Darwin fails closed
  until equivalent `current_exe` and loader semantics are proven. Results record
  the snapshot SHA-256 and version. The gate requires an exact match with the
  current candidate binary.
- **Source freshness:** current-source evidence requires a clean tracked Git
  tree and an exact recorded HEAD commit. KeyHog validates the snapshot before
  scanning, and result-only gates check workspace identity before scoring.

## Two fairness rules (baked into every corpus)

Both were proven against the live keyhog binary, not assumed:

1. **The answer key is excluded from the scan tree.** A scanner pointed at a
   dir containing `manifest.jsonl` (every labeled secret in plaintext) "finds"
   those secrets; betterleaks fires **9392** spurious matches on the mirror
   manifest, kingfisher **7581**. Layout keeps the manifest a *sibling* of the
   scan tree: `<home>/manifest.jsonl` beside `<home>/corpus/<shards>`; scanners
   only ever see `corpus/`.
2. **The scan dir has a neutral name** (`corpus`, never `fixtures`/`test`).
   keyhog applies a path-context test-fixture confidence penalty under
   "fixtures"-shaped paths that `--no-suppress-test-fixtures` does *not*
   override; the same 15k files scored 1880 findings under `fixtures/` vs 2484
   under a neutral name.

On the fair mirror keyhog ranks **#1, well ahead of every competitor** on F1
at near-top precision. The exact figures are not hand-written here; they
drift with the binary and would go stale - read them from the generated
leaderboard in the top-level [`../README.md`](../README.md), regenerated by
`make report`. Always bench the freshly-built release binary (see
*Reproducibility* below); a stale `keyhog` on `PATH` invalidates the run, and
the cross-device harness rejects preinstalled PATH binaries before recording a
row.

## Leakage-safe dataset splits

Any corpus used to train, calibrate, and report a sealed score must pass the
split leakage guard before measurement:

```bash
make -C benchmarks leakage-audit \
  LEAKAGE_MANIFEST=corpora/splits.jsonl \
  LEAKAGE_CONTENT_ROOT=corpora/source \
  LEAKAGE_RECEIPT=reports/leakage-receipt.json
```

The JSONL manifest has an exact schema. Each row supplies `record_id`, `split`,
`corpus_id`, `corpus_sha256`, `repository_family`, `credential_family`,
`secret`, `content_path`, `credential_start`, and `credential_end`. Splits are
`train`, `calibration`, or `sealed-test`. Paths are relative POSIX paths under
the content root. Credential offsets are Unicode character offsets.
`repository_family` must identify the common ancestry root across forks and
mirrors. `credential_family` must identify the normalized credential lineage,
not only its provider label.

The guard fails if repository ancestry, normalized credential lineage,
normalized credential value, or an exact or near-duplicate redacted context
crosses a split. Context fingerprints exclude the credential and use 200
characters on each side. The token checks retain the published SecretBench
leakage thresholds: unique-token Jaccard at 0.80 and multiset Jaccard at 0.70.
Byte 5-grams and normalized structure 4-grams add independent 0.90 checks for
small edits and identifier or literal rewrites. These settings follow the
methodology in [From Data Leak to Secret Misses](https://arxiv.org/abs/2601.22946).

The receipt binds the manifest, pinned corpus digests, redacted source content,
split assignments, grouping results, and policy. It reports raw and
deduplicated sample counts without credential, repository, family, or context
bytes. Detected leakage writes a failure receipt and exits with status 2.
Malformed provenance fails before scoring. Input is capped at 100,000 records,
8 MiB per content file, 512 MiB across unique content files, and 5,000,000
candidate comparisons. Repeated paths reuse one decoded source buffer.

## Layout

```
benchmarks/
  bench/                  importable package
    schema.py             RunResult + nested records (the common contract)
    hardware.py           host capture
    score.py              corpus-owned exact or overlap attribution scorer
    corpus_integrity.py   manifest and scan-tree digest verification
    leakage_guard.py      provenance and near-duplicate split isolation
    generator_checksums.py shared checksum-valid synthetic-token primitives
    corpora/              mirror · homefield · creddata · ioc-recovery · perf adapters
    scanners/             keyhog (+config matrix) · betterleaks · kingfisher · trufflehog · titus · noseyparker
    runner.py             one (scanner,config,corpus) measurement -> RunResult
    leaderboard.py        the matrix: run many scanners/configs, write results/<host>/, rank
    report.py             results -> markdown + idempotent README injection
    analyze.py            top false-negative / false-positive examples from the same scorer
    gate.py               regression + differential gate (keyhog must lead; CI forcing function)
    tests/                pytest
  generators/             corpus generators (not git-ignored)
    mirror/               synthetic SecretBench-shape generator (generate.py + providers/negatives/wrappers)
    homefield/            competitor home-turf harvesters (harvest_betterleaks.py · harvest_kingfisher.py)
    ioc_recovery/         deterministic P0-P12 JavaScript recovery generator
  corpora/                generated data (git-ignored; reproducible through Make targets)
  results/<host>/         one RunResult JSON per run (git-ignored; regenerable)
  reports/                generated markdown (committed): leaderboard.md · perf.md · recall-gap.md
  baselines/              committed known-good scoreboard anchors (regression history)
```

## Corpora

| name | what | labels | get it |
|---|---|---|---|
| `mirror` | 15k synthetic SecretBench-shape (3k positives / 12k negatives) | yes | `make mirror` |
| `homefield-betterleaks` | betterleaks' own `tps`/`fps` rule examples | yes | harvested |
| `homefield-kingfisher` | kingfisher's own rule examples | yes | harvested |
| `creddata` | [Samsung/CredData](https://github.com/Samsung/CredData) (~11k files, pinned commit) | yes (T=pos, F/X=neg) | `make creddata` |
| `ioc-recovery` | 336 sources across P0-P12 JavaScript concealment phases (4,368 fixtures) | yes, exact plaintext | `make ioc-recovery-corpus` |
| `kernel` | Linux kernel tree | no (perf only) | set `KEYHOG_BENCH_KERNEL` |
| `daemon-file` | one regular file for owned-daemon latency | no (perf only) | set `KEYHOG_BENCH_DAEMON_FILE` |

Benchmarked tools and datasets are credited with their licenses in
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md). Competitor corpora and
CredData are **gitignored / fetched locally**; keyhog redistributes none of
their data.

## Exact secret recovery benchmark

`ioc-recovery` is an official corpus in the same adapter, runner, scorer,
result, and reporting system as every other KeyHog benchmark. It adapts the
P0-P12 progression from [*Benchmarking Large Language Models for IoC Recovery
under Adversarial Code Obfuscation and
Encryption*](https://arxiv.org/abs/2605.06910) to deterministic synthetic,
checksum-valid GitHub-token-shaped values:

| phase | transformation |
|---|---|
| P0 | plaintext baseline |
| P1-P4 | Base64, identifier changes, dead code, and structural changes |
| P5-P6 | XOR and AES-256-CBC with embedded recovery material |
| P7-P12 | XOR or AES combined with the simple, dead-code, and structural transforms |

The paper evaluates 336 programs across these 13 phases. KeyHog's generator
therefore emits 4,368 JavaScript fixtures by default. The authors publish
[13 demonstration files](https://github.com/jaimemorales52/llm-ioc-detection/tree/91d45377cf482c1de6c36a0d33744665976a19b6/1.createdFiles)
at commit `91d45377cf482c1de6c36a0d33744665976a19b6`. That repository does not contain
the 336-program evaluation corpus. KeyHog records the repository and commit as
methodology provenance, but generates its own deterministic credential
fixtures. It does not claim byte identity with the paper's evaluation data and
uses no third-party dataset bytes.

Every value is synthetic and deterministic. P5-P12 embed the key and recovery
logic in the program, matching the program-analysis task rather than creating
a brute-force benchmark. Generation requires Node.js for its standard
`crypto` implementation of AES-256-CBC. The generator verifies each encrypted
value round-trips before publishing the corpus, and the test suite executes all
13 phase variants against their exact expected plaintext.

Run the mode comparison with:

```bash
make -C benchmarks ioc-recovery
```

The result directory contains ordinary `RunResult` JSON for `full`, `fast`,
and `deep`. Phase categories (`recovery/p00-*` through `recovery/p12-*`) make
the exact capability boundary visible instead of collapsing it into one
aggregate score.

The Make target holds the backend at deterministic SIMD so differences isolate
scan policy. A GPU host can measure the backend and mode cross-product without
changing the corpus or scorer:

```bash
cd benchmarks
python -m bench leaderboard --corpus ioc-recovery --scanners keyhog \
  --matrix backend,mode --out results-ioc-recovery-backends
```

Each row records host hardware and the full config identity. Explicit GPU rows
use `--require-gpu`, so an unavailable or failed accelerator is reported as an
unavailable result instead of being timed as a silent CPU fallback.

`make -C benchmarks targets` includes the executable deep-mode target: all
4,368 expected plaintexts recovered exactly, with no blind P0-P12 phase. It is
marked `target_spec` because it is an explicit, expensive capability gate. The
checked v0.5.41 SIMD/deep artifact currently satisfies it with 4,368 true
positives, zero false negatives, and zero false positives. The artifact records
the exact commit and detector-set identity.

### AgentRE Linux recovery slice

The AgentRE adapter pins the upstream commit, license, task map, 13 Linux C
sources, ground truths, build script, and scorer by SHA-256. Source material and
binaries stay under the gitignored `benchmarks/corpora/` tree.

```bash
make -C benchmarks agentre-corpus
```

The build uses the pinned Linux amd64 GCC image manifest with networking
disabled, a read-only source mount, no capabilities, bounded memory and PIDs,
and a non-writable container root. It compiles each source with the upstream
flags but never runs a sample. Publication succeeds only when all 13 ELF files
match their pinned digests and the compiler-bound receipt. The published files
are read-only and non-executable. Running the module without `--ensure`
validates an existing corpus:

```bash
cd benchmarks
python -m bench.agentre_build
```

The local scorer reproduces the pinned standard and bonus rubrics, including
partial decoded-C2 credit, set overlap, nested fields, hallucination penalties,
and rounding. Differential tests compare it with the validated upstream scorer.
Analyzers use the explicit benchmark boundary instead of the generic secret
corpus runner:

```python
from bench.corpora.agentre import AgentREBenchmark

benchmark = AgentREBenchmark()
tasks = benchmark.tasks()
report = benchmark.score_analyzer_outputs(outputs_by_task_id)
```

`tasks()` returns all 13 validated binary paths and their canonical identities.
Scoring requires one mapping output for every task, validates all 149 expected
fields, revalidates the sealed binaries, and attaches the score-contract receipt
before returning the report.
The official bonus weights sum to 0.95 although its summary declares a 1.0
bonus maximum. KeyHog exposes both the declared 2.0 total and attainable 1.95
total in a separate score-contract receipt. It does not silently normalize the
upstream result.
No 100% claim is valid until the complete runner also proves field-level score,
backend parity, and fail-visible analyzer coverage.

## Daemon measurements

Daemon performance uses a separate unlabeled, single-file corpus because the
production daemon accepts stdin or one regular file and redacts credentials
in the client report. Raw matches cross the private user-only socket, but the
CLI forbids plaintext rendering on this route. It does not accept directory
trees or benchmark-only plaintext scoring flags. Linux measurements launch the immutable executable
snapshot as a foreground server on a private socket, verify the peer PID with
`SO_PEERCRED`, require request counters `0 -> 1 -> 2`, and stop and reap that
exact process. Active requests must return to zero after each client. The
default user daemon is never contacted.

Only explicit `simd`, `cpu`, `gpu-cuda`, and `gpu-wgpu` backends are eligible. `auto` lacks a
persisted selected-backend receipt. Cache, fast, deep, precision, and confidence axes are
also unavailable because those policies are not bound into daemon startup.
Unsupported combinations produce unavailable rows with the exact reason.
Explicit CPU and SIMD daemon backends disable all GPU runtime work. Explicit
GPU daemon backends require GPU preflight and hard-fail on runtime degradation.

```bash
cd benchmarks
KEYHOG_BENCH_DAEMON_FILE=/path/to/representative-file \
  python -m bench leaderboard --corpus daemon-file --scanners keyhog \
  --matrix backend,daemon --out results-daemon
```

## Tiers

- `quick`: every scanner at its default config (the README leaderboard).
- `perf`: keyhog's in-process `backend × cache × mode` matrix on a tree corpus,
  plus the constrained daemon matrix above on `daemon-file`.

## Gate (CI forcing function)

`python -m bench gate` is the single regression + differential gate (it replaced
the retired `tools/diff_bench` runner). It runs, or with `--results <dir>`,
consumes, a leaderboard, selects the canonical row per scanner with the same
newest-wins logic as the README table, and exits non-zero unless keyhog both:

- leads every available competitor on F1 **strictly** (`--no-beat-competitors`
  to skip), and
- clears the floors you assert: `--min-f1` / `--min-precision` / `--min-recall`,
  and/or `--baseline <RunResult>` + `--epsilon` (regression vs a committed
  anchor in `baselines/`).

Exit codes: `0` pass · `1` violation · `2` undecidable (keyhog produced no
usable result). The `differential-bench` workflow runs it nightly against
TruffleHog; the `bench-nightly` workflow renders the leaderboard the gate reads.

## Continuous-improvement loop

`make -C benchmarks loop` runs the whole improvement cycle in one command:

    pytest (scorer self-tests) -> ensure corpus -> leaderboard (detection + speed
    for every scanner) -> calibrate (per-detector min_confidence floor overlay)
    -> render reports/ -> gate (differential + regression vs baselines/)

It is the local mirror of the scheduled lanes that keep keyhog improving across
vectors without manual babysitting:

- **detection / differential:** `differential-bench` (nightly): `bench gate`
  fails red if a competitor overtakes keyhog on F1 **or** keyhog regresses past
  `baselines/mirror-keyhog-baseline.json` (the committed anchor; ratchet it up
  after a real gain, never down to hide one).
- **leaderboard + speed/RSS:** `bench-nightly` (nightly): renders the tables.
- **strict recall under evasion:** `runners-nightly` (the Rust strict matrix).
- **exact secret recovery:** `bench-nightly` (the P0-P12 full/fast/deep/precision matrix).
- **test depth:** `ci` (`all_tests`, property, e2e on every push).

`loop` deliberately does **not** `--inject` the README: the published tables are
regenerated only by `make report` on a machine with every competitor installed,
so a partial-scanner run can never degrade the committed leaderboard. The
`calibration.toml` overlay it emits is the actionable "what to tune next" signal.

## Cross-device

`cross_device.sh DEVICE=<ssh-alias>` rsyncs the current tree to a device,
installs keyhog via its per-OS build (Linux: Hyperscan SIMD; macOS:
`--features portable`, the system-lib-free vyre CPU path), generates the corpus
on the device's local disk, runs the leaderboard there, and pulls the per-host
RunResult into `results-cross-device/<device>/`. The remote driver always
installs from the synced tree and never treats a `keyhog` found on PATH as
current-code evidence. Results stay **out** of `results/` so a remote host's row
can never shadow the canonical README numbers (the README report's
`canonical_leaderboard` picks newest-per-scanner across everything it loads).
Compare every host with `python -m bench.cross_compare`; the committed snapshot
is [`reports/cross-device.md`](reports/cross-device.md). Windows is
POSIX-incompatible with this script; drive the ThinkPad via PowerShell.

## Reproducibility

Scoring passes `--no-gpu` for the deterministic SIMD path on the default
`simd-*` configs. The exact `gpu-cuda`, `gpu-wgpu`, and `auto` configs dogfood
each GPU peer, and explicit GPU rows pass `--require-gpu` so they fail instead
of timing another driver or CPU. GPU-to-SIMD parity is a separate release gate. The
CredData corpus is
pinned to an exact commit so a score is reproducible against a fixed dataset
revision. The overlap scorer remains bit-identical to the now-retired
`tools/secretbench/scoring/score.py` it replaced. Exact mode is deliberately
stricter for recovery corpora. Both contracts and their per-category
conservation rules are regression-anchored in `bench/tests/`.
