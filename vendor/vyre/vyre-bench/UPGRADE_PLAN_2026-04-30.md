# vyre-bench upgrade plan — 2026-04-30 (release tier)

**Workdir:** `/media/mukund-thiru/SanthData/Santh/libs/performance/matching/vyre/vyre-bench`
**Scope:** ONLY this crate + its baseline data + its CI workflows. Do NOT modify `vyre-foundation`, `vyre-driver*`, `vyre-runtime`, etc. — except to thread per-pass attribution telemetry through (see §7) and to read existing public APIs.
**Commit base:** `11bccf28afe566d8f6366ce51f992ef3d29b8ebc` (origin/main 2026-04-30, dirty).
**Build target dir:** `CARGO_TARGET_DIR=.cargo-target/release-phase0` (already warmed).
**Hardware:** RTX 5090 (local), 4090 (axiomexec), A100/H100/MI300X (cloud — credentials in `/credentials/.env`).

The agent owning this plan must read every section, then execute in the order written. **No deferral.** Sections marked CRITICAL block every later section. Sections marked PARALLEL can be done concurrently with later work. Acceptance criteria per section are stated explicitly — meet them or open a NEW task; never relax them.

---

## §0. Current state (measured 2026-04-30 in session 62c25ef2)

`cargo check -p vyre-bench` → **green** (one initial false-RED was a stale cargo-fleet log; verified clean via `cargo check -p vyre-bench --message-format=short`).

Smoke suite ran end-to-end on RTX 5090 with `--measured-samples 30 --warmup-samples 10`. **11 of 12 listed cases reported** (`adversarial.register_exhaustion.u32_1024` did not appear in the JSON output despite being in `vyre-bench list` — see §3 bug B-3).

Headline numbers (RTX 5090, commit `11bccf28`, smoke suite, 30 measured samples):

| case | speedup vs CPU SOTA | contract | p50 dispatch_ns |
|---|---|---|---|
| foundation.elementwise.add.1m | **155.3×** | ✅ pass | 9 664 |
| foundation.matmul.256 | 29.3× | ❌ (need 100×) | 137 824 |
| foundation.reduce.sum.1m | 7.0× | ❌ | 44 448 |
| foundation.attention.64 | 4.8× | ❌ | 18 432 |
| foundation.gather.u32.1m | 1.4× | ❌ | 1 072 992 |
| foundation.stencil3.u32.1m | 1.2× | ❌ | 1 018 944 |
| foundation.transpose.512 | **0.88×** ⚠ slower-than-CPU | ❌ | 146 848 |
| foundation.histogram.u32_256.1m | **0.69×** ⚠ slower-than-CPU | ❌ | 226 880 |
| foundation.dfa_match.256k | **0.29×** ⚠ 3.5× slower-than-CPU | ❌ | 13 856 |
| foundation.optimizer.impact | n/a (vyre-internal) | — | 1 051 360 |
| runtime.megakernel.dispatch.256 | n/a (vyre-internal) | — | 39 168 |
| adversarial.register_exhaustion.u32_1024 | **DID NOT APPEAR** | — | — |

Already committed baselines (do not delete):
- `vyre-bench/baselines/rtx_5090/elementwise_add_1m_2026-04-30_11bccf28.json` (5-sample early run)
- `vyre-bench/baselines/rtx_5090/smoke_full_2026-04-30_11bccf28.json` (30-sample full smoke)

Existing G-item progress (from `vyre-bench/PLAN.md` checkbox state):
- G1 CUDA events: marked done — verify against §5 acceptance gate.
- G2 Tail latencies p999/p9999: marked done — verified via `MetricStats` keys in JSON output.
- G3 Determinism gate: marked done — verify via §5 §G3 acceptance gate.
- G5 Cache hit rate: marked done — verify.
- **G4 Roofline: NOT DONE.** §6.
- **G6 Commit snapshots: NOT DONE.** §6.
- **G7 Thermal normalization: NOT DONE.** §6.
- **G8 CPU baseline (best-in-class competitor matrix): NOT DONE.** §8.
- **G9 Sweep matrix: NOT DONE.** §6.
- **G10 Cross-backend: NOT DONE.** §6.
- **G11 CUPTI attribution: NOT DONE.** §6.
- **G12 CLI + Audit: NOT DONE.** §6.

---

## §1. Acceptance criteria — the bar this plan must clear

The plan is complete when ALL of the following are simultaneously true. No exceptions. No "we'll get to that next."

1. **Every documented bench bug from §3 is fixed and has a regression test.**
2. **Every G-item (G1–G12) is verifiably complete** with a test that fails when the feature regresses.
3. **The honest-workload suite (§4) ships 14 new cases**, each with a passing CPU baseline pinned to a named SOTA library at a named commit hash, each with the today-failing-baseline JSON committed to `baselines/rtx_5090/honest_workloads/`.
4. **Pass-attribution column (§7) is live** for every case — the result JSON includes a `pass_attribution` array showing wall-clock contribution of each optimizer pass on the run.
5. **Per-commit baseline persistence** writes `snapshots/<commit>.json` on every successful run, and `vyre-bench compare-snapshot --base <sha>` produces a per-case Welch-t-test verdict (improve / regress / flat / noisy).
6. **Competitor matrix (§8) is wired**: each honest workload runs the named SOTA competitor in the same harness, and the result JSON carries `competitor.{name, version, wall_ns, throughput}` per workload.
7. **Roofline overlay (§6 / G4)** populates `bytes_read`, `bytes_written`, `peak_bandwidth_gb_s`, `achieved_bandwidth_gb_s`, `roofline_pct` per case. The CLI `table` format renders a `roofline%` column.
8. **CI regression gate (§9) live**: GitHub Actions workflow `.github/workflows/bench-regression.yml` runs the smoke suite on the self-hosted RTX 5090 runner per PR, compares to `snapshots/main.json`, fails the workflow on >5% regression on any case, posts a per-case delta table as a PR comment.
9. **Public dashboard (§10) generated**: `vyre-bench dashboard` produces `dashboard/index.html` + `dashboard/<case>.svg` (roofline plot per case) + `dashboard/cross-backend.svg`. Static files committed under `vyre-bench/dashboard/` and served via GitHub Pages from `gh-pages` branch.
10. **Documentation updated**: `vyre-bench/README.md` describes every CLI command, every output column, every metric. `vyre-bench/PLAN.md` G-item checkboxes all `[x]`. `vyre-bench/CHANGELOG.md` carries the per-section delta with date + commit hash.

---

## §2. Hardware + environment preconditions

Before starting:

- **NVIDIA driver**: `nvidia-smi` must report at least one CUDA device with compute capability ≥ 8.9 (RTX 5090 = 12.0; 4090 = 8.9). Use `vyre_driver_cuda::CudaBackend::acquire()` to verify; fail fast on no GPU.
- **CARGO_TARGET_DIR**: always export `CARGO_TARGET_DIR=.cargo-target/release-phase0` to reuse the warm build cache. Do not let cargo write under `target/` (memory pressure).
- **NEVER run `cargo` synchronously.** Use `run_in_background: true` always (the harness has a hook that blocks sync cargo). For workspace-scale builds use `mcp__dispatch__cargo_check` / `cargo_test` / `cargo_full` (background by default). For per-crate quick checks use a backgrounded direct `cargo check -p <crate>`.
- **NEVER run `until` loops in shell.** They are banned by the harness hook. Use `Monitor` or `run_in_background` + read-on-completion.
- **Credentials**: `/credentials/.env` has `SANTH_GITHUB_PAT` (fallback PAT — prefer gh CLI keyring), `SANTH_TELEGRAM_BOT_TOKEN` + `CHAT_ID`. **Do not commit credentials.** Do not put them in any file under `vyre-bench/`.
- **Working tree state**: branch off `main` at commit `11bccf28...` (or whatever is current at start). Use a feature branch named `vyre-bench/release-upgrade-<date>`. Do not amend commits; create new ones.

---

## §3. CRITICAL — Bench bugs to fix before any new feature lands

These bugs make the existing numbers untrustworthy. Fix in order, regression-test each.

### B-1. `gb_s_x1000` reports 2.7 TB/s on a 0.9 TB/s device (impossible)

**Where:** `vyre-bench/src/runner/execute.rs` and `vyre-bench/src/cases/elementwise.rs:148-159` (and every other case computing throughput from `wall_ns`).

**Symptom:** RTX 5090 has 896 GB/s peak memory bandwidth (per-NVML report `memory_peak_gb_s_x1000 = 896064`). Vyre reports `gb_s_x1000.p50 = 2_762_430` ⇒ 2 762 GB/s. Physically impossible. Cause: throughput math divides bytes by `dispatch_ns` (kernel-execution-only) instead of `wall_ns` (host-to-host including readback + sync), AND counts 12 MB of bytes when the kernel actually touches resident GPU buffers (no host transfer).

**Fix:** Define throughput consistently across the codebase:
- Add `wall_throughput_gb_s` field to `BenchMetrics` — bytes ÷ `wall_ns` × 1e9.
- Add `device_throughput_gb_s` field — bytes ÷ `device_ns` × 1e9 (this is the kernel-only number, but document it as such).
- The roofline % column (§6 / G4) uses `wall_throughput_gb_s` against device peak.
- Existing `gb_s_x1000` field — RENAME to `device_gb_s_x1000` and clearly document semantics. Add a deprecation note in `CHANGELOG.md` for the rename.
- Cases computing throughput by hand: refactor to derive throughput from a new `metrics.bytes_touched: u64` field + the runner's wall_ns / device_ns values. Cases that resident-buffer (CUDA path) report `bytes_touched = 0` for host transfer and report kernel `bytes_read + bytes_written` for the kernel-only number.

**Regression test:** `vyre-bench/tests/throughput_consistency.rs` — for every case, assert `wall_throughput_gb_s ≤ device_peak_gb_s × 1.05` (5% slop for measurement noise). Failing the assertion is a CI failure.

### B-2. `baseline_wall_ns` has 4× spread on a deterministic CPU baseline (350 µs to 1.5 ms p99)

**Where:** `vyre-bench/src/runner/execute.rs` baseline timing loop, OR `vyre-bench/src/cases/cpu_baselines.rs::elementwise_add_f32_bytes`.

**Symptom:** On the elementwise.add.1m case, the JSON shows `baseline_wall_ns: { min: 350_432, p50: 395_036, p90: 1_556_076, max: 1_556_076 }`. 4× spread between min and p99 on a deterministic CPU op = either thermal throttling on the rayon pool, NUMA migration mid-run, or a one-time JIT/page-fault cost in the warmup-only code path.

**Fix:**
- Move CPU baseline to its own thread pool with `RAYON_NUM_THREADS` set explicitly (matches the rest of the suite). Pin the pool to specific CPU cores via `core_affinity` crate.
- Run baseline warmup separately from baseline measurement (currently the runner re-times the baseline every iteration, paying allocation cost on the first iter only).
- Add `baseline_warmup_runs: u8` (default 5) to `RunConfig`. Discard those runs from the percentile computation.
- Document that baseline runs use the same warm/measure split as the GPU runs.

**Regression test:** `vyre-bench/tests/baseline_determinism.rs` — assert `baseline_wall_ns.stddev / baseline_wall_ns.mean < 0.05` (5% CV) on the elementwise.add case after 30 measured runs.

### B-3. `adversarial.register_exhaustion.u32_1024` listed but never reported

**Where:** Either `vyre-bench/src/runner/execute.rs::execute_suite` filter logic, OR the SuiteKind::Smoke definition in `vyre-bench/src/api/suite.rs`.

**Symptom:** `vyre-bench list` shows the adversarial case, but `vyre-bench run --suite smoke --format json` does not include it in the output. Suspect: smoke suite filters to "foundation.*" + "runtime.*" prefixes and excludes "adversarial.*".

**Fix:** Decide the suite policy explicitly:
- If smoke is intended to skip adversarial cases, ADD a `SuiteKind::Adversarial` separate suite (already exists per RELEASE_BRIEF.md; verify it filters correctly).
- If smoke is intended to include all cases, fix the filter and document in README.

Document the SuiteKind→case-prefix mapping in `vyre-bench/README.md` as a table.

**Regression test:** `vyre-bench/tests/suite_completeness.rs` — for each `SuiteKind`, assert the run output includes exactly the expected set of cases.

### B-4. `--measured-samples 5` produces meaningless percentiles (50% noise)

**Symptom:** First elementwise.add run with 5 samples reported speedup = 68×. Re-run with 30 samples reported 155×. The 5-sample number was warmup-dominated noise.

**Fix:**
- Make `measured_samples` REQUIRE a minimum of 30 for any case marked `DeterminismClass::Deterministic`. Below that, exit with error code 2 and a structured message.
- Document the minimum in CLI help + README.
- Add `--allow-noisy-samples` opt-in flag for users who genuinely want < 30 samples.

**Regression test:** `vyre-bench/tests/min_samples_gate.rs` — `vyre-bench run --suite smoke --measured-samples 10` exits non-zero with a specific error message.

### B-6. `foundation.dfa_match.256k` is structurally broken — not a DFA, not full-text-scan, parity check passes by accident

**Where:** `vyre-bench/src/cases/dfa_match.rs:46-76`.

**Symptom:** Case is a single 4-byte literal match (`b"vyre"`) hard-coded into an `Expr::eq` against `Expr::load("text", idx)`. Workgroup size = 256, only 256 invocations launched. Each thread checks ONE 32-bit word at `idx = gid_x()` ∈ [0, 256). Of 65 536 words in the 256 KB text, **only the first 256 are inspected**. The CPU baseline (`dfa_vyre_match_count_bytes`) scans the entire 256 KB via `memchr::memmem::find_iter(text, b"vyre")` and counts ~64 matches. GPU finds at most 1 match (word 0). The "0.29× DFA match" headline number is comparing a properly-scanning CPU against a GPU kernel that inspects 0.39% of the input. Worse: `verify_exact_outputs()` reports `Correctness::Exact` despite this — either the verify path has a silent-pass bug on count mismatches OR the parity is being papered over.

**Fix path:**
1. Replace the 256-thread point-check with a proper grid-strided loop: launch ⌈word_count / lane_count⌉ workgroups, each thread scans words `[gid, gid+stride, gid+2*stride, ...]` to cover the full input.
2. Replace the `Expr::eq` literal-match with a real DFA execution: build a small DFA program (e.g., 32-state pattern with `[a-z]+vyre[a-z]+` regex), encode the transition table as a constant buffer, walk it byte-by-byte. This makes the case represent its name. Without the DFA, this is a memmem case and should be renamed.
3. Verify the parity contract actually compares match counts byte-equal; investigate whether `verify_exact_outputs()` silently passes on count mismatches and fix the comparator if so.
4. After the rewrite, the 0.29× number will likely worsen (GPU now does real work) — that's the honest baseline, not the dishonest broken one.

**Regression test:** `vyre-bench/tests/dfa_full_coverage.rs` — assert the GPU output match count equals the CPU baseline match count for an input with N known matches; add a synthetic input where N=64 and assert both return 64.

### B-5. `wall_ns` is not in the result JSON at top level

**Where:** `vyre-bench/src/runner/execute.rs::collect_metric_fields` and `BenchMetrics` field set.

**Symptom:** Every case carries `dispatch_ns` and `baseline_wall_ns` in `metrics`, but the GPU `wall_ns` (host-to-host vyre-side wall time) is not surfaced as a top-level metric. The speedup ratio is computed as `baseline_wall_ns / wall_ns` somewhere in `runner/execute.rs::evaluate_contract`, but `wall_ns` is invisible in the JSON.

**Fix:** Surface `wall_ns` as a top-level metric in every case's `metrics` block. Same percentile shape as other timing metrics.

**Regression test:** `vyre-bench/tests/result_schema.rs` — every case's `.metrics` must include exactly the field set documented in the schema (added in §10).

---

## §4. Honest-workload suite — 14 NEW cases (CPU-favorable territory)

The existing 12 cases are GPU-flattering. The release claim is "vyre wins on workloads CPUs win today by ≥10× via 40 years of CPU optimization research." Add the following 14 cases. Each lives in `vyre-bench/src/cases/<workload>.rs` (≤500 LOC), registered via `inventory::submit!` like the existing cases. Each case has:

- `id`: stable identifier per the table below.
- `metadata`: `BenchLayer::Honest`, `WorkloadClass::Honest` (add these new variants to `vyre-bench/src/api/case.rs`).
- `requirements`: `needs_gpu: true`, plus per-case `min_vram_bytes` from the case's resident-buffer math.
- `performance_contract`: positive contract via `PerformanceContract::cpu_sota_<N>x("name", "competitor crate", "competitor library description")`. The N values are the release-tier targets, not where we are today; today's number lives in the baseline JSON, the contract documents the destination.
- `prepare`: build the Program for the workload + load the input corpus from `vyre-bench/corpus/honest/<workload>/`. Corpus files committed under git-lfs (raw JSON / regex inputs / etc. up to ~10 MB per case).
- `run`: dispatch via `BenchContext::dispatch_with_events` to capture per-arm timing.
- `verify`: assert byte-exact output against the CPU baseline (or value-equivalence under the workload's tolerance).

| id | description | CPU SOTA competitor | competitor pin | contract target | input corpus |
|---|---|---|---|---|---|
| `parser.json.simdjson_corpus` | Parse simdjson conformance corpus, branch-heavy recursive descent | simdjson | `simdjson/simdjson@v3.10.1` | ≥10× | `corpus/honest/parser.json/{nativejson-benchmark, jsonchecker, simdjson-conformance}/*.json` (∼50 files, total ~5MB) |
| `parser.peg.json_path` | PEG/recursive-descent JSONPath parser w/ backtracking | pest | `pest-parser/pest@v2.7.13` (PEG grammar from `serde_json_path`) | ≥10× | `corpus/honest/parser.peg/jsonpath-queries.txt` (1000 queries) |
| `regex.backtracking.adversarial` | `(a+)+` against hostile inputs (catastrophic backtracking) | PCRE2 | `PCRE2Project/pcre2@10.44` | ≥100× (CPU goes superlinear) | `corpus/honest/regex.bt/{small,medium,large}.txt` |
| `regex.compiled.dense_dfa.10k` | 10k-state DFA over 1MB stream, no backtracking | RE2 | `google/re2@2024-11-15` | ≥10× | `corpus/honest/regex.dfa/{linux-syslog,nginx-access}.log` |
| `hashtable.openaddr.probe.10m` | 1M lookups against a prebuilt 10M-key table, robin-hood open addressing | hashbrown | `rust-lang/hashbrown@v0.17.0` | ≥10× | synthesized in `prepare` (deterministic seed=0xdeadbeef) |
| `tree.btree.search.10m` | B-tree of 10M u64 keys, 1M random lookups | std::collections::BTreeSet | rustc `1.85.0` std | ≥10× | synthesized |
| `graph.dijkstra.priority_queue.1m` | Single-source shortest path, 1M nodes 10M edges | petgraph | `petgraph/petgraph@v0.6.5` | ≥10× | `corpus/honest/graph/road-NY.csv` (real-world road network from SuiteSparse) |
| `graph.tarjan_scc.1m` | Tarjan strongly-connected-components | petgraph | same | ≥10× | `corpus/honest/graph/cit-Patents.csr` (citation graph, 3.7M nodes) — first 1M-node subset |
| `interpreter.bytecode.dispatch.10m` | Threaded-code interpreter, 10M instr trace | hand-tuned C threaded interpreter | committed at `vyre-bench/competitors/threaded-interp.c` (build via cc crate) | ≥3× | synthesized (random opcode trace) |
| `protocol.http1.chunked_decode.100mb` | HTTP/1.1 chunked-encoding state machine, 100 MB | hyper | `hyperium/hyper@v1.5.2` | ≥10× | `corpus/honest/protocol.http1/{chunked,trailers,malformed}/*.bin` |
| `compress.lz4.decompress.100mb` | LZ4 frame-format decompression, 100 MB | lz4 reference | `lz4/lz4@v1.10.0` | ≥3× | `corpus/honest/compress.lz4/silesia.tar.lz4` (Silesia compression corpus) |
| `crypto.aes_ctr.encrypt.100mb` | AES-128-CTR over 100 MB | ring (AES-NI) | `briansmith/ring@0.17.8` | ≥3× | synthesized |
| `bigint.modexp.4096` | 4096-bit modular exponentiation, RSA-style | gmp | `gmplib/gmp@6.3.0` (via rug crate `1.27`) | ≥3× | synthesized |
| `sparse.spmv.csr.10m` | CSR×dense SpMV on 10M-row matrix, ~30 nnz/row | Eigen sparse | `eigenteam/eigen-git-mirror@3.4.0` | ≥10× | `corpus/honest/sparse/SuiteSparse-stokes64.mtx` |

Per case, two artifacts to commit at the END of §4:
1. The `.rs` file under `vyre-bench/src/cases/`.
2. A baseline JSON capturing today's failing-baseline numbers under `vyre-bench/baselines/rtx_5090/honest_workloads/<id>_<date>_<commit>.json`. The contract WILL fail today; that's the point — the failure is the bar Phase 4–5 closes.

Corpus files: download once via `vyre-bench/scripts/fetch_honest_corpus.sh` (write the script — it's part of this plan). Each download is checksum-verified against a pinned SHA-256 in `vyre-bench/corpus/honest/CHECKSUMS.toml`. CI does not download; CI uses git-lfs to fetch.

---

## §5. G1–G3 + G5 verification (already marked done — verify, don't redo)

For each:
- Read the implementing module.
- Write a regression test that fails if the feature regresses.
- If verification finds the implementation incomplete or incorrect, file as a bug and fix.

### G1. CUDA event-based timing
- **Verify**: `vyre-bench/src/probes/cuda_events.rs` exists; `BenchMetrics` has `kernel_queue_submit_ns`, `kernel_execute_ns`, `device_sync_ns`. The cases that opt in use `dispatch_with_events`.
- **Test**: `vyre-bench/tests/g1_cuda_events.rs` — run elementwise.add with cuda backend, assert all three fields are populated and positive on a backend reporting `cuda_events_supported=true`.

### G2. Tail latencies p999/p9999/max
- **Verify**: `MetricStats` carries `p999, p9999, max`. The CLI table formatter renders them.
- **Test**: `vyre-bench/tests/g2_tail_latency.rs` — run any case with 100 measured samples, assert `p999 ≥ p99 ≥ p95 ≥ p90 ≥ p50` (monotone) and `p9999 ≥ p999`.

### G3. Determinism gate
- **Verify**: `RunConfig.determinism_runs`, `MetricStats.determinism_cv`, the unstable-status code path.
- **Test**: `vyre-bench/tests/g3_determinism.rs` — run elementwise.add 3 times, assert `determinism_cv < 0.005` (0.5%) for `kernel_execute_ns` field. Run a deliberately-flaky synthetic case (sleep with random jitter) and assert it gets `status: "unstable"`.

### G5. Cache hit rate
- **Verify**: `BenchMetrics.cache_hit` populated from `vyre_driver::pipeline::compile`'s validation cache. `MetricStats.cache_hit_rate` aggregated. CLI column shown.
- **Test**: `vyre-bench/tests/g5_cache_hit.rs` — run elementwise.add twice in the same process; first run: `cache_hit_rate < 0.5`; second run: `cache_hit_rate > 0.95`.

---

## §6. G4 + G6–G12 completion (NEW WORK — main body of plan)

### G4. Roofline / memory traffic — populate the bench's idea of physics

**New `BenchMetrics` fields:**
- `bytes_read: u64`, `bytes_written: u64`, `atomic_op_count: u64` — populated per-case.
- `peak_bandwidth_gb_s: f64` — queried from NVML at probe time.
- `achieved_bandwidth_gb_s: f64` — `(bytes_read + bytes_written) / wall_ns × 1e9`.
- `roofline_pct: f64` — `(achieved_bandwidth_gb_s / peak_bandwidth_gb_s) × 100`.

**Per-case population:** Cases that know their access pattern override `BenchCase::bytes_touched(&self, prepared: &PreparedCase) -> (u64, u64)` returning `(bytes_read, bytes_written)`. Default impl: sum of `prepared.inputs.iter().map(Vec::len)` for read, `prepared.outputs.iter().map(Vec::len)` for write — this default is wrong for resident-buffer cases (CUDA path) which transfer no host bytes per dispatch. For resident cases, override to report the GPU-side load+store byte count derived from the Program's `BufferDecl.count × DataType::byte_size()`.

**Peak bandwidth queries:** Extend `vyre-bench/src/probes/nvml.rs` with `query_peak_memory_bandwidth() -> Result<f64>`. NVML formula: `clocks.current.memory × bus_width × 2 / 8` bytes/sec → GB/s. Hardcoded fallbacks: RTX 5090 = 1008 GB/s, RTX 4090 = 1008 GB/s, A100 (80GB) = 2039 GB/s, H100 (SXM) = 3350 GB/s, MI300X = 5300 GB/s. Lookup by `ADAPTER_INFO.name` substring match.

**CLI rendering:** Add `roofline%` column to the `table` format. Add `--roofline-only` flag that suppresses other columns.

**Roofline plot per case (SVG, generated by `vyre-bench dashboard`):** X-axis = arithmetic intensity (FLOP/byte); Y-axis = throughput (GFLOPS). Plot the device's roofline (memory-bound slope + compute-bound ceiling) + dot for each case + dot for each competitor on the same case. SVG output to `dashboard/<case>.svg`.

### G6. Per-commit snapshot history

**Git capture:** Extend `vyre-bench/src/runner/execute.rs::execute_suite` to populate `git: BTreeMap<String, String>` via `git -C <bench dir> rev-parse HEAD`, `git rev-parse --abbrev-ref HEAD`, `git status --porcelain | wc -l` (dirty bit), `git rev-parse HEAD~1` (parent), `git log -1 --format=%ct HEAD` (commit timestamp).

**Snapshot directory:** `vyre-bench/snapshots/<commit>.json`. Pretty-printed (2-space indent). Schema = `ReportSchema` (the existing top-level result type). Overwrites if exists.

**`vyre-bench compare-snapshot --base <commit_sha>` subcommand:** Reads `snapshots/<base>.json` and the latest run's report. For each case compute Welch's t-test on `wall_ns` (already implemented for the `compare` subcommand — refactor into a shared helper at `vyre-bench/src/runner/compare.rs`). Print:
- `case` | `base` | `current` | `delta_%` | `t-stat` | `p-value` | `verdict`
- Verdicts: `improve` (p<0.01 and median improved), `regress` (p<0.01 and median worsened), `flat` (p≥0.01), `noisy` (CV>0.1).
- Exit non-zero if any case has `verdict=regress` AND `delta_% > 5`.

**Tests:** `vyre-bench/tests/g6_snapshot.rs` — run smoke twice, generate two snapshot files, run `compare-snapshot` with the first as base, assert exit 0. Inject an artificial regression in the second run (sleep added to a baseline), assert exit 1.

### G7. Power & thermal normalization

**Capture:** Extend `vyre-bench/src/probes/nvml.rs::capture_nvml_telemetry` to also query `clocks.current.graphics`, `clocks.current.memory`, `clocks.current.sm`. Store under `metrics.gpu_counter` per sample.

**Drift detection:** After all samples, compute per-metric drift across samples:
- `temperature_drift_c = max - min` over samples; threshold 5°C.
- `clock_drift_pct = (max - min) / mean × 100` for `clocks.current.sm`; threshold 5%.

**Status update:** If either threshold exceeded, set case status to `"thermal_unstable"` (new variant on the existing `Status` enum), surface `metrics.custom = {thermal_drift: 1, clock_drift: 1}`. Increment `summary.thermal_unstable`.

**Tests:** `vyre-bench/tests/g7_thermal.rs` — synthetic case with NVML mock returning thermally-stable data passes; mock returning >5°C drift gets `thermal_unstable` status.

### G8. CPU baseline (best-in-class competitor matrix) — see §8 (this is the big one)

### G9. Sweep matrix

**New `SuiteKind::Sweep`:** Iterates over a workgroup × size grid. Per case, the case can declare `sweep_axes() -> Option<SweepAxes>` returning `{ workgroup_sizes: Vec<[u32;3]>, problem_sizes: Vec<usize> }`. The Sweep suite materializes the cross product of axes per case, runs each, emits one result entry per (case, workgroup, problem_size) tuple with id `<case_id>.wg=<wg>.size=<sz>`.

**CLI:** `vyre-bench run --suite sweep --case <case_id>` to sweep one case; `--case-glob "foundation.*"` to sweep many.

**Output:** Each sweep result entry has the same shape as a regular case. The summary block adds a per-case best-config selection: `summary.best_configs: Map<case_id, {workgroup, problem_size, speedup}>`.

**Tests:** `vyre-bench/tests/g9_sweep.rs` — define a synthetic case with `sweep_axes` returning 4 wgs × 3 sizes = 12 entries; assert all 12 appear in output.

### G10. Cross-backend matrix

**New `SuiteKind::CrossBackend`:** For each registered backend (cuda, wgpu, cpu-ref), run every case. Result entries get id `<case_id>.<backend>`. The summary tracks per-case backend ranking.

**CLI:** `vyre-bench run --suite cross-backend [--backend cuda,wgpu]` (filter to a subset).

**Tests:** `vyre-bench/tests/g10_cross_backend.rs` — assert elementwise.add appears for each available backend.

### G11. CUPTI attribution (best-effort)

Behind `feature = "cupti"`. CUPTI provides per-kernel-instance stall reasons + memory hierarchy attribution. Wire `cupti-rs` (or hand-roll FFI to `libcupti.so` if no Rust binding); per kernel instance capture: `stall_inst_fetch`, `stall_exec_dependency`, `stall_memory_dependency`, `stall_texture`, `stall_sync`, `stall_other`. Store in `metrics.gpu_counter` under prefixed keys.

**Best-effort means:** If `cupti` feature off OR libcupti absent OR CUPTI version mismatch, log a warning + populate `cupti_unavailable=1`. Do NOT fail the run.

**Tests:** `vyre-bench/tests/g11_cupti.rs` (gated on `feature="cupti"`) — run elementwise.add with cuda, assert at least one stall metric populated.

### G12. CLI extensions + Audit subcommand

**New CLI commands:**
- `vyre-bench audit --case <case_id> [--samples 100]` — runs one case with full attribution: pass-by-pass timing, per-arm timing, CUPTI stall breakdown, roofline plot. Outputs flame graph to `audit/<case>_<commit>.svg` + Markdown report to `audit/<case>_<commit>.md`.
- `vyre-bench dashboard` — generates `dashboard/index.html` + per-case SVGs from the most-recent snapshot. (See §10.)
- `vyre-bench schema --output <path>` — emits the JSON schema for the report format. Used by external tooling + the regression test in B-5.

**New CLI flags:**
- `--enforce-budgets` (already exists — verify) makes contract failures exit non-zero.
- `--allow-noisy-samples` (B-4).
- `--roofline-only` (G4).
- `--baseline-only` — run only the CPU baseline path; useful for competitor calibration.
- `--no-warmup` — for diagnostic runs that intentionally skip warmup.

**Tests:** `vyre-bench/tests/g12_audit.rs` — `vyre-bench audit --case foundation.elementwise.add.1m` produces both expected artifacts.

---

## §7. Pass-attribution column (the truth-teller)

The headline claim of "1000× over SOTA" requires answering "which optimizer passes contributed how much." Today: nothing. The data is captured (`PassRunMetric` in `vyre-foundation/src/optimizer/scheduler.rs:52`) but not surfaced in bench output.

**Wire it through:**

1. `BenchContext::dispatch_with_events` returns a new `KernelTimings` shape. Extend it with `optimizer_report: Option<vyre_foundation::optimizer::OptimizerRunReport>` carrying the per-pass `PassRunMetric` rows.
2. `BenchMetrics` gains a `pass_attribution: Vec<PassAttributionEntry>` field. `PassAttributionEntry { pass: String, ran: bool, changed: bool, runtime_ns: u128, contribution_pct: f64, nodes_delta: i64 }`. The `contribution_pct` is the pass's fraction of `wall_ns_with_optimizer - wall_ns_without_optimizer` ATTRIBUTED to it. Attribution is greedy: rerun without each pass once and measure the delta.
3. `vyre-bench audit --case X` (G12) renders pass attribution as a stacked bar chart in the SVG.
4. CLI table format gains a `--show-passes` flag.

**Per-pass A/B run:** For attribution, the runner re-executes each case with each pass disabled (one at a time) and captures the wall_ns delta. This is N+1 runs per case (N passes + 1 baseline). Cache the deltas in `attribution_cache.json` keyed on (case_id, pass_name, commit_hash) so a repeat audit doesn't re-run.

**Tests:** `vyre-bench/tests/g7_attribution.rs` — for elementwise.add, assert `pass_attribution` is non-empty + sums to ≥95% of measured speedup.

---

## §8. Competitor matrix (G8) — the apples-to-apples spine

Today: every case has an inline CPU baseline (`cpu_baselines.rs::elementwise_add_f32_bytes` etc.) using `wide+rayon`. That's a CPU baseline, not a SOTA competitor. Real claim requires running named SOTA competitors at pinned versions.

### Vendor competitors

`vyre-bench/competitors.toml` declares each competitor with its commit pin:

```toml
[[competitor]]
name = "simdjson"
crate = "simdjson-rust"
git = "https://github.com/SunDoge/simdjson-rust"
rev = "v0.3.0"
license = "Apache-2.0"
homepage = "https://simdjson.org"

[[competitor]]
name = "hashbrown"
crate = "hashbrown"
version = "=0.16.1"

# ... one entry per competitor in the §4 honest-workload table
```

Cargo workspace gains `vyre-bench/competitors/Cargo.toml` (sub-crate) that depends on every competitor at the pinned version. The bench harness imports the sub-crate via path.

### Run competitors in the same harness

New trait `CompetitorRun` in `vyre-bench/src/api/competitor.rs`:

```rust
pub trait CompetitorRun: Send + Sync {
    fn name(&self) -> &'static str;
    fn version(&self) -> &'static str;
    fn run(&self, ctx: &mut BenchContext, prepared: &PreparedCase) -> Result<CompetitorMetrics, BenchError>;
}

pub struct CompetitorMetrics {
    pub wall_ns: u64,
    pub bytes_processed: u64,
    pub output_hash: blake3::Hash, // for parity check
}
```

Each honest-workload case provides `competitors() -> Vec<Box<dyn CompetitorRun>>`. The runner iterates each competitor, captures metrics, attaches to result JSON as:

```json
{
  "id": "parser.json.simdjson_corpus",
  "competitors": [
    {"name": "simdjson", "version": "3.10.1", "wall_ns_p50": 1234, "throughput_gb_s": 5.6, "output_hash": "...", "parity": true},
    ...
  ]
}
```

### Parity check

After the competitor runs, assert `competitor.output_hash == vyre.output_hash`. Mismatch = parity violation, surfaced as `case.status = "parity_violation"`, exit non-zero from `--enforce-budgets` runs.

### Output: scorecard

After the suite, generate `scorecard.md` at `vyre-bench/baselines/<hw>/<commit>/scorecard.md` with one row per (workload, vyre, competitor) tuple:

| workload | vyre wall_ns | competitor | competitor wall_ns | speedup vs competitor | contract target | contract pass |
|---|---|---|---|---|---|---|

This is the public number that anchors the release claim.

**Tests:** `vyre-bench/tests/g8_competitors.rs` — for one honest workload, run vyre + competitor, assert both produce results, assert parity check is enforced.

---

## §9. CI regression gate

`.github/workflows/bench-regression.yml` runs on every PR + push to main:

```yaml
name: bench-regression
on:
  pull_request:
    paths:
      - 'libs/performance/matching/vyre/**'
  push:
    branches: [main]
jobs:
  bench:
    runs-on: [self-hosted, gpu, rtx-5090]
    steps:
      - uses: actions/checkout@v4
        with: { lfs: true }
      - name: Build vyre-bench
        run: |
          cd libs/performance/matching/vyre
          CARGO_TARGET_DIR=.cargo-target/ci cargo build --release -p vyre-bench
      - name: Run smoke + honest suites
        run: |
          cd libs/performance/matching/vyre
          ./.cargo-target/ci/release/vyre-bench run --suite smoke --measured-samples 30 > smoke.json
          ./.cargo-target/ci/release/vyre-bench run --suite honest --measured-samples 30 > honest.json
      - name: Compare against main
        run: |
          cd libs/performance/matching/vyre
          ./.cargo-target/ci/release/vyre-bench compare-snapshot --base $(git merge-base HEAD origin/main) --current smoke.json --output diff.md
      - name: Comment PR
        if: github.event_name == 'pull_request'
        uses: peter-evans/create-or-update-comment@v4
        with:
          issue-number: ${{ github.event.pull_request.number }}
          body-path: libs/performance/matching/vyre/diff.md
      - name: Fail on regression
        run: |
          ./.cargo-target/ci/release/vyre-bench compare-snapshot --base $(git merge-base HEAD origin/main) --current smoke.json --fail-on-regression
```

Self-hosted runner setup: install via `actions/runner` on the local RTX 5090 box. Runner labels: `self-hosted, gpu, rtx-5090`. NVML must be accessible (run as user with cuda group access, NOT root).

**Tests:** the workflow runs against itself once before merging — first PR landing this workflow must pass it.

---

## §10. Public dashboard

`vyre-bench dashboard --output dashboard/` reads the most-recent snapshot JSON + writes:

- `dashboard/index.html` — top-level page with the case scorecard table, per-case roofline plots embedded, cross-backend ranking, per-commit history sparklines (SVG inline).
- `dashboard/<case>.svg` — roofline plot per case (G4).
- `dashboard/cross-backend.svg` — bar chart per backend per case.
- `dashboard/history/<case>.svg` — sparkline of wall_ns over the last 30 commits.
- `dashboard/scorecard.md` — markdown version of the table.
- `dashboard/data/results.json` — copy of the latest snapshot for any external consumer.

**Templating:** Hand-roll Rust string templates (no JS framework). The HTML embeds SVGs inline (no external assets). Total output ≤ 5 MB to keep gh-pages fast.

**Auto-publish:** A second workflow `.github/workflows/dashboard-publish.yml` runs on push to main, generates the dashboard, commits + force-pushes to `gh-pages` branch. GH Pages serves from there. URL: `https://santhsecurity.github.io/vyre/bench-dashboard/`.

**Tests:** `vyre-bench/tests/g10_dashboard.rs` — `vyre-bench dashboard --output /tmp/test_dashboard` produces all expected files with non-zero size.

---

## §11. Data file sizes + git-lfs setup

Honest-workload corpora are large. Use git-lfs for any single file > 1 MB.

`vyre-bench/.gitattributes`:
```
corpus/honest/**/* filter=lfs diff=lfs merge=lfs -text
baselines/**/*.json !filter
snapshots/**/*.json !filter
```

`vyre-bench/scripts/fetch_honest_corpus.sh`:
- Downloads each corpus per `vyre-bench/corpus/honest/CHECKSUMS.toml`.
- Verifies SHA-256.
- Places under `vyre-bench/corpus/honest/<workload>/`.
- Idempotent — skips if checksum matches.

CI uses `actions/checkout@v4` with `lfs: true`. Local devs run `git lfs install` once + `git lfs pull` after clone.

---

## §12. Documentation updates

End-of-plan documentation:

- **`vyre-bench/README.md`** — full rewrite. Sections: What is vyre-bench, Suite kinds, CLI commands, Output schema, Result interpretation guide, Honest workloads (link to §4), Competitor matrix (link to §8), Roofline interpretation (link to §6), CI integration, Local-dev workflow, Dashboard URL.
- **`vyre-bench/PLAN.md`** — close out G-items (all `[x]`), append a "what's next" pointer to the catalog of pass + megakernel work that depends on the bench rig.
- **`vyre-bench/CHANGELOG.md`** — one entry per section with date + commit hash.
- **`vyre-bench/RELEASE_BRIEF.md`** — preserve as historical context; add a header note pointing to this UPGRADE_PLAN as the current source of truth.
- **`vyre-bench/SCHEMA.md`** — NEW. Documents the result JSON schema field-by-field. Exported by `vyre-bench schema`.

---

## §13. Order of execution (do these in order, no skipping)

1. §3 (B-1 through B-5) — bench bugs. Block all later work because they make every measurement untrustworthy.
2. §5 — verify G1/G2/G3/G5 marked-done items. Land regression tests for each. If any verification fails, fix as part of this step.
3. §6 G4 (roofline) + G6 (snapshot) + G7 (thermal). These three are the metric-substrate foundation for §8 + §9.
4. §6 G9 (sweep) + G10 (cross-backend) + G12 (CLI/audit). Pure CLI/runner work.
5. §8 (competitor matrix). Big one — vendor each competitor, parity gate per workload, scorecard generation.
6. §4 (honest workloads). Each case writes against the scaffolding from §6 + §8.
7. §6 G11 (CUPTI). Best-effort; if it lands, great; if not, document the gap.
8. §7 (pass attribution). Cross-crate (touches `vyre-foundation` for the `OptimizerRunReport` re-export and `vyre-driver` to thread the report). Coordinate any cross-crate change carefully.
9. §10 (dashboard). Pure rendering on top of all earlier work.
10. §9 (CI gate). Wire the workflow only after §10 dashboard + scorecard exist (the workflow consumes them).
11. §11 (LFS) + §12 (docs). Final polish.

Each step's commit message: `vyre-bench: §<N> <short subject>` so the commit history maps to plan sections.

---

## §14. Acceptance gate (the door this plan walks through)

When ALL of the following are true on a single CI run, the plan is COMPLETE — file a PR labeled `vyre-bench/release` and request review.

- [ ] `cargo test -p vyre-bench --all-features` green.
- [ ] `cargo clippy -p vyre-bench --all-features -- -D warnings` green.
- [ ] `cargo doc -p vyre-bench --no-deps --all-features` green with no `missing_docs` warnings.
- [ ] `vyre-bench/tests/throughput_consistency.rs` passes (B-1 fixed).
- [ ] `vyre-bench/tests/baseline_determinism.rs` passes (B-2 fixed).
- [ ] `vyre-bench/tests/suite_completeness.rs` passes (B-3 fixed).
- [ ] `vyre-bench/tests/min_samples_gate.rs` passes (B-4 fixed).
- [ ] `vyre-bench/tests/result_schema.rs` passes (B-5 fixed).
- [ ] `vyre-bench/tests/g1_cuda_events.rs` through `g12_audit.rs` all pass.
- [ ] `vyre-bench/baselines/rtx_5090/honest_workloads/` contains 14 JSON files (one per honest workload).
- [ ] `vyre-bench/competitors/Cargo.toml` exists; every honest workload has at least one competitor wired.
- [ ] `vyre-bench/scripts/fetch_honest_corpus.sh` exists, executable, idempotent.
- [ ] `vyre-bench dashboard --output /tmp/dash` produces all expected files.
- [ ] `.github/workflows/bench-regression.yml` exists, triggered, green on at least one PR.
- [ ] `.github/workflows/dashboard-publish.yml` exists, has run successfully against `main` at least once.
- [ ] `vyre-bench/README.md`, `PLAN.md`, `CHANGELOG.md`, `SCHEMA.md` all updated per §12.
- [ ] No file under `vyre-bench/src/` exceeds 500 LOC. Split as needed.

---

## §15. Out of scope (do NOT touch in this PR)

- Anything in `vyre-foundation/`, `vyre-driver/`, `vyre-driver-wgpu/`, `vyre-driver-cuda/`, `vyre-driver-reference/`, `vyre-runtime/`, `vyre-spec/`, `vyre-primitives/`, `vyre-intrinsics/`, `vyre-libs/`, `vyre-macros/`, `vyre-conform/*` — EXCEPT to **read** their public APIs and EXCEPT for the two pass-attribution wiring spots (`vyre-foundation` re-export + `vyre-driver` report threading) which are surgical.
- Adding new optimizer passes — that's a separate Phase-4 stream of work.
- Changing the IR / Program / wire format — frozen, Phase-1+ only.
- Touching `vyre-libs/` consumer surface — out of scope.
- Building or modifying any consumer crate (surgec, etc.) — out of scope.

---

## §16. Common pitfalls (read before starting)

- **`cargo run` in cwd != bench dir** can produce wrong git-info paths. Use `git -C <abspath>`.
- **NVML can fail silently on locked-down systems.** Always check return codes; populate `nvml_unavailable=1` rather than crash.
- **CUDA backend startup cost is 80-200ms.** First-run measurements include this. Warmup already accounts for it; do not add extra warmup-only logic that changes the timing semantics.
- **wgpu adapter selection on multi-GPU hosts is non-deterministic.** Pin the adapter via `WGPU_ADAPTER_NAME` env var in CI.
- **Self-hosted runner can be hijacked by other workflows.** Add a `concurrency` block to the workflow to serialize bench runs.
- **simdjson-rust binding may lag upstream.** If `simdjson-rust@v0.3.0` is too old, vendor `cxx`-bridged binding to upstream `simdjson@v3.10.1` directly.
- **Eigen-rust binding is poor.** Likely have to FFI manually via `cc` crate. Budget extra time for the sparse SpMV competitor.
- **Petgraph's Dijkstra is single-threaded.** Make sure the comparison is fair — petgraph is the named SOTA, but if it's outperformed by a parallelized baseline, document the asymmetry.
- **CHECKSUMS.toml drift on corpus updates** is a pain. Pin upstream commit hashes for every corpus source, not version tags (tags can move).

---

## §17. Hand-off contract

The agent owning this plan:

- Reads this entire document before starting.
- Executes sections in the order in §13.
- Files no deferral language ("we'll do X later"). Open new tasks instead.
- Leaves the bench harness in a state where every CI run produces a defensible scorecard.
- On completion, files a PR labeled `vyre-bench/release`, posts the URL to `@SanthCEObot` Telegram channel, and tags this document with `# COMPLETE — <commit-hash>` at the top.

Done.
