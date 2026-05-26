# KeyHog Testing Program

Operational plan for massive parallel test expansion, dogfooding, stress testing,
adversarial coverage, per-file micro gates, end-to-end pipeline proofs, review,
and fix loops.

**Canonical repo:** `/media/mukund-thiru/SanthData/Santh/software/keyhog`

---

## 1. Core model (not “write 10,000 tests”)

Three layers multiply work without hand-authoring every assertion:

| Layer | What | Output |
|-------|------|--------|
| **Data** | `crates/scanner/tests/contracts/*.toml`, companion contracts, detector TOMLs | Ground truth per detector |
| **Multipliers** | `*_runner.rs` binaries (explosion, encoding, path, noise, unicode, …) | 10k–50k+ variant assertions per full run |
| **Gates** | `KEYHOG_*_STRICT=1`, CI, proptest regressions | Red wall → triage → fix → strict |

**Lego rule:** build harness once; contributors (and automation) add **data**, not duplicate Rust.

**Anti-rigging law** (from `audits/rigged_tests.md`): every fix asserts **credential value + context**, not `!is_empty()`, not loose perf floors, not length-only checks. Every engine fix gets a **proving test + negative twin** in the same change.

---

## 2. Three depth axes (all required)

### A. Macro — end-to-end (product = binary)

Drive `env!("CARGO_BIN_EXE_keyhog")` through real argv, temp fixtures, exit codes, JSON/SARIF shape.

| Slice | Entry | Test home |
|-------|-------|-----------|
| CLI scan | `keyhog scan` | `crates/cli/tests/e2e_binary.rs`, `break_it.rs` |
| Git modes | `--git-staged`, `--git-diff`, `--git-history` | e2e + `crates/sources/tests/unit/git_*.rs` |
| Daemon | `keyhog daemon` wire v2 | `crates/cli/src/daemon/*` + new e2e |
| Hooks / CI | `keyhog hook`, baseline, incremental | e2e + orchestrator tests |
| Verify | `--verify`, live creds | `live_verify.rs` (`KEYHOG_LIVE_VERIFY=1`) |
| System scan | `scan-system` | e2e (env-gated) |
| Formats | json, sarif, jsonl, text | `crates/core/tests/unit/report.rs` + e2e |
| Flags matrix | `--fast`, `--deep`, `--lockdown`, `--no-daemon`, GPU backends | orchestrator + `routing_matrix` |

**E2E must cover every hop:** args parse → orchestrator → source emits `Chunk`s → scanner `CompiledScanner::scan` → dedup/filter/suppress → reporter → exit code.

### B. Meso — pipeline slices (integration without full CLI)

Prove each stage in isolation with real types, not mocks:

```
Source::iter_chunks → normalize_scannable_chunk → decode pipeline →
engine (AC / SIMD / GPU / fallback) → resolution → confidence/ML →
build_raw_match → core dedup/SARIF → verifier (optional)
```

| Stage | Crate / module | Integration tests |
|-------|----------------|-------------------|
| Spec load + validate | `core/spec/*` | `detector_validation`, `test_toml_compat` |
| Compile detectors | `scanner/compiler.rs` | `all_detectors_self_validate` |
| Decode-through | `scanner/decode/*` | `decode_test`, `encoding_explosion_runner` |
| Engine backends | `scanner/engine/*` | `backend_parity_matrix`, `gpu_parity`, adversarial `engine_cases/` |
| Sources | `sources/filesystem`, git, http, archives | `integration/filesystem`, property fuzz |
| Verifier | `verifier/*` | `break_it_cases/*`, httpmock |

### C. Micro — every source file, every public surface

**167 Rust files** under `crates/{core,scanner,sources,verifier,cli}/src/` (excluding `vendor/`).

Per file minimum contract:

| Requirement | Notes |
|-------------|-------|
| `#[cfg(test)] mod tests` or `crates/*/tests/unit/<module>.rs` | At least one test module targeting the file |
| Happy path | One representative input → expected output |
| Error path | Invalid input → typed error / empty / skip (whatever the API promises) |
| Boundary | empty, max size, unicode, off-by-one offset |
| Negative twin | “almost secret” must not fire when applicable |

Track coverage in `tests/FILE_GATE_MATRIX.toml` (to add): rows = source path, columns = happy / error / boundary / adversarial / e2e-linked.

**Parallel work:** split file list by crate into batches (core 24, scanner 74, sources 22, verifier 16, cli 31); each batch closes matrix rows independently.

---

## 3. Maximal adversarial conditions

### 3.1 Data-driven (contract × runners)

Already shipped multipliers — run **strict** after contract corpus is complete:

| Runner | ~scale @ 891 contracts | Strict env |
|--------|------------------------|------------|
| `contracts_runner` | ~3k | always strict |
| `adversarial_explosion_runner` | ~14k | `KEYHOG_ADVERSARIAL_STRICT=1` |
| `encoding_explosion_runner` | ~12k | `KEYHOG_ENCODING_STRICT=1` |
| `path_shape_runner` | ~10k | `KEYHOG_PATH_SHAPE_STRICT=1` |
| `noise_injection_runner` | ~8k | `KEYHOG_NOISE_STRICT=1` |
| `unicode_confusable_runner` | ~8k | `KEYHOG_UNICODE_STRICT=1` |
| `whitespace_normalization_runner` | ~8k | `KEYHOG_WHITESPACE_STRICT=1` |
| `line_length_runner` | ~8k | `KEYHOG_LINE_LEN_STRICT=1` |
| `entropy_edge_runner` | ~8k | `KEYHOG_ENTROPY_STRICT=1` |
| `compound_encoding_runner` | multi-layer nested encode | strict when stable |
| `multi_secret_runner` | colliding secrets | `KEYHOG_MULTI_STRICT=1` |
| `comment_embed_runner` | secrets in comments / TODO | strict |
| `companion_contracts_runner` | companion-required detectors | always |
| `cve_replay_runner` | historical leak shapes | always |

### 3.2 Evasion class matrix (from `audits/adversarial_audit.md`)

Wire **dead fixtures** into `engine_cases/` — zero Rust references today:

- `tests/data/corpus/evasion/*` (8 files)
- `tests/data/recall/kh_challenging/*` (14 items)
- Port `tests/scripts/adversarial_suite.py` (1411 lines) → Rust runner or CI subprocess gate

Each evasion class needs: **positive (fires)** + **negative twin (same shape, fake cred)** + engine verification.

Classes include: homoglyph keywords, zero-width inside value, RTL override, base64 wrap at 64 cols, hex+underscore, split-string concat, URL encoding, variable indirection, multiline JSON, binary embed, JWT stuffing, polyglot files, AC prefilter bypass, decode-bomb caps, etc.

### 3.3 Property + fuzz (continuous adversarial)

| Suite | Location |
|-------|----------|
| Scanner fuzz | `crates/scanner/tests/property/scanner_fuzz.rs` |
| Decode properties | `property/decode.rs` |
| HTTP policy | `crates/sources/tests/property/http_fuzz.rs` (40k cases) |
| SARIF dedup | `crates/core/tests/property/sarif_dedup.rs` |
| GPU invariants | `gpu_proptest_invariants.rs` |

New failures → commit `*.proptest-regressions` (permanent gate).

---

## 4. Dogfooding (parallel track)

Use KeyHog on KeyHog while building tests. Capture friction as **actionable issues**, not notes.

| Activity | How | Output |
|----------|-----|--------|
| Real scans | `keyhog scan .`, `--git-staged`, on repo + large external trees | Findings → `TODO.md` or issue |
| `--dogfood` | `keyhog scan --dogfood` → stderr JSON trace | Every suppression, skip, backend choice, decode depth |
| Demo fixture | `demo-secret.env` + suppression telemetry | e2e regression already exists; extend |
| CLI UX | Wrong flags, empty paths, lockdown violations | `break_it.rs` cases |
| Competitor diff | `tools/diff_bench/`, nightly workflow | Recall gaps → new contracts |
| Field corpus | Scan known-leak repos (gated, no commit secrets) | CVE replay + contract seeds |

Dogfood items triage like test failures: **bug / UX / doc / wontfix**.

---

## 5. Stress testing (parallel track)

Prove behavior under resource pressure and scale — not just correctness on tiny fixtures.

| Stress | Existing | Expand |
|--------|----------|--------|
| Huge single chunk | `oom_test.rs` (513 MiB skip gate + time bound) | 1 GiB, parallel chunks |
| Many detectors | 891 compiled | compile time + scan RSS ceiling |
| Deep decode nest | decode wall budget | 4+ layers, bomb inputs |
| Concurrent scans | `concurrent/` mods | rayon + daemon parallel clients |
| Timeout | `timeout_test.rs` | deadline propagation per stage |
| Archive bombs | `gzip_bomb_caps`, nested archive | sources adversarial |
| GPU batch cap | `gpu_ac_recall_bug_56` | cap+1 truncation sentinel |
| Merkle incremental | core `merkle_index` | 10k file tree, skip vs rescan |
| Rate limit verify | `verifier/rate_limit` | burst + cache eviction |

Stress failures → **perf (P)** or **engine (E)** bucket; never silence without measured baseline in `perf` contract section.

---

## 6. Parallel execution model

### 6.1 Workstreams (run simultaneously)

| ID | Stream | Deliverable |
|----|--------|-------------|
| **A** | Generate **547** missing `tests/contracts/<detector>.toml` | 891/891 contract coverage |
| **B** | Companion contracts for all `companion_required` detectors | `contracts/companion/` complete |
| **C** | Wire dead evasion fixtures + adversarial_suite | `engine_cases/` + CI |
| **D** | FILE_GATE_MATRIX micro tests per source file | 167/167 rows green |
| **E** | E2E expansion (git, daemon, hook, baseline, incremental) | `cli/tests/e2e_*` |
| **F** | sources + verifier break_it / property | crate parity |
| **G** | Dogfood passes on real trees + `--dogfood` traces | `TODO.md` / issues |
| **H** | Stress suite expansion | oom, concurrent, bombs |
| **I** | De-rig `audits/rigged_tests.md` | tightened assertions |
| **J** | CI: full runner strict + workspace test tier | `.github/workflows/ci.yml` |

**Do not parallelize:** two agents editing the same contract TOML or same detector spec without coordination.

### 6.2 Red wall command (after A completes)

```bash
cd /media/mukund-thiru/SanthData/Santh/software/keyhog

export KEYHOG_ADVERSARIAL_STRICT=1
export KEYHOG_ENCODING_STRICT=1
export KEYHOG_PATH_SHAPE_STRICT=1
export KEYHOG_NOISE_STRICT=1
export KEYHOG_UNICODE_STRICT=1
export KEYHOG_WHITESPACE_STRICT=1
export KEYHOG_LINE_LEN_STRICT=1
export KEYHOG_ENTROPY_STRICT=1
export KEYHOG_MULTI_STRICT=1

cargo test -p keyhog-scanner --profile release-fast \
  --test contracts_runner \
  --test adversarial_explosion_runner \
  --test encoding_explosion_runner \
  --test path_shape_runner \
  --test noise_injection_runner \
  --test unicode_confusable_runner \
  --test whitespace_normalization_runner \
  --test line_length_runner \
  --test entropy_edge_runner \
  --test compound_encoding_runner \
  --test multi_secret_runner \
  --test comment_embed_runner \
  --test companion_contracts_runner \
  --test cve_replay_runner

cargo test -p keyhog-scanner --lib --profile release-fast
cargo test -p keyhog-core -p keyhog-sources -p keyhog-verifier --lib
cargo test -p keyhog --test e2e_binary --profile release-fast
cargo test -p keyhog-scanner property::scanner_fuzz --profile release-fast
```

LFS: `git lfs pull` before contracts (CI uses `actions/checkout` with `lfs: true`).

---

## 7. Triage → fix → review loop

### 7.1 Triage buckets (every failure exactly one)

| Bucket | Meaning | Action |
|--------|---------|--------|
| **E** | Engine bug — real secret, correct contract | Fix `scanner` / `engine` / `decode` |
| **C** | Contract wrong — doesn't match detector spec | Fix TOML only |
| **R** | Runner too strict — out of README promise | Fix runner floor or document limit |
| **P** | Perf / scale budget blown | Optimize or re-baseline with numbers |
| **F** | False positive — negative fired | Detector TOML / confidence / ML |
| **X** | Dogfood / stress-only (OOM, UX, hang) | Product fix outside contract |

Runners aggregate misses: `(detector_id, variant, credential)` list before panic — **split list by prefix across parallel fixers**.

### 7.2 Fix loop

```
1. Run red wall → capture full miss list
2. Classify each line E/C/R/P/F/X
3. Batch by root cause (e.g. "decode splice loses Bearer context")
4. Fix + proving test + negative twin
5. Re-run ONLY the failing runner(s)
6. Repeat until wall is green
7. Flip any report-only runner to STRICT in CI
```

### 7.3 Review pass (after green wall)

Not random code reading — close **audit artifacts**:

| Audit | Path | Action |
|-------|------|--------|
| Rigged tests | `audits/rigged_tests.md` | Tighten assertions |
| Adversarial gaps | `audits/adversarial_audit.md` | Each row → Y |
| Detector TOML | `audits/detector_toml_quality.md` | Spec fixes |
| Security | `audits/release-2026-04-26/` | Re-verify closed items |
| Destroy / blind fresh | `audits/destroy_*.md`, `blind_fresh_*.md` | New engine_cases |

Review output = **tests + fixes**, not new markdown.

### 7.4 Issue hunting (continuous)

While tests run in parallel, actively look for:

- Silent drops (GPU cap, Hyperscan compile, alphabet filter)
- Credential leaks in logs (`Debug`, dogfood, scan_system JSON)
- SSRF / verify template bugs
- Lockdown disk writes
- Drift between backends (CPU vs GPU vs SIMD)
- README claims vs `readme_claims.rs` / contracts

Log in `audits/round<N>.md` or GitHub issues with repro command.

---

## 8. Phased timeline

| Phase | Work | Exit criterion |
|-------|------|----------------|
| **0** | Parallel A–H streams | Contracts 891/891; matrix file created |
| **1** | Red wall all strict runners | Aggregate miss list empty |
| **2** | Fix loop E→F→P | Per-runner green |
| **3** | FILE_GATE_MATRIX 167/167 | Every `src/*.rs` gated |
| **4** | E2E pipeline complete | Every orchestrator branch has binary test |
| **5** | Review audits + de-rig | Audit rows closed |
| **6** | CI hardening | PR runs strict runners + workspace lib tests |
| **7** | Perf / parity / diff_bench | `perf_floor_matrix`, `backend_parity_matrix` green |

---

## 9. Definition of done

- [ ] **891/891** detector contracts (+ companions where required)
- [ ] All `*_runner` **STRICT in CI**
- [ ] **0** unreferenced files under `tests/data/corpus/` and `kh_challenging/`
- [ ] `adversarial_suite.py` in CI or replaced by Rust runner
- [ ] **167/167** source files in FILE_GATE_MATRIX
- [ ] E2E covers: scan, git modes, daemon, hook, baseline, incremental, formats, lockdown
- [ ] `audits/rigged_tests.md` — zero open items
- [ ] `audits/adversarial_audit.md` — evasion matrix all **Y**
- [ ] `cargo test --workspace` green (feature matrix documented)
- [ ] Dogfood pass on repo + at least one large external tree documented
- [ ] CHANGELOG entry with hit-rate tables (project convention)

---

## 10. Source file inventory (micro gate targets)

| Crate | Files | Primary test dirs |
|-------|-------|-------------------|
| `keyhog-core` | 24 | `crates/core/tests/unit/`, `property/`, `adversarial/` |
| `keyhog-scanner` | 74 | `crates/scanner/tests/unit/`, `adversarial/engine_cases/`, inline `#[cfg(test)]` |
| `keyhog-sources` | 22 | `crates/sources/tests/unit/`, `integration/`, `property/` |
| `keyhog-verifier` | 16 | `crates/verifier/tests/unit/`, `break_it_cases/` |
| `keyhog` (cli) | 31 | `crates/cli/tests/`, orchestrator unit tests |

**Total: 167 files** — each row in FILE_GATE_MATRIX must reach green.

---

## 11. Contract template (per detector)

```toml
schema_version = 1
detector_id = "<id>"
service = "<service>"
severity = "<level>"

[[positive]]
text = "..."
credential = "..."
reason = "..."

[[negative]]
text = "..."
reason = "..."

[[evasion]]
text = "..."
credential = "..."
reason = "..."

[perf]
fixture_bytes = 4096
max_microseconds = 25000

[scale]
fixture_bytes = 1048576
min_findings = 1
max_seconds = 2.0

readme_claim = "..."
```

Copy nearest-neighbor contract; validate with `cargo test -p keyhog-scanner --test contracts_runner -- <detector_id>`.

---

*Last updated: 2026-05-25 — testing program for parallel expansion, dogfood, stress, micro+E2E+adversarial gates.*
