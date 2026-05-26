# KeyHog → Linux-Grade Quality Program

Multi-round, 10+ parallel agent push. **Canonical testing law:** `../../STANDARD.md` § Test Contract + `../../infra/testforge/docs/santh-testing-standard.md`.

**Mission (frozen):** Production-grade secret scanner — correct, fast, honest docs, zero open micro-flaws at green CI.

---

## 0. What “Linux-level” means here

Not “lots of tests.” Means:

| Linux kernel habit | KeyHog equivalent |
|--------------------|-------------------|
| `-rc` cycles with explicit regressions | Rounds 1–12 below; each ends with red→green ledger |
| `MAINTAINERS` + file ownership | Agent slice table (§4); one owner per `src/` subtree |
| `checkpatch` / mechanical gates | 588 micro gates + testforge + `santh-conform` |
| Bug fixes ship `regression-test:` | Every fix = proving test + adversarial twin |
| No silent fallback paths | GPU/CPU parity; no skip-as-pass |
| Spec = behavior | `tests/contract/` for CLI/README/env |
| Performance is a regression | `benches/` + `perf_floor*` with committed baselines |

**Axiom:** If CI is green, there is no knowable micro flaw in scope. Otherwise the suite is lying.

---

## 1. Three layers (multiply, don’t spam)

From `TESTING_PROGRAM.md`:

```
DATA (contracts/*.toml, GAP_FINDINGS.toml)
  × MULTIPLIERS (*_runner.rs, proptest, fuzz)
  × GATES (micro gates, strict env, gap tests)
  = millions of executions, thousands of falsifiable assertions
```

Hand-written tests target **invariants and bar-misses**, not duplicate runner logic.

---

## 2. Round structure (12 rounds × 10 agents)

Each round: **inventory (read-only) → parallel fix → merge → full test matrix → update GAP_FINDINGS**.

### Round 0 — Sync & truth (1 day)

| Agent | Task |
|-------|------|
| A0 | Merge origin/main (`fe5d74f`) with Wave 10 local; resolve conflicts |
| A1 | Fix build env: `env -u CC`, Hyperscan, vyre `test_support` |
| A2 | Pull desktop cursor rules; verify paths |
| A3 | Regenerate claims baseline (detector count, verify count) |
| A4–A9 | Read-only macro snapshot per crate → `ROUNDS.md` |

**Exit:** `cargo test -p keyhog-core --test all_tests` green on one crate.

### Round 1 — Structural honesty (folder contract)

**Primary vector:** Organization · Testing

| Agent | Owns |
|-------|------|
| A1–A5 | Migrate inline `src/` tests → `tests/unit/` per crate (core/scanner/sources/verifier/cli) |
| A6 | Add lint preamble all 5 `lib.rs` |
| A7 | Wire all `tests/gap/` + `tests/contract/` in `all_tests.rs` |
| A8 | Delete tautology tests (`analyze_keyword_only`, GPU tautologies) |
| A9 | testforge checklist on new tests |
| A10 | Update GAP_FINDINGS: close KH-GAP-004 entries as files migrate |

**Exit:** all `*_no_inline_tests` gates green.

### Round 2 — Modularity (god files)

**Primary vector:** Architecture · Organization

Split order (LOC):

1. `scanner/src/pipeline.rs` (~1923)
2. `cli/src/orchestrator.rs` (~1586)
3. `scanner/src/engine/mod.rs` (~1237)
4. `scanner/src/engine/scan_gpu.rs` (~1153)
5. `core/src/spec/validate.rs` (~1129)

One agent per file split; no cross-file drive-by refactors.

**Exit:** all `*_file_size_cap` gates green.

### Round 3 — Correctness oracles (engine)

**Primary vector:** Correctness · Testing.conform

| Agent | Task |
|-------|------|
| A1 | KH-GAP-001 megakernel/literal-set parity — fix or SPEC waiver with expiry |
| A2 | KH-GAP-002 GPU silent CPU fallback — error or explicit degrade flag |
| A3 | KH-GAP-003 GPU tests fail-not-skip when `KEYHOG_REQUIRE_GPU=1` |
| A4 | Boundary scan parity all backends |
| A5 | Decode-through splice regressions |
| A6–A8 | `backend_parity_matrix`, `gpu_parity`, `decode_backend_matrix` harden |
| A9 | Regression files for each fix |
| A10 | Evidence JSON for parity runs |

**Exit:** gap tests KH-GAP-001..003 green or waived in SPEC.

### Round 4 — Contract surface (external truth)

**Primary vector:** Contract · Claims integrity

Per crate `tests/contract/`:

- CLI `--help` examples compile/run
- Env precedence (`KEYHOG_*`)
- Exit codes 0/1/2/3 documented and tested
- SARIF/JSON schema snapshots
- README perf table → repro script

**Exit:** no README claim without `Command:` → `Output:` in `contract/`.

### Round 5 — Adversarial depth

**Primary vector:** testing.adversarial · Security

Expand `engine_cases/`, verifier `break_it_cases/`, sources archive fuzz paths.

Targets: OOM, unicode, path traversal in sources, SSRF variants, poisoned HS DB.

**Exit:** strict runners default-on in CI (`KEYHOG_*_STRICT=1`).

### Round 6 — Property & volume

**Primary vector:** testing.volume · testing.property

- proptest: chunk boundaries, encoding roundtrips, dedup invariants
- Fuzz targets per crate touching untrusted input
- Witness grid for top 50 detectors

**Exit:** documented trial counts in push report.

### Round 7 — Performance

**Primary vector:** Performance · Operability

- `perf_floor*` baselines committed
- No hot-path alloc regressions (`local_context_window`, etc.)
- Binary source streaming (KH-GAP-010)
- Criterion benches in CI (threshold, not noise)

**Exit:** perf regression test green; streaming gate green.

### Round 8 — Fleet STANDARD alignment

**Primary vector:** Wiring · Supply chain

- `authors = contact@santh.dev`
- Exact-pinned deps
- `santh-error` / `santh-tracing` adoption plan (or gap tests for deferral)
- `cargo-rdme` README generation per crate

### Round 9 — Verify matrix

**Primary vector:** Correctness · Contract

341 `[detector.verify]` handlers — contract test per handler class or gap for missing.

### Round 10 — Dedup & deprecation

**Primary vector:** Dedup · Deprecation

- Single banner impl (KH-GAP-009)
- Remove dead code / `allow(dead_code)`
- Orphan contract/runner cleanup

### Round 11 — Release evidence

**Primary vector:** Release/evidence

- `RELEASE_*_GATE.md` checklist
- Regenerated evidence manifests
- Version bump + CHANGELOG

### Round 12 — Macro re-scan

**Primary vector:** Macro

Full fleet inventory; zero OPEN in `GAP_FINDINGS.toml` or all red tests explained.

---

## 3. Parallel execution model

```
Coordinator (A0)
  ├── does NOT edit src — merge, GAP_FINDINGS, CI, agent prompts
  ├── assigns non-overlapping paths (see .cursor/memories/linux-quality-push.md)
  └── blocks merge if: weakened assertion, charter creep, missing evidence

Workers A1–A10
  ├── one primary vector per PR chunk
  ├── max ~500 LOC diff per agent per round (reviewable)
  └── mandatory self-review (STANDARD § Infinite-workforce bar)
```

**Merge order:** core → scanner → sources → verifier → cli (dependency direction).

**Conflict avoidance:** file-level locks in `ROUNDS.md` (`owner: A3`, `path: scanner/src/decode/*`).

---

## 4. Micro-flaw taxonomy (anticipate all classes)

| Class | Hunt command / gate |
|-------|---------------------|
| unwrap/expect in prod | `*_no_unwrap_expect` gates |
| inline tests | `*_no_inline_tests` |
| god files | `*_file_size_cap` |
| decorative tests | grep `eprintln!.*SKIP`; zero-assert tests |
| GPU skip | grep `return;` in gpu_* tests |
| contract drift | `detector id` vs `contracts/` |
| claims lies | `readme_claims`, verify count band |
| perf fantasy | README table vs `perf_floor` |
| memory unbounded | binary `fs::read`, chunk size caps |
| SSRF / verify | break_it_cases |
| duplicate logic | cross-crate banner, stealth re-roll |
| supply chain | floating deps in Cargo.toml |
| doc limitation theater | README "limitations" + green CI |

Every class → either **fixed** or **KH-GAP-NNN** with red test.

---

## 5. CI matrix (after Round 0)

```bash
env -u CC cargo test --workspace --test all_tests
env -u CC cargo test -p keyhog-scanner --test contracts_runner
KEYHOG_ADVERSARIAL_STRICT=1 cargo test -p keyhog-scanner --test adversarial_explosion_runner
KEYHOG_ENCODING_STRICT=1 cargo test -p keyhog-scanner --test encoding_explosion_runner
# ... all strict runners from TESTING_PROGRAM.md
cargo bench -p keyhog-scanner --no-run
```

---

## 6. Cursor rules & memory (this server)

| Location | Purpose |
|----------|---------|
| `~/.cursor/rules/santh-general.mdc` | Fleet axiom + self-review (merged from desktop) |
| `~/.cursor/rules/santh-server-project-root.mdc` | Paths + SSH desktop |
| `software/keyhog/.cursor/rules/keyhog-charter.mdc` | Scope gate |
| `software/keyhog/.cursor/rules/keyhog-testing.mdc` | Testing bar |
| `software/keyhog/.cursor/memories/linux-quality-push.md` | Agent coordination state |

**Desktop sync:**

```bash
scp mukund-thiru@100.127.90.39:~/.cursor/rules/santh-general.mdc ~/.cursor/rules/
# Compare: diff desktop vs server Santh/.cursor/rules/main-only-git.mdc
```

---

## 7. Immediate next actions

1. **Stash or commit Wave 10** locally, then `git pull origin main` (83 commits behind).
2. **Fix build** on server (Hyperscan, vyre vendor, unset CC).
3. **Launch Round 1** with 10 agents on inline-test migration slices.
4. **Run micro gates** — expect ~100+ reds; triage by finding class, fix in round order.

---

## 8. Definition of done (Linux-grade for KeyHog)

- [ ] Zero OPEN entries in `GAP_FINDINGS.toml` (or SPEC-waived with expiry)
- [ ] All 588 micro gates green
- [ ] All 8 test categories present on all 5 crates
- [ ] Strict runners green in CI
- [ ] No inline `#[cfg(test)]` in `src/`
- [ ] All files ≤500 LOC
- [ ] README/SPEC/CLI contract tests green
- [ ] Parity evidence archived with repro commands
- [ ] Push report filled via `coordination/PUSH_TEMPLATE.md`
