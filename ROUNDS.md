# KeyHog Testing Rounds

Orchestration log for parallel subagent waves. Canonical repo:
`/media/mukund-thiru/SanthData/Santh/software/keyhog`

See `TESTING_PROGRAM.md` for full strategy.

## Round model

| Round | Goal | Parallel streams | Exit gate |
|-------|------|------------------|-----------|
| **R1** | Blast: data + micro + wire fixtures | 12+ agents | Deliverables land in repo |
| **R2** | Red wall: strict runners, full miss list | 4 agents (by crate) | Aggregate failure inventory |
| **R3** | Fix loop: E→F→C→P batches | N agents by failure signature | Per-runner green |
| **R4** | Strict CI + audit closure | 2 agents | CI yaml + rigged/adversarial audits closed |
| **R5** | Dogfood + stress + perf | 3 agents | TODO/issues + stress green |

## Round 1 — launched 2026-05-25

| Agent | Stream | Deliverable |
|-------|--------|-------------|
| R1-A | Contracts script + batch A–G | `scripts/generate_contracts.py`, ~90 contract TOMLs |
| R1-B | Contracts batch H–N | ~90 contract TOMLs |
| R1-C | Contracts batch O–T | ~90 contract TOMLs |
| R1-D | Contracts batch U–Z + numeric | ~90 contract TOMLs |
| R1-E | Companion contracts | `tests/contracts/companion/` gaps closed |
| R1-F | Evasion corpus → engine_cases | `engine_cases/dead_corpus_evasion.rs` |
| R1-G | kh_challenging → engine_cases | `engine_cases/dead_corpus_challenging.rs` |
| R1-H | FILE_GATE_MATRIX + core micro | `tests/FILE_GATE_MATRIX.toml`, core unit gaps |
| R1-I | Scanner decode/context micro | unit tests under `scanner/tests/unit/` |
| R1-J | Scanner engine micro | `engine_cases/` + unit gaps |
| R1-K | sources + verifier + cli micro/e2e | integration + e2e expansions |
| R1-L | Red wall snapshot | `audits/round-r1-red-wall.md` failure list |

**After R1 merges:** run R2 red wall on integrated tree.

## Round 1 — completed 2026-05-25

| Agent | Result |
|-------|--------|
| R1-A | 135 contracts + `scripts/generate_contracts.py`; 53 fail validation |
| R1-B | 140 contracts; 59 fail |
| R1-C | 135 contracts; 46 fail |
| R1-D | 137 contracts; 1 fail (`zora-api-key`); blocker: `private-key.toml` malformed |
| R1-E | **177/177 companion contracts — green** |
| R1-F | 8/8 evasion corpus wired; 5 engine bugs (E) |
| R1-G | 9/9 kh_challenging wired; **14/14 green** |
| R1-H | `tests/FILE_GATE_MATRIX.toml` 167 rows; **core 24/24 green** |
| R1-I | +51 decode/context/multiline tests; all green |
| R1-J | 8 new engine_cases; 4 pass / 4 fail (TESTKEY suppression, concat, hex) |
| R1-K | sources/verifier/cli expanded; **e2e 13/13, sources 61/61, verifier 40/40** |
| R1-L | Red wall: **185/192 pass**, 1970 triaged misses — see `audits/round-r1-red-wall.md` |

**Contract TOMLs on disk:** ~891 (verify with `ls crates/scanner/tests/contracts/*.toml | wc -l`)

## Round 2 — launched 2026-05-25 (fix loop)

| Agent | Stream |
|-------|--------|
| R2-A | Fix `private-key.toml` + contracts_runner parse blockers |
| R2-B | Contract fixes: positive MISSED batch (top 50 from red wall) |
| R2-C | Contract fixes: evasion DROPPED / JSON envelope batch |
| R2-D | Engine: TESTKEY doc-marker suppression + concat + hex underscore |
| R2-E | Engine: dead_corpus_evasion 5 failures (split/reverse/binary) |
| R2-F | adversarial_explosion_runner misses (format wrappers) |
| R2-G | encoding_explosion + path_shape strict floors |
| R2-H | companion_contracts_runner surplus/mismatch |
| R2-I | FILE_GATE scanner/sources/verifier/cli rows (143 files) |
| R2-J | CI: strict env in `.github/workflows/ci.yml` |
| R2-K | Red wall R2 snapshot |

## Round 2 — completed 2026-05-25

| Agent | Result |
|-------|--------|
| R2-A | `private-key.toml` TOML fixed; contracts parse |
| R2-B | **50/50** top positive MISSED fixed |
| R2-C | **223** evasion DROPPED fixed (230→7) |
| R2-D | engine_cases unicode/rtl/concat/hex **8/8**; TESTKEY suppression scoped |
| R2-E | `dead_corpus_evasion` **19/19** |
| R2-F | adversarial_explosion **0 misses** (13600 variants) |
| R2-G | encoding + path_shape strict **green** |
| R2-H | companion_contracts_runner **2/2** |
| R2-I | FILE_GATE_MATRIX **167/167**; +262 file_gate tests |
| R2-J | CI `strict-runners` job + `runners-nightly.yml` |
| R2-K | Integrated snapshot noisy (concurrent edits); see R3 |

## Round 3 — completed 2026-05-25 (reconcile)

| Agent | Result |
|-------|--------|
| R3-A | contracts_runner **5/5 green** |
| R3-B | adversarial_explosion strict **green** (spotify hex fix) |
| R3-C | encoding_explosion strict **green** |
| R3-D | path_shape + unicode_confusable strict **green** |
| R3-E | companion_contracts_runner **2/2** |
| R3-F | **345** LFS pointer contracts materialized on disk |
| R3-G | See integrated verify below |

**Integrated verify (parent agent, 2026-05-25):** contracts_runner, adversarial_explosion, encoding_explosion, path_shape — all **pass** under strict env.

## Metrics (update after each round)

| Metric | R0 | R1 | R3 |
|--------|----|----|-----|
| Contract TOMLs | 346 | ~893 | **893** |
| Companion contracts | partial | 177/177 | **177/177** |
| kh_challenging wired | 0 | 9/9 | **9/9** |
| Evasion corpus wired | 0 | 8/8 | **8/8** (+ engine fixes) |
| FILE_GATE_MATRIX green | 0 | 24/167 | **167/167** |
| Core strict runners (4) | — | partial | **green** |
| Effective test surface | ~2k | **10k–50k+** (runners × contracts) | same |

## Next: Round 4–5

- **R4:** Nightly full 14-runner matrix green; close `audits/rigged_tests.md` + adversarial audit matrix
- **R5:** Dogfood large trees, stress (oom/concurrent), perf_floor_matrix

---

## Round 10 — Linux-quality push (2026-05-26)

**Program:** `KEYHOG_LINUX_QUALITY_PROGRAM.md` · **Agents:** `AGENTS.md` · **Gaps:** `GAP_FINDINGS.toml`

| Agent | Stream | Lock |
|-------|--------|------|
| A0 | Coordinator — merge, GAP registry, CI | no `src/` edits |
| A1 | core inline-test migration + lint preamble | `crates/core/src/**` |
| A2 | scanner engine + GPU parity | `crates/scanner/src/engine/**`, `hw_probe.rs` |
| A3 | pipeline + decode split/migrate | `pipeline.rs`, `decode/**` |
| A4 | scanner context/confidence migrate | `context/**`, `confidence/**` |
| A5 | sources + KH-GAP-010 streaming | `crates/sources/**` |
| A6 | verifier break_it + contract | `crates/verifier/**` |
| A7 | cli orchestrator + exit codes | `crates/cli/**` |
| A8 | gap/contract dirs + registry integrity | `tests/gap/**`, `tests/contract/**` |
| A9 | weak test purge | `*_runner.rs`, tautology tests |
| A10 | micro gates + docs/claims | `scripts/generate_micro_gate_tests.py`, README gates |

**Delivered Wave 10 (santhserver):** 588 micro gates, 12 GAP findings, cursor rules/memories, desktop rule merge.

**Blockers:** local tree 83 commits behind `origin/main`; build needs Hyperscan + `env -u CC`.

**Exit:** all micro gates green + zero OPEN GAP_FINDINGS (or SPEC-waived).
