# LR1 launch — 10 parallel agents

**Round:** 1 (Hunt + red inventory + first test wave)  
**Repo:** `/mnt/santh-desktop/software/keyhog`  
**Do not edit outside your slice.**

---

## Shared rules

1. Read `KEYHOG_LINUX_QUALITY_PROGRAM.md` and `../../STANDARD.md` § Test Contract
2. **HUNT first** (read-only grep/audit) — 30 min equivalent before any fix
3. Register findings in `GAP_FINDINGS.toml` (append `[[finding]]` blocks)
4. Write **≥50 hand-written test files** (A8: ≥30, A9: ≥20, A10: ≥5) — one `#[test]` per file
5. Wire new modules in `tests/*/mod.rs` and `all_tests.rs`
6. Write evidence to `coordination/rounds/LR1-A{k}.md`
7. **No** `assert!(ok)` / skip-as-pass / weakened assertions
8. Post lock line at top of your ledger: `LOCK: <paths>`

---

## A1 — core

**Slice:** `crates/core/src/**`, `crates/core/tests/**`

**Hunt:** all 23 `#[cfg(test)]` in src; unwrap in prod; report/sarif/dedup/merkle edge cases

**Deliver:** ≥50 tests in `tests/unit/`, `tests/gap/`, `tests/contract/`, `tests/adversarial/` — migrate inline tests from at least 5 modules (encoding already done — continue allowlist, dedup, sarif, spec)

**Ledger:** `coordination/rounds/LR1-A1.md`

---

## A2 — scanner engine/GPU

**Slice:** `crates/scanner/src/engine/**`, `hw_probe.rs`, `gpu*.rs`, `simd.rs`

**Hunt:** GPU skip, silent CPU fallback, megakernel parity, boundary scan gaps

**Deliver:** ≥50 hand tests; extend `tests/gap/` for KH-GAP-001..003; harden gpu_parity/megakernel (no SKIP)

**Ledger:** `coordination/rounds/LR1-A2.md`

---

## A3 — pipeline/decode/multiline

**Slice:** `pipeline.rs`, `decode/**`, `multiline/**`

**Hunt:** 1924 LOC pipeline, hot-path allocs, decode splice, phantom append class

**Deliver:** ≥50 tests — adversarial decode, gap modularity, unit per decode module

**Ledger:** `coordination/rounds/LR1-A3.md`

---

## A4 — context/confidence/entropy/compiler

**Slice:** `context/**`, `confidence/**`, `entropy/**`, `compiler*.rs`

**Hunt:** weak oracles, keyword-only, confidence calibration holes

**Deliver:** ≥50 tests — property seeds, unit boundaries, gap bar-misses

**Ledger:** `coordination/rounds/LR1-A4.md`

---

## A5 — sources

**Slice:** `crates/sources/**`

**Hunt:** binary read (check if capped), git/archive bombs, timeouts, symlink policy

**Deliver:** ≥50 tests — integration, adversarial, gap, contract

**Ledger:** `coordination/rounds/LR1-A5.md`

---

## A6 — verifier

**Slice:** `crates/verifier/**`

**Hunt:** 9 inline tests, SSRF bypass variants, verify handler coverage holes

**Deliver:** ≥50 tests — break_it expansion, contract per SSRF class, gap inline-test gate

**Ledger:** `coordination/rounds/LR1-A6.md`

---

## A7 — cli

**Slice:** `crates/cli/**`

**Hunt:** orchestrator 1586 LOC, exit codes, e2e coverage map, daemon gaps

**Deliver:** ≥50 tests — contract CLI surface, gap modularity, e2e expansions

**Ledger:** `coordination/rounds/LR1-A7.md`

---

## A8 — test suite quality

**Slice:** `crates/*/tests/**` audit (don't edit src); `FILE_GATE_MATRIX.toml`; rigged tests

**Hunt:** full fleet grep for `assert!(.*is_ok`, SKIP, tautologies, `#[ignore]` without FINDING

**Deliver:** ≥30 weak tests fixed or deleted; inventory in `audits/LR1-weak-tests.md`; draft `tests/FILE_GATE_MATRIX.toml` (167 rows)

**Ledger:** `coordination/rounds/LR1-A8.md`

---

## A9 — detectors + claims

**Slice:** `detectors/**`, README, SPEC, claim scripts

**Hunt:** verify count vs README, perf table without repro, detector metadata holes

**Deliver:** ≥20 contract tests; ≥5 new evasion TOMLs; claims ledger `coordination/rounds/LR1-claims.md`

**Ledger:** `coordination/rounds/LR1-A9.md`

---

## A10 — CI + infra

**Slice:** `.github/workflows/**`, `benches/**`, `scripts/**`, `coordination/**`, `fuzz/**`

**Hunt:** CI skips, distcc, Hyperscan, which runners lack strict env

**Deliver:** CI gap tests; `coordination/rounds/LR1-ci-matrix.md`; ≥5 hand tests for operability

**Ledger:** `coordination/rounds/LR1-A10.md`

---

## Evidence format (every agent)

```markdown
# LR1-A{k}
LOCK: ...
## Hunt
- finding count: N
## Tests added
- count: N (list directories)
## Commands
- `env -u CC cargo test -p ... --test all_tests ...` → pass/fail counts
## GAP_FINDINGS appended
- KH-GAP-xxx ...
```
