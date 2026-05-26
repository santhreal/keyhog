# LR2 launch — structural honesty (10 agents)

**Round 2 theme:** Inline test exile · god-file splits · gates green · fix LR1 blockers

**Repo:** `/mnt/santh-desktop/software/keyhog`

---

## Shared rules (same as LR1)

- ≥40 new hand-written test files per A1–A7; A8 ≥30; A9 ≥20; A10 ≥10
- One #[test] per file; strong oracles
- Fix code in slice; close or SPEC-waive GAP entries from LR1
- Ledger: `coordination/rounds/LR2-A{k}.md`

---

## A1 — core inline exile (remaining 17 modules)

Migrate ALL remaining `#[cfg(test)]` from `crates/core/src/**` → `tests/unit/`.  
Split any file >500 LOC. Target: `gap::no_inline_tests_in_src` **green**.

---

## A2 — engine split + GPU error path

Split `engine/mod.rs`, `scan_gpu.rs`. Implement explicit error when `KEYHOG_BACKEND=gpu` but GPU unavailable (close KH-GAP-002).  
Target: KH-GAP-001 parity fix or SPEC waiver with expiry.

---

## A3 — pipeline split phase 1

Extract from `pipeline.rs` (1923 LOC): at minimum `pipeline/context_window.rs`, `pipeline/scan_loop.rs`, `pipeline/postprocess.rs`.  
Integrate `a3_all_tests.rs` into `all_tests.rs`. Close KH-GAP-014.

---

## A4 — A4 inline exile + entropy fix

Remove all A4-slice inline tests. Fix KH-GAP-017 normalized_entropy > 1.0 if in scope.

---

## A5 — sources inline exile + read_file_safe cap

Migrate sources inline tests. Cap `read_file_safe` (KH-GAP-013). Wire `.zip` archive policy (KH-GAP-018).

---

## A6 — verifier inline migration complete

Finish migrating auth/credential/oob tests from src (KH-GAP-028..032).

---

## A7 — orchestrator split phase 1

Extract from `orchestrator.rs`: config resolution, scan dispatch, reporting hooks (≥3 modules). Wire `--exclude-paths` or gap-waive KH-GAP-011.

---

## A8 — integrate harnesses + gate cleanup

Merge `a3_all_tests`, `gate/` modules into standard `all_tests.rs` per crate. Renumber duplicate GAP ids in GAP_FINDINGS.toml.

---

## A9 — contract drift fixes

Fix stale 889 claims (KH-GAP-011 A9), add missing contracts, remove orphan `nih-pubmed-api`.

---

## A10 — CI hardening

Add `env -u CC` to workflows; document Hyperscan install for secretbench; wire fuzz smoke in CI or gap-waive.

---

## LR2 exit gate

- [ ] core `no_inline_tests_in_src` green
- [ ] pipeline.rs <800 LOC (phase 1; full <500 in LR3 if needed)
- [ ] orchestrator.rs <800 LOC phase 1
- [ ] +350 new hand tests cumulative
- [ ] Full `env -u CC cargo test` matrix on all 5 crates
