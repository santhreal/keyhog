# LR1-A2

LOCK: crates/scanner/src/engine/**, hw_probe.rs, gpu*.rs, simd.rs, crates/scanner/tests/unit/engine_cases/**, crates/scanner/tests/unit/hw_probe_cases/**, crates/scanner/tests/unit/gpu_cases/**, crates/scanner/tests/gap/gpu*.rs, crates/scanner/tests/gap/megakernel*.rs, crates/scanner/tests/gpu_parity.rs, crates/scanner/tests/megakernel_parity.rs, crates/scanner/tests/support/**

## Hunt

- finding count: 6 (KH-GAP-001..003 registry + KH-GAP-A2-004..006 new)
- gpu_parity.rs: 4× `eprintln!("SKIP:…"); return;` — SKIP-as-pass on detector load + zero-GPU degenerate case
- megakernel_parity.rs: already hard-fail (no SKIP)
- decode_backend_matrix.rs: still contains SKIP (outside A2 fix scope; gated by gpu_tests_fail_not_skip)
- engine/boundary.rs + engine/scan_gpu.rs: inline `#[cfg(test)]` modules (7 tests in src)
- scan_gpu.rs + backend.rs: silent CPU fallback when `gpu_matcher()` is None (warn-only in prod)
- boundary scan: overlap/gap/path skip paths audited — adversarial coverage exists under tests/adversarial/engine_cases/

## Tests added

- count: **60** hand-written files (one `#[test]` per file)
- directories:
  - `crates/scanner/tests/unit/engine_cases/` (35)
  - `crates/scanner/tests/unit/hw_probe_cases/` (17)
  - `crates/scanner/tests/unit/gpu_cases/` (8)
- wired in `crates/scanner/tests/unit/mod.rs` → `all_tests.rs`
- shared gate: `crates/scanner/tests/support/gpu_gate.rs`

## Fixes

- **gpu_parity.rs**: removed all SKIP-as-pass; `expect()` on detector load; `assert_gpu_not_silent_empty` + `require_gpu_or_panic` helpers
- **megakernel_parity.rs**: no change needed (already hard-fail)
- **KH-GAP-001..003** gap tests present and wired in `tests/gap/mod.rs`

## Commands

```bash
env -u CC cargo test -p keyhog-scanner --test all_tests --profile release-fast 'engine_cases::'
# → 35 passed; 0 failed

env -u CC cargo test -p keyhog-scanner --test all_tests --profile release-fast 'hw_probe_cases::'
# → 17 passed; 0 failed

env -u CC cargo test -p keyhog-scanner --test all_tests --profile release-fast 'gpu_cases::'
# → 8 passed; 0 failed

env -u CC cargo test -p keyhog-scanner --test all_tests --profile release-fast gap::gpu gap::megakernel_literal_set_parity
# → 4 passed; 0 failed

env -u CC cargo test -p keyhog-scanner --test gpu_parity --profile release-fast
# → 4 passed; 0 failed

env -u CC cargo test -p keyhog-scanner --test megakernel_parity --profile release-fast
# → 1 passed; 0 failed
```

**Aggregate (A2 slice):** 69 passed / 0 failed / 0 ignored  
**all_tests total inventory:** 655 tests

## GAP_FINDINGS appended

- KH-GAP-003 → status **fixed** (gpu_parity SKIP removed)
- KH-GAP-A2-004 inline engine src tests (open)
- KH-GAP-A2-005 gpu_parity SKIP-as-pass (fixed)
- KH-GAP-A2-006 silent warm_backend degrade (open)
