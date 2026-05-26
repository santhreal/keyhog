# Wave 10 — Multi-agent gap hunt + micro gate expansion (2026-05-26)

## Delivered this wave

| Item | Count | Location |
|------|-------|----------|
| Micro gate tests (generated) | **588** | `crates/*/tests/unit/gates/*.rs` |
| Gap finding registry | **12** | `GAP_FINDINGS.toml` |
| Hand-written gap tests | **5** | `crates/scanner/tests/gap/` |
| Hand-written contract tests | **3** | `crates/scanner/tests/contract/`, `crates/cli/tests/contract/` |
| Generator | 1 | `scripts/generate_micro_gate_tests.py` |

## Gate categories per source file (×166 modules)

1. `*_non_empty` — no todo!/unimplemented! in prod lines
2. `*_no_inline_tests` — no `#[cfg(test)]` in src/
3. `*_file_size_cap` — 500 LOC modularity (expect reds on god files)
4. `*_no_unwrap_expect` — no unwrap/expect in prod lines

## Expected red inventory (roadmap)

Run (needs Hyperscan + working vyre vendor):

```bash
env -u CC cargo test -p keyhog-scanner --test all_tests unit::gates:: 2>&1 | rg 'FAILED|failures'
env -u CC cargo test -p keyhog-scanner --test all_tests gap:: 2>&1
```

Known reds until fixed:

- **KH-GAP-001** megakernel/literal-set parity (GPU path)
- **KH-GAP-004** inline src tests (~67 files fail `no_inline_tests` gates)
- **KH-GAP-005** god files fail `file_size_cap` gates
- **KH-GAP-010** binary source streaming (sources crate)

## Fix order

1. GPU parity / silent fallback (scanner engine)
2. Inline test migration → `tests/unit/`
3. God file splits (`pipeline.rs`, `orchestrator.rs`)
4. Fleet lint preamble on all crates
5. Full exit-code taxonomy (IO/detector load → 3)

## Agent coordination

- Registry: `GAP_FINDINGS.toml` — one test file per finding id
- Integrity gate: `gap/findings_registry_integrity.rs`
- Do not weaken gate assertions to green CI; fix code or waive in SPEC
