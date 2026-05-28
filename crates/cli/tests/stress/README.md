# R1-D1 stress tests

Hand-written regressions from R1-D1 dogfood. Wire into `crates/cli/tests/all_tests.rs`:

```rust
pub mod stress;
```

Copy this directory to `crates/cli/tests/stress/` and append `GAP_FINDINGS_append.toml`
to `GAP_FINDINGS.toml`.

Run:

```bash
cargo test -p keyhog --test all_tests stress::
```

Expected: tests **fail** while gaps KH-GAP-081..084 remain open (intentional red gates).
