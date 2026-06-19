# CLI Stress Tests

Hand-written dogfood regressions for CLI worst-case behavior. This directory is
already wired through `crates/cli/tests/all_tests.rs` via `pub mod stress;`;
new files must be added to `crates/cli/tests/stress/mod.rs`.

Run:

```bash
cargo test -p keyhog --test all_tests stress::
```

Expected: the wired stress shard passes. A new failing stress case is a product
finding until the underlying behavior is fixed.
