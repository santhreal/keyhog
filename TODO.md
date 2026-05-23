# KeyHog — Dogfooding Findings

> Captured during real usage. Every item here is a friction point a bug bounty hunter will hit in the field.

## 2026-05-17

- [x] **BUG**: `vyre-runtime` missing from workspace.dependencies — build fails on clean clone
  - Severity: HIGH (blocks first-time contributors / CI)
  - Context: Fresh clone, `cargo build --release`
  - Impact: Cannot build without manually editing `Cargo.toml`
  - Repro: `cd software/keyhog && cargo build --release`
  - Error: `dependency.vyre-runtime was not found in workspace.dependencies`
  - Fix: Added `vyre-runtime = { version = "=0.4.1", path = "vendor/vyre/vyre-runtime" }` to workspace root `Cargo.toml`
  - Status: **FIXED** in this session

- [x] **UX**: Demo secrets (`demo-secret.env`) use `EXAMPLE` suffix — scanner returns "No secrets found"
  - Original v0.5.6 fix wired engine-side EXAMPLE-token telemetry, but the
    orchestrator's `test_fixture_suppressions.suppresses()` branch ran
    EARLIER on the demo-secret.env input (AKIAIOSFODNN7EXAMPLE is on the
    bundled substring suppression list) and never bumped the counter. The
    reporter then read `example_suppression_count() == 0` and printed the
    clean-repo summary instead of the suppressed-example summary.
  - Fixed by extending the orchestrator filter to call
    `keyhog_scanner::telemetry::record_example_suppression(..., "test_fixture_suppression")`
    before returning `false` from the test-fixture branch.
  - Regression test: `crates/cli/tests/e2e_binary.rs::demo_secret_aws_example_summary_distinguishes_suppression_from_clean`.

- [x] **FEATURE**: Add `--dogfood` flag or env var that emits structured JSON of every internal decision
  - Shipped in v0.5.6 (see `crates/scanner/src/telemetry.rs`,
    `crates/cli/src/args.rs::dogfood`). Pair with the demo-secret.env fix above
    so the counter actually fires for fixture-style suppressions.
