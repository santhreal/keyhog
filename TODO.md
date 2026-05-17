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

- [ ] **UX**: Demo secrets (`demo-secret.env`) use `EXAMPLE` suffix — scanner returns "No secrets found"
  - Severity: LOW (confusing for new users evaluating the tool)
  - Context: Testing with the provided demo file after build
  - Impact: User thinks the tool is broken or their config is wrong
  - Repro: `./target/release/keyhog scan demo-secret.env`
  - Expected: At minimum a note like "1 example/test key found (not a real secret)"
  - Actual: "No secrets found. Your code is clean."
  - Suggestion: Detect example/test keys explicitly and report them differently, or use a real-looking fake secret in the demo

- [ ] **FEATURE**: Add `--dogfood` flag or env var that emits structured JSON of every internal decision
  - Context: Debugging why a detector didn't fire
  - Impact: Impossible to tell if a miss is a false negative or a config issue
  - Suggestion: `keyhog scan --dogfood` emits per-file/per-detector match attempts, entropy scores, and why-match-failed reasons
