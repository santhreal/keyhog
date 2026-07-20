#![cfg(test)]

// Standalone integration test for the heavy e2e binary-spawning suite.
// Kept out of all_tests so the contract/gap aggregator finishes in CI time.
#[path = "e2e/mod.rs"]
mod e2e;
