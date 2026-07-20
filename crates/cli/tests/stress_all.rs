#![cfg(test)]

// Standalone integration test for stress scenarios.
#[path = "stress/mod.rs"]
mod stress;
#[path = "e2e/support.rs"]
mod support;
