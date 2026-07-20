#![cfg(test)]

// Standalone integration test for the release dogfood gate.
#[path = "dogfood/mod.rs"]
mod dogfood;
#[path = "e2e/support.rs"]
mod support;
