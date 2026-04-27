//! Adversarial test suite for the scanning engine.
//!
//! These tests exercise edge cases, evasion techniques, and boundary
//! conditions that real-world credential scanners must handle correctly.

#[path = "engine_cases/backtracking.rs"]
mod backtracking;
#[path = "engine_cases/boundary.rs"]
mod boundary;
#[path = "engine_cases/contexts.rs"]
mod contexts;
#[path = "engine_cases/dedupe.rs"]
mod dedupe;
#[path = "engine_cases/encoded_inputs.rs"]
mod encoded_inputs;
#[path = "engine_cases/evasion_fixtures.rs"]
mod evasion_fixtures;
#[path = "engine_cases/known_prefix.rs"]
mod known_prefix;
#[path = "engine_cases/support.rs"]
mod support;
#[path = "engine_cases/suppression.rs"]
mod suppression;
#[path = "engine_cases/unicode_parallel.rs"]
mod unicode_parallel;
