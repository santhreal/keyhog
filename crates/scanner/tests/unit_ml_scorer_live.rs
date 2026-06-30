//! Bounded unit test target for the MoE secret classifier (`src/ml_scorer.rs`).
//!
//! Cargo does not auto-discover `tests/unit/ml_scorer.rs`, and no other target
//! mounts it, so the module was declared in `tests/unit/mod.rs` but never
//! compiled or run — its assertions about the shipped model were dead. This
//! target mounts that one slice (no dependency on the larger historical scanner
//! unit forest) so both the long-standing scoring checks AND the
//! clean-separation contract (real secrets score high, structured non-secrets
//! score low, with a substantial margin) run on every `cargo test`.
//!
//! Why this matters: `entropy_ml_authoritative` defaults true, so the MoE is the
//! authoritative recall lever for entropy-fallback candidates. A regressing
//! retrain that eroded the model's secret-vs-structured separation would
//! silently cut recall with no other gate to catch it. These tests turn the
//! measured +0.95 separation margin into an enforced CI floor.

#[path = "unit/ml_scorer.rs"]
mod ml_scorer;
