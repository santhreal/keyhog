//! Driver binary for the CAPABILITY TARGET-SPEC suite.
//!
//! These are TARGET-SPEC tests (CLAUDE.md doctrine): they assert the recall
//! capability keyhog SHOULD have across the whole ~900-detector set — that each
//! detector fires not only on its single canonical contract example but on a
//! realistic VARIANT of that credential (re-contexted into env/yaml/json/code,
//! rotated, decoded through N base64 layers, reassembled across concatenated
//! lines, or surrounded by homoglyph/NBSP evasion). A large fraction are EXPECTED
//! TO FAIL today — each red is a tracked recall gap (a narrow detector / a
//! decode-recursion cap / a normalization hole), which is the worklist, never a
//! test to weaken (Law 6 / Law 9).
//!
//! Cargo treats every top-level `tests/*.rs` as one integration-test binary but
//! does NOT auto-discover files in `tests/target_spec/`; this driver wires that
//! subtree in. The shared harness (`target_spec/mod.rs`) is mounted as
//! `crate::target_spec` so the capability modules reach `crate::target_spec::*`.
//! `mod.rs` is intentionally NOT touched by the integrator's `all_tests.rs`
//! aggregator — this lane is a standalone, separately-named binary.

#![allow(clippy::needless_borrow, clippy::needless_update, clippy::useless_vec)]

#[path = "target_spec/mod.rs"]
mod target_spec;

#[path = "target_spec/capability_context_variants.rs"]
mod capability_context_variants;

#[path = "target_spec/capability_decode_depth.rs"]
mod capability_decode_depth;

#[path = "target_spec/capability_unicode_evasion.rs"]
mod capability_unicode_evasion;

#[path = "target_spec/recall_generation_gap.rs"]
mod recall_generation_gap;
