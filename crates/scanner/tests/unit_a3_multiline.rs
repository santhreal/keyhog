//! Bounded unit multiline test target.
//!
//! Cargo does not auto-discover `tests/unit/a3_multiline/*.rs`. This target
//! mounts that subtree without pulling in the larger historical scanner unit
//! forest.

#[path = "unit/a3_multiline/mod.rs"]
mod a3_multiline;
