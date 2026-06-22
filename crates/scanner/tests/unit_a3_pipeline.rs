//! Bounded unit pipeline test target.
//!
//! Cargo does not auto-discover `tests/unit/a3_pipeline/*.rs`. This target
//! mounts that subtree without pulling in the larger historical scanner unit
//! forest.

#[path = "unit/a3_pipeline/mod.rs"]
mod a3_pipeline;
