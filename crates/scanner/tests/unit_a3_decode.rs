//! Bounded unit decode test target.
//!
//! Cargo does not auto-discover `tests/unit/a3_decode/*.rs`. This target mounts
//! that subtree without pulling in the larger historical scanner unit forest.

#[path = "unit/a3_decode/mod.rs"]
mod a3_decode;
