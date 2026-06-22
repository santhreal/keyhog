//! Bounded adversarial decode-hostile test target.
//!
//! Cargo does not auto-discover `tests/adversarial/a3_decode/*.rs`. This target
//! mounts that subtree without pulling the much larger historical adversarial
//! module tree into `all_tests`.

#[path = "adversarial/a3_decode/mod.rs"]
mod a3_decode;
