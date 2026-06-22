//! Bounded segment-attribution property target.
//!
//! Cargo does not auto-discover `tests/property/*.rs` unless each file is
//! mounted by an explicit root target or `[[test]]`.

#[path = "property/segment_attribution_proptest.rs"]
mod segment_attribution_proptest;
