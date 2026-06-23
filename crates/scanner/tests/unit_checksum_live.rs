//! Bounded checksum unit target.
//!
//! Cargo does not auto-discover files under `tests/unit/`. This target keeps
//! checksum validator behavior live without pulling in the larger historical
//! scanner unit forest.

#[path = "unit/checksum_extended.rs"]
mod checksum_extended;

#[path = "unit/sub_facade/sub_checksum.rs"]
mod sub_checksum;
