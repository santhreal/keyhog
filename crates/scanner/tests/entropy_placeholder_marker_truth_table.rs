//! Top-level test binary for the entropy-placeholder-marker characterization
//! truth-table. The scanner shards its `unit/root_facade` tests one-file-per-
//! binary (each is registered in `unit/root_facade/mod.rs` AND given a top-level
//! binary here via `#[path]`); see the sibling `regression_ac_overlap_shadow.rs`
//! for the same pattern. This module is self-contained (it only calls the public
//! `keyhog_scanner::testing` facade), so it needs no shared `support` module.

#[path = "unit/root_facade/entropy_placeholder_marker_truth_table.rs"]
mod entropy_placeholder_marker_truth_table;
