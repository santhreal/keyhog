//! Security / taint compositions — the surgec-facing op surface.
//!
//! Each op registers via `inventory::submit!(OpEntry { … })` and
//! exports a `fn(...) -> Program`. Surgec's lowerer
//! (`surgec/src/lower/mod.rs`) emits against these paths directly.
//!
//! All security ops compose GPU-parallel graph algorithms over the
//! vyre IR: forward / backward reachability, dominator walks, and
//! taint propagation with sanitizer masking.

pub mod auth_check_dominates;
pub mod bounded_by_comparison;
pub mod buffer_size_check;
pub mod dominator_tree;
pub(crate) mod flow_composition;
pub mod flows_to;
pub mod flows_to_to_sink;
pub mod flows_to_with_sanitizer;
pub mod format_string_check;
pub mod integer_overflow_arith;
pub mod label_by_family;
pub mod lock_dominates;
pub mod path_canonical;
pub mod path_reconstruct;
pub mod sanitized_by;
pub mod sanitizer_dominates;
pub mod sink_intersection;
pub mod sql_param_bound;
pub mod taint_flow;
pub mod taint_kill;
pub mod taint_pollution;
pub mod topology;
pub mod unchecked_return;
pub mod xss_escape;

pub use bounded_by_comparison::bounded_by_comparison;
pub use dominator_tree::dominator_tree;
pub use flows_to::flows_to;
pub use flows_to_to_sink::flows_to_to_sink;
pub use flows_to_with_sanitizer::flows_to_with_sanitizer;
pub use label_by_family::label_by_family;
pub use path_reconstruct::path_reconstruct;
pub use sanitized_by::sanitized_by;
pub use taint_flow::taint_flow;
pub use taint_kill::taint_kill;
// `match_order` — no parent re-export. Per AUDIT_CLAUDE_2026-04-24
// F7, callers must import from `vyre_libs::range_ordering::
// match_order`. The `#[deprecated]` alias in `topology.rs` is kept
// as a soft-landing for out-of-tree callers but does NOT surface
// from this parent so its deprecation warning actually fires.
