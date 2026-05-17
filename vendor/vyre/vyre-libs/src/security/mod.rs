//! Security / taint compositions — the surgec-facing op surface.
//!
//! Each op registers via `inventory::submit!(OpEntry { … })` and
//! exports a `fn(...) -> Program`. Surgec's lowerer
//! (`surgec/src/lower/mod.rs`) emits against these paths directly.
//!
//! All security ops compose GPU-parallel graph algorithms over the
//! vyre IR: forward / backward reachability, dominator walks, and
//! taint propagation with sanitizer masking.
//!
//! ## Module re-export rule
//!
//! Every `pub mod foo` in this file re-exports its primary entry
//! point as `pub use foo::foo;` at parent, alphabetized below.
//! Callers reach a primitive by `vyre_libs::security::foo(...)`
//! without learning the file layout. The single intentional
//! exception is `topology::match_order` — per
//! AUDIT_CLAUDE_2026-04-24 F7, the `match_order` symbol must be
//! imported from `vyre_libs::range_ordering::match_order`; the
//! `#[deprecated]` shim in `topology.rs` is a soft-landing for
//! out-of-tree callers and is intentionally NOT re-exported here
//! so its deprecation warning fires.
//!
//! `flow_composition` is `pub(crate)` because its helpers
//! (`fuse_security_flow`, `dataflow_hit_program`,
//! `sanitized_dataflow_hit_program`) are internal building blocks
//! the public primitives compose; consumers should reach them only
//! through a stable public op.

pub mod aliases_dataflow;
pub mod auth_check_dominates;
pub mod bounded_by_comparison;
pub mod buffer_size_check;
mod catalog;
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

pub use aliases_dataflow::{aliases_dataflow, try_aliases_dataflow};
pub use auth_check_dominates::auth_check_dominates;
pub use bounded_by_comparison::bounded_by_comparison;
pub use buffer_size_check::buffer_size_check;
pub use dominator_tree::dominator_tree;
pub use flows_to::flows_to;
pub use flows_to_to_sink::flows_to_to_sink;
pub use flows_to_with_sanitizer::flows_to_with_sanitizer;
pub use format_string_check::format_string_check;
pub use integer_overflow_arith::integer_overflow_arith;
pub use label_by_family::label_by_family;
pub use lock_dominates::lock_dominates;
pub use path_canonical::path_canonical;
pub use path_reconstruct::path_reconstruct;
pub use sanitized_by::sanitized_by;
pub use sanitizer_dominates::sanitizer_dominates;
pub use sink_intersection::sink_intersection;
pub use sql_param_bound::sql_param_bound;
pub use taint_flow::taint_flow;
pub use taint_kill::taint_kill;
pub use taint_pollution::taint_pollution;
pub use unchecked_return::unchecked_return;
pub use xss_escape::xss_escape;
