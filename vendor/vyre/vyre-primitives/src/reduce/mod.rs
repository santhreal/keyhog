//! Tier 2.5 reduction primitives — `count`/`min`/`max`/`sum` over
//! bitsets and fixed-width u32 ValueSets.
//!
//! Single-lane Programs driven by invocation 0 (the entire reduction
//! fits one work-group loop). Parallel tree-reductions live one tier
//! up; these are the correctness-critical primitives that surgec's
//! `count(...)`, `min(...)`, `max(...)`, `sum(...)` aggregates lower
//! into.

pub mod all;
pub mod any;
pub mod count;
pub mod count_non_zero;
pub mod gather;
pub mod histogram;
pub mod max;
pub mod min;
pub mod radix_sort;
pub mod range_counts;
pub mod scatter;
pub mod segment_reduce;
pub mod sum;
pub mod workgroup_any;
