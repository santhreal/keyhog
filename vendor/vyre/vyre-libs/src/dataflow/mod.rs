//! Dataflow engine — the depth layer under surgec's detection rules.
//!
//! This module is the Wave-1..Wave-3 deliverable of `docs/LEGENDARY_PLAN_2026-04-23.md`.
//! Each submodule is one dataflow primitive, composed as a vyre `Program`
//! (no raw WGSL — everything emits through the IR so CPU parity + GPU
//! dispatch work identically).
//!
//! ## Layer position
//! T3 — library compositions of T2 intrinsics + T2.5 primitives. Consumers
//! (surgec, karyx, keyhog) import these ops by name; surgec's predicate
//! registry calls into this module for every dataflow predicate.
//!
//! ## Primitives — ownership & precision contract
//! Every primitive obeys the zero-FP precision contract defined in the
//! legendary plan: the primitive is either sound (may over-approximate,
//! producing additional taint edges that a rule must filter) or exact
//! (may not over-approximate). The [`Soundness`] marker on each primitive
//! documents which regime it is in; rules that require zero-FP semantics
//! MUST compose only exact primitives or explicitly-bounded sound
//! primitives with sanitizer filters.
//!
//! ```text
//!                        ┌──── DF-1 ssa
//!                        ├──── DF-2 reaching  ─┐
//!     AST buffer ───────►├──── DF-5 callgraph ─┼──► DF-4 ifds ──► rule
//!     (from AP-2 lower)  ├──── DF-3 points_to ─┘      ▲
//!                        ├──── DF-7 range ─────────────┘
//!                        ├──── DF-8 escape
//!                        ├──── DF-6 slice (backward from sink)
//!                        ├──── DF-9 summary (persistent fixpoint)
//!                        └──── DF-10 loop_sum (fixpoint acceleration)
//! ```
//!
//! All ten primitives register via `inventory::submit!` at crate init
//! so surgec's predicate registry can look them up by stable op id.

pub mod soundness;

pub use soundness::{Soundness, SoundnessTagged};

pub mod callgraph;
pub mod control_dependence;
/// Cross-language dataflow primitive — forward reach REQUIRING the
/// path to traverse at least one FFI edge (Python ctypes / JNI /
/// N-API / Rust bindgen). Op id:
/// `vyre-libs::dataflow::cross_language`. Soundness: `MayOver`.
pub mod cross_language;
pub mod def_use;
pub mod escape;
pub mod escapes;
pub mod ifds;
/// GPU-native IFDS driver (G3). Reduces interprocedural dataflow to
/// reachability on the exploded supergraph so the GPU primitives
/// (`csr_forward_traverse`, `adaptive_traverse`, `bitset_fixpoint`)
/// own the hot path.
pub mod ifds_gpu;
pub mod live;
pub mod live_at;
pub mod loop_sum;
pub mod may_alias;
pub mod must_init;
pub mod points_to;
pub mod post_dominates;
pub mod range;
pub mod range_check;
pub mod reaching;
pub mod reaching_def;
pub mod scc_query;
pub mod slice;
pub mod ssa;
pub mod summary;
pub mod value_set;
