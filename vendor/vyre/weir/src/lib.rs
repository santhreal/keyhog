//! `weir` — GPU-resident dataflow primitives.
//!
//! A weir is a low barrier built across a stream that gates and
//! measures the flow passing through it. This crate is the same
//! idea applied to program graphs: each primitive places a
//! deterministic gate over the IR that lets us measure and reason
//! about every fact flowing through a function, file, or whole
//! program.
//!
//! `weir` is the **first wrapper** in the vyre wrapper namespace.
//! `vyre-*` is closed (substrate only); wrappers like `weir` consume
//! vyre and own exactly one capability. Companion wrappers:
//! `writ` (CPU symbolic execution + exploit witness, Z3-backed),
//! `scry` (GPU-resident symbolic execution, vyre-native research
//! stub — no CPU primitives), `ambit` (context evaluation —
//! entrypoint / auth / rate-limit / validation dominators,
//! deploy-graph membership). See `vyre/VISION.md` section "The
//! wrapper namespace and its closed-set rule" for the architecture.
//!
//! ## What lives here
//!
//! Ten Program-emitting dataflow primitives, each lowered to a
//! `vyre::Program` (no raw WGSL — everything flows through the IR
//! so CPU parity and GPU dispatch agree bit-for-bit):
//!
//! ```text
//!                         ┌──── DF-1 ssa
//!                         ├──── DF-2 reaching  ─┐
//!      AST buffer ───────►├──── DF-5 callgraph ─┼──► DF-4 ifds ──► rule
//!     (parser output)     ├──── DF-3 points_to ─┘      ▲
//!                         ├──── DF-7 range ─────────────┘
//!                         ├──── DF-8 escape
//!                         ├──── DF-6 slice (backward from sink)
//!                         ├──── DF-9 summary (persistent fixpoint)
//!                         └──── DF-10 loop_sum (fixpoint acceleration)
//! ```
//!
//! ## Soundness contract
//!
//! Every primitive carries a [`Soundness`] tag — `Exact`, `MayOver`,
//! or `MustHave`. Rules that demand zero-false-positive semantics
//! compose only `Exact` primitives or explicitly-bounded `MayOver`
//! primitives paired with a sanitizer filter. The contract is
//! enforced at registration time so a careless author can't ship a
//! `MayOver` op with the soundness label of an `Exact` one.
//!
//! ## Standalone usage
//!
//! `weir` depends only on `vyre`, `vyre-primitives`, and
//! `vyre-foundation`. It is **not** a member of the vyre namespace
//! (which is reserved for vyre internals); it consumes vyre as a
//! third-party crate exactly the way `surgec` does. Anyone building
//! a compiler, profiler, deobfuscator, or rule engine on top of
//! GPU-native IR can take `weir` standalone — the security domain
//! is just the first consumer.
//!
//! ## Registration
//!
//! Primitives publish through the `OpEntry` inventory in
//! [`vyre_libs::harness`](vyre_libs::harness). `surgec`'s predicate
//! registry walks that inventory so a new primitive becomes
//! available the moment its file appears in `weir/src/`.

pub mod soundness;

pub use soundness::{Soundness, SoundnessTagged};

pub mod callgraph;
pub mod control_dependence;
/// Cross-language dataflow primitive — forward reach REQUIRING the
/// path to traverse at least one FFI edge (Python ctypes / JNI /
/// N-API / Rust bindgen). Op id:
/// `weir::cross_language`. Soundness: `MayOver`.
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
pub mod reachability_witness;
pub mod reaching;
pub mod reaching_def;
pub mod scc_query;
pub mod slice;
pub mod ssa;
pub mod summary;
pub mod value_set;
