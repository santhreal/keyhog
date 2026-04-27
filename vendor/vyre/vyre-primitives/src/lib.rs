//! `vyre-primitives` — compositional primitives for vyre.
//!
//! Shape (mirrors Linux kernel `fs/` / `mm/` / `net/` — subsystem
//! directories under one crate, feature-gated for consumers):
//!
//! ```text
//! vyre-primitives/
//!   src/
//!     lib.rs                  # subsystem table (this file)
//!     markers.rs              # unit-struct marker types, always on
//!     text/                   # feature = "text"
//!       mod.rs
//!       char_class.rs
//!       utf8_validate.rs
//!       line_index.rs
//!     matching/               # feature = "matching"
//!       mod.rs
//!       bracket_match.rs
//!     bitset/                 # feature = "bitset"
//!     fixpoint/               # feature = "fixpoint"
//!     graph/                  # feature = "graph"     (CSR + BFS + SCC + motif + toposort)
//!     hash/                   # feature = "hash"
//!     label/                  # feature = "label"
//!     math/                   # feature = "math"
//!     nn/                     # feature = "nn"
//!     parsing/                # feature = "parsing"
//!     predicate/              # feature = "predicate"
//!     reduce/                 # feature = "reduce"
//! ```
//!
//! Two kinds of primitive live here:
//!
//! 1. **Marker types** (`markers`, always on, zero deps) — unit
//!    structs the reference interpreter and backend emitters dispatch
//!    on.
//!
//! 2. **Tier 2.5 substrate** (per-domain feature flags) — shared
//!    `fn(...) -> Program` primitives reused by ≥ 2 Tier-3 dialects.
//!    Each domain is one folder + one feature flag. Tier 3 crates
//!    depend on `vyre-primitives` and enable only the domains they
//!    need.
//!
//! The path IS the interface. Subsystem `mod.rs` exposes sub-modules,
//! not a flat namespace — callers write
//! `vyre_primitives::text::char_class::char_class(...)` so the LEGO
//! chain is visible at every call site.
//!
//! See `docs/primitives-tier.md` and `docs/lego-block-rule.md` for
//! the tier rule, admission criteria, and Gate 1 enforcement.

mod markers;
pub use markers::{
    ArithAdd, ArithMul, BitwiseAnd, BitwiseOr, BitwiseXor, Clz, CombineOp, CompareEq, CompareLt,
    Gather, HashBlake3, HashFnv1a, PatternMatchDfa, PatternMatchLiteral, Popcount, Reduce,
    RegionId, Scan, Scatter, ShiftLeft, ShiftRight, Shuffle,
};

/// Domain-neutral byte-range primitive.
///
/// CRITIQUE_VISION_ALIGNMENT_2026-04-23 V1: the foundation tier ships a
/// matching-flavoured `Match { pattern_id, start, end }` today. This
/// module introduces `ByteRange { tag, start, end }` as the neutral
/// name so new dialects do not have to adopt matching vocabulary. The
/// full migration (demoting `Match` to a deprecated alias in
/// foundation) happens in a later sweep; this is the forward-compat
/// half so new dialects are unblocked.
pub mod range;

/// Tier-2.5 primitive registry. See [`harness::OpEntry`]. Gated
/// behind the `inventory-registry` feature so default builds stay
/// dep-free; the conform harness + xtask enable the feature.
#[cfg(feature = "inventory-registry")]
pub mod harness;

/// Text primitives.
#[cfg(feature = "text")]
pub mod text;

/// Pattern-matching primitives.
#[cfg(feature = "matching")]
pub mod matching;

/// Decode primitives.
#[cfg(feature = "decode")]
pub mod decode;

/// NFA primitives — subgroup-cooperative simulator (G1 GPU perf).
#[cfg(feature = "nfa")]
pub mod nfa;

/// Hash primitives (FNV-1a 32/64, CRC-32).
#[cfg(feature = "hash")]
pub mod hash;

/// Math primitives (dot, scan, reduce, broadcast).
#[cfg(feature = "math")]
pub mod math;

/// Parsing primitives (optimizer and AST scan kernels).
#[cfg(feature = "parsing")]
pub mod parsing;

/// Neural-network primitives (attention and normalization sub-kernels).
#[cfg(feature = "nn")]
pub mod nn;

/// Graph primitives (topological sort, reachability, CSR traversal,
/// SCC decomposition, path reconstruction — the Tier 2.5 substrate
/// that surgec's stdlib rules compose against).
#[cfg(feature = "graph")]
pub mod graph;

/// Bitset primitives — `and`/`or`/`not`/`xor`/`popcount`/`any`/
/// `contains` over packed u32 bitsets. The NodeSet / ValueSet
/// representation every graph primitive consumes.
#[cfg(feature = "bitset")]
pub mod bitset;

/// Reduction primitives — `count`/`min`/`max`/`sum` over bitsets and
/// fixed-width ValueSets. Backs SURGE aggregates.
#[cfg(feature = "reduce")]
pub mod reduce;

/// Label → NodeSet resolver — turn a TagFamily bitmask into a
/// NodeSet bitset. Implements the `@family` lookup that surgec's
/// label surface surfaces.
#[cfg(feature = "label")]
pub mod label;

/// Frozen predicate primitives — the ~10 engine primitives (call_to,
/// return_value_of, arg_of, size_argument_of, edge, in_function,
/// in_file, in_package, literal_of, node_kind) that SURGE stdlib
/// rules compose into every higher-level query.
#[cfg(feature = "predicate")]
pub mod predicate;

/// Deterministic fixpoint primitive (ping-pong with convergence
/// flag). Composes `csr_forward_traverse` + bitset OR into the
/// transitive-closure driver every stdlib taint rule needs.
#[cfg(feature = "fixpoint")]
pub mod fixpoint;

/// Virtual File System DMA primitives. Uses `vyre_foundation::ir`
/// so it's gated behind the same set of features that pull
/// vyre-foundation in as an optional dep. Any of the domain
/// features enables vfs.
#[cfg(any(
    feature = "text",
    feature = "matching",
    feature = "decode",
    feature = "math",
    feature = "nn",
    feature = "hash",
    feature = "parsing",
    feature = "graph",
    feature = "bitset",
    feature = "reduce",
    feature = "label",
    feature = "predicate",
    feature = "fixpoint",
))]
pub mod vfs;

/// Wire-format envelope re-exported from vyre-foundation.
///
/// Every primitive that ships its own `to_bytes` / `from_bytes` (today:
/// `CompiledDfa`; future: serializable region tables, hash tables,
/// parser plans) composes this envelope. Re-exporting at the
/// vyre-primitives root keeps the import path uniform for consumers:
/// `vyre_primitives::serial_data::WireWriter` regardless of whether
/// the type lives at the primitive layer or higher up.
///
/// Available when any feature that pulls vyre-foundation is enabled
/// (every primitive domain enables it).
#[cfg(feature = "vyre-foundation")]
pub mod serial_data {
    pub use vyre_foundation::serial::envelope::{
        test_helpers, EnvelopeError, WireReader, WireWriter,
    };
}
