//! Frozen predicate primitives — the ~10 engine primitives listed in
//! surgec's vision as "the engine has ≈10 true primitives; everything
//! else is SURGE stdlib." Each is a thin wrapper that emits a vyre
//! Program composing [`crate::graph`] + [`crate::bitset`] +
//! [`crate::label`] primitives with a specific edge-kind mask, tag
//! mask, or node-kind constant.
//!
//! The ten primitives:
//! - `call_to` — edge kind `CallArg` from frontier to callee.
//! - `return_value_of` — edge kind `Return` from call to binding.
//! - `arg_of` — edge kind `CallArg` reverse (arg → call).
//! - `size_argument_of` — arg_of restricted to integer literal args.
//! - `edge` — raw edge matcher (forward, any mask).
//! - `in_function` — node_tags ∩ `TAG_FAMILY_FUNCTION`.
//! - `in_file` — node_tags ∩ `TAG_FAMILY_FILE`.
//! - `in_package` — node_tags ∩ `TAG_FAMILY_PACKAGE`.
//! - `literal_of` — `nodes[v] == NODE_KIND_LITERAL` AND value matches.
//! - `node_kind` — `nodes[v] == kind`.

/// Canonical edge-kind bitmasks matching surgec's
/// `ProgramGraph::EdgeKind`. One bit per kind; multiple bits can
/// coexist in the same `edge_kind_mask[e]` word.
pub mod edge_kind {
    /// Dataflow assignment edge.
    pub const ASSIGNMENT: u32 = 1 << 0;
    /// Function-call argument edge.
    pub const CALL_ARG: u32 = 1 << 1;
    /// Function return-value edge.
    pub const RETURN: u32 = 1 << 2;
    /// SSA Phi edge.
    pub const PHI: u32 = 1 << 3;
    /// Dominance edge.
    pub const DOMINANCE: u32 = 1 << 4;
    /// Alias edge.
    pub const ALIAS: u32 = 1 << 5;
    /// Memory store edge.
    pub const MEM_STORE: u32 = 1 << 6;
    /// Memory load edge.
    pub const MEM_LOAD: u32 = 1 << 7;
    /// Mutable reference edge.
    pub const MUT_REF: u32 = 1 << 8;
    /// Control-flow edge.
    pub const CONTROL: u32 = 1 << 9;
}

/// Canonical tag-family bitmasks matching surgec's `TagFamily`.
pub mod tag_family {
    /// `in_function` mask.
    pub const FUNCTION: u32 = 1 << 0;
    /// `in_file` mask.
    pub const FILE: u32 = 1 << 1;
    /// `in_package` mask.
    pub const PACKAGE: u32 = 1 << 2;
}

/// Canonical `NodeKind` constants mirroring surgec's enum.
pub mod node_kind {
    /// `Variable`.
    pub const VARIABLE: u32 = 1;
    /// `Call`.
    pub const CALL: u32 = 2;
    /// `Import`.
    pub const IMPORT: u32 = 3;
    /// `Literal`.
    pub const LITERAL: u32 = 4;
    /// `SSA`.
    pub const SSA: u32 = 5;
    /// `BasicBlock`.
    pub const BASIC_BLOCK: u32 = 6;
    /// `Binary`.
    pub const BINARY: u32 = 7;
    /// `FunctionDecl`.
    pub const FUNCTION_DECL: u32 = 8;
}

pub mod arg_of;
pub mod call_to;
pub mod edge;
pub mod in_file;
pub mod in_function;
pub mod in_package;
pub mod literal_of;
pub mod node_kind_eq;
pub mod return_value_of;
pub mod size_argument_of;

/// Little-endian `u32` word packing for [`inventory::submit!`] GPU fixtures.
///
/// Centralizes the repeated `to_le_bytes` flatten used by every graph
/// predicate's registry block (`audits/VYRE_PRIMITIVES_GAPS.md` dedup).
#[cfg(feature = "inventory-registry")]
pub(crate) fn inventory_u32_le_bytes(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|v| v.to_le_bytes()).collect()
}
