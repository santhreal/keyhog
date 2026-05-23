//! Frozen predicate primitives — the ~10 engine primitives listed in
//! a downstream analyzer's vision as "the engine has ≈10 true primitives; everything
//! else is source-query dialect stdlib." Each is a thin wrapper that emits a vyre
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

/// Canonical edge-kind bitmasks matching a downstream analyzer's
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

    // Slot-accessor edges — bits 10..14 — emitted by surge-source's
    // walker on AST nodes whose semantic operands need direct access
    // by name (`base_of`, `index_of`, `upper_bound_of`,
    // `induction_variable_of`, `format_string_argument_of`). The
    // edge points FROM the parent AST node TO the operand SSA value
    // so a backward CSR traversal masked on the kind bit picks up
    // exactly the operand for any node in the input frontier.

    /// Edge from `arr[idx]` → `idx` operand. Emitted on
    /// subscript_expression / array_access / array_subscript nodes.
    pub const INDEX: u32 = 1 << 10;
    /// Edge from `arr[idx]` → `arr` operand.
    pub const BASE: u32 = 1 << 11;
    /// Edge from a for/while loop → its induction-variable
    /// declaration (the `i` in `for (int i = 0; ...; ...)`).
    pub const INDUCTION_VARIABLE: u32 = 1 << 12;
    /// Edge from a for/while/do-while loop → its upper-bound
    /// expression (the right-hand side of the loop test).
    pub const UPPER_BOUND: u32 = 1 << 13;
    /// Edge from a printf-family call → its format-string argument.
    /// The walker consults `printf_family.toml`'s [c.format_slot]
    /// table to determine which argument slot carries the format
    /// string (slot 0 for printf, 1 for fprintf/sprintf/snprintf,
    /// 2 for swprintf, etc.).
    pub const FORMAT_STRING_ARG: u32 = 1 << 14;

    // Per-slot CALL_ARG subkinds — bits 16..23. Pre-fix `arg_of(call,
    // N)` returned ALL CALL_ARG predecessors regardless of N because
    // the underlying csr_backward_traverse only filtered by the
    // generic CALL_ARG bit. With these subkind bits the walker emits
    // BOTH the generic CALL_ARG bit AND the per-slot bit on each
    // call-arg edge, and `arg_of(call, N)` masks on
    // `CALL_ARG_SLOT_BASE << N`. 8 slots cover every realistic
    // launch-shape arity (every shape uses index ≤ 2). A 9th slot
    // demand requires widening edge_kind_mask to u64 — a substrate
    // change tracked in the open backlog.
    /// First per-slot call-argument bit. Slot `N` uses
    /// `CALL_ARG_SLOT_BASE << N` while the generic [`CALL_ARG`] bit remains
    /// set for recall-safe scans.
    pub const CALL_ARG_SLOT_BASE: u32 = 1 << 16;
    /// Edge from a call expression to argument slot 0.
    pub const CALL_ARG_0: u32 = CALL_ARG_SLOT_BASE;
    /// Edge from a call expression to argument slot 1.
    pub const CALL_ARG_1: u32 = CALL_ARG_SLOT_BASE << 1;
    /// Edge from a call expression to argument slot 2.
    pub const CALL_ARG_2: u32 = CALL_ARG_SLOT_BASE << 2;
    /// Edge from a call expression to argument slot 3.
    pub const CALL_ARG_3: u32 = CALL_ARG_SLOT_BASE << 3;
    /// Edge from a call expression to argument slot 4.
    pub const CALL_ARG_4: u32 = CALL_ARG_SLOT_BASE << 4;
    /// Edge from a call expression to argument slot 5.
    pub const CALL_ARG_5: u32 = CALL_ARG_SLOT_BASE << 5;
    /// Edge from a call expression to argument slot 6.
    pub const CALL_ARG_6: u32 = CALL_ARG_SLOT_BASE << 6;
    /// Edge from a call expression to argument slot 7.
    pub const CALL_ARG_7: u32 = CALL_ARG_SLOT_BASE << 7;

    /// Maximum directly-addressable CALL_ARG slot.
    pub const CALL_ARG_MAX_SLOT: u32 = 7;

    /// Slot-precise edge from a sized-input-read / sized-memory-copy /
    /// reallocator call to the argument carrying the byte-count
    /// (recv arg-2, memcpy arg-2, copy_from_user arg-2, realloc arg-1,
    /// fread arg-1, etc.). Walker emits this edge when the callee has
    /// an entry in `[<lang>.size_argument_slot]`.
    /// `size_argument_of($call)` walks back along this single edge
    /// instead of every CALL_ARG, restoring slot-precise FP elimination
    /// (every-arg-is-size over-match was the substrate-level FP
    /// source on every recv / memcpy / copy_from_user shape).
    pub const SIZE_ARG: u32 = 1 << 24;

    /// Build the per-slot mask. Slot N maps to
    /// `CALL_ARG_SLOT_BASE << N` for N in 0..=7. Beyond that the
    /// caller must fall back to the generic CALL_ARG bit (recall-safe
    /// but precision-loose) until the substrate widens to u64.
    #[must_use]
    pub const fn call_arg_slot(n: u32) -> u32 {
        if n > CALL_ARG_MAX_SLOT {
            CALL_ARG
        } else {
            CALL_ARG_SLOT_BASE << n
        }
    }
}

/// Canonical tag-family bitmasks matching a downstream analyzer's `TagFamily`.
pub mod tag_family {
    /// `in_function` mask.
    pub const FUNCTION: u32 = 1 << 0;
    /// `in_file` mask.
    pub const FILE: u32 = 1 << 1;
    /// `in_package` mask.
    pub const PACKAGE: u32 = 1 << 2;
}

/// Canonical `NodeKind` constants mirroring a downstream analyzer's enum.
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
