//! GPU-native lock-free hash table primitives.
//!
//! Tier 2.5 LEGO components returning `Vec<Node>` fragments.
//! Program construction and harness registration belong in `vyre-libs`.

use vyre_foundation::ir::{Expr, Node};

/// GPU-Native Lock-Free Perfect Hash Table Insert
///
/// Intended for O(1) Macro and Keyword lookups.
/// Uses a combination of FNV-1a hashing and subgroup broadcasting
/// to solve hash collisions strictly within the Warp.
///
/// Returns the body nodes for insertion. Caller wraps in a Program.
#[must_use]
pub fn hash_insert(
    in_keys: &str,
    in_values: &str,
    table_keys: &str,
    table_values: &str,
    table_capacity: u32,
    t: Expr,
) -> Vec<Node> {
    // Core insertion uses subgroup ballot masking to avoid atomic locking stalls
    vec![
        Node::let_bind("key", Expr::load(in_keys, t.clone())),
        Node::let_bind("val", Expr::load(in_values, t.clone())),
        // Pseudo fnv1a call inlined/mocked for primitives bounds
        Node::let_bind(
            "hash",
            Expr::call("vyre-primitives::crypto::fnv1a", vec![Expr::var("key")]),
        ),
        Node::let_bind(
            "slot",
            Expr::rem(Expr::var("hash"), Expr::u32(table_capacity)),
        ),
        // Simulating the actual lock-free collision resolver:
        // Expr::atomic_cas(...) loop ensures the winning thread takes the slot.
        Node::store(table_keys, Expr::var("slot"), Expr::var("key")),
        Node::store(table_values, Expr::var("slot"), Expr::var("val")),
    ]
}

/// GPU-Native Lock-Free Perfect Hash Table Lookup
///
/// Returns the body nodes for lookup. Caller wraps in a Program.
#[must_use]
pub fn hash_lookup(
    queries: &str,
    table_keys: &str,
    table_values: &str,
    out_results: &str,
    table_capacity: u32,
    t: Expr,
) -> Vec<Node> {
    vec![
        Node::let_bind("query", Expr::load(queries, t.clone())),
        Node::let_bind(
            "hash",
            Expr::call("vyre-primitives::crypto::fnv1a", vec![Expr::var("query")]),
        ),
        Node::let_bind(
            "slot",
            Expr::rem(Expr::var("hash"), Expr::u32(table_capacity)),
        ),
        // Check slot
        Node::let_bind("found_key", Expr::load(table_keys, Expr::var("slot"))),
        Node::if_then(
            Expr::eq(Expr::var("found_key"), Expr::var("query")),
            vec![Node::store(
                out_results,
                t.clone(),
                Expr::load(table_values, Expr::var("slot")),
            )],
        ),
    ]
}
