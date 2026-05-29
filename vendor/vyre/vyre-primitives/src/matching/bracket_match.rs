//! Tier 2.5 bracket-pair detector  -  bounded-stack scanner over a
//! token-kind buffer.
//!
//! The op runs as a single invocation. It maintains a bounded stack
//! in a scratch buffer and writes symmetric `open_idx <-> close_idx`
//! links into `match_pairs` for every matched brace pair, leaving
//! unmatched entries at [`MATCH_NONE`].
//!
//! Migrated from `vyre-libs/src/parsing/bracket_match.rs` per
//! `docs/primitives-tier.md` Step 2 + `docs/lego-block-rule.md`.
//! Reused by every parser dialect that needs matched-brace detection
//! (C, Rust, Go, Python f-string interpolation).

use std::sync::Arc;
use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Stable op id for the Tier 2.5 primitive.
pub const OP_ID: &str = "vyre-primitives::matching::bracket_match";

/// Token kind: not a brace.
pub const OTHER: u32 = 0;
/// Token kind: `{`
pub const OPEN_BRACE: u32 = 1;
/// Token kind: `}`
pub const CLOSE_BRACE: u32 = 2;
/// Unmatched sentinel written to `match_pairs`.
pub const MATCH_NONE: u32 = u32::MAX;

/// Build a Program that matches brace tokens using a bounded stack.
///
/// `kinds[i]` is `OTHER`, `OPEN_BRACE`, or `CLOSE_BRACE`.
/// `stack` is scratch storage with `max_depth` entries.
/// Initializes unmatched entries to [`MATCH_NONE`] and writes bidirectional
/// links for every matched brace pair.
#[must_use]
pub fn bracket_match(
    kinds: &str,
    stack: &str,
    match_pairs: &str,
    n: u32,
    max_depth: u32,
) -> Program {
    let body = vec![Node::Region {
        generator: Ident::from(OP_ID),
        source_region: None,
        body: Arc::new(vec![Node::if_then(
            Expr::eq(Expr::InvocationId { axis: 0 }, Expr::u32(0)),
            vec![
                Node::let_bind("depth", Expr::u32(0)),
                Node::loop_for(
                    "i",
                    Expr::u32(0),
                    Expr::u32(n),
                    vec![
                        Node::let_bind("k", Expr::load(kinds, Expr::var("i"))),
                        Node::store(match_pairs, Expr::var("i"), Expr::u32(MATCH_NONE)),
                        Node::if_then_else(
                            Expr::eq(Expr::var("k"), Expr::u32(OPEN_BRACE)),
                            vec![Node::if_then(
                                Expr::lt(Expr::var("depth"), Expr::u32(max_depth)),
                                vec![
                                    Node::store(stack, Expr::var("depth"), Expr::var("i")),
                                    Node::assign(
                                        "depth",
                                        Expr::add(Expr::var("depth"), Expr::u32(1)),
                                    ),
                                ],
                            )],
                            vec![Node::if_then(
                                Expr::eq(Expr::var("k"), Expr::u32(CLOSE_BRACE)),
                                vec![Node::if_then(
                                    Expr::lt(Expr::u32(0), Expr::var("depth")),
                                    vec![
                                        Node::assign(
                                            "depth",
                                            Expr::sub(Expr::var("depth"), Expr::u32(1)),
                                        ),
                                        Node::let_bind(
                                            "open_idx",
                                            Expr::load(stack, Expr::var("depth")),
                                        ),
                                        Node::store(
                                            match_pairs,
                                            Expr::var("open_idx"),
                                            Expr::var("i"),
                                        ),
                                        Node::store(
                                            match_pairs,
                                            Expr::var("i"),
                                            Expr::var("open_idx"),
                                        ),
                                    ],
                                )],
                            )],
                        ),
                    ],
                ),
            ],
        )]),
    }];

    Program::wrapped(
        vec![
            BufferDecl::storage(kinds, 0, BufferAccess::ReadOnly, DataType::U32).with_count(n),
            BufferDecl::read_write(stack, 1, DataType::U32).with_count(max_depth),
            BufferDecl::output(match_pairs, 2, DataType::U32).with_count(n),
        ],
        [1, 1, 1],
        body,
    )
}

/// CPU reference: bounded-stack pair-matching walk over `kinds`.
#[must_use]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn cpu_ref(kinds: &[u32], max_depth: u32) -> Vec<u32> {
    let mut match_pairs = Vec::new();
    let mut stack = Vec::new();
    cpu_ref_into(kinds, max_depth, &mut match_pairs, &mut stack);
    match_pairs
}

/// CPU reference writing into caller-owned output and stack scratch.
///
/// This is the allocation-free parity path for parser workloads that run
/// bracket matching across thousands of token shards. `match_pairs` is fully
/// overwritten on every call and `stack` is cleared before use.
#[cfg(any(test, feature = "cpu-parity"))]
pub fn cpu_ref_into(
    kinds: &[u32],
    max_depth: u32,
    match_pairs: &mut Vec<u32>,
    stack: &mut Vec<u32>,
) {
    match_pairs.clear();
    match_pairs.resize(kinds.len(), MATCH_NONE);
    stack.clear();
    let max_depth = max_depth as usize;
    for (index, kind) in kinds.iter().copied().enumerate() {
        if kind == OPEN_BRACE {
            if stack.len() < max_depth {
                stack.push(index as u32);
            }
            continue;
        }
        if kind == CLOSE_BRACE {
            if let Some(open_idx) = stack.pop() {
                match_pairs[open_idx as usize] = index as u32;
                match_pairs[index] = open_idx;
            }
        }
    }
}

/// Pack `[u32]` into the LE-byte layout the harness uses.
#[must_use]
pub fn pack_u32(words: &[u32]) -> Vec<u8> {
    crate::wire::pack_u32_slice(words)
}

#[cfg(feature = "inventory-registry")]
inventory::submit! {
    crate::harness::OpEntry::new(
        OP_ID,
        || bracket_match("kinds", "stack", "match_pairs", 4, 4),
        Some(|| vec![vec![
            pack_u32(&[OPEN_BRACE, OPEN_BRACE, CLOSE_BRACE, CLOSE_BRACE]),
            pack_u32(&[0, 0, 0, 0]),
            pack_u32(&[MATCH_NONE, MATCH_NONE, MATCH_NONE, MATCH_NONE]),
        ]]),
        Some(|| vec![vec![
            pack_u32(&[0, 1, 0, 0]),
            pack_u32(&[3, 2, 1, 0]),
        ]]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_ref_balanced_single_pair() {
        assert_eq!(
            cpu_ref(&[OPEN_BRACE, OTHER, CLOSE_BRACE], 3),
            vec![2, MATCH_NONE, 0]
        );
    }

    #[test]
    fn cpu_ref_nested_pairs() {
        assert_eq!(
            cpu_ref(&[OPEN_BRACE, OPEN_BRACE, CLOSE_BRACE, CLOSE_BRACE], 4),
            vec![3, 2, 1, 0]
        );
    }

    #[test]
    fn cpu_ref_unbalanced_extra_open() {
        assert_eq!(
            cpu_ref(&[OPEN_BRACE, OPEN_BRACE, CLOSE_BRACE], 3),
            vec![MATCH_NONE, 2, 1]
        );
    }

    #[test]
    fn cpu_ref_unbalanced_extra_close() {
        assert_eq!(
            cpu_ref(&[CLOSE_BRACE, OPEN_BRACE, CLOSE_BRACE], 3),
            vec![MATCH_NONE, 2, 1]
        );
    }

    #[test]
    fn cpu_ref_depth_cap_truncates_extra_opens() {
        assert_eq!(
            cpu_ref(
                &[
                    OPEN_BRACE,
                    OPEN_BRACE,
                    OPEN_BRACE,
                    CLOSE_BRACE,
                    CLOSE_BRACE,
                    CLOSE_BRACE
                ],
                2,
            ),
            vec![4, 3, MATCH_NONE, 1, 0, MATCH_NONE]
        );
    }

    #[test]
    fn cpu_ref_into_reuses_output_and_stack_storage() {
        let mut out = Vec::with_capacity(16);
        out.extend_from_slice(&[7, 8, 9, 10, 11]);
        let mut stack = Vec::with_capacity(8);
        stack.extend_from_slice(&[99, 100, 101]);
        let out_cap = out.capacity();
        let stack_cap = stack.capacity();

        cpu_ref_into(
            &[OPEN_BRACE, OTHER, CLOSE_BRACE, OPEN_BRACE],
            4,
            &mut out,
            &mut stack,
        );

        assert_eq!(out, vec![2, MATCH_NONE, 0, MATCH_NONE]);
        assert_eq!(out.capacity(), out_cap);
        assert_eq!(stack.capacity(), stack_cap);
        assert_eq!(
            stack,
            vec![3],
            "Fix: cpu_ref_into must clear stale stack entries before each run and leave only currently-unmatched opens."
        );

        cpu_ref_into(&[OTHER], 4, &mut out, &mut stack);
        assert_eq!(out, vec![MATCH_NONE]);
        assert!(stack.is_empty());
        assert_eq!(out.capacity(), out_cap);
        assert_eq!(stack.capacity(), stack_cap);
    }
}
