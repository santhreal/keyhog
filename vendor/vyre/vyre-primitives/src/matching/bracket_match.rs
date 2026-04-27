//! Tier 2.5 bracket-pair detector — bounded-stack scanner over a
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

/// Stable op id for the registered Tier 3 wrapper.
pub const OP_ID: &str = "vyre-libs::parsing::bracket_match";

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
/// `match_pairs` must be initialized to [`MATCH_NONE`] before dispatch.
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
pub fn cpu_ref(kinds: &[u32], max_depth: u32) -> Vec<u32> {
    let mut match_pairs = vec![MATCH_NONE; kinds.len()];
    let mut stack = Vec::with_capacity(max_depth as usize);

    for (index, kind) in kinds.iter().copied().enumerate() {
        if kind == OPEN_BRACE {
            if stack.len() < max_depth as usize {
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

    match_pairs
}

/// Pack `[u32]` into the LE-byte layout the harness uses.
#[must_use]
pub fn pack_u32(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
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
}
