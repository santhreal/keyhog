//! Packed-frontier bitset utilities and fused frontier absorption.

use core::fmt;
use std::sync::Arc;

use crate::bitset::bitset_words;
use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program, UnOp};

/// Canonical op id for fused frontier absorption.
pub const ABSORB_NEW_BITS_OP_ID: &str = "vyre-primitives::bitset::frontier_absorb_new_bits";

/// Error returned by packed-frontier helpers.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FrontierError {
    /// A frontier slice length does not match `bitset_words(node_count)`.
    BadShape {
        /// Human-readable slice role.
        name: &'static str,
        /// Declared graph/node domain width.
        node_count: u32,
        /// Expected number of u32 words.
        expected_words: usize,
        /// Actual number of u32 words.
        actual_words: usize,
    },
    /// A popcount exceeded the compact u32 count representation.
    PopcountOverflow {
        /// Number of frontier words counted before overflow.
        frontier_words: usize,
    },
    /// Caller-owned output frontier could not reserve enough storage.
    Allocation {
        /// Human-readable output buffer role.
        name: &'static str,
        /// Requested u32 words.
        requested_words: usize,
        /// Allocator detail.
        source: String,
    },
}

impl fmt::Display for FrontierError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadShape {
                name,
                node_count,
                expected_words,
                actual_words,
            } => write!(
                f,
                "{name} frontier for {node_count} nodes requires {expected_words} u32 words, got {actual_words}."
            ),
            Self::PopcountOverflow { frontier_words } => write!(
                f,
                "frontier popcount exceeds u32::MAX for {frontier_words} frontier words."
            ),
            Self::Allocation {
                name,
                requested_words,
                source,
            } => write!(
                f,
                "{name} frontier could not reserve {requested_words} u32 words: {source}."
            ),
        }
    }
}

impl std::error::Error for FrontierError {}

/// Summary from absorbing a neighbor frontier into a visited frontier.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FrontierAbsorbSummary {
    /// True when at least one previously-unvisited node was added.
    pub added_any: bool,
    /// Number of newly-added in-domain nodes.
    pub added_popcount: u32,
}

/// Number of u32 words expected for a frontier over `node_count` nodes.
#[must_use]
pub const fn frontier_words(node_count: u32) -> usize {
    bitset_words(node_count) as usize
}

/// Mask for valid bits in the final frontier word.
#[must_use]
pub const fn frontier_tail_mask(node_count: u32) -> u32 {
    let tail_bits = node_count % u32::BITS;
    if tail_bits == 0 {
        u32::MAX
    } else {
        (1u32 << tail_bits) - 1
    }
}

/// Build a fused GPU program for one frontier-closure absorption step.
#[must_use]
pub fn frontier_absorb_new_bits_program(
    visited: &str,
    neighbors: &str,
    next_wave: &str,
    added_counts: &str,
    words: u32,
    final_word_mask: u32,
) -> Program {
    let t = Expr::InvocationId { axis: 0 };
    let final_word = words.saturating_sub(1);
    let body = vec![
        Node::let_bind(
            "frontier_absorb_old_visited",
            Expr::load(visited, t.clone()),
        ),
        Node::let_bind(
            "frontier_absorb_neighbors",
            Expr::load(neighbors, t.clone()),
        ),
        Node::let_bind(
            "frontier_absorb_domain_mask",
            Expr::select(
                Expr::eq(t.clone(), Expr::u32(final_word)),
                Expr::u32(final_word_mask),
                Expr::u32(u32::MAX),
            ),
        ),
        Node::let_bind(
            "frontier_absorb_in_domain_neighbors",
            Expr::bitand(
                Expr::var("frontier_absorb_neighbors"),
                Expr::var("frontier_absorb_domain_mask"),
            ),
        ),
        Node::let_bind(
            "frontier_absorb_new_bits",
            Expr::bitand(
                Expr::var("frontier_absorb_in_domain_neighbors"),
                Expr::bitnot(Expr::var("frontier_absorb_old_visited")),
            ),
        ),
        Node::store(next_wave, t.clone(), Expr::var("frontier_absorb_new_bits")),
        Node::store(
            visited,
            t.clone(),
            Expr::bitor(
                Expr::var("frontier_absorb_old_visited"),
                Expr::var("frontier_absorb_new_bits"),
            ),
        ),
        Node::store(
            added_counts,
            t.clone(),
            Expr::UnOp {
                op: UnOp::Popcount,
                operand: Box::new(Expr::var("frontier_absorb_new_bits")),
            },
        ),
    ];

    Program::wrapped(
        vec![
            BufferDecl::storage(visited, 0, BufferAccess::ReadWrite, DataType::U32)
                .with_count(words),
            BufferDecl::storage(neighbors, 1, BufferAccess::ReadOnly, DataType::U32)
                .with_count(words),
            BufferDecl::storage(next_wave, 2, BufferAccess::ReadWrite, DataType::U32)
                .with_count(words),
            BufferDecl::storage(added_counts, 3, BufferAccess::ReadWrite, DataType::U32)
                .with_count(words),
        ],
        [256, 1, 1],
        vec![Node::Region {
            generator: Ident::from(ABSORB_NEW_BITS_OP_ID),
            source_region: None,
            body: Arc::new(vec![Node::if_then(Expr::lt(t, Expr::u32(words)), body)]),
        }],
    )
}

/// Build a fused frontier-absorption GPU program from the logical node count.
#[must_use]
pub fn frontier_absorb_new_bits_for_node_count_program(
    visited: &str,
    neighbors: &str,
    next_wave: &str,
    added_counts: &str,
    node_count: u32,
) -> Program {
    frontier_absorb_new_bits_program(
        visited,
        neighbors,
        next_wave,
        added_counts,
        bitset_words(node_count),
        frontier_tail_mask(node_count),
    )
}

/// Validate that `frontier` has the canonical packed shape for `node_count`.
pub fn validate_frontier_shape(
    node_count: u32,
    frontier: &[u32],
    name: &'static str,
) -> Result<usize, FrontierError> {
    let expected_words = frontier_words(node_count);
    if frontier.len() != expected_words {
        return Err(FrontierError::BadShape {
            name,
            node_count,
            expected_words,
            actual_words: frontier.len(),
        });
    }
    Ok(expected_words)
}

/// Count set bits in a packed u32 frontier with checked overflow reporting.
pub fn checked_frontier_popcount(frontier: &[u32]) -> Result<u32, FrontierError> {
    let mut popcount = 0u32;
    for &word in frontier {
        popcount =
            popcount
                .checked_add(word.count_ones())
                .ok_or(FrontierError::PopcountOverflow {
                    frontier_words: frontier.len(),
                })?;
    }
    Ok(popcount)
}

/// Clear out-of-domain bits in the final frontier word.
pub fn mask_frontier_tail_bits(node_count: u32, frontier: &mut [u32]) {
    if let Some(last_word) = frontier.last_mut() {
        *last_word &= frontier_tail_mask(node_count);
    }
}

/// Merge a neighbor frontier into a visited set and materialize only new bits.
pub fn absorb_new_frontier_bits(
    node_count: u32,
    visited: &mut [u32],
    neighbors: &[u32],
    next_wave: &mut Vec<u32>,
) -> Result<FrontierAbsorbSummary, FrontierError> {
    let expected_words = validate_frontier_shape(node_count, visited, "visited")?;
    validate_frontier_shape(node_count, neighbors, "neighbors")?;
    if expected_words > next_wave.capacity() {
        next_wave
            .try_reserve_exact(expected_words - next_wave.capacity())
            .map_err(|source| FrontierError::Allocation {
                name: "next_wave",
                requested_words: expected_words,
                source: source.to_string(),
            })?;
    }
    next_wave.clear();
    next_wave.resize(expected_words, 0);
    let mut summary = FrontierAbsorbSummary::default();
    let last_word_index = expected_words.saturating_sub(1);
    let tail_mask = frontier_tail_mask(node_count);
    for (word_index, (visited_word, neighbor_word)) in visited
        .iter_mut()
        .zip(neighbors.iter().copied())
        .enumerate()
    {
        let in_domain_neighbors = if word_index == last_word_index {
            neighbor_word & tail_mask
        } else {
            neighbor_word
        };
        let new_bits = in_domain_neighbors & !*visited_word;
        next_wave[word_index] = new_bits;
        *visited_word |= new_bits;
        summary.added_any |= new_bits != 0;
        summary.added_popcount = summary
            .added_popcount
            .checked_add(new_bits.count_ones())
            .ok_or(FrontierError::PopcountOverflow {
                frontier_words: expected_words,
            })?;
    }
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absorb_masks_tail_and_reports_added_popcount() {
        let mut visited = vec![0b0001, 0b0001];
        let neighbors = vec![0b0111, 0b1000_0111];
        let mut next_wave = Vec::new();
        let summary = absorb_new_frontier_bits(35, &mut visited, &neighbors, &mut next_wave)
            .expect("Fix: valid frontier");
        assert_eq!(summary.added_popcount, 4);
        assert_eq!(next_wave, vec![0b0110, 0b0110]);
        assert_eq!(visited, vec![0b0111, 0b0111]);
    }

    #[test]
    fn absorb_reuses_next_wave_and_clears_stale_tail() {
        let mut visited = vec![0b0001, 0b0001];
        let neighbors = vec![0b0111, 0b1000_0111];
        let mut next_wave = Vec::with_capacity(8);
        next_wave.extend_from_slice(&[u32::MAX; 8]);
        let ptr = next_wave.as_ptr();

        let summary = absorb_new_frontier_bits(35, &mut visited, &neighbors, &mut next_wave)
            .expect("Fix: valid frontier");

        assert_eq!(summary.added_popcount, 4);
        assert_eq!(next_wave, vec![0b0110, 0b0110]);
        assert_eq!(next_wave.as_ptr(), ptr);
    }

    #[test]
    fn absorb_rejects_bad_shape_without_mutating_buffers() {
        let mut visited = vec![0b0001, 0b0010];
        let before_visited = visited.clone();
        let neighbors = vec![0b0111];
        let mut next_wave = vec![0xDEAD_BEEF];

        let err = absorb_new_frontier_bits(35, &mut visited, &neighbors, &mut next_wave)
            .expect_err("bad neighbor shape must fail before mutation");

        assert!(matches!(
            err,
            FrontierError::BadShape {
                name: "neighbors",
                ..
            }
        ));
        assert_eq!(visited, before_visited);
        assert_eq!(next_wave, vec![0xDEAD_BEEF]);
    }

    #[test]
    fn generated_absorb_matches_scalar_reference() {
        let patterns = [0, u32::MAX, 0x5555_5555, 0xAAAA_AAAA, 0x1357_9BDF];
        for node_count in 0..=512 {
            let words = frontier_words(node_count);
            for (case_index, pattern) in patterns.into_iter().enumerate() {
                let mut visited = (0..words)
                    .map(|word| pattern.rotate_left((word as u32 + case_index as u32) % 32))
                    .collect::<Vec<_>>();
                let neighbors = (0..words)
                    .map(|word| (!pattern).rotate_right((word as u32 * 7) % 32))
                    .collect::<Vec<_>>();
                mask_frontier_tail_bits(node_count, &mut visited);
                let before = visited.clone();
                let mut next_wave = Vec::new();
                let summary =
                    absorb_new_frontier_bits(node_count, &mut visited, &neighbors, &mut next_wave)
                        .expect("Fix: generated shapes are valid");
                let tail_index = words.saturating_sub(1);
                let tail_mask = frontier_tail_mask(node_count);
                let expected_next = before
                    .iter()
                    .zip(neighbors.iter())
                    .enumerate()
                    .map(|(idx, (&old, &neighbor))| {
                        let in_domain = if idx == tail_index {
                            neighbor & tail_mask
                        } else {
                            neighbor
                        };
                        in_domain & !old
                    })
                    .collect::<Vec<_>>();
                assert_eq!(next_wave, expected_next, "node_count={node_count}");
                assert_eq!(
                    summary.added_popcount,
                    expected_next
                        .iter()
                        .map(|word| word.count_ones())
                        .sum::<u32>()
                );
            }
        }
    }
}
