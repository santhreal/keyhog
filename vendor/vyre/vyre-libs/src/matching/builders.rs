//! IR LEGO BLOCKS for matching dialects.
//!
//! Exposes granular primitives that can be composed into custom
//! scanning engines (e.g. combined DFA + ML, decoder-aware scanners).

use vyre::ir::{Expr, Node};

/// LEGO BLOCK: Load a byte from a packed U32 haystack.
pub fn load_packed_byte(haystack: &str, idx: Expr) -> (Node, Expr) {
    let word_idx = Expr::div(idx.clone(), Expr::u32(4));
    let byte_offset = Expr::mul(Expr::rem(idx, Expr::u32(4)), Expr::u32(8));

    let node = Node::let_bind("_byte_word", Expr::load(haystack, word_idx));
    let byte_expr = Expr::bitand(
        Expr::shr(Expr::var("_byte_word"), byte_offset),
        Expr::u32(0xFF),
    );

    (node, byte_expr)
}

/// LEGO BLOCK: Append a match to a standardized hit buffer.
///
/// Use \`append_match_subgroup\` for production paths that benefit from
/// subgroup-coalesced atomics (Innovation I.17).
pub fn append_match(
    hits_buffer: &str,
    count_buffer: &str,
    tag: impl Into<Expr>,
    start: impl Into<Expr>,
    end: impl Into<Expr>,
) -> Node {
    let slot = Expr::atomic_add(count_buffer, Expr::u32(0), Expr::u32(1));
    let max_hits = Expr::div(Expr::buf_len(hits_buffer), Expr::u32(3));

    Node::if_then(
        Expr::lt(slot.clone(), max_hits),
        vec![
            Node::store(
                hits_buffer,
                Expr::mul(slot.clone(), Expr::u32(3)),
                tag.into(),
            ),
            Node::store(
                hits_buffer,
                Expr::add(Expr::mul(slot.clone(), Expr::u32(3)), Expr::u32(1)),
                start.into(),
            ),
            Node::store(
                hits_buffer,
                Expr::add(Expr::mul(slot, Expr::u32(3)), Expr::u32(2)),
                end.into(),
            ),
        ],
    )
}

/// Innovation I.17: Subgroup-Coalesced Match Append.
///
/// Uses subgroup-ballot and subgroup-shuffle to perform a single
/// \`atomic_add\` per subgroup, drastically reducing global memory
/// serialization on high-hit-rate workloads.
pub fn append_match_subgroup(
    hits_buffer: &str,
    count_buffer: &str,
    tag: impl Into<Expr>,
    start: impl Into<Expr>,
    end: impl Into<Expr>,
    cond: Expr,
) -> Vec<Node> {
    let tag = tag.into();
    let start = start.into();
    let end = end.into();
    let max_hits = Expr::div(Expr::buf_len(hits_buffer), Expr::u32(3));
    let lane_mask = Expr::sub(
        Expr::shl(Expr::u32(1), Expr::subgroup_local_id()),
        Expr::u32(1),
    );
    let rank = Expr::popcount(Expr::bitand(Expr::var("_vyre_match_ballot"), lane_mask));
    let leader_pred = Expr::and(
        cond.clone(),
        Expr::eq(Expr::var("_vyre_match_rank"), Expr::u32(0)),
    );
    let slot = Expr::add(
        Expr::subgroup_shuffle(
            Expr::var("_vyre_match_leader_base"),
            Expr::var("_vyre_match_leader"),
        ),
        Expr::var("_vyre_match_rank"),
    );
    let ballot_cond = cond.clone();
    let bounded_hit = Expr::and(cond, Expr::lt(slot.clone(), max_hits));

    vec![
        Node::let_bind("_vyre_match_ballot", Expr::subgroup_ballot(ballot_cond)),
        Node::let_bind("_vyre_match_rank", rank),
        Node::let_bind(
            "_vyre_match_count",
            Expr::popcount(Expr::var("_vyre_match_ballot")),
        ),
        Node::let_bind(
            "_vyre_match_leader",
            Expr::select(
                Expr::eq(Expr::var("_vyre_match_count"), Expr::u32(0)),
                Expr::u32(0),
                Expr::ctz(Expr::var("_vyre_match_ballot")), // Fixed: relative to subgroup,
            ),
        ),
        Node::let_bind("_vyre_match_leader_base", Expr::u32(0)),
        Node::if_then(
            leader_pred,
            vec![Node::assign(
                "_vyre_match_leader_base",
                Expr::atomic_add(count_buffer, Expr::u32(0), Expr::var("_vyre_match_count")),
            )],
        ),
        Node::let_bind("_vyre_match_slot", slot),
        Node::if_then(
            bounded_hit,
            vec![
                Node::store(
                    hits_buffer,
                    Expr::mul(Expr::var("_vyre_match_slot"), Expr::u32(3)),
                    tag,
                ),
                Node::store(
                    hits_buffer,
                    Expr::add(
                        Expr::mul(Expr::var("_vyre_match_slot"), Expr::u32(3)),
                        Expr::u32(1),
                    ),
                    start,
                ),
                Node::store(
                    hits_buffer,
                    Expr::add(
                        Expr::mul(Expr::var("_vyre_match_slot"), Expr::u32(3)),
                        Expr::u32(2),
                    ),
                    end,
                ),
            ],
        ),
    ]
}
