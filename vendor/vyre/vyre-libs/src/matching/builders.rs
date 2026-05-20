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
///
/// **Invariant**: the atomic slot reservation MUST be computed once,
/// then re-used as a bound variable across all three stores. The
/// previous implementation expressed the slot as a fresh
/// `Expr::atomic_add(...)` and cloned it four times (one `Expr::lt`
/// + three store indices); vyre lowers each clone to a separate
/// `atomicAdd` op, so the counter raced ahead by 4 per call and the
/// three stores landed in three *different* slots — producing
/// shredded triples like `(tag, 0, 0)`, `(0, start, 0)`,
/// `(0, 0, end)` instead of one well-formed `(tag, start, end)`
/// record. Caught by `gpu_ac_smoke::ushers_overlapping_patterns`
/// when `classic_ac_bounded_ranges_program` became the first
/// production consumer of this lego block.
///
/// The fix wraps the body in a `Node::Block` that let-binds
/// `_vyre_match_slot` once, then uses `Expr::var` everywhere the
/// slot value is read — same pattern `append_match_subgroup` uses
/// for `_vyre_match_ballot`/`_vyre_match_rank` for the same reason.
pub fn append_match(
    hits_buffer: &str,
    count_buffer: &str,
    tag: impl Into<Expr>,
    start: impl Into<Expr>,
    end: impl Into<Expr>,
) -> Node {
    let max_hits = Expr::div(Expr::buf_len(hits_buffer), Expr::u32(3));
    let slot = Expr::var("_vyre_match_slot");

    Node::Block(vec![
        Node::let_bind(
            "_vyre_match_slot",
            Expr::atomic_add(count_buffer, Expr::u32(0), Expr::u32(1)),
        ),
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
        ),
    ])
}

// `append_match_workgroup` would coalesce one global atomic_add per
// WORKGROUP using a workgroup-shared atomic counter, removing the 4
// global atomics per workgroup that `append_match_subgroup` issues at
// workgroup_size=128. It is NOT shipped here because vyre's memory
// model validator V025 (`validate/atomic_rules.rs:79`) explicitly
// rejects atomic operations on `BufferAccess::Workgroup` buffers
// ("Workgroup atomics require additional OOB and ordering
// specification before they can be validated"). The primitive needs
// either a memory-model extension that admits workgroup atomics, OR a
// storage-backed per-workgroup scratch buffer indexed by
// `workgroup_id` (~num_workgroups × 2 u32 of allocated scratch). Both
// are valid follow-ups; neither is a single-file lego block.

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
