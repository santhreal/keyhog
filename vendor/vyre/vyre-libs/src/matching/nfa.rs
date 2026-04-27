//! Subgroup-cooperative NFA scan (G1 consumer).
//!
//! Composes [`vyre_primitives::nfa::subgroup_nfa::nfa_step`] semantics
//! into a full scan loop that walks an input byte stream, advances
//! NFA state across bytes, and emits `(pattern_id, start, end)` hits
//! into `hit_buf` whenever an accept state fires.
//!
//! # Encoding (matches `subgroup_nfa`)
//!
//! - `state_word` (per-lane u32): bits of the active-state set this
//!   lane owns. Lane `k` holds states `k*32 .. k*32+32`.
//! - `nfa_transition` (ReadOnly, u32): lane-major
//!   `[num_states × 256 × LANES_PER_SUBGROUP]`. Entry
//!   `trans[src * 256 * LANES + byte * LANES + lane]` is the u32 of
//!   destination bits that lane `lane` is responsible for, reached
//!   from state `src` on byte `byte`. Lane-major layout is required
//!   by [`subgroup_nfa::nfa_step`]; the composition must not diverge
//!   from the primitive's contract (VYRE_MEM_LAYOUT CRITICAL-2).
//! - `nfa_epsilon` (ReadOnly, u32): lane-major
//!   `[num_states × LANES_PER_SUBGROUP]`. All zero for literal-only
//!   pattern sets.
//!
//! # Current literal-only scope
//!
//! This module supports byte-literal pattern NFAs. Regex syntax belongs
//! in a grammar-to-NFA compiler layer that produces the same transition
//! and epsilon tables before calling this scan kernel.

use std::sync::Arc;

use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Ident, Node, Program};

use vyre_primitives::nfa::subgroup_nfa::{LANES_PER_SUBGROUP, MAX_STATES_PER_SUBGROUP};

/// Canonical op id for the end-to-end scan kernel.
pub const OP_ID: &str = "vyre-libs::matching::nfa_scan";

/// Compile a set of patterns into a scan Program.
///
/// See module docs for buffer encoding. Hit buffer layout is
/// `[counter, p0, s0, e0, p1, s1, e1, …]` — slot 0 is an atomic
/// counter, each match does `atomic_add(counter, 1)` and writes its
/// `(pattern_id, start, end)` triple at `1 + 3*slot`.
///
/// # Panics
///
/// Panics when the total NFA state count exceeds
/// [`MAX_STATES_PER_SUBGROUP`]. Callers with larger pattern sets
/// should shard via [`plan_shards`].
#[must_use]
pub fn nfa_scan(patterns: &[&str], input_buf: &str, hit_buf: &str, input_len: u32) -> Program {
    let plan = compile(patterns).for_input_len(input_len);
    assert!(
        plan.num_states <= MAX_STATES_PER_SUBGROUP as u32,
        "Fix: NFA state count {} exceeds MAX_STATES_PER_SUBGROUP {}. \
         Use `plan_shards` to split the pattern set across dispatches.",
        plan.num_states,
        MAX_STATES_PER_SUBGROUP,
    );
    // input_len == 0 is legal: the byte loop runs 0 times and the
    // hit buffer stays empty. This is the natural answer for an
    // empty haystack; consumers should not special-case it at the
    // call site.

    let lane = Expr::LocalId { axis: 0 };
    let start = Expr::WorkgroupId { axis: 0 };
    let lane_u32 = || lane.clone();
    let start_u32 = || start.clone();
    let num_states = plan.num_states;
    let accepts = plan.accept_states.clone();
    let accept_state_ids = plan.accept_state_ids.clone();
    // PHASE3_SCAN: skip the epsilon closure when no pattern has
    // epsilon transitions (literal-only pattern set). Saves one full
    // transition-table-sized pass per input byte.
    let has_epsilon = build_epsilon_table(patterns).iter().any(|w| *w != 0);

    // Per-cursor body. Runs inside the byte loop.
    let mut cursor_body: Vec<Node> = Vec::new();
    fn packed_byte(input_buf: &str, index: Expr) -> Expr {
        Expr::bitand(
            Expr::shr(
                Expr::load(input_buf, Expr::div(index.clone(), Expr::u32(4))),
                Expr::mul(Expr::rem(index, Expr::u32(4)), Expr::u32(8)),
            ),
            Expr::u32(0xFF),
        )
    }

    cursor_body.push(Node::let_bind(
        "byte",
        packed_byte(input_buf, Expr::var("cursor")),
    ));
    cursor_body.push(Node::let_bind("next_state", Expr::u32(0)));

    // Transition. Lane-major gather matching `subgroup_nfa::nfa_step`:
    //   for peer lane k in 0..LANES:
    //     peer = subgroup_shuffle(state_word, k)
    //     for bit i in 0..32:
    //       src = k*32 + i
    //       if src < num_states && ((peer >> i) & 1) != 0:
    //         next_state |= trans[src*256*LANES + byte*LANES + lane]
    //
    // WGSL subgroup_shuffle requires compile-time peer so we unroll
    // k. We also unroll i (identical pattern to the primitive) so
    // each byte step is a straight-line block the optimiser can fold.
    for k in 0..LANES_PER_SUBGROUP as u32 {
        let peer_name = format!("peer_{k}");
        cursor_body.push(Node::let_bind(
            &peer_name,
            Expr::subgroup_shuffle(Expr::var("state_word"), Expr::u32(k)),
        ));
        for i in 0..32_u32 {
            let src_state = k * 32 + i;
            if src_state >= num_states {
                continue;
            }
            let src_row = src_state * 256 * LANES_PER_SUBGROUP as u32;
            cursor_body.push(Node::if_then(
                Expr::ne(
                    Expr::bitand(Expr::shr(Expr::var(&peer_name), Expr::u32(i)), Expr::u32(1)),
                    Expr::u32(0),
                ),
                vec![Node::assign(
                    "next_state",
                    Expr::bitor(
                        Expr::var("next_state"),
                        Expr::load(
                            "nfa_transition",
                            Expr::add(
                                Expr::add(
                                    Expr::u32(src_row),
                                    Expr::mul(
                                        Expr::var("byte"),
                                        Expr::u32(LANES_PER_SUBGROUP as u32),
                                    ),
                                ),
                                lane_u32(),
                            ),
                        ),
                    ),
                )],
            ));
        }
    }

    // Epsilon closure — only when the pattern set has ε edges.
    // OR is idempotent so a fixed `num_states` iteration count
    // reaches fixpoint.
    if has_epsilon {
        let eps_iters = num_states.min(32).max(1);
        let mut eps_body: Vec<Node> = Vec::new();
        for k in 0..LANES_PER_SUBGROUP as u32 {
            let eps_peer_name = format!("eps_peer_{k}");
            eps_body.push(Node::let_bind(
                &eps_peer_name,
                Expr::subgroup_shuffle(Expr::var("next_state"), Expr::u32(k)),
            ));
            for i in 0..32_u32 {
                let src_state = k * 32 + i;
                if src_state >= num_states {
                    continue;
                }
                eps_body.push(Node::if_then(
                    Expr::ne(
                        Expr::bitand(
                            Expr::shr(Expr::var(&eps_peer_name), Expr::u32(i)),
                            Expr::u32(1),
                        ),
                        Expr::u32(0),
                    ),
                    vec![Node::assign(
                        "next_state",
                        Expr::bitor(
                            Expr::var("next_state"),
                            Expr::load(
                                "nfa_epsilon",
                                Expr::add(
                                    Expr::mul(
                                        Expr::u32(src_state),
                                        Expr::u32(LANES_PER_SUBGROUP as u32),
                                    ),
                                    lane_u32(),
                                ),
                            ),
                        ),
                    )],
                ));
            }
        }
        cursor_body.push(Node::loop_for(
            "eps_iter",
            Expr::u32(0),
            Expr::u32(eps_iters),
            eps_body,
        ));
    }

    cursor_body.push(Node::assign("state_word", Expr::var("next_state")));

    // Per-cursor accept emission. Fixes the post-loop-only bug the
    // PHASE3_SCAN audit flagged — intermediate matches were lost.
    // Slot 0 of hit_buf is the atomic counter; each match claims
    // the next `(pattern_id, start, end)` triple via atomic_add(1).
    let max_hits = 10_000u32;
    for (&accept_state, &(pattern_id, _pattern_len)) in accept_state_ids.iter().zip(&accepts) {
        let word_idx = accept_state / 32;
        let bit_offset = accept_state % 32;
        cursor_body.push(Node::if_then(
            Expr::eq(lane_u32(), Expr::u32(word_idx)),
            vec![Node::if_then(
                Expr::ne(
                    Expr::bitand(
                        Expr::var("state_word"),
                        Expr::shl(Expr::u32(1), Expr::u32(bit_offset)),
                    ),
                    Expr::u32(0),
                ),
                vec![
                    Node::let_bind(
                        "slot_idx",
                        Expr::atomic_add(hit_buf, Expr::u32(0), Expr::u32(1)),
                    ),
                    Node::if_then(
                        Expr::lt(Expr::var("slot_idx"), Expr::u32(max_hits)),
                        vec![
                            Node::let_bind(
                                "triple_base",
                                Expr::add(
                                    Expr::u32(1),
                                    Expr::mul(Expr::var("slot_idx"), Expr::u32(3)),
                                ),
                            ),
                            Node::store(hit_buf, Expr::var("triple_base"), Expr::u32(pattern_id)),
                            Node::store(
                                hit_buf,
                                Expr::add(Expr::var("triple_base"), Expr::u32(1)),
                                start_u32(),
                            ),
                            Node::store(
                                hit_buf,
                                Expr::add(Expr::var("triple_base"), Expr::u32(2)),
                                Expr::add(Expr::var("cursor"), Expr::u32(1)),
                            ),
                        ],
                    ),
                ],
            )],
        ));
    }

    // Top-level body: seed state 0 in lane 0, then loop over input.
    let mut body: Vec<Node> = Vec::new();
    body.push(Node::let_bind(
        "state_word",
        Expr::select(
            Expr::eq(lane_u32(), Expr::u32(0)),
            Expr::u32(1),
            Expr::u32(0),
        ),
    ));
    body.push(Node::loop_for(
        "cursor",
        start_u32(),
        Expr::u32(plan.input_len),
        cursor_body,
    ));

    let num_hit_slots = 1 + 10_000 * 3;
    let input_words = plan.input_len.div_ceil(4).max(1);
    let buffers = vec![
        BufferDecl::storage(input_buf, 0, BufferAccess::ReadOnly, DataType::U32)
            .with_count(input_words),
        BufferDecl::storage("nfa_transition", 1, BufferAccess::ReadOnly, DataType::U32)
            .with_count(num_states * 256 * LANES_PER_SUBGROUP as u32),
        BufferDecl::storage("nfa_epsilon", 2, BufferAccess::ReadOnly, DataType::U32)
            .with_count(num_states * LANES_PER_SUBGROUP as u32),
        BufferDecl::storage(hit_buf, 3, BufferAccess::ReadWrite, DataType::U32)
            .with_count(num_hit_slots),
    ];

    Program::wrapped(
        buffers,
        [LANES_PER_SUBGROUP as u32, 1, 1],
        vec![Node::Region {
            generator: Ident::from(OP_ID),
            source_region: None,
            body: Arc::new(vec![Node::if_then(
                Expr::and(
                    Expr::lt(lane_u32(), Expr::u32(LANES_PER_SUBGROUP as u32)),
                    Expr::lt(start_u32(), Expr::u32(plan.input_len)),
                ),
                body,
            )]),
        }],
    )
}

/// Compiled plan for a pattern set.
#[derive(Debug, Clone)]
pub struct NfaPlan {
    /// Total NFA state count (across every pattern + the shared entry).
    pub num_states: u32,
    /// Input buffer length the plan was compiled against.
    pub input_len: u32,
    /// One `(pattern_id, pattern_len)` per accept state.
    pub accept_states: Vec<(u32, u32)>,
    /// NFA state id for each entry in [`accept_states`](Self::accept_states).
    pub accept_state_ids: Vec<u32>,
}

impl NfaPlan {
    /// Attach the expected input length.
    #[must_use]
    pub fn for_input_len(mut self, input_len: u32) -> Self {
        self.input_len = input_len;
        self
    }
}

/// Compile patterns into an [`NfaPlan`]. Literal-only: each pattern
/// contributes `len(p)` states; all patterns share state 0 (entry),
/// so total state count is `1 + sum(len(p))`.
#[must_use]
pub fn compile(patterns: &[&str]) -> NfaPlan {
    let mut accept_states = Vec::with_capacity(patterns.len());
    let mut accept_state_ids = Vec::with_capacity(patterns.len());
    let mut next_state: u32 = 1;
    for (pid, p) in patterns.iter().enumerate() {
        let len = p.len() as u32;
        accept_states.push((pid as u32, len));
        accept_state_ids.push(if len == 0 { 0 } else { next_state + len - 1 });
        next_state += len;
    }
    NfaPlan {
        num_states: next_state,
        input_len: 0,
        accept_states,
        accept_state_ids,
    }
}

/// Build the `nfa_transition` lane-major bit-table matching the
/// [`subgroup_nfa::nfa_step`] contract:
/// `[num_states × 256 × LANES_PER_SUBGROUP]` u32s. Entry
/// `trans[src * 256 * LANES + byte * LANES + dst_lane]` is the
/// destination bitset held by `dst_lane` when state `src` sees `byte`.
///
/// [`subgroup_nfa::nfa_step`]: vyre_primitives::nfa::subgroup_nfa::nfa_step
#[must_use]
pub fn build_transition_table(patterns: &[&str]) -> Vec<u32> {
    let plan = compile(patterns);
    let num_states = plan.num_states as usize;
    let mut table = vec![0_u32; num_states * 256 * LANES_PER_SUBGROUP];
    let mut state_cursor: usize = 1;
    for p in patterns {
        let mut src = 0_usize;
        for b in p.bytes() {
            let dst = state_cursor;
            let dst_lane = dst / 32;
            let dst_bit = 1_u32 << (dst % 32);
            let idx = src * 256 * LANES_PER_SUBGROUP + (b as usize) * LANES_PER_SUBGROUP + dst_lane;
            table[idx] |= dst_bit;
            src = dst;
            state_cursor += 1;
        }
    }
    table
}

/// Lane-major transition table where each lane's slice is contiguous.
///
/// Layout: `lane * padded_num_states * 256 + byte * padded_num_states + src_state`
/// where `padded_num_states = LANES_PER_SUBGROUP * ceil(num_states / LANES_PER_SUBGROUP)`.
///
/// # Cache-line + coalescing rationale
///
/// The flat layout (`src * 256 * LANES + byte * LANES + lane`) keeps all
/// lanes' data for one `(src, byte)` tuple adjacent. This coalesces
/// perfectly when every lane reads the same `src`/`byte` simultaneously,
/// but when a lane needs to scan across *all* source states for a single
/// byte (e.g. a vectorized bit-test that replaces the 1024 per-bit
/// branches), each load strides by `LANES` u32s, defeating SIMD gather.
///
/// This layout transposes the dimensions so that for a fixed `lane` and
/// `byte`, the `num_states` entries are contiguous. A single 128-bit SIMD
/// load fetches four states; on AVX-512 / subgroup-shuffle paths a full
/// cache line (16 states) arrives in one cycle. The padded row length
/// aligns each byte's row to a multiple of the subgroup width, ensuring
/// that cross-lane addresses in a workgroup dispatch fall on different
/// cache banks and avoid bank conflicts.
#[must_use]
pub fn build_transition_table_lane_major(patterns: &[&str]) -> Vec<u32> {
    let plan = compile(patterns);
    let num_states = plan.num_states as usize;
    let padded_states = LANES_PER_SUBGROUP * num_states.div_ceil(LANES_PER_SUBGROUP);
    let mut table = vec![0_u32; padded_states * 256 * LANES_PER_SUBGROUP];
    let mut state_cursor: usize = 1;
    for p in patterns {
        let mut src = 0_usize;
        for b in p.bytes() {
            let dst = state_cursor;
            let dst_lane = dst / 32;
            let dst_bit = 1_u32 << (dst % 32);
            let idx = dst_lane * padded_states * 256 + (b as usize) * padded_states + src;
            table[idx] |= dst_bit;
            src = dst;
            state_cursor += 1;
        }
    }
    table
}

/// Build the `nfa_epsilon` lane-major table
/// `[num_states × LANES_PER_SUBGROUP]`. Literal-only → all zero.
#[must_use]
pub fn build_epsilon_table(patterns: &[&str]) -> Vec<u32> {
    let n = compile(patterns).num_states as usize;
    vec![0_u32; n * LANES_PER_SUBGROUP]
}

/// Shard a pattern set across multiple NFA plans so each shard fits
/// in [`MAX_STATES_PER_SUBGROUP`]. Greedy first-fit.
#[must_use]
pub fn plan_shards<'a>(patterns: &'a [&'a str]) -> Vec<Vec<&'a str>> {
    let mut shards: Vec<Vec<&str>> = Vec::new();
    let mut current: Vec<&str> = Vec::new();
    let mut current_states: usize = 1;
    for p in patterns {
        let extra = p.len();
        assert!(
            1 + extra <= MAX_STATES_PER_SUBGROUP,
            "pattern {p:?} ({} chars) alone exceeds MAX_STATES_PER_SUBGROUP ({})",
            p.len(),
            MAX_STATES_PER_SUBGROUP,
        );
        if current_states + extra > MAX_STATES_PER_SUBGROUP {
            shards.push(std::mem::take(&mut current));
            current_states = 1;
        }
        current.push(*p);
        current_states += extra;
    }
    if !current.is_empty() {
        shards.push(current);
    }
    shards
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compile_literal_pattern_counts_states() {
        let plan = compile(&["abc"]);
        assert_eq!(plan.num_states, 4);
        assert_eq!(plan.accept_states.len(), 1);
    }

    #[test]
    fn compile_two_patterns_share_entry_state() {
        let plan = compile(&["ab", "cd"]);
        assert_eq!(plan.num_states, 5);
        assert_eq!(plan.accept_states.len(), 2);
    }

    #[test]
    fn transition_table_has_lane_major_size() {
        let t = build_transition_table(&["abc", "de"]);
        let plan = compile(&["abc", "de"]);
        assert_eq!(
            t.len(),
            (plan.num_states as usize) * 256 * LANES_PER_SUBGROUP,
            "transition table must be lane-major [num_states × 256 × LANES_PER_SUBGROUP] \
             to match subgroup_nfa::nfa_step contract (VYRE_MEM_LAYOUT CRITICAL-2)",
        );
    }

    #[test]
    fn transition_table_encodes_first_character_in_dst_lane() {
        // "abc": states are entry=0, 1('a'-consumed), 2('b'-consumed), 3('c'-consumed).
        // 0 ->'a'-> 1 means dst=1 is held in lane 0 bit 1.
        let t = build_transition_table(&["abc"]);
        let idx = 0 * 256 * LANES_PER_SUBGROUP + (b'a' as usize) * LANES_PER_SUBGROUP + 0;
        assert_eq!(t[idx], 1_u32 << 1, "0 -a-> 1 should set lane-0 bit-1");
    }

    #[test]
    fn transition_table_spans_correct_dst_lane_when_dst_gte_32() {
        // 33 patterns of length 1 produces state_cursor 1..=33, so
        // one transition lands in dst_lane 1 (dst state 32 → lane 1 bit 0).
        let pats: Vec<String> = (0..33)
            .map(|i| format!("{}", char::from(b'a' + i)))
            .collect();
        let refs: Vec<&str> = pats.iter().map(String::as_str).collect();
        let t = build_transition_table(&refs);
        let plan = compile(&refs);
        // Dst state 32 is reached from entry (state 0) on byte ('a' + 32) = '!' + … — find it by search.
        // Any entry at lane 1 should be non-zero.
        let has_lane1 = (0..256)
            .map(|byte| t[0 * 256 * LANES_PER_SUBGROUP + byte * LANES_PER_SUBGROUP + 1])
            .any(|v| v != 0);
        assert!(
            has_lane1,
            "dst states ≥32 must populate lane ≥1 (plan has {} states)",
            plan.num_states
        );
    }

    #[test]
    fn transition_table_encodes_every_byte_independently() {
        let t = build_transition_table(&["xy"]);
        let x_idx = 0 * 256 * LANES_PER_SUBGROUP + (b'x' as usize) * LANES_PER_SUBGROUP + 0;
        let y_idx = 0 * 256 * LANES_PER_SUBGROUP + (b'y' as usize) * LANES_PER_SUBGROUP + 0;
        assert_ne!(t[x_idx], 0);
        assert_eq!(t[y_idx], 0, "entry does not take 'y' directly");
    }

    #[test]
    fn epsilon_table_has_lane_major_size() {
        let n = compile(&["abc"]).num_states as usize;
        assert_eq!(build_epsilon_table(&["abc"]).len(), n * LANES_PER_SUBGROUP,);
    }

    #[test]
    fn epsilon_table_all_zero_for_literals() {
        let t = build_epsilon_table(&["abc"]);
        assert!(t.iter().all(|&w| w == 0));
    }

    #[test]
    fn plan_shards_fit_within_limit() {
        let big: Vec<String> = (0..12).map(|_| "a".repeat(100)).collect();
        let refs: Vec<&str> = big.iter().map(String::as_str).collect();
        let shards = plan_shards(&refs);
        for s in &shards {
            let sum: usize = s.iter().map(|p| p.len()).sum();
            assert!(sum + 1 <= MAX_STATES_PER_SUBGROUP);
        }
        assert!(shards.len() >= 2);
    }

    #[test]
    fn lane_major_transition_table_has_correct_size() {
        let t = build_transition_table_lane_major(&["abc", "de"]);
        let plan = compile(&["abc", "de"]);
        let padded = LANES_PER_SUBGROUP * (plan.num_states as usize).div_ceil(LANES_PER_SUBGROUP);
        assert_eq!(
            t.len(),
            padded * 256 * LANES_PER_SUBGROUP,
            "lane-major table must be padded to LANES multiple per byte row"
        );
    }

    #[test]
    fn lane_major_transition_table_encodes_same_edges_as_flat() {
        let patterns = &["abc", "xyz"];
        let flat = build_transition_table(patterns);
        let lm = build_transition_table_lane_major(patterns);
        let plan = compile(patterns);
        let num_states = plan.num_states as usize;
        let padded = LANES_PER_SUBGROUP * num_states.div_ceil(LANES_PER_SUBGROUP);

        // Every (src, byte, lane) entry must match between the two layouts.
        for src in 0..num_states {
            for byte in 0..256 {
                for lane in 0..LANES_PER_SUBGROUP {
                    let flat_idx =
                        src * 256 * LANES_PER_SUBGROUP + byte * LANES_PER_SUBGROUP + lane;
                    let lm_idx = lane * padded * 256 + byte * padded + src;
                    assert_eq!(
                        flat[flat_idx], lm[lm_idx],
                        "mismatch at src={src} byte={byte} lane={lane}"
                    );
                }
            }
        }
    }

    #[test]
    fn plan_shards_empty_on_empty_input() {
        let empty: &[&str] = &[];
        assert!(plan_shards(empty).is_empty());
    }

    #[test]
    fn nfa_scan_emits_valid_program_with_expected_buffers() {
        let p = nfa_scan(&["abc"], "input", "hits", 16);
        assert_eq!(p.workgroup_size, [LANES_PER_SUBGROUP as u32, 1, 1]);
        let names: Vec<&str> = p.buffers.iter().map(|b| b.name()).collect();
        assert!(names.contains(&"input"));
        assert!(names.contains(&"nfa_transition"));
        assert!(names.contains(&"nfa_epsilon"));
        assert!(names.contains(&"hits"));
    }

    #[test]
    fn nfa_scan_transition_buffer_has_primitive_compatible_count() {
        let p = nfa_scan(&["abc"], "input", "hits", 16);
        let trans = p
            .buffers
            .iter()
            .find(|b| b.name() == "nfa_transition")
            .expect("nfa_transition buffer");
        let plan = compile(&["abc"]);
        assert_eq!(
            trans.count,
            plan.num_states * 256 * LANES_PER_SUBGROUP as u32,
            "buffer count must match lane-major [num_states × 256 × LANES] layout \
             that subgroup_nfa::nfa_step consumes",
        );
    }

    #[test]
    fn nfa_scan_epsilon_buffer_has_primitive_compatible_count() {
        let p = nfa_scan(&["abc"], "input", "hits", 16);
        let eps = p
            .buffers
            .iter()
            .find(|b| b.name() == "nfa_epsilon")
            .expect("nfa_epsilon buffer");
        let plan = compile(&["abc"]);
        assert_eq!(eps.count, plan.num_states * LANES_PER_SUBGROUP as u32);
    }

    #[test]
    #[should_panic(expected = "exceeds MAX_STATES_PER_SUBGROUP")]
    fn nfa_scan_rejects_over_budget_patterns() {
        let big: Vec<String> = (0..12).map(|_| "a".repeat(100)).collect();
        let refs: Vec<&str> = big.iter().map(String::as_str).collect();
        let _ = nfa_scan(&refs, "input", "hits", 16);
    }

    #[test]
    fn nfa_scan_accepts_zero_input_len() {
        // Contract: input_len == 0 produces a valid empty-result
        // Program, so callers can route empty haystacks through the
        // same dispatch builder as non-empty inputs.
        let prog = nfa_scan(&["abc"], "input", "hits", 0);
        assert!(!prog.entry().is_empty());
    }

    #[test]
    fn nfa_plan_input_len_is_attachable() {
        let plan = compile(&["abc"]).for_input_len(64);
        assert_eq!(plan.input_len, 64);
    }
}

/// Benchmark-only helpers for NFA transition-table layout comparison.
///
/// Gated behind the `bench` feature so normal consumers do not pay
/// compile-time cost for code that is only exercised by Criterion.
#[cfg(feature = "bench")]
pub mod bench {
    pub use super::build_transition_table;
    pub use super::build_transition_table_lane_major;
    pub use super::compile;
    pub use vyre_primitives::nfa::subgroup_nfa::LANES_PER_SUBGROUP;

    use vyre_primitives::nfa::subgroup_nfa::MAX_EPSILON_ITERS;

    /// CPU-reference NFA step using the **lane-major** transition table.
    ///
    /// Layout: `lane * padded_num_states * 256 + byte * padded_num_states + src_state`.
    /// Mirrors the semantics of `vyre_primitives::nfa::subgroup_nfa::cpu_step`
    /// but indexes into the lane-major table produced by
    /// [`build_transition_table_lane_major`].
    pub fn cpu_step_lane_major(
        state: &[u32],
        byte: u8,
        transition: &[u32],
        epsilon: &[u32],
        num_states: usize,
    ) -> Vec<u32> {
        assert_eq!(state.len(), LANES_PER_SUBGROUP);
        let padded_states = LANES_PER_SUBGROUP * num_states.div_ceil(LANES_PER_SUBGROUP);
        assert_eq!(
            transition.len(),
            padded_states * 256 * LANES_PER_SUBGROUP,
            "lane-major transition table size mismatch"
        );
        assert_eq!(
            epsilon.len(),
            num_states * LANES_PER_SUBGROUP,
            "epsilon table size mismatch"
        );

        let mut acc = vec![0_u32; LANES_PER_SUBGROUP];
        for (k, &peer) in state.iter().enumerate() {
            for i in 0..32 {
                let src_state = k * 32 + i;
                if src_state >= num_states {
                    break;
                }
                if (peer >> i) & 1 == 0 {
                    continue;
                }
                for (lane, slot) in acc.iter_mut().enumerate() {
                    let idx =
                        lane * padded_states * 256 + (byte as usize) * padded_states + src_state;
                    *slot |= transition[idx];
                }
            }
        }

        // Epsilon closure — real fixpoint. Same logic as flat layout;
        // epsilon table is not transposed.
        for _ in 0..MAX_EPSILON_ITERS as usize {
            let prev = acc.clone();
            for (k, &peer) in prev.iter().enumerate() {
                for i in 0..32 {
                    let src_state = k * 32 + i;
                    if src_state >= num_states {
                        break;
                    }
                    if (peer >> i) & 1 == 0 {
                        continue;
                    }
                    for (lane, slot) in acc.iter_mut().enumerate() {
                        let idx = src_state * LANES_PER_SUBGROUP + lane;
                        *slot |= epsilon[idx];
                    }
                }
            }
            if acc == prev {
                break;
            }
        }
        acc
    }
}
