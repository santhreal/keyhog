//! `dominator_frontier` — query the dominance frontier of a node
//! set, packed as a per-node bitset.
//!
//! The dominance frontier of node `n` is the set of nodes `m` such
//! that `n` dominates a predecessor of `m` but does NOT dominate `m`
//! itself. SSA phi placement uses this directly; frontend rules can
//! reach for it via the `vyre.graph.dominator_frontier.v1` ExternCall.
//!
//! Soundness: exact when the supplied dominator-tree CSR is
//! correctly computed (the caller is responsible for that — usually
//! via `vyre-libs::dataflow::ssa::compute_dominators`).

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

use crate::graph::csr_forward_traverse::bitset_words;

/// Canonical op id.
pub const OP_ID: &str = "vyre-primitives::graph::dominator_frontier";

/// Validated dominance-frontier dispatch layout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DominatorFrontierLayout {
    /// Number of u32 words in the frontier/seed bitset.
    pub words: usize,
    /// Number of dominance-closure CSR edges.
    pub dom_edge_count: u32,
    /// Number of predecessor CSR edges.
    pub pred_edge_count: u32,
}

/// Build a Program that evaluates the exact dominance-frontier
/// predicate:
///
/// `m ∈ DF(seed)` iff some seeded node `n` dominates at least one
/// predecessor of `m`, and `n` does not strictly dominate `m`.
///
/// `dom_offsets`/`dom_targets` encode dominance closure by dominator.
/// `pred_offsets`/`pred_targets` encode CFG predecessors by candidate
/// node.
#[must_use]
pub fn dominator_frontier(
    node_count: u32,
    dom_edge_count: u32,
    pred_edge_count: u32,
    seed: &str,
    out: &str,
) -> Program {
    match try_dominator_frontier(node_count, dom_edge_count, pred_edge_count, seed, out) {
        Ok(program) => program,
        Err(error) => {
            eprintln!("{error}");
            inert_dominator_frontier_program(seed, out)
        }
    }
}

/// Build a dominance-frontier Program with checked CSR launch-shape
/// validation.
pub fn try_dominator_frontier(
    node_count: u32,
    dom_edge_count: u32,
    pred_edge_count: u32,
    seed: &str,
    out: &str,
) -> Result<Program, String> {
    let words = bitset_words(node_count).max(1);
    let offset_count = node_count.checked_add(1).ok_or_else(|| {
        format!(
            "dominator_frontier node_count={node_count} overflows CSR offset buffer count. Fix: shard the graph before GPU dispatch."
        )
    });
    let offset_count = offset_count?;
    let t = Expr::InvocationId { axis: 0 };
    let dominator_is_seed = vec![
        Node::let_bind(
            "seed_word",
            Expr::load(seed, Expr::shr(Expr::var("n"), Expr::u32(5))),
        ),
        Node::let_bind(
            "seed_bit",
            Expr::shl(Expr::u32(1), Expr::bitand(Expr::var("n"), Expr::u32(31))),
        ),
        Node::if_then(
            Expr::ne(
                Expr::bitand(Expr::var("seed_word"), Expr::var("seed_bit")),
                Expr::u32(0),
            ),
            vec![
                Node::let_bind(
                    "pred_start",
                    Expr::load("pred_offsets", Expr::var("candidate")),
                ),
                Node::let_bind(
                    "pred_end",
                    Expr::load(
                        "pred_offsets",
                        Expr::add(Expr::var("candidate"), Expr::u32(1)),
                    ),
                ),
                Node::let_bind("dominates_a_predecessor", Expr::u32(0)),
                Node::loop_for(
                    "p",
                    Expr::var("pred_start"),
                    Expr::var("pred_end"),
                    vec![Node::if_then(
                        Expr::eq(Expr::var("dominates_a_predecessor"), Expr::u32(0)),
                        vec![
                            Node::let_bind("pred", Expr::load("pred_targets", Expr::var("p"))),
                            Node::let_bind(
                                "dom_start_pred",
                                Expr::load("dom_offsets", Expr::var("n")),
                            ),
                            Node::let_bind(
                                "dom_end_pred",
                                Expr::load("dom_offsets", Expr::add(Expr::var("n"), Expr::u32(1))),
                            ),
                            Node::loop_for(
                                "d_pred",
                                Expr::var("dom_start_pred"),
                                Expr::var("dom_end_pred"),
                                vec![Node::if_then(
                                    Expr::eq(
                                        Expr::load("dom_targets", Expr::var("d_pred")),
                                        Expr::var("pred"),
                                    ),
                                    vec![Node::assign("dominates_a_predecessor", Expr::u32(1))],
                                )],
                            ),
                        ],
                    )],
                ),
                Node::let_bind("dominates_candidate", Expr::u32(0)),
                Node::let_bind(
                    "dom_start_candidate",
                    Expr::load("dom_offsets", Expr::var("n")),
                ),
                Node::let_bind(
                    "dom_end_candidate",
                    Expr::load("dom_offsets", Expr::add(Expr::var("n"), Expr::u32(1))),
                ),
                Node::loop_for(
                    "d_candidate",
                    Expr::var("dom_start_candidate"),
                    Expr::var("dom_end_candidate"),
                    vec![Node::if_then(
                        Expr::eq(
                            Expr::load("dom_targets", Expr::var("d_candidate")),
                            Expr::var("candidate"),
                        ),
                        vec![Node::assign("dominates_candidate", Expr::u32(1))],
                    )],
                ),
                Node::let_bind("strictly_dominates_candidate", Expr::u32(0)),
                Node::if_then(
                    Expr::and(
                        Expr::eq(Expr::var("dominates_candidate"), Expr::u32(1)),
                        Expr::ne(Expr::var("n"), Expr::var("candidate")),
                    ),
                    vec![Node::assign("strictly_dominates_candidate", Expr::u32(1))],
                ),
                Node::if_then(
                    Expr::and(
                        Expr::eq(Expr::var("dominates_a_predecessor"), Expr::u32(1)),
                        Expr::eq(Expr::var("strictly_dominates_candidate"), Expr::u32(0)),
                    ),
                    vec![
                        Node::let_bind(
                            "candidate_word",
                            Expr::shr(Expr::var("candidate"), Expr::u32(5)),
                        ),
                        Node::let_bind(
                            "candidate_bit",
                            Expr::shl(
                                Expr::u32(1),
                                Expr::bitand(Expr::var("candidate"), Expr::u32(31)),
                            ),
                        ),
                        Node::let_bind(
                            "_prev",
                            Expr::atomic_or(
                                out,
                                Expr::var("candidate_word"),
                                Expr::var("candidate_bit"),
                            ),
                        ),
                    ],
                ),
            ],
        ),
    ];
    Ok(Program::wrapped(
        vec![
            BufferDecl::storage("dom_offsets", 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(offset_count),
            BufferDecl::storage("dom_targets", 1, BufferAccess::ReadOnly, DataType::U32)
                .with_count(dom_edge_count.max(1)),
            BufferDecl::storage("pred_offsets", 2, BufferAccess::ReadOnly, DataType::U32)
                .with_count(offset_count),
            BufferDecl::storage("pred_targets", 3, BufferAccess::ReadOnly, DataType::U32)
                .with_count(pred_edge_count.max(1)),
            BufferDecl::storage(seed, 4, BufferAccess::ReadOnly, DataType::U32).with_count(words),
            BufferDecl::storage(out, 5, BufferAccess::ReadWrite, DataType::U32).with_count(words),
        ],
        [1, 1, 1],
        vec![Node::Region {
            generator: Ident::from(OP_ID),
            source_region: None,
            body: Arc::new(vec![Node::if_then(
                Expr::lt(t.clone(), Expr::u32(node_count)),
                vec![
                    Node::let_bind("candidate", t),
                    Node::loop_for("n", Expr::u32(0), Expr::u32(node_count), dominator_is_seed),
                ],
            )]),
        }],
    ))
}

fn inert_dominator_frontier_program(seed: &str, out: &str) -> Program {
    Program::wrapped(
        vec![
            BufferDecl::storage("dom_offsets", 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(1),
            BufferDecl::storage("dom_targets", 1, BufferAccess::ReadOnly, DataType::U32)
                .with_count(1),
            BufferDecl::storage("pred_offsets", 2, BufferAccess::ReadOnly, DataType::U32)
                .with_count(1),
            BufferDecl::storage("pred_targets", 3, BufferAccess::ReadOnly, DataType::U32)
                .with_count(1),
            BufferDecl::storage(seed, 4, BufferAccess::ReadOnly, DataType::U32).with_count(1),
            BufferDecl::storage(out, 5, BufferAccess::ReadWrite, DataType::U32).with_count(1),
        ],
        [1, 1, 1],
        vec![Node::Region {
            generator: Ident::from(OP_ID),
            source_region: None,
            body: Arc::new(vec![Node::return_()]),
        }],
    )
}

/// CPU oracle: returns the dominance-frontier bitset for the seed set.
///
/// `dom_offsets` / `dom_targets` encode the dominance closure by dominator:
/// row `n` contains every node dominated by `n`, including `n`.
#[must_use]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn cpu_ref(
    node_count: u32,
    dom_offsets: &[u32],
    dom_targets: &[u32],
    pred_offsets: &[u32],
    pred_targets: &[u32],
    seed: &[u32],
) -> Vec<u32> {
    let mut frontier = Vec::new();
    cpu_ref_into(
        node_count,
        dom_offsets,
        dom_targets,
        pred_offsets,
        pred_targets,
        seed,
        &mut frontier,
    );
    frontier
}

/// CPU oracle into caller-owned output storage.
///
/// `dom_offsets` / `dom_targets` encode the dominance closure by dominator:
/// row `n` contains every node dominated by `n`, including `n`.
#[cfg(any(test, feature = "cpu-parity"))]
pub fn cpu_ref_into(
    node_count: u32,
    dom_offsets: &[u32],
    dom_targets: &[u32],
    pred_offsets: &[u32],
    pred_targets: &[u32],
    seed: &[u32],
    frontier: &mut Vec<u32>,
) {
    let words = bitset_words(node_count) as usize;
    assert!(
        seed.len() >= words,
        "dominator_frontier CPU oracle received seed_len={} for node_count={node_count} requiring {words} words. Fix: pass a complete seed bitset before parity comparison.",
        seed.len()
    );
    require_csr_shape(
        "dominator_frontier dominator closure",
        node_count,
        dom_offsets,
        dom_targets,
    );
    require_csr_shape(
        "dominator_frontier predecessor graph",
        node_count,
        pred_offsets,
        pred_targets,
    );
    frontier.clear();
    frontier.resize(words, 0);
    for n in 0..node_count {
        let n_word = (n / 32) as usize;
        let n_bit = 1u32 << (n % 32);
        if seed[n_word] & n_bit == 0 {
            continue;
        }
        for m in 0..node_count {
            let pred_start = pred_offsets[m as usize] as usize;
            let pred_end = pred_offsets[m as usize + 1] as usize;
            let dominates_a_predecessor = pred_targets[pred_start..pred_end]
                .iter()
                .copied()
                .any(|pred| dominates(dom_offsets, dom_targets, n, pred));
            let strictly_dominates_m = n != m && dominates(dom_offsets, dom_targets, n, m);
            if dominates_a_predecessor && !strictly_dominates_m {
                let m_word = (m / 32) as usize;
                let m_bit = 1u32 << (m % 32);
                frontier[m_word] |= m_bit;
            }
        }
    }
}

/// Number of nodes flagged in a dominance-frontier bitset.
#[must_use]
pub fn frontier_size(frontier: &[u32]) -> u32 {
    frontier.iter().map(|word| word.count_ones()).sum()
}

/// Validate a CSR buffer pair for `node_count` rows.
///
/// # Errors
///
/// Returns an actionable diagnostic when offsets are the wrong length,
/// non-monotonic, inconsistent with target count, or targets point outside
/// `0..node_count`.
pub fn validate_csr_shape(
    label: &str,
    node_count: u32,
    offsets: &[u32],
    targets: &[u32],
) -> Result<u32, String> {
    let expected_offsets = (node_count as usize).checked_add(1).ok_or_else(|| {
        format!(
            "Fix: dominator_frontier {label} node_count + 1 overflows usize for node_count={node_count}."
        )
    })?;
    if offsets.len() != expected_offsets {
        return Err(format!(
            "Fix: dominator_frontier {label} offsets length must be {expected_offsets}, got {}.",
            offsets.len()
        ));
    }
    let mut previous = 0u32;
    for (idx, &offset) in offsets.iter().enumerate() {
        if idx > 0 && offset < previous {
            return Err(format!(
                "Fix: dominator_frontier {label} offsets must be monotonic; offsets[{idx}]={offset} after {previous}."
            ));
        }
        previous = offset;
    }
    if offsets.last().copied().unwrap_or(0) as usize != targets.len() {
        return Err(format!(
            "Fix: dominator_frontier {label} final offset must equal target count {}, got {}.",
            targets.len(),
            offsets.last().copied().unwrap_or(0)
        ));
    }
    for (idx, &target) in targets.iter().enumerate() {
        if target >= node_count {
            return Err(format!(
                "Fix: dominator_frontier {label} target[{idx}]={target} is outside node_count {node_count}."
            ));
        }
    }
    u32::try_from(targets.len()).map_err(|_| {
        format!(
            "Fix: dominator_frontier {label} target count {} exceeds u32 index space.",
            targets.len()
        )
    })
}

/// Validate the full dominance-frontier CPU/dispatch input contract.
///
/// # Errors
///
/// Returns an actionable diagnostic when either CSR is malformed or when the
/// seed bitset does not contain exactly the required number of words.
pub fn validate_dominator_frontier_inputs(
    node_count: u32,
    dom_offsets: &[u32],
    dom_targets: &[u32],
    pred_offsets: &[u32],
    pred_targets: &[u32],
    seed: &[u32],
) -> Result<DominatorFrontierLayout, String> {
    let words = bitset_words(node_count) as usize;
    if seed.len() != words {
        return Err(format!(
            "Fix: dominator_frontier expected seed length {words} words for {node_count} nodes, got {}.",
            seed.len()
        ));
    }
    let dom_edge_count = validate_csr_shape("dominance", node_count, dom_offsets, dom_targets)?;
    let pred_edge_count =
        validate_csr_shape("predecessor", node_count, pred_offsets, pred_targets)?;
    Ok(DominatorFrontierLayout {
        words,
        dom_edge_count,
        pred_edge_count,
    })
}

#[cfg(any(test, feature = "cpu-parity"))]
fn require_csr_shape(stage: &str, node_count: u32, offsets: &[u32], targets: &[u32]) {
    validate_csr_shape(stage, node_count, offsets, targets)
        .unwrap_or_else(|err| panic!("{stage} CPU oracle received malformed CSR. {err}"));
}

#[cfg(any(test, feature = "cpu-parity"))]
fn dominates(dom_offsets: &[u32], dom_targets: &[u32], dominator: u32, node: u32) -> bool {
    let start = dom_offsets[dominator as usize] as usize;
    let end = dom_offsets[dominator as usize + 1] as usize;
    dom_targets[start..end].contains(&node)
}

#[cfg(feature = "inventory-registry")]
inventory::submit! {
    crate::harness::OpEntry::new(
        OP_ID,
        || dominator_frontier(4, 4, 4, "idom", "df"),
        None,
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_seed_yields_empty_frontier() {
        let out = cpu_ref(4, &[0, 0, 0, 0, 0], &[], &[0, 0, 0, 0, 0], &[], &[0]);
        assert_eq!(out, vec![0]);
    }

    #[test]
    fn single_node_with_no_predecessors_has_empty_frontier() {
        // node 0 with no predecessors → df(0) = {}.
        let out = cpu_ref(2, &[0, 0, 0], &[], &[0, 0, 0], &[], &[0b01]);
        assert_eq!(out, vec![0]);
    }

    #[test]
    fn dom_frontier_picks_up_join_node() {
        // CFG: 0 -> 1, 0 -> 2, 1 -> 3, 2 -> 3.
        // Predecessors of 3: [1, 2]. 1 dominates itself only, 2 same.
        // df(1) includes 3 because 1 dominates predecessor 1 of 3,
        // but 1 does not dominate 3.
        let pred_offsets = vec![0u32, 0, 1, 2, 4];
        let pred_targets = vec![0u32, 0, 1, 2];
        // Dominator sets: 0 dominates {0,1,2,3}; 1 dominates {1};
        // 2 dominates {2}; 3 dominates {3}.
        let dom_offsets = vec![0u32, 4, 5, 6, 7];
        let dom_targets = vec![0u32, 1, 2, 3, 1, 2, 3];
        let out = cpu_ref(
            4,
            &dom_offsets,
            &dom_targets,
            &pred_offsets,
            &pred_targets,
            &[0b0010],
        );
        assert_eq!(out, vec![0b1000]);
    }

    #[test]
    fn cpu_ref_into_reuses_frontier_storage() {
        let mut out = Vec::with_capacity(8);
        let dom_offsets = vec![0u32, 4, 5, 6, 7];
        let dom_targets = vec![0u32, 1, 2, 3, 1, 2, 3];
        let pred_offsets = vec![0u32, 0, 1, 2, 4];
        let pred_targets = vec![0u32, 0, 1, 2];
        cpu_ref_into(
            4,
            &dom_offsets,
            &dom_targets,
            &pred_offsets,
            &pred_targets,
            &[0b0010],
            &mut out,
        );
        let capacity = out.capacity();
        assert_eq!(out, vec![0b1000]);

        cpu_ref_into(
            4,
            &dom_offsets,
            &dom_targets,
            &pred_offsets,
            &pred_targets,
            &[0],
            &mut out,
        );
        assert_eq!(out.capacity(), capacity);
        assert_eq!(out, vec![0]);
    }

    #[test]
    fn reusable_validation_rejects_bad_csr_and_seed() {
        let err = validate_dominator_frontier_inputs(2, &[0, 1, 1], &[1], &[0, 1, 0], &[0], &[1])
            .unwrap_err();
        assert!(err.contains("predecessor offsets must be monotonic"));

        let err =
            validate_dominator_frontier_inputs(33, &[0; 34], &[], &[0; 34], &[], &[1]).unwrap_err();
        assert!(err.contains("expected seed length 2 words"));
    }

    #[test]
    fn reusable_validation_returns_dispatch_layout() {
        let layout = validate_dominator_frontier_inputs(
            4,
            &[0, 4, 5, 6, 7],
            &[0, 1, 2, 3, 1, 2, 3],
            &[0, 0, 1, 2, 4],
            &[0, 1, 2, 3],
            &[0b0010],
        )
        .expect("canonical dominance-frontier input should validate");

        assert_eq!(
            layout,
            DominatorFrontierLayout {
                words: 1,
                dom_edge_count: 7,
                pred_edge_count: 4,
            }
        );
    }

    #[test]
    fn frontier_size_counts_set_bits() {
        assert_eq!(frontier_size(&[0]), 0);
        assert_eq!(frontier_size(&[0b1011]), 3);
        assert_eq!(frontier_size(&[u32::MAX, 1]), 33);
    }

    #[test]
    fn checked_builder_rejects_offset_count_overflow() {
        let error = try_dominator_frontier(u32::MAX, 0, 0, "seed", "out")
            .expect_err("checked dominator-frontier builder must reject CSR offset overflow");

        assert!(
            error.contains("overflows CSR offset buffer count"),
            "error should describe the CSR offset overflow: {error}"
        );
    }

    #[test]
    fn legacy_builder_does_not_panic_on_offset_count_overflow() {
        let program = dominator_frontier(u32::MAX, 0, 0, "seed", "out");

        assert_eq!(program.workgroup_size, [1, 1, 1]);
    }

    #[test]
    fn dominator_frontier_release_builder_has_checked_api_without_panics() {
        let source = include_str!("dominator_frontier.rs");
        let production = source
            .split("/// CPU oracle:")
            .next()
            .expect("dominator-frontier builder source must precede CPU oracle");

        assert!(
            production.contains("pub fn try_dominator_frontier(")
                && !production.contains(concat!("panic", "!("))
                && !production.contains(".unwrap_or_else("),
            "Fix: dominator_frontier builder must expose checked release API and avoid production panics."
        );
    }

    #[test]
    #[should_panic(expected = "complete seed bitset")]
    fn missing_seed_word_fails_loudly() {
        let _ = cpu_ref(2, &[0, 0, 0], &[], &[0, 0, 0], &[], &[]);
    }
}
