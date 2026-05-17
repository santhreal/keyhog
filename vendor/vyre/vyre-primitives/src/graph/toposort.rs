//! Kahn-style topological sort with LIFO worklist — CPU reference +
//! single-invocation GPU `Program` builder.
//!
//! Consumed by the optimizer's reaching-defs pass, surgec
//! `dominator_tree`, and graph-IR analyses that need a DAG walk.
//!
//! AUDIT_2026-04-24 F-TS-04: `toposort_program` emits a single-invocation
//! Program that runs Kahn's algorithm serially on lane 0. The serial
//! lane-0 builder is the current Tier-2.5 contract because topological
//! ordering has a loop-carried dependency; callers that need large-DAG
//! throughput compose this with graph partitioning or SCC batching.
//!
//! AUDIT_2026-04-24 F-TS-02: the classical Kahn presentation uses a
//! FIFO queue (BFS-ish). This module uses a stack (LIFO) via
//! `Vec::pop` because it is O(1), has better cache locality on the
//! worklist, and produces an equally valid topological order — both
//! orderings satisfy the Kahn invariant (a node is emitted only
//! after all its prerequisites). If a caller needs stable BFS order
//! for deterministic diffs, swap in a `VecDeque` worklist; the
//! correctness of the sort does not depend on the worklist policy.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Canonical op id.
pub const OP_ID: &str = "vyre-primitives::graph::toposort";

/// Errors from topological sorting.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ToposortError {
    /// The input graph contains a cycle — returned with the first
    /// node id that participates in the cycle, for diagnostic use.
    Cycle {
        /// One node id on the cycle. Callers can walk the adjacency
        /// list from here to enumerate the full cycle.
        node: u32,
    },
    /// An edge references a node id not present in `node_count`.
    UnknownNode {
        /// Offending edge index.
        edge: usize,
        /// The out-of-range node id that tripped the check.
        node: u32,
    },
}

/// CPU reference: Kahn's algorithm over `(node_count, edges)`.
///
/// `edges` is a slice of `(from, to)` u32 pairs — `from` depends on
/// `to`, so `to` comes first in the sort. Returns a `Vec<u32>` in
/// topological order on success, or `ToposortError::Cycle` if the
/// graph has a cycle.
///
/// # Errors
///
/// Returns `ToposortError::Cycle` when the input has a cycle, or
/// `ToposortError::UnknownNode` when an edge names a node id
/// outside `0..node_count`.
pub fn toposort(node_count: u32, edges: &[(u32, u32)]) -> Result<Vec<u32>, ToposortError> {
    const NONE: usize = usize::MAX;

    let n = node_count as usize;
    let mut indeg = vec![0u32; n];
    let mut outgoing_head = vec![NONE; n];
    let mut outgoing_to = Vec::with_capacity(edges.len());
    let mut outgoing_next = Vec::with_capacity(edges.len());
    let mut depends_head = vec![NONE; n];
    let mut depends_to = Vec::with_capacity(edges.len());
    let mut depends_next = Vec::with_capacity(edges.len());

    for (edge_idx, &(from, to)) in edges.iter().enumerate() {
        if (from as usize) >= n {
            return Err(ToposortError::UnknownNode {
                edge: edge_idx,
                node: from,
            });
        }
        if (to as usize) >= n {
            return Err(ToposortError::UnknownNode {
                edge: edge_idx,
                node: to,
            });
        }
        let outgoing_idx = outgoing_to.len();
        outgoing_to.push(from);
        outgoing_next.push(outgoing_head[to as usize]);
        outgoing_head[to as usize] = outgoing_idx;

        let depends_idx = depends_to.len();
        depends_to.push(to);
        depends_next.push(depends_head[from as usize]);
        depends_head[from as usize] = depends_idx;

        // AUDIT_2026-04-24 F-TS-01: saturating_add so pathological
        // graphs with > u32::MAX in-edges per node don't wrap
        // silently (yielding 0, which then falsely indicates a root
        // node in the toposort seed phase).
        indeg[from as usize] = indeg[from as usize].saturating_add(1);
    }

    let mut queue: Vec<u32> = (0..node_count)
        .filter(|&v| indeg[v as usize] == 0)
        .collect();
    let mut out = Vec::with_capacity(n);

    while let Some(&v) = queue.last() {
        queue.pop();
        out.push(v);
        let mut edge = outgoing_head[v as usize];
        while edge != NONE {
            let u = outgoing_to[edge];
            let slot = &mut indeg[u as usize];
            *slot = slot.saturating_sub(1);
            if *slot == 0 {
                queue.push(u);
            }
            edge = outgoing_next[edge];
        }
    }

    if out.len() != n {
        // AUDIT_2026-04-24 F-TS-03: returning the first node with
        // indeg > 0 is misleading — that node may be *downstream* of
        // a cycle (its predecessor is stuck, not itself). Instead,
        // walk outgoing "depends on" edges from any unemitted node
        // until we revisit a node already on the walk — that revisit
        // point is guaranteed to lie on the cycle.
        let seed = indeg
            .iter()
            .enumerate()
            .find(|(_, &deg)| deg > 0)
            .map(|(i, _)| i as u32)
            .unwrap_or(0);
        let mut on_stack = vec![false; n];
        let mut cursor = seed;
        let cycle_node = loop {
            if on_stack[cursor as usize] {
                break cursor;
            }
            on_stack[cursor as usize] = true;
            let mut edge = depends_head[cursor as usize];
            let mut next = None;
            while edge != NONE {
                let candidate = depends_to[edge];
                if indeg[candidate as usize] > 0 {
                    next = Some(candidate);
                    break;
                }
                edge = depends_next[edge];
            }
            match next {
                Some(n) => cursor = n,
                // No unemitted successor — defensive fallback. This
                // cannot happen when out.len() != n and the graph is
                // well-formed, but we stay total to avoid panicking
                // on hand-crafted inputs.
                None => break cursor,
            }
        };
        return Err(ToposortError::Cycle { node: cycle_node });
    }
    Ok(out)
}

/// Build a single-invocation Program that runs Kahn's algorithm
/// serially on lane 0.
///
/// `offsets_buf` is a CSR row-pointer array with `node_count + 1`
/// entries; `targets_buf` is the CSR column array. `indeg_scratch`
/// and `queue_scratch` are caller-provided temporary buffers of
/// length `node_count`. `order_out` receives the topological order
/// (length `node_count` on an acyclic graph; fewer on a cyclic
/// graph because the kernel does not diagnose cycles).
///
/// Workgroup size is `[1, 1, 1]`. The kernel only executes on
/// invocation 0; other lanes return immediately.
#[must_use]
pub fn toposort_program(
    node_count: u32,
    offsets_buf: &str,
    targets_buf: &str,
    indeg_scratch: &str,
    queue_scratch: &str,
    order_out: &str,
) -> Program {
    let lane0 = Expr::eq(Expr::InvocationId { axis: 0 }, Expr::u32(0));

    let body = vec![
        // Zero out indeg_scratch.
        Node::loop_for(
            "i",
            Expr::u32(0),
            Expr::u32(node_count),
            vec![Node::store(indeg_scratch, Expr::var("i"), Expr::u32(0))],
        ),
        // Fill indegrees from edges. Edge count = offsets_buf[node_count].
        Node::let_bind("edge_count", Expr::load(offsets_buf, Expr::u32(node_count))),
        Node::loop_for(
            "e",
            Expr::u32(0),
            Expr::var("edge_count"),
            vec![
                Node::let_bind("t", Expr::load(targets_buf, Expr::var("e"))),
                Node::let_bind("old", Expr::load(indeg_scratch, Expr::var("t"))),
                Node::store(
                    indeg_scratch,
                    Expr::var("t"),
                    Expr::add(Expr::var("old"), Expr::u32(1)),
                ),
            ],
        ),
        // Seed queue with every node whose indegree is zero.
        Node::let_bind("write_head", Expr::u32(0)),
        Node::loop_for(
            "v",
            Expr::u32(0),
            Expr::u32(node_count),
            vec![Node::if_then(
                Expr::eq(Expr::load(indeg_scratch, Expr::var("v")), Expr::u32(0)),
                vec![
                    Node::store(queue_scratch, Expr::var("write_head"), Expr::var("v")),
                    Node::assign(
                        "write_head",
                        Expr::add(Expr::var("write_head"), Expr::u32(1)),
                    ),
                ],
            )],
        ),
        // Pop / decrement / push until the queue is empty.
        Node::let_bind("read_head", Expr::u32(0)),
        Node::let_bind("out_idx", Expr::u32(0)),
        Node::loop_for(
            "step",
            Expr::u32(0),
            Expr::u32(node_count),
            vec![Node::if_then(
                Expr::lt(Expr::var("read_head"), Expr::var("write_head")),
                vec![
                    Node::let_bind("v", Expr::load(queue_scratch, Expr::var("read_head"))),
                    Node::assign("read_head", Expr::add(Expr::var("read_head"), Expr::u32(1))),
                    Node::store(order_out, Expr::var("out_idx"), Expr::var("v")),
                    Node::assign("out_idx", Expr::add(Expr::var("out_idx"), Expr::u32(1))),
                    Node::let_bind("edge_start", Expr::load(offsets_buf, Expr::var("v"))),
                    Node::let_bind(
                        "edge_end",
                        Expr::load(offsets_buf, Expr::add(Expr::var("v"), Expr::u32(1))),
                    ),
                    Node::loop_for(
                        "e",
                        Expr::var("edge_start"),
                        Expr::var("edge_end"),
                        vec![
                            Node::let_bind("u", Expr::load(targets_buf, Expr::var("e"))),
                            Node::let_bind(
                                "new_deg",
                                Expr::sub(Expr::load(indeg_scratch, Expr::var("u")), Expr::u32(1)),
                            ),
                            Node::store(indeg_scratch, Expr::var("u"), Expr::var("new_deg")),
                            Node::if_then(
                                Expr::eq(Expr::var("new_deg"), Expr::u32(0)),
                                vec![
                                    Node::store(
                                        queue_scratch,
                                        Expr::var("write_head"),
                                        Expr::var("u"),
                                    ),
                                    Node::assign(
                                        "write_head",
                                        Expr::add(Expr::var("write_head"), Expr::u32(1)),
                                    ),
                                ],
                            ),
                        ],
                    ),
                ],
            )],
        ),
    ];

    Program::wrapped(
        vec![
            BufferDecl::storage(offsets_buf, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(node_count.saturating_add(1)),
            BufferDecl::storage(targets_buf, 1, BufferAccess::ReadOnly, DataType::U32),
            BufferDecl::storage(indeg_scratch, 2, BufferAccess::ReadWrite, DataType::U32)
                .with_count(node_count.max(1)),
            BufferDecl::storage(queue_scratch, 3, BufferAccess::ReadWrite, DataType::U32)
                .with_count(node_count.max(1)),
            BufferDecl::storage(order_out, 4, BufferAccess::ReadWrite, DataType::U32)
                .with_count(node_count.max(1)),
        ],
        [1, 1, 1],
        vec![Node::Region {
            generator: Ident::from(OP_ID),
            source_region: None,
            body: Arc::new(vec![Node::if_then(lane0, body)]),
        }],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_graph_sorts_to_empty() {
        assert_eq!(toposort(0, &[]), Ok(Vec::new()));
    }

    #[test]
    fn no_edges_returns_all_nodes() {
        let got = toposort(3, &[])
            .expect("Fix: no-cycle case; restore this invariant before continuing.");
        assert_eq!(got.len(), 3);
        let mut sorted = got.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, vec![0, 1, 2]);
    }

    #[test]
    fn linear_chain_respects_order() {
        // 0 depends on 1 depends on 2 → sort places 2 before 1 before 0.
        let got = toposort(3, &[(0, 1), (1, 2)])
            .expect("Fix: linear chain is acyclic; restore this invariant before continuing.");
        let pos = |v: u32| got.iter().position(|&x| x == v).unwrap();
        assert!(pos(2) < pos(1));
        assert!(pos(1) < pos(0));
    }

    #[test]
    fn cycle_is_rejected() {
        let err = toposort(2, &[(0, 1), (1, 0)]).expect_err("2-cycle must be detected");
        assert!(matches!(err, ToposortError::Cycle { .. }));
    }

    #[test]
    fn cycle_diagnostic_names_node_on_cycle_not_downstream() {
        // AUDIT_2026-04-24 F-TS-03: graph where node 0 depends on
        // the cycle {1 → 2 → 3 → 1} but is not on it. Prior code
        // reported the first `indeg > 0` node (node 0 — downstream of
        // the cycle), which was misleading because 0 itself is not on
        // any cycle. Diagnostic must name a node actually on a cycle.
        let err = toposort(4, &[(0, 1), (1, 2), (2, 3), (3, 1)])
            .expect_err("3-cycle with downstream consumer must be detected");
        match err {
            ToposortError::Cycle { node } => {
                assert!(
                    matches!(node, 1..=3),
                    "cycle node {node} must be on the cycle {{1,2,3}}, not the downstream node 0"
                );
            }
            other => panic!("expected Cycle error, got {other:?}"),
        }
    }

    #[test]
    fn unknown_node_surfaces_edge_index() {
        let err = toposort(2, &[(0, 5)]).expect_err("node 5 is out of range");
        match err {
            ToposortError::UnknownNode { edge, node } => {
                assert_eq!(edge, 0);
                assert_eq!(node, 5);
            }
            _ => panic!("expected UnknownNode"),
        }
    }

    #[test]
    fn diamond_graph_sorts() {
        // 0 depends on 1 and 2; both depend on 3.
        let got = toposort(4, &[(0, 1), (0, 2), (1, 3), (2, 3)])
            .expect("Fix: diamond is acyclic; restore this invariant before continuing.");
        let pos = |v: u32| got.iter().position(|&x| x == v).unwrap();
        assert!(pos(3) < pos(1));
        assert!(pos(3) < pos(2));
        assert!(pos(1) < pos(0));
        assert!(pos(2) < pos(0));
    }

    #[test]
    fn emitted_program_has_expected_buffers_and_workgroup_size() {
        let p = toposort_program(4, "offsets", "targets", "indeg", "queue", "order");
        assert_eq!(p.workgroup_size, [1, 1, 1]);
        let names: Vec<&str> = p.buffers.iter().map(|b| b.name()).collect();
        assert_eq!(names, vec!["offsets", "targets", "indeg", "queue", "order"]);
        assert_eq!(p.buffers[0].count(), 5); // node_count + 1
        assert_eq!(p.buffers[2].count(), 4); // node_count
        assert_eq!(p.buffers[3].count(), 4); // node_count
        assert_eq!(p.buffers[4].count(), 4); // node_count
    }

    // ------------------------------------------------------------------
    // Adversarial fixtures — empty/single/disconnected/self-loop/max-size.
    // ------------------------------------------------------------------

    #[test]
    fn single_node_no_edges() {
        assert_eq!(toposort(1, &[]), Ok(vec![0]));
    }

    #[test]
    fn self_loops_only_rejected() {
        // Every node has a self-loop — each is a 1-cycle.
        let err = toposort(3, &[(0, 0), (1, 1), (2, 2)]).expect_err("self-loops are cycles");
        assert!(matches!(err, ToposortError::Cycle { .. }));
    }

    #[test]
    fn disconnected_components_sorts_all() {
        // Component A: 0 depends on 1. Component B: 2 depends on 3.
        let got = toposort(4, &[(0, 1), (2, 3)]).unwrap();
        assert_eq!(got.len(), 4);
        let pos = |v: u32| got.iter().position(|&x| x == v).unwrap();
        assert!(pos(1) < pos(0), "1 must come before 0");
        assert!(pos(3) < pos(2), "3 must come before 2");
    }

    #[test]
    fn max_node_count_min_edges() {
        // 1000 nodes, one chain edge 0→1.
        let got = toposort(1000, &[(0, 1)]).unwrap();
        assert_eq!(got.len(), 1000);
        let pos = |v: u32| got.iter().position(|&x| x == v).unwrap();
        assert!(pos(1) < pos(0), "1 must come before 0");
    }

    #[test]
    fn cycle_on_large_graph_diagnostic_is_on_cycle() {
        // 100 nodes in a line, back-edge creating cycle 50→51→…→99→50.
        let mut edges: Vec<(u32, u32)> = (0..99).map(|i| (i, i + 1)).collect();
        edges.push((99, 50));
        let err = toposort(100, &edges).expect_err("cycle must be detected");
        match err {
            ToposortError::Cycle { node } => {
                assert!(
                    (50..=99).contains(&node),
                    "cycle node {node} must be on the back-edge cycle"
                );
            }
            other => panic!("expected Cycle, got {other:?}"),
        }
    }
}
