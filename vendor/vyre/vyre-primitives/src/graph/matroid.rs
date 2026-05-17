//! Matroid intersection augmenting-path step.
//!
//! Edmonds (1970) matroid intersection finds the max independent set
//! in the intersection of two matroids — generalizes bipartite
//! matching, common spanning forests, scheduling. Recent work
//! (Chakrabarty-Lee-Sidford 2021) cuts the per-iteration cost via
//! sparse linear-system solves.
//!
//! At each iteration, the algorithm searches for an "augmenting path"
//! in an exchange graph. This file ships the **exchange-graph BFS
//! step** primitive — given the current independent set and the
//! exchange-edge masks, advance the BFS frontier one layer.
//!
//! # Why this primitive is dual-use
//!
//! | Consumer | Use |
//! |---|---|
//! | `vyre-libs::opt::scheduling` | combinatorial scheduling |
//! | `vyre-libs::opt::bipartite` | bipartite matching |
//! | `vyre-runtime/src/megakernel/planner.rs` (#22 self-consumer) | **vyre's megakernel scheduler** — fusion-grouping subject to memory + sync constraints IS a matroid intersection problem (graphic matroid × partition matroid) |

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Op id.
pub const OP_ID: &str = "vyre-primitives::graph::matroid_exchange_bfs_step";

/// Emit one BFS layer of the matroid-exchange graph.
///
/// Inputs:
/// - `frontier_in`: length-`n` u32 lanes — `1` if node is in the
///   current frontier.
/// - `exchange_adj`: row-major `n × n` u32 — `1` if edge `(i, j)`
///   exists in the exchange graph (i.e. swapping i for j preserves
///   independence in both matroids).
/// - `visited`: length-`n` u32 — `1` if node already reached.
///
/// Output:
/// - `frontier_out`: length-`n` u32 — `1` for newly-reached nodes
///   in this BFS layer (excludes already-visited).
/// - `any_change`: single-element u32 — `1` if frontier_out has any
///   set bits (caller uses to detect convergence).
#[must_use]
pub fn matroid_exchange_bfs_step(
    frontier_in: &str,
    exchange_adj: &str,
    visited: &str,
    frontier_out: &str,
    any_change: &str,
    n: u32,
) -> Program {
    if n == 0 {
        return crate::invalid_output_program(
            OP_ID,
            frontier_out,
            DataType::U32,
            format!("Fix: matroid_exchange_bfs_step requires n > 0, got {n}."),
        );
    }

    let t = Expr::InvocationId { axis: 0 };

    // Lane t computes frontier_out[t]:
    //   1 iff (visited[t] == 0)  AND  ∃ k. frontier_in[k] == 1 AND adj[k, t] == 1
    let body = vec![Node::if_then(
        Expr::lt(t.clone(), Expr::u32(n)),
        vec![
            Node::let_bind("reached", Expr::u32(0)),
            Node::if_then(
                Expr::eq(Expr::load(visited, t.clone()), Expr::u32(0)),
                vec![Node::loop_for(
                    "k",
                    Expr::u32(0),
                    Expr::u32(n),
                    vec![Node::if_then(
                        Expr::and(
                            Expr::ne(Expr::load(frontier_in, Expr::var("k")), Expr::u32(0)),
                            Expr::ne(
                                Expr::load(
                                    exchange_adj,
                                    Expr::add(Expr::mul(Expr::var("k"), Expr::u32(n)), t.clone()),
                                ),
                                Expr::u32(0),
                            ),
                        ),
                        vec![Node::assign("reached", Expr::u32(1))],
                    )],
                )],
            ),
            Node::store(frontier_out, t.clone(), Expr::var("reached")),
            // Lane 0 also writes any_change OR-reduced. To keep the
            // primitive single-pass without atomics, we write a per-
            // lane bit and let lane 0 OR-reduce in a final loop.
            Node::if_then(
                Expr::eq(t.clone(), Expr::u32(0)),
                vec![
                    Node::let_bind("changed", Expr::u32(0)),
                    Node::loop_for(
                        "j",
                        Expr::u32(0),
                        Expr::u32(n),
                        vec![Node::if_then(
                            Expr::ne(Expr::load(frontier_out, Expr::var("j")), Expr::u32(0)),
                            vec![Node::assign("changed", Expr::u32(1))],
                        )],
                    ),
                    Node::store(any_change, Expr::u32(0), Expr::var("changed")),
                ],
            ),
        ],
    )];

    Program::wrapped(
        vec![
            BufferDecl::storage(frontier_in, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(n),
            BufferDecl::storage(exchange_adj, 1, BufferAccess::ReadOnly, DataType::U32)
                .with_count(n * n),
            BufferDecl::storage(visited, 2, BufferAccess::ReadOnly, DataType::U32).with_count(n),
            BufferDecl::storage(frontier_out, 3, BufferAccess::ReadWrite, DataType::U32)
                .with_count(n),
            BufferDecl::storage(any_change, 4, BufferAccess::ReadWrite, DataType::U32)
                .with_count(1),
        ],
        [256, 1, 1],
        vec![Node::Region {
            generator: Ident::from(OP_ID),
            source_region: None,
            body: Arc::new(body),
        }],
    )
}

/// CPU reference for one BFS layer.
#[must_use]
pub fn matroid_exchange_bfs_step_cpu(
    frontier_in: &[u32],
    exchange_adj: &[u32],
    visited: &[u32],
    n: usize,
) -> (Vec<u32>, bool) {
    let mut out = vec![0u32; n];
    let mut any = false;
    for j in 0..n {
        if visited.get(j).copied().unwrap_or(0) != 0 {
            continue;
        }
        for k in 0..n {
            let frontier = frontier_in.get(k).copied().unwrap_or(0);
            let exchange = exchange_adj.get(k * n + j).copied().unwrap_or(0);
            if frontier != 0 && exchange != 0 {
                out[j] = 1;
                any = true;
                break;
            }
        }
    }
    (out, any)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_one_step_advances() {
        // 3 nodes; frontier = {0}; edges 0→1 in exchange graph.
        let f = vec![1, 0, 0];
        let adj = vec![
            0, 1, 0, // 0 → 1
            0, 0, 0, 0, 0, 0,
        ];
        let v = vec![0, 0, 0];
        let (out, any) = matroid_exchange_bfs_step_cpu(&f, &adj, &v, 3);
        assert_eq!(out, vec![0, 1, 0]);
        assert!(any);
    }

    #[test]
    fn cpu_visited_blocks_re_advance() {
        let f = vec![1, 0, 0];
        let adj = vec![0, 1, 0, 0, 0, 0, 0, 0, 0];
        let v = vec![0, 1, 0]; // node 1 already visited
        let (out, any) = matroid_exchange_bfs_step_cpu(&f, &adj, &v, 3);
        assert_eq!(out, vec![0, 0, 0]);
        assert!(!any);
    }

    #[test]
    fn cpu_empty_frontier_no_change() {
        let f = vec![0; 3];
        let adj = vec![1; 9];
        let v = vec![0; 3];
        let (out, any) = matroid_exchange_bfs_step_cpu(&f, &adj, &v, 3);
        assert_eq!(out, vec![0; 3]);
        assert!(!any);
    }

    #[test]
    fn cpu_malformed_inputs_treat_missing_entries_as_zero() {
        let (out, any) = matroid_exchange_bfs_step_cpu(&[1], &[], &[], 2);
        assert_eq!(out, vec![0, 0]);
        assert!(!any);
    }

    #[test]
    fn cpu_multiple_sources_advance_all_targets() {
        // frontier = {0, 1}; adj 0→2, 1→3.
        let f = vec![1, 1, 0, 0];
        let adj = vec![
            0, 0, 1, 0, // 0 → 2
            0, 0, 0, 1, // 1 → 3
            0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let v = vec![0; 4];
        let (out, _) = matroid_exchange_bfs_step_cpu(&f, &adj, &v, 4);
        assert_eq!(out, vec![0, 0, 1, 1]);
    }

    #[test]
    fn ir_program_buffer_layout() {
        let p = matroid_exchange_bfs_step("fi", "adj", "v", "fo", "ch", 4);
        assert_eq!(p.workgroup_size, [256, 1, 1]);
        let names: Vec<&str> = p.buffers.iter().map(|b| b.name()).collect();
        assert_eq!(names, vec!["fi", "adj", "v", "fo", "ch"]);
        assert_eq!(p.buffers[0].count(), 4);
        assert_eq!(p.buffers[1].count(), 16);
        assert_eq!(p.buffers[2].count(), 4);
        assert_eq!(p.buffers[3].count(), 4);
        assert_eq!(p.buffers[4].count(), 1);
    }

    #[test]
    fn zero_n_traps() {
        let p = matroid_exchange_bfs_step("fi", "adj", "v", "fo", "ch", 0);
        assert!(p.stats().trap());
    }
}
