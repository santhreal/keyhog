//! Matroid intersection full Edmonds algorithm (#P-PRIM-10).
//!
//! Finds the maximum common independent set of two matroids by
//! repeatedly finding augmenting paths in the exchange graph.
//!
//! Composes `matroid_exchange_bfs_step` and `path_reconstruct`.

use crate::graph::path_reconstruct::path_reconstruct;
use std::sync::Arc;
use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Op id.
pub const OP_ID: &str = "vyre-primitives::math::matroid_intersection_full";

/// Build a full matroid intersection Program.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn matroid_intersection_full(
    exchange_adj: &str,
    sources: &str,
    sinks: &str,
    set_x: &str,
    parent: &str,
    frontier: &str,
    next_frontier: &str,
    visited: &str,
    any_change: &str,
    path_out: &str,
    path_len: &str,
    n: u32,
    max_augmentations: u32,
) -> Program {
    let mut nodes = Vec::new();

    for _ in 0..max_augmentations {
        // 1. Find augmenting path via BFS
        nodes.push(Node::loop_for(
            "__i",
            Expr::u32(0),
            Expr::u32(n),
            vec![
                Node::store(
                    frontier,
                    Expr::var("__i"),
                    Expr::load(sources, Expr::var("__i")),
                ),
                Node::store(
                    visited,
                    Expr::var("__i"),
                    Expr::load(sources, Expr::var("__i")),
                ),
            ],
        ));
        nodes.push(Node::loop_for(
            "i",
            Expr::u32(0),
            Expr::u32(n),
            vec![Node::if_then(
                Expr::ne(Expr::load(sources, Expr::var("i")), Expr::u32(0)),
                vec![Node::store(parent, Expr::var("i"), Expr::var("i"))],
            )],
        ));

        nodes.push(Node::let_bind("found_sink", Expr::u32(0)));
        nodes.push(Node::let_bind("sink_node", Expr::u32(0)));

        nodes.push(Node::loop_for(
            "step",
            Expr::u32(0),
            Expr::u32(n),
            vec![Node::if_then(
                Expr::eq(Expr::var("found_sink"), Expr::u32(0)),
                vec![
                    Node::loop_for(
                        "u",
                        Expr::u32(0),
                        Expr::u32(n),
                        vec![Node::if_then(
                            Expr::ne(Expr::load(frontier, Expr::var("u")), Expr::u32(0)),
                            vec![Node::loop_for(
                                "v",
                                Expr::u32(0),
                                Expr::u32(n),
                                vec![Node::if_then(
                                    Expr::and(
                                        Expr::eq(Expr::load(visited, Expr::var("v")), Expr::u32(0)),
                                        Expr::ne(
                                            Expr::load(
                                                exchange_adj,
                                                Expr::add(
                                                    Expr::mul(Expr::var("u"), Expr::u32(n)),
                                                    Expr::var("v"),
                                                ),
                                            ),
                                            Expr::u32(0),
                                        ),
                                    ),
                                    vec![
                                        Node::store(visited, Expr::var("v"), Expr::u32(1)),
                                        Node::store(next_frontier, Expr::var("v"), Expr::u32(1)),
                                        Node::store(parent, Expr::var("v"), Expr::var("u")),
                                        Node::if_then(
                                            Expr::ne(
                                                Expr::load(sinks, Expr::var("v")),
                                                Expr::u32(0),
                                            ),
                                            vec![
                                                Node::assign("found_sink", Expr::u32(1)),
                                                Node::assign("sink_node", Expr::var("v")),
                                            ],
                                        ),
                                    ],
                                )],
                            )],
                        )],
                    ),
                    Node::loop_for(
                        "i",
                        Expr::u32(0),
                        Expr::u32(n),
                        vec![Node::store(
                            frontier,
                            Expr::var("i"),
                            Expr::load(next_frontier, Expr::var("i")),
                        )],
                    ),
                    Node::loop_for(
                        "i",
                        Expr::u32(0),
                        Expr::u32(n),
                        vec![Node::store(next_frontier, Expr::var("i"), Expr::u32(0))],
                    ),
                ],
            )],
        ));

        let recon = path_reconstruct(parent, "target_node_buf", path_out, path_len, n);
        nodes.push(Node::if_then(
            Expr::ne(Expr::var("found_sink"), Expr::u32(0)),
            vec![
                Node::store("target_node_buf", Expr::u32(0), Expr::var("sink_node")),
                Node::Region {
                    generator: Ident::from(OP_ID),
                    source_region: None,
                    body: Arc::new(recon.entry().to_vec()),
                },
                Node::let_bind("p_len", Expr::load(path_len, Expr::u32(0))),
                Node::loop_for(
                    "idx",
                    Expr::u32(0),
                    Expr::var("p_len"),
                    vec![
                        Node::let_bind("node", Expr::load(path_out, Expr::var("idx"))),
                        Node::let_bind("current_x", Expr::load(set_x, Expr::var("node"))),
                        Node::store(
                            set_x,
                            Expr::var("node"),
                            Expr::sub(Expr::u32(1), Expr::var("current_x")),
                        ),
                    ],
                ),
            ],
        ));
    }

    Program::wrapped(
        vec![
            BufferDecl::storage(exchange_adj, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(n * n),
            BufferDecl::storage(sources, 1, BufferAccess::ReadOnly, DataType::U32).with_count(n),
            BufferDecl::storage(sinks, 2, BufferAccess::ReadOnly, DataType::U32).with_count(n),
            BufferDecl::storage(set_x, 3, BufferAccess::ReadWrite, DataType::U32).with_count(n),
            BufferDecl::storage(parent, 4, BufferAccess::ReadWrite, DataType::U32).with_count(n),
            BufferDecl::storage(frontier, 5, BufferAccess::ReadWrite, DataType::U32).with_count(n),
            BufferDecl::storage(next_frontier, 6, BufferAccess::ReadWrite, DataType::U32)
                .with_count(n),
            BufferDecl::storage(visited, 7, BufferAccess::ReadWrite, DataType::U32).with_count(n),
            BufferDecl::storage(any_change, 8, BufferAccess::ReadWrite, DataType::U32)
                .with_count(1),
            BufferDecl::storage(path_out, 9, BufferAccess::ReadWrite, DataType::U32).with_count(n),
            BufferDecl::storage(path_len, 10, BufferAccess::ReadWrite, DataType::U32).with_count(1),
            BufferDecl::storage(
                "target_node_buf",
                11,
                BufferAccess::ReadWrite,
                DataType::U32,
            )
            .with_count(1),
        ],
        [1, 1, 1],
        vec![Node::Region {
            generator: Ident::from(OP_ID),
            source_region: None,
            body: Arc::new(nodes),
        }],
    )
}

/// CPU reference: One full Edmonds augmentation.
#[must_use]
pub fn cpu_ref(
    exchange_adj: &[u32],
    sources: &[u32],
    sinks: &[u32],
    set_x: &[u32],
    n: usize,
) -> Vec<u32> {
    let mut out = Vec::new();
    let mut parent = Vec::new();
    let mut visited = Vec::new();
    let mut queue = Vec::new();
    cpu_ref_into(
        exchange_adj,
        sources,
        sinks,
        set_x,
        n,
        &mut out,
        &mut parent,
        &mut visited,
        &mut queue,
    );
    out
}

/// CPU reference using caller-owned BFS scratch.
#[allow(clippy::too_many_arguments)]
pub fn cpu_ref_into(
    exchange_adj: &[u32],
    sources: &[u32],
    sinks: &[u32],
    set_x: &[u32],
    n: usize,
    out: &mut Vec<u32>,
    parent: &mut Vec<u32>,
    visited: &mut Vec<u32>,
    queue: &mut Vec<usize>,
) {
    out.clear();
    out.extend_from_slice(set_x);
    parent.clear();
    parent.resize(n, 0);
    visited.clear();
    visited.resize(n, 0);
    queue.clear();

    for i in 0..n {
        if sources[i] != 0 {
            queue.push(i);
            visited[i] = 1;
            parent[i] = i as u32;
        }
    }

    let mut found_sink = None;
    let mut head = 0;
    while head < queue.len() {
        let u = queue[head];
        head += 1;
        if sinks[u] != 0 {
            found_sink = Some(u);
            break;
        }
        for v in 0..n {
            if visited[v] == 0 && exchange_adj[u * n + v] != 0 {
                visited[v] = 1;
                parent[v] = u as u32;
                queue.push(v);
            }
        }
    }

    if let Some(sink) = found_sink {
        let mut curr = sink;
        loop {
            out[curr] = 1 - out[curr];
            let next = parent[curr] as usize;
            if next == curr {
                break;
            }
            curr = next;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_ref_single_augmentation() {
        let adj = vec![0, 1, 0, 0, 0, 1, 0, 0, 0];
        let src = vec![1, 0, 0];
        let snk = vec![0, 0, 1];
        let x = vec![0, 0, 0];
        let x_new = cpu_ref(&adj, &src, &snk, &x, 3);
        assert_eq!(x_new, vec![1, 1, 1]);
    }

    #[test]
    fn cpu_ref_into_reuses_bfs_storage() {
        let adj = vec![0, 1, 0, 0, 0, 1, 0, 0, 0];
        let src = vec![1, 0, 0];
        let snk = vec![0, 0, 1];
        let x = vec![0, 0, 0];
        let mut out = Vec::new();
        let mut parent = Vec::new();
        let mut visited = Vec::new();
        let mut queue = Vec::new();

        cpu_ref_into(
            &adj,
            &src,
            &snk,
            &x,
            3,
            &mut out,
            &mut parent,
            &mut visited,
            &mut queue,
        );
        let out_ptr = out.as_ptr();
        let queue_ptr = queue.as_ptr();
        cpu_ref_into(
            &adj,
            &src,
            &snk,
            &x,
            3,
            &mut out,
            &mut parent,
            &mut visited,
            &mut queue,
        );

        assert_eq!(out, vec![1, 1, 1]);
        assert_eq!(out.as_ptr(), out_ptr);
        assert_eq!(queue.as_ptr(), queue_ptr);
    }

    #[test]
    fn program_buffer_layout() {
        let p = matroid_intersection_full(
            "adj", "src", "snk", "x", "p", "f", "nf", "v", "ch", "po", "pl", 4, 1,
        );
        assert_eq!(p.buffers().len(), 12);
    }
}
