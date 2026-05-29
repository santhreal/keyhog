use std::sync::Arc;

use super::layout::{
    BATCH_OP_ID, BINDING_CHANGED, BINDING_FRONTIER_IN, BINDING_FRONTIER_OUT, OP_ID,
    PERSISTENT_BFS_WORKGROUP_SIZE,
};
use crate::graph::persistent_bfs_step::persistent_bfs_step_child_prefixed_with_active;
use crate::graph::program_graph::ProgramGraphShape;
use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Words needed to hold a bitset over `node_count` nodes.
#[must_use]
pub const fn bitset_words(node_count: u32) -> u32 {
    crate::bitset::bitset_words(node_count)
}

/// Build the IR `Program` for persistent BFS.
///
/// The kernel copies `frontier_in` into `frontier_out`, then performs up
/// to `max_iters` forward traversal steps.  The first four iterations are
/// unrolled with inter-step workgroup barriers and a shared `wg_scratch`
/// array; any additional iterations run in a plain bounded loop.
///
/// `changed` is a single u32 word that is set to `1` if *any* step produced
/// a new reachable node.
#[must_use]
pub fn persistent_bfs(
    shape: ProgramGraphShape,
    frontier_in: &str,
    frontier_out: &str,
    edge_kind_mask: u32,
    max_iters: u32,
) -> Program {
    let words = bitset_words(shape.node_count);
    let t = Expr::gid_x();

    let unrolled_iter = |iter: u32| -> Node {
        persistent_bfs_step_child_prefixed_with_active(
            OP_ID,
            shape,
            frontier_out,
            "changed",
            "wg_scratch",
            "wg_active",
            edge_kind_mask,
            &format!("unroll_{iter}"),
        )
    };

    let mut entry: Vec<Node> = vec![
        // Seed frontier_out from frontier_in.
        Node::if_then(
            Expr::eq(Expr::local_x(), Expr::u32(0)),
            vec![Node::loop_for(
                "seed_word_idx",
                Expr::u32(0),
                Expr::u32(words),
                vec![Node::store(
                    frontier_out,
                    Expr::var("seed_word_idx"),
                    Expr::load(frontier_in, Expr::var("seed_word_idx")),
                )],
            )],
        ),
        // Zero the global changed flag.
        Node::if_then(
            Expr::eq(t.clone(), Expr::u32(0)),
            vec![
                Node::store("changed", Expr::u32(0), Expr::u32(0)),
                Node::store("wg_active", Expr::u32(0), Expr::u32(1)),
            ],
        ),
        // Barrier clears fusion hazards from the plain store above before the
        // first atomic access inside the unrolled steps.
        Node::barrier(),
    ];

    let unroll_count = max_iters.min(4);
    for iter in 0..unroll_count {
        entry.push(unrolled_iter(iter));
    }

    let remaining = max_iters.saturating_sub(unroll_count);
    if remaining > 0 {
        entry.push(Node::loop_for(
            "iter",
            Expr::u32(0),
            Expr::u32(remaining),
            vec![Node::if_then(
                Expr::ne(
                    Expr::load("wg_active", Expr::u32(0)),
                    Expr::u32(0),
                ),
                vec![
                    Node::let_bind("local_changed", Expr::u32(0)),
                    Node::if_then(
                        Expr::lt(t.clone(), Expr::u32(shape.node_count)),
                        vec![
                            crate::graph::csr_forward_or_changed::csr_forward_or_changed_child_prefixed(
                                OP_ID,
                                shape,
                                frontier_out,
                                "local_changed",
                                edge_kind_mask,
                                "remaining_csr",
                            ),
                        ],
                    ),
                    Node::if_then(
                        Expr::eq(t.clone(), Expr::u32(0)),
                        vec![Node::store(
                            "wg_active",
                            Expr::u32(0),
                            Expr::var("local_changed"),
                        )],
                    ),
                    Node::if_then(
                        Expr::eq(Expr::var("local_changed"), Expr::u32(1)),
                        vec![Node::let_bind(
                            "_",
                            Expr::atomic_or("changed", Expr::u32(0), Expr::u32(1)),
                        )],
                    ),
                ],
            )],
        ));
    }

    let mut buffers = shape.read_only_buffers();
    buffers.push(
        BufferDecl::storage(
            frontier_in,
            BINDING_FRONTIER_IN,
            BufferAccess::ReadOnly,
            DataType::U32,
        )
        .with_count(words.max(1)),
    );
    buffers.push(
        BufferDecl::storage(
            frontier_out,
            BINDING_FRONTIER_OUT,
            BufferAccess::ReadWrite,
            DataType::U32,
        )
        .with_count(words.max(1)),
    );
    buffers.push(
        BufferDecl::storage(
            "changed",
            BINDING_CHANGED,
            BufferAccess::ReadWrite,
            DataType::U32,
        )
        .with_count(1),
    );
    buffers.push(BufferDecl::workgroup("wg_scratch", 256, DataType::U32));
    buffers.push(BufferDecl::workgroup("wg_active", 1, DataType::U32));

    Program::wrapped(
        buffers,
        PERSISTENT_BFS_WORKGROUP_SIZE,
        vec![Node::Region {
            generator: Ident::from(OP_ID),
            source_region: None,
            body: Arc::new(entry),
        }],
    )
}

/// Build a batched persistent-BFS Program.
///
/// Frontier buffers are flat `[query][word]` arrays. The launch topology is
/// one workgroup per query on `grid.y`; inside each query the same persistent
/// CSR expansion contract as [`persistent_bfs`] is applied to that query's
/// frontier slice.
#[must_use]
pub fn persistent_bfs_batch(
    shape: ProgramGraphShape,
    frontier_in: &str,
    frontier_out: &str,
    changed: &str,
    query_count: u32,
    edge_kind_mask: u32,
    max_iters: u32,
) -> Program {
    try_persistent_bfs_batch(
        shape,
        frontier_in,
        frontier_out,
        changed,
        query_count,
        edge_kind_mask,
        max_iters,
    )
    .unwrap_or_else(|err| panic!("{err}"))
}

/// Build a batched persistent-BFS Program with checked flat-frontier sizing.
pub fn try_persistent_bfs_batch(
    shape: ProgramGraphShape,
    frontier_in: &str,
    frontier_out: &str,
    changed: &str,
    query_count: u32,
    edge_kind_mask: u32,
    max_iters: u32,
) -> Result<Program, String> {
    let words = bitset_words(shape.node_count).max(1);
    let q = Expr::gid_y();
    let base = Expr::mul(q.clone(), Expr::u32(words));

    let src = "batch_src";
    let word_idx = "batch_word_idx";
    let bit_mask = "batch_bit_mask";
    let src_word = "batch_src_word";
    let edge_start = "batch_edge_start";
    let edge_end = "batch_edge_end";
    let edge_iter = "batch_edge";
    let kind_mask = "batch_kind_mask";
    let dst = "batch_dst";
    let dst_word_idx = "batch_dst_word_idx";
    let dst_bit = "batch_dst_bit";
    let old = "batch_old";
    let local_changed = "batch_local_changed";
    let active = "batch_active";

    let per_source = vec![
        Node::let_bind(word_idx, Expr::shr(Expr::var(src), Expr::u32(5))),
        Node::let_bind(
            bit_mask,
            Expr::shl(Expr::u32(1), Expr::bitand(Expr::var(src), Expr::u32(31))),
        ),
        Node::let_bind(
            src_word,
            Expr::load(frontier_out, Expr::add(base.clone(), Expr::var(word_idx))),
        ),
        Node::if_then(
            Expr::ne(
                Expr::bitand(Expr::var(src_word), Expr::var(bit_mask)),
                Expr::u32(0),
            ),
            vec![
                Node::let_bind(edge_start, Expr::load("pg_edge_offsets", Expr::var(src))),
                Node::let_bind(
                    edge_end,
                    Expr::load("pg_edge_offsets", Expr::add(Expr::var(src), Expr::u32(1))),
                ),
                Node::loop_for(
                    edge_iter,
                    Expr::var(edge_start),
                    Expr::var(edge_end),
                    vec![
                        Node::let_bind(
                            kind_mask,
                            Expr::load("pg_edge_kind_mask", Expr::var(edge_iter)),
                        ),
                        Node::if_then(
                            Expr::ne(
                                Expr::bitand(Expr::var(kind_mask), Expr::u32(edge_kind_mask)),
                                Expr::u32(0),
                            ),
                            vec![
                                Node::let_bind(
                                    dst,
                                    Expr::load("pg_edge_targets", Expr::var(edge_iter)),
                                ),
                                Node::if_then(
                                    Expr::lt(Expr::var(dst), Expr::u32(shape.node_count)),
                                    vec![
                                        Node::let_bind(
                                            dst_word_idx,
                                            Expr::shr(Expr::var(dst), Expr::u32(5)),
                                        ),
                                        Node::let_bind(
                                            dst_bit,
                                            Expr::shl(
                                                Expr::u32(1),
                                                Expr::bitand(Expr::var(dst), Expr::u32(31)),
                                            ),
                                        ),
                                        Node::let_bind(
                                            old,
                                            Expr::atomic_or(
                                                frontier_out,
                                                Expr::add(base.clone(), Expr::var(dst_word_idx)),
                                                Expr::var(dst_bit),
                                            ),
                                        ),
                                        Node::if_then(
                                            Expr::eq(
                                                Expr::bitand(Expr::var(old), Expr::var(dst_bit)),
                                                Expr::u32(0),
                                            ),
                                            vec![Node::assign(local_changed, Expr::u32(1))],
                                        ),
                                    ],
                                ),
                            ],
                        ),
                    ],
                ),
            ],
        ),
    ];

    let iter_body = vec![
        Node::let_bind(local_changed, Expr::u32(0)),
        Node::if_then(
            Expr::ne(Expr::var(active), Expr::u32(0)),
            vec![Node::if_then(
                Expr::eq(Expr::local_x(), Expr::u32(0)),
                vec![Node::loop_for(
                    src,
                    Expr::u32(0),
                    Expr::u32(shape.node_count),
                    per_source,
                )],
            )],
        ),
        Node::assign(active, Expr::var(local_changed)),
        Node::if_then(
            Expr::eq(Expr::var(local_changed), Expr::u32(1)),
            vec![Node::let_bind(
                "batch_changed_old",
                Expr::atomic_or(changed, q.clone(), Expr::u32(1)),
            )],
        ),
        Node::barrier(),
    ];

    let entry: Vec<Node> = vec![
        Node::if_then(
            Expr::eq(Expr::local_x(), Expr::u32(0)),
            vec![Node::loop_for(
                "batch_copy_word",
                Expr::u32(0),
                Expr::u32(words),
                vec![Node::store(
                    frontier_out,
                    Expr::add(base.clone(), Expr::var("batch_copy_word")),
                    Expr::load(
                        frontier_in,
                        Expr::add(base.clone(), Expr::var("batch_copy_word")),
                    ),
                )],
            )],
        ),
        Node::if_then(
            Expr::eq(Expr::local_x(), Expr::u32(0)),
            vec![Node::store(changed, q.clone(), Expr::u32(0))],
        ),
        Node::barrier(),
        Node::let_bind(active, Expr::u32(1)),
        Node::loop_for("batch_iter", Expr::u32(0), Expr::u32(max_iters), iter_body),
    ];

    let total_words = checked_batch_frontier_words(words, query_count, BATCH_OP_ID)?;
    let mut buffers = shape.try_read_only_buffers()?;
    buffers.push(
        BufferDecl::storage(
            frontier_in,
            BINDING_FRONTIER_IN,
            BufferAccess::ReadOnly,
            DataType::U32,
        )
        .with_count(total_words.max(1)),
    );
    buffers.push(
        BufferDecl::storage(
            frontier_out,
            BINDING_FRONTIER_OUT,
            BufferAccess::ReadWrite,
            DataType::U32,
        )
        .with_count(total_words.max(1)),
    );
    buffers.push(
        BufferDecl::storage(
            changed,
            BINDING_CHANGED,
            BufferAccess::ReadWrite,
            DataType::U32,
        )
        .with_count(query_count.max(1)),
    );

    Ok(Program::wrapped(
        buffers,
        PERSISTENT_BFS_WORKGROUP_SIZE,
        vec![Node::Region {
            generator: Ident::from(BATCH_OP_ID),
            source_region: None,
            body: Arc::new(entry),
        }],
    ))
}

fn checked_batch_frontier_words(
    words_per_query: u32,
    query_count: u32,
    op_id: &'static str,
) -> Result<u32, String> {
    words_per_query.checked_mul(query_count.max(1)).ok_or_else(|| {
        format!(
            "{op_id} frontier words overflow u32: words_per_query={words_per_query}, query_count={query_count}. Fix: shard the BFS query batch before GPU dispatch."
        )
    })
}

