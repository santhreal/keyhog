//! `persistent_bfs` — on-device multi-step BFS frontier expansion.
//!
//! The kernel copies `frontier_in` into `frontier_out`, then performs up to
//! `max_iters` forward traversal steps, accumulating reachable nodes into
//! `frontier_out` via atomic OR.  The first `min(max_iters, 4)` iterations
//! are unrolled and use a workgroup-local `wg_scratch` buffer to coalesce
//! per-workgroup change detection between steps.
//!
use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

use crate::graph::persistent_bfs_step::persistent_bfs_step_child_prefixed_with_active;
use crate::graph::program_graph::{ProgramGraphShape, BINDING_PRIMITIVE_START};

/// Canonical op id.
pub const OP_ID: &str = "vyre-primitives::graph::persistent_bfs";
/// Canonical op id for batched persistent BFS over many seed frontiers.
pub const BATCH_OP_ID: &str = "vyre-primitives::graph::persistent_bfs_batch";

/// Canonical binding index for the input frontier bitset.
pub const BINDING_FRONTIER_IN: u32 = BINDING_PRIMITIVE_START;
/// Canonical binding index for the output frontier bitset.
pub const BINDING_FRONTIER_OUT: u32 = BINDING_PRIMITIVE_START + 1;
/// Canonical binding index for the global changed flag.
pub const BINDING_CHANGED: u32 = BINDING_PRIMITIVE_START + 2;

/// Validated persistent-BFS graph layout metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PersistentBfsLayout {
    /// Number of graph nodes accepted by the primitive.
    pub node_count: u32,
    /// Number of logical CSR edges.
    pub edge_count: u32,
    /// Number of u32 words in one frontier bitset.
    pub words: usize,
    /// Number of u32 words in one frontier bitset, narrowed for cache keys.
    pub words_u32: u32,
    /// Number of u32 words required by node-indexed scratch buffers.
    pub node_words: usize,
    /// Number of u32 words required by physical edge buffers after padding.
    pub edge_storage_words: usize,
}

/// Validated flat-frontier batch metadata for persistent BFS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PersistentBfsBatchLayout {
    /// Number of queries in the batch, narrowed for GPU grid dimensions.
    pub query_count: u32,
    /// Total number of u32 words in the flat `[query][word]` frontier array.
    pub total_words: usize,
}

/// Validated single-frontier metadata for resident persistent BFS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PersistentBfsFrontierLayout {
    /// Number of u32 words in the frontier bitset.
    pub words: usize,
    /// Number of u32 words in the frontier bitset, narrowed for primitive metadata.
    pub words_u32: u32,
}

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
        Node::let_bind("seed_word_idx", t.clone()),
        Node::if_then(
            Expr::lt(Expr::var("seed_word_idx"), Expr::u32(words)),
            vec![Node::store(
                frontier_out,
                Expr::var("seed_word_idx"),
                Expr::load(frontier_in, Expr::var("seed_word_idx")),
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
        [256, 1, 1],
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
    match try_persistent_bfs_batch(
        shape,
        frontier_in,
        frontier_out,
        changed,
        query_count,
        edge_kind_mask,
        max_iters,
    ) {
        Ok(program) => program,
        Err(error) => {
            eprintln!("{error}");
            inert_persistent_bfs_batch_program(shape, frontier_in, frontier_out, changed)
        }
    }
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
    let t = Expr::gid_x();
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
            Expr::lt(t.clone(), Expr::u32(words)),
            vec![Node::store(
                frontier_out,
                Expr::add(base.clone(), t.clone()),
                Expr::load(frontier_in, Expr::add(base.clone(), t.clone())),
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
    let mut buffers = shape.read_only_buffers();
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
        [256, 1, 1],
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

fn inert_persistent_bfs_batch_program(
    shape: ProgramGraphShape,
    frontier_in: &str,
    frontier_out: &str,
    changed: &str,
) -> Program {
    let mut buffers = shape.read_only_buffers();
    buffers.push(
        BufferDecl::storage(
            frontier_in,
            BINDING_FRONTIER_IN,
            BufferAccess::ReadOnly,
            DataType::U32,
        )
        .with_count(1),
    );
    buffers.push(
        BufferDecl::storage(
            frontier_out,
            BINDING_FRONTIER_OUT,
            BufferAccess::ReadWrite,
            DataType::U32,
        )
        .with_count(1),
    );
    buffers.push(
        BufferDecl::storage(
            changed,
            BINDING_CHANGED,
            BufferAccess::ReadWrite,
            DataType::U32,
        )
        .with_count(1),
    );

    Program::wrapped(
        buffers,
        [256, 1, 1],
        vec![Node::Region {
            generator: Ident::from(BATCH_OP_ID),
            source_region: None,
            body: Arc::new(vec![Node::return_()]),
        }],
    )
}

/// CPU reference: run BFS up to `max_iters` steps, accumulating into a
/// running bitset.  Returns the final frontier and a sticky `changed`
/// flag (`1` if any step added new nodes, else `0`).
#[must_use]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn cpu_ref(
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    frontier_in: &[u32],
    allow_mask: u32,
    max_iters: u32,
) -> (Vec<u32>, u32) {
    let mut out = Vec::new();
    let changed = cpu_ref_into(
        node_count,
        edge_offsets,
        edge_targets,
        edge_kind_mask,
        frontier_in,
        allow_mask,
        max_iters,
        &mut out,
    );
    (out, changed)
}

/// CPU reference into caller-owned output storage.
///
/// Runs BFS up to `max_iters` steps, accumulating into `frontier_out`. Returns
/// a sticky changed flag (`1` if any step added new nodes, else `0`).
#[cfg(any(test, feature = "cpu-parity"))]
pub fn cpu_ref_into(
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    frontier_in: &[u32],
    allow_mask: u32,
    max_iters: u32,
    frontier_out: &mut Vec<u32>,
) -> u32 {
    validate_persistent_bfs_inputs(
        node_count,
        edge_offsets,
        edge_targets,
        edge_kind_mask,
        frontier_in,
    )
    .unwrap_or_else(|err| panic!("persistent_bfs CPU oracle received malformed input. {err}"));
    let layout = validate_persistent_bfs_inputs(
        node_count,
        edge_offsets,
        edge_targets,
        edge_kind_mask,
        frontier_in,
    )
    .unwrap_or_else(|err| panic!("persistent_bfs CPU oracle received malformed input. {err}"));
    let words = layout.words;
    frontier_out.clear();
    frontier_out.extend_from_slice(frontier_in);
    frontier_out.resize(words, 0);
    let mut changed = 0u32;

    for _ in 0..max_iters {
        let step = crate::graph::csr_forward_traverse::cpu_ref(
            node_count,
            edge_offsets,
            edge_targets,
            edge_kind_mask,
            frontier_out,
            allow_mask,
        );
        let mut step_changed = false;
        for w in 0..words {
            let old = frontier_out[w];
            frontier_out[w] |= step[w];
            if frontier_out[w] != old {
                step_changed = true;
            }
        }
        if step_changed {
            changed = 1;
        } else {
            break;
        }
    }
    changed
}

/// Validate a persistent-BFS CSR graph layout.
///
/// # Errors
///
/// Returns an actionable diagnostic when offsets are malformed, masks and
/// targets diverge, the edge count exceeds u32 indexing, or an edge target is
/// outside `0..node_count`.
pub fn validate_persistent_bfs_graph_layout(
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
) -> Result<PersistentBfsLayout, String> {
    let expected_offsets = (node_count as usize).checked_add(1).ok_or_else(|| {
        format!("Fix: persistent_bfs node_count + 1 overflows usize for node_count={node_count}.")
    })?;
    if edge_offsets.len() != expected_offsets {
        return Err(format!(
            "Fix: persistent_bfs expected {expected_offsets} CSR offsets for {node_count} nodes, got {}.",
            edge_offsets.len()
        ));
    }
    if edge_targets.len() != edge_kind_mask.len() {
        return Err(format!(
            "Fix: persistent_bfs requires edge_targets.len() == edge_kind_mask.len(), got {} vs {}.",
            edge_targets.len(),
            edge_kind_mask.len()
        ));
    }
    let edge_count = u32::try_from(edge_targets.len()).map_err(|_| {
        format!(
            "Fix: persistent_bfs edge count {} exceeds u32 index space.",
            edge_targets.len()
        )
    })?;
    let final_offset = edge_offsets[expected_offsets - 1] as usize;
    if final_offset != edge_targets.len() {
        return Err(format!(
            "Fix: persistent_bfs final CSR offset {final_offset} must equal edge_count {}.",
            edge_targets.len()
        ));
    }
    for (row, pair) in edge_offsets.windows(2).enumerate() {
        if pair[0] > pair[1] {
            return Err(format!(
                "Fix: persistent_bfs CSR offsets are non-monotonic at row {row}: {} > {}.",
                pair[0], pair[1]
            ));
        }
    }
    for (idx, &target) in edge_targets.iter().enumerate() {
        if target >= node_count {
            return Err(format!(
                "Fix: persistent_bfs CSR target[{idx}]={target} is outside node_count {node_count}."
            ));
        }
    }
    let words_u32 = bitset_words(node_count);
    Ok(PersistentBfsLayout {
        node_count,
        edge_count,
        words: words_u32 as usize,
        words_u32,
        node_words: node_count as usize,
        edge_storage_words: edge_targets.len().max(1),
    })
}

/// Validate the full non-resident persistent-BFS dispatch/input contract.
///
/// # Errors
///
/// Returns an actionable diagnostic when the graph layout is malformed or the
/// seed frontier length does not match the graph.
pub fn validate_persistent_bfs_inputs(
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    frontier_in: &[u32],
) -> Result<PersistentBfsLayout, String> {
    let layout = validate_persistent_bfs_graph_layout(
        node_count,
        edge_offsets,
        edge_targets,
        edge_kind_mask,
    )?;
    if frontier_in.len() != layout.words {
        return Err(format!(
            "Fix: persistent_bfs expected frontier length {} words for {node_count} nodes, got {}.",
            layout.words,
            frontier_in.len()
        ));
    }
    Ok(layout)
}

/// Validate flat-frontier batch shape for persistent BFS.
///
/// The frontier buffer is laid out as `[query][word]`, where
/// `words_per_query` is derived from the already-validated graph layout.
///
/// # Errors
///
/// Returns an actionable diagnostic when query count cannot be represented by
/// GPU grid dimensions, the flat word count overflows, or the supplied
/// frontier buffer length does not match `words_per_query * query_count`.
pub fn validate_persistent_bfs_batch_frontiers(
    words_per_query: usize,
    frontier_inputs: &[u32],
    query_count: usize,
) -> Result<PersistentBfsBatchLayout, String> {
    let query_count_u32 = u32::try_from(query_count).map_err(|_| {
        format!(
            "Fix: persistent_bfs_batch query_count {query_count} exceeds u32::MAX; shard the BFS query batch before GPU dispatch."
        )
    })?;
    let total_words = words_per_query.checked_mul(query_count).ok_or_else(|| {
        format!(
            "Fix: persistent_bfs_batch word count overflows usize for {words_per_query} words/query and {query_count} queries; shard the BFS query batch before GPU dispatch."
        )
    })?;
    if frontier_inputs.len() != total_words {
        return Err(format!(
            "Fix: persistent_bfs_batch expected {total_words} frontier word(s), got {}.",
            frontier_inputs.len()
        ));
    }
    Ok(PersistentBfsBatchLayout {
        query_count: query_count_u32,
        total_words,
    })
}

/// Validate a single persistent-BFS frontier against an already-validated graph layout.
///
/// # Errors
///
/// Returns an actionable diagnostic when the graph frontier width cannot be
/// represented by primitive metadata, or when the supplied frontier length
/// does not match the graph frontier width.
pub fn validate_persistent_bfs_frontier(
    words_per_query: usize,
    frontier_in: &[u32],
) -> Result<PersistentBfsFrontierLayout, String> {
    let words_u32 = u32::try_from(words_per_query).map_err(|_| {
        format!(
            "Fix: persistent_bfs frontier word count {words_per_query} exceeds u32::MAX; shard the graph before GPU dispatch."
        )
    })?;
    if frontier_in.len() != words_per_query {
        return Err(format!(
            "Fix: persistent_bfs expected frontier length {words_per_query} word(s), got {}.",
            frontier_in.len()
        ));
    }
    Ok(PersistentBfsFrontierLayout {
        words: words_per_query,
        words_u32,
    })
}

/// Stable FNV-1a hash of a persistent-BFS graph layout.
#[must_use]
pub fn persistent_bfs_layout_hash(
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    fn mix(hash: &mut u64, value: u32) {
        for byte in value.to_le_bytes() {
            *hash ^= u64::from(byte);
            *hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    mix(&mut hash, node_count);
    mix(&mut hash, edge_offsets.len() as u32);
    for &value in edge_offsets {
        mix(&mut hash, value);
    }
    mix(&mut hash, edge_targets.len() as u32);
    for &value in edge_targets {
        mix(&mut hash, value);
    }
    mix(&mut hash, edge_kind_mask.len() as u32);
    for &value in edge_kind_mask {
        mix(&mut hash, value);
    }
    hash
}

#[cfg(feature = "inventory-registry")]
inventory::submit! {
    crate::harness::OpEntry::new(
        OP_ID,
        || persistent_bfs(ProgramGraphShape::new(4, 4), "fin", "fout", 0xFFFF_FFFF, 4),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![
                to_bytes(&[0, 0, 0, 0]),          // pg_nodes
                to_bytes(&[0, 2, 3, 4, 4]),       // pg_edge_offsets
                to_bytes(&[1, 2, 3, 3]),          // pg_edge_targets
                to_bytes(&[1, 1, 1, 1]),          // pg_edge_kind_mask
                to_bytes(&[0, 0, 0, 0]),          // pg_node_tags
                to_bytes(&[0b0001]),              // frontier_in = {0}
                to_bytes(&[0]),                   // frontier_out
                to_bytes(&[0]),                   // changed
            ]]
        }),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            // After 4 iterations the graph 0→1,0→2,1→3,2→3 is fully closed.
            vec![vec![
                to_bytes(&[0b1111]),              // frontier_out = {0,1,2,3}
                to_bytes(&[1]),                   // changed
            ]]
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persistent_bfs_reaches_closure() {
        let (frontier, changed) = cpu_ref(
            4,
            &[0, 2, 3, 4, 4],
            &[1, 2, 3, 3],
            &[1, 1, 1, 1],
            &[0b0001],
            0xFFFF_FFFF,
            4,
        );
        assert_eq!(frontier, vec![0b1111]);
        assert_eq!(changed, 1);
    }

    #[test]
    fn cpu_ref_into_reuses_frontier_storage() {
        let mut frontier = Vec::with_capacity(8);
        let changed = cpu_ref_into(
            4,
            &[0, 1, 2, 3, 3],
            &[1, 2, 3],
            &[1, 1, 1],
            &[0b0001],
            0xFFFF_FFFF,
            8,
            &mut frontier,
        );
        let capacity = frontier.capacity();
        assert_eq!(frontier, vec![0b1111]);
        assert_eq!(changed, 1);

        let changed = cpu_ref_into(
            4,
            &[0, 1, 2, 3, 3],
            &[1, 2, 3],
            &[1, 1, 1],
            &[0],
            0xFFFF_FFFF,
            8,
            &mut frontier,
        );
        assert_eq!(frontier.capacity(), capacity);
        assert_eq!(frontier, vec![0]);
        assert_eq!(changed, 0);
    }

    #[test]
    fn reusable_layout_validation_rejects_bad_csr_and_frontier() {
        let err = validate_persistent_bfs_graph_layout(2, &[0, 2, 1], &[1], &[1]).unwrap_err();
        assert!(err.contains("final CSR offset") || err.contains("non-monotonic"));

        let err = validate_persistent_bfs_graph_layout(2, &[0, 1, 1], &[2], &[1]).unwrap_err();
        assert!(err.contains("outside node_count"));

        let err = validate_persistent_bfs_inputs(33, &[0; 34], &[], &[], &[0]).unwrap_err();
        assert!(err.contains("frontier length 2 words"));
    }

    #[test]
    fn reusable_graph_layout_returns_dispatch_shape() {
        assert_eq!(
            validate_persistent_bfs_graph_layout(33, &[0; 34], &[], &[]).unwrap(),
            PersistentBfsLayout {
                node_count: 33,
                edge_count: 0,
                words: 2,
                words_u32: 2,
                node_words: 33,
                edge_storage_words: 1,
            }
        );
        assert_eq!(
            validate_persistent_bfs_inputs(4, &[0, 1, 2, 3, 3], &[1, 2, 3], &[1, 1, 1], &[0])
                .unwrap(),
            PersistentBfsLayout {
                node_count: 4,
                edge_count: 3,
                words: 1,
                words_u32: 1,
                node_words: 4,
                edge_storage_words: 3,
            }
        );
    }

    #[test]
    fn reusable_batch_frontier_validation_accepts_empty_and_canonical_batches() {
        assert_eq!(
            validate_persistent_bfs_batch_frontiers(2, &[], 0).unwrap(),
            PersistentBfsBatchLayout {
                query_count: 0,
                total_words: 0,
            }
        );

        assert_eq!(
            validate_persistent_bfs_batch_frontiers(2, &[1, 0, 2, 0, 4, 0], 3).unwrap(),
            PersistentBfsBatchLayout {
                query_count: 3,
                total_words: 6,
            }
        );
    }

    #[test]
    fn reusable_batch_frontier_validation_rejects_bad_shape_and_overflow() {
        let err = validate_persistent_bfs_batch_frontiers(2, &[1, 0, 2], 2).unwrap_err();
        assert!(err.contains("expected 4 frontier word"));

        let err = validate_persistent_bfs_batch_frontiers(usize::MAX, &[], 2).unwrap_err();
        assert!(err.contains("word count overflows usize"));

        let err =
            validate_persistent_bfs_batch_frontiers(1, &[], u32::MAX as usize + 1).unwrap_err();
        assert!(err.contains("query_count"));
    }

    #[test]
    fn reusable_single_frontier_validation_accepts_canonical_frontier() {
        assert_eq!(
            validate_persistent_bfs_frontier(2, &[1, 0]).unwrap(),
            PersistentBfsFrontierLayout {
                words: 2,
                words_u32: 2,
            }
        );
    }

    #[test]
    fn reusable_single_frontier_validation_rejects_bad_shape_and_overflow() {
        let err = validate_persistent_bfs_frontier(2, &[1]).unwrap_err();
        assert!(err.contains("expected frontier length 2 word"));

        let err = validate_persistent_bfs_frontier(u32::MAX as usize + 1, &[]).unwrap_err();
        assert!(err.contains("frontier word count"));
    }

    #[test]
    fn layout_hash_distinguishes_edges_and_masks() {
        let a = persistent_bfs_layout_hash(2, &[0, 1, 1], &[1], &[1]);
        let b = persistent_bfs_layout_hash(2, &[0, 1, 1], &[1], &[2]);
        let c = persistent_bfs_layout_hash(2, &[0, 1, 1], &[0], &[1]);
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn empty_frontier_stays_empty() {
        let (frontier, changed) = cpu_ref(
            4,
            &[0, 2, 3, 4, 4],
            &[1, 2, 3, 3],
            &[1, 1, 1, 1],
            &[0],
            0xFFFF_FFFF,
            4,
        );
        assert_eq!(frontier, vec![0]);
        assert_eq!(changed, 0);
    }

    #[test]
    fn edge_mask_limits_reachability() {
        // 0→1 (mask 0b10), 0→2 (mask 0b01), 1→3 (mask 0b01), 2→3 (mask 0b01)
        let (frontier, changed) = cpu_ref(
            4,
            &[0, 2, 3, 4, 4],
            &[1, 2, 3, 3],
            &[0b10, 0b01, 0b01, 0b01],
            &[0b0001],
            0b01,
            4,
        );
        // From 0, only 0→2 is allowed. Then 2→3 is allowed.
        assert_eq!(frontier, vec![0b1101]);
        assert_eq!(changed, 1);
    }

    #[test]
    fn max_iters_caps_expansion() {
        // Chain: 0→1, 1→2, 2→3. Frontier = {0}.
        let (frontier, changed) = cpu_ref(
            4,
            &[0, 1, 2, 3, 3],
            &[1, 2, 3],
            &[1, 1, 1],
            &[0b0001],
            0xFFFF_FFFF,
            2,
        );
        // After 2 steps: {0,1,2}
        assert_eq!(frontier, vec![0b0111]);
        assert_eq!(changed, 1);
    }

    #[test]
    fn zero_max_iters_is_noop() {
        let (frontier, changed) = cpu_ref(
            4,
            &[0, 2, 3, 4, 4],
            &[1, 2, 3, 3],
            &[1, 1, 1, 1],
            &[0b0001],
            0xFFFF_FFFF,
            0,
        );
        assert_eq!(frontier, vec![0b0001]);
        assert_eq!(changed, 0);
    }

    #[test]
    fn program_builds_and_validates() {
        let program = persistent_bfs(ProgramGraphShape::new(8, 8), "fin", "fout", 0xFF, 4);
        assert_eq!(program.workgroup_size, [256, 1, 1]);
        // 5 canonical PG buffers + frontier_in + frontier_out + changed + wg_scratch + wg_active
        assert_eq!(program.buffers().len(), 10);
    }

    #[test]
    fn program_carries_device_side_convergence_flag() {
        let program = persistent_bfs(ProgramGraphShape::new(8, 8), "fin", "fout", 0xFF, 8);
        let debug = format!("{:?}", program.entry);
        assert!(
            debug.contains("wg_active"),
            "persistent_bfs must gate later device work through a workgroup-resident active flag"
        );
    }

    #[test]
    fn batch_program_carries_per_query_convergence_flag() {
        let program = persistent_bfs_batch(
            ProgramGraphShape::new(8, 8),
            "fin",
            "fout",
            "changed",
            4,
            0xFF,
            8,
        );
        let debug = format!("{:?}", program.entry);
        assert!(
            debug.contains("batch_active"),
            "persistent_bfs_batch must gate later per-query device work through an active flag"
        );
    }

    #[test]
    fn checked_batch_builder_rejects_flat_frontier_overflow() {
        let error = try_persistent_bfs_batch(
            ProgramGraphShape::new(u32::MAX, 0),
            "fin",
            "fout",
            "changed",
            33,
            0xFF,
            1,
        )
        .expect_err("checked batched persistent BFS builder must reject flat frontier overflow");

        assert!(
            error.contains("frontier words overflow u32"),
            "error should describe the flat frontier overflow: {error}"
        );
    }

    #[test]
    fn legacy_batch_builder_does_not_panic_on_flat_frontier_overflow() {
        let program = persistent_bfs_batch(
            ProgramGraphShape::new(u32::MAX, 0),
            "fin",
            "fout",
            "changed",
            33,
            0xFF,
            1,
        );

        assert_eq!(program.workgroup_size, [256, 1, 1]);
    }

    #[test]
    fn persistent_bfs_batch_release_source_has_checked_builder_without_panics() {
        let source = include_str!("persistent_bfs.rs");
        let batch_source = source
            .split("/// Build a batched persistent-BFS Program.")
            .nth(1)
            .expect("persistent BFS batch builder source must be present")
            .split("/// CPU reference:")
            .next()
            .expect("persistent BFS batch builder source must precede CPU oracle");

        assert!(
            batch_source.contains("pub fn try_persistent_bfs_batch(")
                && !batch_source.contains(concat!("panic", "!("))
                && !batch_source.contains(".unwrap_or_else("),
            "Fix: persistent_bfs_batch must expose checked release API and avoid production panics."
        );
    }
}
