//! Exploded supergraph primitive (G3).
//!
//! # What this is
//!
//! IFDS / IDE reframes interprocedural dataflow as a reachability
//! problem on the **exploded supergraph**: each `(proc, block,
//! fact)` triple is a graph vertex, and the edges are the flow
//! functions (GEN / KILL + summary + call-to-return). Once
//! expanded, the analysis collapses to a BFS over this graph —
//! which is the exact shape
//! [`crate::graph::csr_forward_traverse`] already handles.
//!
//! This module owns the **node encoding** — the bit-layout that
//! packs `(proc_id, block_id, fact_id)` into a single `u32` node id
//! — plus a CPU reference that builds the exploded CSR so tests in
//! `vyre-libs::dataflow::ifds_gpu` can prove the GPU kernel produces
//! byte-identical CSR output.
//!
//! # Bit layout
//!
//! ```text
//!   bits 31..20   proc_id   (12 bits — 4096 procedures per module)
//!   bits 19..10   block_id  (10 bits — 1024 blocks per procedure)
//!   bits 9..0     fact_id   (10 bits — 1024 facts per workgroup;
//!                            matches FACTS_PER_WORKGROUP and the
//!                            NFA subgroup sizing)
//! ```
//!
//! This deliberately leaves no room for >4096 procedures in a
//! single module. Any real codebase that exceeds that split along
//! a module boundary first — doing interprocedural dataflow over
//! 10 000+ procs in one pass is a different problem that we don't
//! solve here and shouldn't pretend to.
//!
//! # Status
//!
//! Node encoding, CSR builder, and tests. The GPU Program wrapper
//! (the actual kernel that walks edges in parallel) lives in
//! `vyre-libs::dataflow::ifds_gpu` and composes this encoding with
//! `csr_forward_traverse`.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Canonical op id for the IFDS CSR construction program.
pub const OP_ID: &str = "vyre-primitives::graph::exploded_build_ifds_csr";

/// Bits reserved for each component of the packed node id.
pub const PROC_BITS: u32 = 12;
/// Bits reserved for the basic-block component of the packed node id.
pub const BLOCK_BITS: u32 = 10;
/// Bits reserved for the fact component of the packed node id.
pub const FACT_BITS: u32 = 10;
const _SANITY: () = assert!(PROC_BITS + BLOCK_BITS + FACT_BITS == 32);

/// Max values for each component — one less than the available
/// space because zero is a valid id.
pub const MAX_PROC_ID: u32 = (1 << PROC_BITS) - 1;
/// Maximum encodable basic-block id.
pub const MAX_BLOCK_ID: u32 = (1 << BLOCK_BITS) - 1;
/// Maximum encodable fact id.
pub const MAX_FACT_ID: u32 = (1 << FACT_BITS) - 1;

/// Number of facts per workgroup lane. A 32-lane subgroup x
/// 32 bits = 1024 facts; wider subgroup layouts preserve the same budget.
/// Matches the
/// NFA window sizing in `nfa::subgroup_nfa` so both subsystems
/// share occupancy budget.
pub const FACTS_PER_WORKGROUP: usize = 1024;

const BLOCK_SHIFT: u32 = FACT_BITS;
const PROC_SHIFT: u32 = FACT_BITS + BLOCK_BITS;
const FACT_MASK: u32 = MAX_FACT_ID;
const BLOCK_MASK: u32 = MAX_BLOCK_ID;
const PROC_MASK: u32 = MAX_PROC_ID;

/// Checked dispatch layout for an exploded IFDS CSR build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IfdsCsrLayout {
    /// Whether the declared IFDS domain is empty and should not dispatch.
    pub empty: bool,
    /// Number of procedures in the exploded domain.
    pub num_procs: u32,
    /// Number of blocks per procedure.
    pub blocks_per_proc: u32,
    /// Number of facts per procedure.
    pub facts_per_proc: u32,
    /// Number of intra-procedural control-flow edges.
    pub intra_count: u32,
    /// Number of inter-procedural call/return edges.
    pub inter_count: u32,
    /// Number of GEN rules.
    pub gen_count: u32,
    /// Number of KILL rules.
    pub kill_count: u32,
    /// Number of u32 words required by each intra edge field buffer.
    pub intra_storage_words: usize,
    /// Number of u32 words required by each inter edge field buffer.
    pub inter_storage_words: usize,
    /// Number of u32 words required by each GEN rule field buffer.
    pub gen_storage_words: usize,
    /// Number of u32 words required by each KILL rule field buffer.
    pub kill_storage_words: usize,
    /// Dense nodes per procedure.
    pub slots_per_proc: u32,
    /// Total dense node count.
    pub total_nodes: u32,
    /// Number of `u32` words in `row_ptr`.
    pub row_words: usize,
    /// Number of `u32` words in the dispatch row cursor scratch buffer.
    pub row_cursor_words: usize,
    /// Maximum emitted column count for the declared edge/rule counts.
    pub max_col_count: u32,
    /// Number of `u32` words allocated for `col_idx`.
    pub col_buffer_words: usize,
}

/// Checked exploded-supergraph node count.
#[must_use]
pub fn ifds_node_count_checked(
    num_procs: u32,
    blocks_per_proc: u32,
    facts_per_proc: u32,
) -> Option<u32> {
    num_procs
        .checked_mul(blocks_per_proc)?
        .checked_mul(facts_per_proc)
}

/// Saturating exploded-supergraph node count for capacity planning UIs.
#[must_use]
pub fn ifds_node_count_saturating(
    num_procs: u32,
    blocks_per_proc: u32,
    facts_per_proc: u32,
) -> u32 {
    num_procs
        .saturating_mul(blocks_per_proc)
        .saturating_mul(facts_per_proc)
}

/// Maximum column count needed by the deterministic IFDS CSR builder.
#[must_use]
pub fn max_ifds_col_count(
    intra_count: u32,
    inter_count: u32,
    gen_count: u32,
    facts_per_proc: u32,
) -> Option<u32> {
    intra_count
        .checked_mul(facts_per_proc)
        .and_then(|v| v.checked_add(intra_count.checked_mul(gen_count)?))
        .and_then(|v| v.checked_add(inter_count.checked_mul(facts_per_proc)?))
}

/// Validate dimensions/counts and return the exact dispatch buffer layout.
pub fn validate_ifds_csr_layout(
    num_procs: u32,
    blocks_per_proc: u32,
    facts_per_proc: u32,
    intra_count: u32,
    inter_count: u32,
    gen_count: u32,
) -> Result<IfdsCsrLayout, String> {
    if num_procs == 0 || blocks_per_proc == 0 || facts_per_proc == 0 {
        return Err(format!(
            "Fix: exploded IFDS dimensions must be nonzero, got procs={num_procs}, blocks={blocks_per_proc}, facts={facts_per_proc}."
        ));
    }
    if !fits(
        num_procs.saturating_sub(1),
        blocks_per_proc.saturating_sub(1),
        facts_per_proc.saturating_sub(1),
    ) {
        return Err(format!(
            "Fix: exploded IFDS dimensions exceed packed IFDS limits: procs={num_procs}, blocks={blocks_per_proc}, facts={facts_per_proc}."
        ));
    }
    let slots_per_proc = blocks_per_proc.checked_mul(facts_per_proc).ok_or_else(|| {
        format!(
            "Fix: exploded IFDS blocks*facts overflows u32: {blocks_per_proc}*{facts_per_proc}."
        )
    })?;
    let total_nodes = num_procs.checked_mul(slots_per_proc).ok_or_else(|| {
        format!(
            "Fix: exploded IFDS procs*blocks*facts overflows u32: {num_procs}*{blocks_per_proc}*{facts_per_proc}."
        )
    })?;
    let row_ptr_count = total_nodes.checked_add(1).ok_or_else(|| {
        format!(
            "Fix: exploded IFDS total_nodes={total_nodes} overflows row_ptr count. Shard the IFDS graph before GPU dispatch."
        )
    })?;
    let max_col_count = max_ifds_col_count(intra_count, inter_count, gen_count, facts_per_proc)
        .ok_or_else(|| "Fix: exploded IFDS maximum column count overflows u32.".to_string())?;
    Ok(IfdsCsrLayout {
        empty: false,
        num_procs,
        blocks_per_proc,
        facts_per_proc,
        intra_count,
        inter_count,
        gen_count,
        kill_count: 0,
        intra_storage_words: (intra_count as usize).max(1),
        inter_storage_words: (inter_count as usize).max(1),
        gen_storage_words: (gen_count as usize).max(1),
        kill_storage_words: 1,
        slots_per_proc,
        total_nodes,
        row_words: row_ptr_count as usize,
        row_cursor_words: (total_nodes as usize).max(1),
        max_col_count,
        col_buffer_words: (max_col_count as usize).max(1),
    })
}

/// Validate the full IFDS CSR dispatch contract from caller-owned rule slices.
///
/// Returns the exact primitive dispatch layout so consumers do not narrow rule
/// counts or decide padded input-buffer widths locally.
pub fn validate_ifds_csr_inputs(
    num_procs: u32,
    blocks_per_proc: u32,
    facts_per_proc: u32,
    intra_edges: &[(u32, u32, u32)],
    inter_edges: &[(u32, u32, u32, u32)],
    flow_gen: &[(u32, u32, u32)],
    flow_kill: &[(u32, u32, u32)],
) -> Result<IfdsCsrLayout, String> {
    let intra_count = checked_rule_count("intra edge", intra_edges.len())?;
    let inter_count = checked_rule_count("inter edge", inter_edges.len())?;
    let gen_count = checked_rule_count("GEN", flow_gen.len())?;
    let kill_count = checked_rule_count("KILL", flow_kill.len())?;

    if num_procs == 0 || blocks_per_proc == 0 || facts_per_proc == 0 {
        if intra_count == 0 && inter_count == 0 && gen_count == 0 && kill_count == 0 {
            return Ok(IfdsCsrLayout {
                empty: true,
                num_procs,
                blocks_per_proc,
                facts_per_proc,
                intra_count,
                inter_count,
                gen_count,
                kill_count,
                intra_storage_words: 1,
                inter_storage_words: 1,
                gen_storage_words: 1,
                kill_storage_words: 1,
                slots_per_proc: 0,
                total_nodes: 0,
                row_words: 1,
                row_cursor_words: 1,
                max_col_count: 0,
                col_buffer_words: 1,
            });
        }
        return Err(format!(
            "Fix: exploded IFDS empty dimensions cannot carry rules, got intra={intra_count}, inter={inter_count}, gen={gen_count}, kill={kill_count}."
        ));
    }

    let mut layout = validate_ifds_csr_layout(
        num_procs,
        blocks_per_proc,
        facts_per_proc,
        intra_count,
        inter_count,
        gen_count,
    )?;
    layout.kill_count = kill_count;
    layout.kill_storage_words = flow_kill.len().max(1);
    Ok(layout)
}

fn checked_rule_count(kind: &str, len: usize) -> Result<u32, String> {
    u32::try_from(len)
        .map_err(|_| format!("Fix: exploded IFDS {kind} count {len} exceeds u32 index space."))
}

/// Sort each CSR row in place after validating row ranges.
pub fn canonicalize_csr_within_rows_in_place(
    row_ptr: &[u32],
    col_idx: &mut [u32],
) -> Result<(), String> {
    for window in row_ptr.windows(2) {
        let start = window[0] as usize;
        let end = window[1] as usize;
        if start > end || end > col_idx.len() {
            return Err(format!(
                "Fix: exploded IFDS CSR row range {start}..{end} exceeds col_idx.len()={}.",
                col_idx.len()
            ));
        }
        col_idx[start..end].sort_unstable();
    }
    Ok(())
}

/// Return a row-canonical CSR copy.
#[must_use]
pub fn canonicalize_csr_within_rows(row_ptr: &[u32], col_idx: &[u32]) -> (Vec<u32>, Vec<u32>) {
    let mut canonical_col = col_idx.to_vec();
    canonicalize_csr_within_rows_in_place(row_ptr, &mut canonical_col)
        .expect("exploded IFDS CSR canonicalization received invalid row_ptr/col_idx");
    (row_ptr.to_vec(), canonical_col)
}

/// Build a GPU Program that emits the exploded-supergraph CSR.
///
/// This is a deterministic single-lane construction pass: count each
/// source row, prefix row counts, then fill `col_idx`. It removes the
/// production CPU-reference path while preserving a stable API for a
/// later parallel count/scan/fill implementation.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn build_ifds_csr_program(
    num_procs: u32,
    blocks_per_proc: u32,
    facts_per_proc: u32,
    intra_count: u32,
    inter_count: u32,
    gen_count: u32,
    kill_count: u32,
    max_col_count: u32,
) -> Program {
    if num_procs == 0 || blocks_per_proc == 0 || facts_per_proc == 0 {
        return crate::invalid_output_program(
            OP_ID,
            "row_ptr",
            DataType::U32,
            format!(
                "Fix: exploded IFDS dimensions must be nonzero, got procs={num_procs}, blocks={blocks_per_proc}, facts={facts_per_proc}."
            ),
        );
    }
    let Some(slots_per_proc) = blocks_per_proc.checked_mul(facts_per_proc) else {
        return crate::invalid_output_program(
            OP_ID,
            "row_ptr",
            DataType::U32,
            "Fix: exploded IFDS slots_per_proc overflowed u32.".to_string(),
        );
    };
    let Some(total_nodes) = num_procs.checked_mul(slots_per_proc) else {
        return crate::invalid_output_program(
            OP_ID,
            "row_ptr",
            DataType::U32,
            "Fix: exploded IFDS total node count overflowed u32.".to_string(),
        );
    };
    let Some(row_ptr_count) = total_nodes.checked_add(1) else {
        return crate::invalid_output_program(
            OP_ID,
            "row_ptr",
            DataType::U32,
            format!(
                "Fix: exploded IFDS total_nodes={total_nodes} overflows row_ptr count. Shard the IFDS graph before GPU dispatch."
            ),
        );
    };

    let idx_expr = |p: Expr, b: Expr, f: Expr| {
        Expr::add(
            Expr::add(
                Expr::mul(p, Expr::u32(slots_per_proc)),
                Expr::mul(b, Expr::u32(facts_per_proc)),
            ),
            f,
        )
    };
    let in_proc_block = |p: Expr, b: Expr| {
        Expr::and(
            Expr::lt(p, Expr::u32(num_procs)),
            Expr::lt(b, Expr::u32(blocks_per_proc)),
        )
    };
    let valid_intra = Expr::and(
        in_proc_block(Expr::var("intra_p"), Expr::var("intra_src_b")),
        Expr::lt(Expr::var("intra_dst_b"), Expr::u32(blocks_per_proc)),
    );
    let valid_inter = Expr::and(
        in_proc_block(Expr::var("inter_sp"), Expr::var("inter_sb")),
        in_proc_block(Expr::var("inter_dp"), Expr::var("inter_db")),
    );

    let count_row = |src: Expr| {
        Node::store(
            "row_ptr",
            Expr::add(src.clone(), Expr::u32(1)),
            Expr::add(
                Expr::load("row_ptr", Expr::add(src, Expr::u32(1))),
                Expr::u32(1),
            ),
        )
    };
    let fill_col = |src: Expr, dst: Expr| {
        vec![
            Node::let_bind("emit_slot", Expr::load("row_cursor", src.clone())),
            Node::store("col_idx", Expr::var("emit_slot"), dst),
            Node::store(
                "row_cursor",
                src,
                Expr::add(Expr::var("emit_slot"), Expr::u32(1)),
            ),
        ]
    };

    let kill_scan = vec![
        Node::let_bind("is_killed", Expr::u32(0)),
        Node::loop_for(
            "kill_i",
            Expr::u32(0),
            Expr::u32(kill_count),
            vec![
                Node::let_bind("kill_p", Expr::load("kill_proc", Expr::var("kill_i"))),
                Node::let_bind("kill_b", Expr::load("kill_block", Expr::var("kill_i"))),
                Node::let_bind("kill_f", Expr::load("kill_fact", Expr::var("kill_i"))),
                Node::if_then(
                    Expr::and(
                        Expr::and(
                            Expr::eq(Expr::var("kill_p"), Expr::var("intra_p")),
                            Expr::eq(Expr::var("kill_b"), Expr::var("intra_src_b")),
                        ),
                        Expr::eq(Expr::var("kill_f"), Expr::var("fact")),
                    ),
                    vec![Node::assign("is_killed", Expr::u32(1))],
                ),
            ],
        ),
    ];

    let mut count_intra_fact = kill_scan.clone();
    count_intra_fact.push(Node::if_then(
        Expr::eq(Expr::var("is_killed"), Expr::u32(0)),
        vec![
            Node::let_bind(
                "src_dense",
                idx_expr(
                    Expr::var("intra_p"),
                    Expr::var("intra_src_b"),
                    Expr::var("fact"),
                ),
            ),
            count_row(Expr::var("src_dense")),
        ],
    ));

    let count_gen = vec![
        Node::let_bind("gen_p", Expr::load("gen_proc", Expr::var("gen_i"))),
        Node::let_bind("gen_b", Expr::load("gen_block", Expr::var("gen_i"))),
        Node::let_bind("gen_f", Expr::load("gen_fact", Expr::var("gen_i"))),
        Node::if_then(
            Expr::and(
                Expr::and(
                    Expr::eq(Expr::var("gen_p"), Expr::var("intra_p")),
                    Expr::eq(Expr::var("gen_b"), Expr::var("intra_src_b")),
                ),
                Expr::lt(Expr::var("gen_f"), Expr::u32(facts_per_proc)),
            ),
            vec![
                Node::let_bind(
                    "src_dense",
                    idx_expr(Expr::var("intra_p"), Expr::var("intra_src_b"), Expr::u32(0)),
                ),
                count_row(Expr::var("src_dense")),
            ],
        ),
    ];

    let mut fill_intra_fact = kill_scan;
    fill_intra_fact.push(Node::if_then(
        Expr::eq(Expr::var("is_killed"), Expr::u32(0)),
        {
            let mut nodes = vec![
                Node::let_bind(
                    "src_dense",
                    idx_expr(
                        Expr::var("intra_p"),
                        Expr::var("intra_src_b"),
                        Expr::var("fact"),
                    ),
                ),
                Node::let_bind(
                    "dst_dense",
                    idx_expr(
                        Expr::var("intra_p"),
                        Expr::var("intra_dst_b"),
                        Expr::var("fact"),
                    ),
                ),
            ];
            nodes.extend(fill_col(Expr::var("src_dense"), Expr::var("dst_dense")));
            nodes
        },
    ));

    let fill_gen = vec![
        Node::let_bind("gen_p", Expr::load("gen_proc", Expr::var("gen_i"))),
        Node::let_bind("gen_b", Expr::load("gen_block", Expr::var("gen_i"))),
        Node::let_bind("gen_f", Expr::load("gen_fact", Expr::var("gen_i"))),
        Node::if_then(
            Expr::and(
                Expr::and(
                    Expr::eq(Expr::var("gen_p"), Expr::var("intra_p")),
                    Expr::eq(Expr::var("gen_b"), Expr::var("intra_src_b")),
                ),
                Expr::lt(Expr::var("gen_f"), Expr::u32(facts_per_proc)),
            ),
            {
                let mut nodes = vec![
                    Node::let_bind(
                        "src_dense",
                        idx_expr(Expr::var("intra_p"), Expr::var("intra_src_b"), Expr::u32(0)),
                    ),
                    Node::let_bind(
                        "dst_dense",
                        idx_expr(
                            Expr::var("intra_p"),
                            Expr::var("intra_dst_b"),
                            Expr::var("gen_f"),
                        ),
                    ),
                ];
                nodes.extend(fill_col(Expr::var("src_dense"), Expr::var("dst_dense")));
                nodes
            },
        ),
    ];

    let mut entry = vec![
        Node::loop_for(
            "row_i",
            Expr::u32(0),
            Expr::u32(row_ptr_count),
            vec![Node::store("row_ptr", Expr::var("row_i"), Expr::u32(0))],
        ),
        Node::store("col_len", Expr::u32(0), Expr::u32(0)),
    ];

    entry.push(Node::loop_for(
        "intra_i",
        Expr::u32(0),
        Expr::u32(intra_count),
        vec![
            Node::let_bind("intra_p", Expr::load("intra_proc", Expr::var("intra_i"))),
            Node::let_bind(
                "intra_src_b",
                Expr::load("intra_src_block", Expr::var("intra_i")),
            ),
            Node::let_bind(
                "intra_dst_b",
                Expr::load("intra_dst_block", Expr::var("intra_i")),
            ),
            Node::if_then(
                valid_intra.clone(),
                vec![
                    Node::loop_for(
                        "fact",
                        Expr::u32(0),
                        Expr::u32(facts_per_proc),
                        count_intra_fact,
                    ),
                    Node::loop_for("gen_i", Expr::u32(0), Expr::u32(gen_count), count_gen),
                ],
            ),
        ],
    ));
    entry.push(Node::loop_for(
        "inter_i",
        Expr::u32(0),
        Expr::u32(inter_count),
        vec![
            Node::let_bind(
                "inter_sp",
                Expr::load("inter_src_proc", Expr::var("inter_i")),
            ),
            Node::let_bind(
                "inter_sb",
                Expr::load("inter_src_block", Expr::var("inter_i")),
            ),
            Node::let_bind(
                "inter_dp",
                Expr::load("inter_dst_proc", Expr::var("inter_i")),
            ),
            Node::let_bind(
                "inter_db",
                Expr::load("inter_dst_block", Expr::var("inter_i")),
            ),
            Node::if_then(
                valid_inter.clone(),
                vec![Node::loop_for(
                    "fact",
                    Expr::u32(0),
                    Expr::u32(facts_per_proc),
                    vec![
                        Node::let_bind(
                            "src_dense",
                            idx_expr(
                                Expr::var("inter_sp"),
                                Expr::var("inter_sb"),
                                Expr::var("fact"),
                            ),
                        ),
                        count_row(Expr::var("src_dense")),
                    ],
                )],
            ),
        ],
    ));
    entry.extend([
        Node::let_bind("prefix_sum", Expr::u32(0)),
        Node::loop_for(
            "prefix_row",
            Expr::u32(0),
            Expr::u32(total_nodes),
            vec![
                Node::let_bind(
                    "row_count",
                    Expr::load("row_ptr", Expr::add(Expr::var("prefix_row"), Expr::u32(1))),
                ),
                Node::assign(
                    "prefix_sum",
                    Expr::add(Expr::var("prefix_sum"), Expr::var("row_count")),
                ),
                Node::store(
                    "row_ptr",
                    Expr::add(Expr::var("prefix_row"), Expr::u32(1)),
                    Expr::var("prefix_sum"),
                ),
            ],
        ),
        Node::store("col_len", Expr::u32(0), Expr::var("prefix_sum")),
        Node::loop_for(
            "cursor_row",
            Expr::u32(0),
            Expr::u32(total_nodes),
            vec![Node::store(
                "row_cursor",
                Expr::var("cursor_row"),
                Expr::load("row_ptr", Expr::var("cursor_row")),
            )],
        ),
    ]);
    entry.push(Node::loop_for(
        "intra_i",
        Expr::u32(0),
        Expr::u32(intra_count),
        vec![
            Node::let_bind("intra_p", Expr::load("intra_proc", Expr::var("intra_i"))),
            Node::let_bind(
                "intra_src_b",
                Expr::load("intra_src_block", Expr::var("intra_i")),
            ),
            Node::let_bind(
                "intra_dst_b",
                Expr::load("intra_dst_block", Expr::var("intra_i")),
            ),
            Node::if_then(
                valid_intra,
                vec![
                    Node::loop_for(
                        "fact",
                        Expr::u32(0),
                        Expr::u32(facts_per_proc),
                        fill_intra_fact,
                    ),
                    Node::loop_for("gen_i", Expr::u32(0), Expr::u32(gen_count), fill_gen),
                ],
            ),
        ],
    ));
    entry.push(Node::loop_for(
        "inter_i",
        Expr::u32(0),
        Expr::u32(inter_count),
        vec![
            Node::let_bind(
                "inter_sp",
                Expr::load("inter_src_proc", Expr::var("inter_i")),
            ),
            Node::let_bind(
                "inter_sb",
                Expr::load("inter_src_block", Expr::var("inter_i")),
            ),
            Node::let_bind(
                "inter_dp",
                Expr::load("inter_dst_proc", Expr::var("inter_i")),
            ),
            Node::let_bind(
                "inter_db",
                Expr::load("inter_dst_block", Expr::var("inter_i")),
            ),
            Node::if_then(
                valid_inter,
                vec![Node::loop_for(
                    "fact",
                    Expr::u32(0),
                    Expr::u32(facts_per_proc),
                    {
                        let mut nodes = vec![
                            Node::let_bind(
                                "src_dense",
                                idx_expr(
                                    Expr::var("inter_sp"),
                                    Expr::var("inter_sb"),
                                    Expr::var("fact"),
                                ),
                            ),
                            Node::let_bind(
                                "dst_dense",
                                idx_expr(
                                    Expr::var("inter_dp"),
                                    Expr::var("inter_db"),
                                    Expr::var("fact"),
                                ),
                            ),
                        ];
                        nodes.extend(fill_col(Expr::var("src_dense"), Expr::var("dst_dense")));
                        nodes
                    },
                )],
            ),
        ],
    ));

    Program::wrapped(
        vec![
            BufferDecl::storage("intra_proc", 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(intra_count.max(1)),
            BufferDecl::storage("intra_src_block", 1, BufferAccess::ReadOnly, DataType::U32)
                .with_count(intra_count.max(1)),
            BufferDecl::storage("intra_dst_block", 2, BufferAccess::ReadOnly, DataType::U32)
                .with_count(intra_count.max(1)),
            BufferDecl::storage("inter_src_proc", 3, BufferAccess::ReadOnly, DataType::U32)
                .with_count(inter_count.max(1)),
            BufferDecl::storage("inter_src_block", 4, BufferAccess::ReadOnly, DataType::U32)
                .with_count(inter_count.max(1)),
            BufferDecl::storage("inter_dst_proc", 5, BufferAccess::ReadOnly, DataType::U32)
                .with_count(inter_count.max(1)),
            BufferDecl::storage("inter_dst_block", 6, BufferAccess::ReadOnly, DataType::U32)
                .with_count(inter_count.max(1)),
            BufferDecl::storage("gen_proc", 7, BufferAccess::ReadOnly, DataType::U32)
                .with_count(gen_count.max(1)),
            BufferDecl::storage("gen_block", 8, BufferAccess::ReadOnly, DataType::U32)
                .with_count(gen_count.max(1)),
            BufferDecl::storage("gen_fact", 9, BufferAccess::ReadOnly, DataType::U32)
                .with_count(gen_count.max(1)),
            BufferDecl::storage("kill_proc", 10, BufferAccess::ReadOnly, DataType::U32)
                .with_count(kill_count.max(1)),
            BufferDecl::storage("kill_block", 11, BufferAccess::ReadOnly, DataType::U32)
                .with_count(kill_count.max(1)),
            BufferDecl::storage("kill_fact", 12, BufferAccess::ReadOnly, DataType::U32)
                .with_count(kill_count.max(1)),
            BufferDecl::storage("row_ptr", 13, BufferAccess::ReadWrite, DataType::U32)
                .with_count(row_ptr_count),
            BufferDecl::storage("row_cursor", 14, BufferAccess::ReadWrite, DataType::U32)
                .with_count(total_nodes.max(1)),
            BufferDecl::storage("col_idx", 15, BufferAccess::ReadWrite, DataType::U32)
                .with_count(max_col_count.max(1)),
            BufferDecl::storage("col_len", 16, BufferAccess::ReadWrite, DataType::U32)
                .with_count(1),
        ],
        [1, 1, 1],
        vec![Node::Region {
            generator: Ident::from(OP_ID),
            source_region: None,
            body: Arc::new(vec![Node::if_then(
                Expr::eq(Expr::gid_x(), Expr::u32(0)),
                entry,
            )]),
        }],
    )
}

/// Pack a `(proc_id, block_id, fact_id)` triple into a 32-bit
/// node id.
///
/// Invalid triples have no non-aliasing `u32` representation, so the
/// failure is explicit instead of silently clamping or masking.
#[must_use]
pub fn encode_node(proc_id: u32, block_id: u32, fact_id: u32) -> Option<u32> {
    fits(proc_id, block_id, fact_id)
        .then_some((proc_id << PROC_SHIFT) | (block_id << BLOCK_SHIFT) | fact_id)
}

/// Unpack a node id back into `(proc_id, block_id, fact_id)`.
#[must_use]
pub fn decode_node(node_id: u32) -> (u32, u32, u32) {
    let proc_id = (node_id >> PROC_SHIFT) & PROC_MASK;
    let block_id = (node_id >> BLOCK_SHIFT) & BLOCK_MASK;
    let fact_id = node_id & FACT_MASK;
    (proc_id, block_id, fact_id)
}

/// Whether a `(proc, block, fact)` triple fits in the packed
/// 32-bit representation. Callers on the production path should
/// verify this before calling [`encode_node`].
#[must_use]
pub fn fits(proc_id: u32, block_id: u32, fact_id: u32) -> bool {
    proc_id <= MAX_PROC_ID && block_id <= MAX_BLOCK_ID && fact_id <= MAX_FACT_ID
}

/// CPU-reference CSR builder for the exploded supergraph.
///
/// `intra_edges` are `(src_block, dst_block)` pairs **within** a
/// procedure — the standard CFG. `inter_edges` are `(src_proc,
/// src_block, dst_proc, dst_block)` call / return edges. Flow
/// functions are encoded as per-block GEN / KILL bitsets over the
/// fact domain.
///
/// Returns `(row_ptr, col_idx)` in the **dense** index space
/// `idx(p, b, f) = p * blocks * facts + b * facts + f`. This is
/// the space every traversal kernel operates in — packing via
/// [`encode_node`] is only used at the I/O boundary when the
/// caller needs to report results as `(proc, block, fact)`
/// triples. The two spaces coincide only in the degenerate case
/// `blocks_per_proc == 1 << BLOCK_BITS` and `facts_per_proc == 1 << FACT_BITS`;
/// the dense layout works for any dimensions that fit in
/// 32-bit encoding.
#[must_use]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn build_cpu_reference(
    num_procs: u32,
    blocks_per_proc: u32,
    facts_per_proc: u32,
    intra_edges: &[(u32, u32, u32)], // (proc, src_block, dst_block)
    inter_edges: &[(u32, u32, u32, u32)], // (src_proc, src_block, dst_proc, dst_block)
    flow_gen: &[(u32, u32, u32)],    // (proc, block, fact) — GEN bits
    flow_kill: &[(u32, u32, u32)],   // (proc, block, fact) — KILL bits
) -> (Vec<u32>, Vec<u32>) {
    if num_procs == 0 || blocks_per_proc == 0 || facts_per_proc == 0 {
        panic!(
            "exploded IFDS CPU reference dimensions must be nonzero, got procs={num_procs}, blocks={blocks_per_proc}, facts={facts_per_proc}. Fix: pass a real exploded-supergraph domain before parity comparison."
        );
    }
    if !fits(num_procs - 1, blocks_per_proc - 1, facts_per_proc - 1) {
        panic!(
            "exploded IFDS CPU reference dimensions exceed packed node-id limits: procs={num_procs}, blocks={blocks_per_proc}, facts={facts_per_proc}. Fix: shard the IFDS graph before parity comparison."
        );
    }

    // PHASE7_GRAPH C4: every multiply checked. The previous unchecked
    // chain (`blocks * facts`, then `procs * slots`) wraps silently
    // when the caller passes the maximum dimensions for each field
    // (4096 × 1024 × 1024 = 2^32 = wraps to 0 on 32-bit usize and
    // sits exactly at the overflow boundary on 64-bit). Either case
    // produced a tiny `Vec<Vec<u32>>` and catastrophic OOB writes in
    // the edge-emit loops below.
    let Some(slots_per_proc) = (blocks_per_proc as usize).checked_mul(facts_per_proc as usize)
    else {
        panic!(
            "exploded IFDS CPU reference blocks={blocks_per_proc} facts={facts_per_proc} overflow slots_per_proc. Fix: shard the IFDS graph before parity comparison."
        );
    };
    let Some(total_nodes) = (num_procs as usize).checked_mul(slots_per_proc) else {
        panic!(
            "exploded IFDS CPU reference procs={num_procs} slots_per_proc={slots_per_proc} overflow total node count. Fix: shard the IFDS graph before parity comparison."
        );
    };
    if total_nodes > u32::MAX as usize {
        panic!(
            "exploded IFDS CPU reference total_nodes={total_nodes} exceeds u32 dense-node encoding. Fix: shard the IFDS graph before parity comparison."
        );
    }
    let mut edges_flat: Vec<(u32, u32)> = Vec::new();
    let block_count = (num_procs as usize) * (blocks_per_proc as usize);

    let idx = |p: u32, b: u32, f: u32| -> u32 {
        ((p as usize) * slots_per_proc + (b as usize) * facts_per_proc as usize + f as usize) as u32
    };
    let block_idx =
        |p: u32, b: u32| -> usize { (p as usize) * blocks_per_proc as usize + b as usize };
    let in_space =
        |p: u32, b: u32, f: u32| p < num_procs && b < blocks_per_proc && f < facts_per_proc;

    let mut killed = vec![false; total_nodes];
    for &(p, b, f) in flow_kill {
        if in_space(p, b, f) {
            killed[idx(p, b, f) as usize] = true;
        }
    }

    let mut gen_offsets = vec![0usize; block_count + 1];
    for &(p, b, f) in flow_gen {
        if in_space(p, b, f) {
            gen_offsets[block_idx(p, b) + 1] += 1;
        }
    }
    for i in 1..gen_offsets.len() {
        gen_offsets[i] += gen_offsets[i - 1];
    }
    let mut gen_cursor = gen_offsets[..block_count].to_vec();
    let mut gen_facts = vec![0u32; gen_offsets[block_count]];
    for &(p, b, f) in flow_gen {
        if in_space(p, b, f) {
            let key = block_idx(p, b);
            let slot = gen_cursor[key];
            gen_facts[slot] = f;
            gen_cursor[key] += 1;
        }
    }

    // Intra-procedural CFG edges, cross-producted with fact-propagation:
    // an edge (B_src -> B_dst) gives rise to an edge in the exploded
    // supergraph between every pair (f, f) that survives the flow
    // function at B_src (fact f propagates iff f is not killed).
    for &(p, src_b, dst_b) in intra_edges {
        if p >= num_procs || src_b >= blocks_per_proc || dst_b >= blocks_per_proc {
            continue;
        }
        for f in 0..facts_per_proc {
            if killed[idx(p, src_b, f) as usize] {
                continue;
            }
            edges_flat.push((idx(p, src_b, f), idx(p, dst_b, f)));
        }
        // GEN edges: standard IFDS 0-fact encoding — fact 0 is the
        // tautological "always present" fact. `GEN(src_b, gf)` emits
        // edge `(src_b, 0) → (dst_b, gf)`, so seeding `(entry, 0)`
        // triggers every GEN along the reachable CFG. Callers that
        // don't use the 0-fact convention see GEN as a no-op.
        let gen_key = block_idx(p, src_b);
        for &gf in &gen_facts[gen_offsets[gen_key]..gen_offsets[gen_key + 1]] {
            edges_flat.push((idx(p, src_b, 0), idx(p, dst_b, gf)));
        }
    }

    // Inter-procedural call / return edges propagate every fact
    // (IFDS handles parameter mapping via summary edges in the full
    // algorithm; this CPU reference is the unfiltered
    // "every-fact-flows" upper bound used for correctness tests).
    for &(sp, sb, dp, db) in inter_edges {
        if sp >= num_procs || dp >= num_procs || sb >= blocks_per_proc || db >= blocks_per_proc {
            continue;
        }
        for f in 0..facts_per_proc {
            edges_flat.push((idx(sp, sb, f), idx(dp, db, f)));
        }
    }

    // Flatten into CSR — row_ptr has total_nodes+1 entries.
    if edges_flat.len() > u32::MAX as usize {
        panic!(
            "exploded IFDS CPU reference edge_count={} exceeds u32 CSR encoding. Fix: shard the IFDS graph before parity comparison.",
            edges_flat.len()
        );
    }
    let row_ptr_len = total_nodes.checked_add(1).unwrap_or_else(|| {
        panic!(
            "exploded IFDS CPU reference total_nodes={total_nodes} overflows row_ptr length. Fix: shard the IFDS graph before parity comparison."
        )
    });
    let mut row_ptr = vec![0u32; row_ptr_len];
    for &(src, _) in &edges_flat {
        let row = src as usize;
        row_ptr[row + 1] = row_ptr[row + 1].checked_add(1).unwrap_or_else(|| {
            panic!(
                "exploded IFDS CPU reference row {row} edge count overflowed u32. Fix: shard the IFDS graph before parity comparison."
            )
        });
    }
    for row in 1..row_ptr.len() {
        row_ptr[row] = row_ptr[row].checked_add(row_ptr[row - 1]).unwrap_or_else(|| {
            panic!(
                "exploded IFDS CPU reference CSR prefix overflowed at row {row}. Fix: shard the IFDS graph before parity comparison."
            )
        });
    }
    let mut cursor = row_ptr[..total_nodes]
        .iter()
        .map(|&offset| offset as usize)
        .collect::<Vec<_>>();
    let mut col_idx = vec![0u32; edges_flat.len()];
    for (src, dst) in edges_flat {
        let row = src as usize;
        let slot = cursor[row];
        col_idx[slot] = dst;
        cursor[row] += 1;
    }
    (row_ptr, col_idx)
}

/// Convert a dense `(proc, block, fact)` index — the space
/// [`build_cpu_reference`] operates in — into the packed
/// [`encode_node`] form for reporting or cross-subsystem handoff.
#[must_use]
pub fn dense_to_encoded(dense: u32, blocks_per_proc: u32, facts_per_proc: u32) -> Option<u32> {
    let slots_per_proc = blocks_per_proc.checked_mul(facts_per_proc)?;
    if slots_per_proc == 0 {
        return None;
    }
    let p = dense / slots_per_proc;
    let within_proc = dense % slots_per_proc;
    let b = within_proc / facts_per_proc;
    let f = within_proc % facts_per_proc;
    encode_node(p, b, f)
}

/// Inverse of [`dense_to_encoded`].
#[must_use]
pub fn encoded_to_dense(node_id: u32, blocks_per_proc: u32, facts_per_proc: u32) -> Option<u32> {
    let (p, b, f) = decode_node(node_id);
    let proc_span = blocks_per_proc.checked_mul(facts_per_proc)?;
    let proc_offset = p.checked_mul(proc_span)?;
    let block_offset = b.checked_mul(facts_per_proc)?;
    proc_offset.checked_add(block_offset)?.checked_add(f)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrips_at_max_values() {
        let n = encode_node(MAX_PROC_ID, MAX_BLOCK_ID, MAX_FACT_ID).unwrap();
        assert_eq!(n, u32::MAX);
        assert_eq!(decode_node(n), (MAX_PROC_ID, MAX_BLOCK_ID, MAX_FACT_ID));
    }

    #[test]
    fn encode_decode_roundtrips_at_zero() {
        let n = encode_node(0, 0, 0).unwrap();
        assert_eq!(n, 0);
        assert_eq!(decode_node(n), (0, 0, 0));
    }

    #[test]
    fn encode_decode_roundtrips_at_component_boundaries() {
        for (p, b, f) in [
            (0, 0, 1),
            (0, 1, 0),
            (1, 0, 0),
            (0, 0, MAX_FACT_ID),
            (0, MAX_BLOCK_ID, 0),
            (MAX_PROC_ID, 0, 0),
            (1, 2, 3),
            (42, 17, 99),
            (MAX_PROC_ID / 2, MAX_BLOCK_ID / 2, MAX_FACT_ID / 2),
        ] {
            let n = encode_node(p, b, f).unwrap();
            assert_eq!(
                decode_node(n),
                (p, b, f),
                "roundtrip failed for {p}/{b}/{f}"
            );
        }
    }

    #[test]
    fn fits_catches_over_range_components() {
        assert!(fits(MAX_PROC_ID, MAX_BLOCK_ID, MAX_FACT_ID));
        assert!(!fits(MAX_PROC_ID + 1, 0, 0));
        assert!(!fits(0, MAX_BLOCK_ID + 1, 0));
        assert!(!fits(0, 0, MAX_FACT_ID + 1));
        assert_eq!(encode_node(MAX_PROC_ID + 1, 0, 0), None);
    }

    #[test]
    fn csr_of_empty_graph_has_only_sentinel_row_ptr() {
        let (row_ptr, col_idx) = build_cpu_reference(1, 1, 1, &[], &[], &[], &[]);
        assert_eq!(row_ptr, vec![0, 0]);
        assert!(col_idx.is_empty());
    }

    // Dense-index helper mirrors the one inside build_cpu_reference.
    fn di(p: u32, b: u32, f: u32, blocks: u32, facts: u32) -> u32 {
        p * blocks * facts + b * facts + f
    }

    #[test]
    fn csr_single_intra_edge_produces_per_fact_duplicate_edges() {
        // 1 proc, 2 blocks (B0→B1), 4 facts; no kills → each fact
        // flows forward once.
        let (row_ptr, col_idx) = build_cpu_reference(1, 2, 4, &[(0, 0, 1)], &[], &[], &[]);
        assert_eq!(row_ptr.len(), 9);
        assert_eq!(col_idx.len(), 4);
        for f in 0..4 {
            let src = di(0, 0, f, 2, 4) as usize;
            let edge_start = row_ptr[src] as usize;
            assert_eq!(col_idx[edge_start], di(0, 1, f, 2, 4));
        }
    }

    #[test]
    fn csr_kill_suppresses_edge_for_that_fact() {
        let (row_ptr, col_idx) = build_cpu_reference(
            1,
            2,
            4,
            &[(0, 0, 1)],
            &[],
            &[],
            &[(0, 0, 2)], // KILL fact 2 at (0, 0)
        );
        let n_edges: u32 = row_ptr.windows(2).map(|w| w[1] - w[0]).sum();
        assert_eq!(n_edges, 3);
        assert_eq!(col_idx.len(), n_edges as usize);
        let killed_src = di(0, 0, 2, 2, 4) as usize;
        assert_eq!(row_ptr[killed_src + 1] - row_ptr[killed_src], 0);
    }

    #[test]
    fn csr_inter_edges_connect_procs() {
        let (row_ptr, col_idx) = build_cpu_reference(
            2,
            2,
            2,
            &[],
            &[(0, 1, 1, 0)], // call: P0/B1 → P1/B0
            &[],
            &[],
        );
        assert_eq!(row_ptr.len(), 9);
        assert_eq!(col_idx.len(), 2);
        let src0 = di(0, 1, 0, 2, 2) as usize;
        let src1 = di(0, 1, 1, 2, 2) as usize;
        assert_eq!(
            &col_idx[row_ptr[src0] as usize..row_ptr[src0 + 1] as usize],
            &[di(1, 0, 0, 2, 2)]
        );
        assert_eq!(
            &col_idx[row_ptr[src1] as usize..row_ptr[src1 + 1] as usize],
            &[di(1, 0, 1, 2, 2)]
        );
    }

    #[test]
    fn dense_encoded_roundtrips() {
        for &(p, b, f, blocks, facts) in &[
            (0_u32, 0_u32, 0_u32, 2_u32, 2_u32),
            (1, 1, 1, 2, 2),
            (42, 17, 99, 64, 128),
            (MAX_PROC_ID, 3, 7, 16, 16),
        ] {
            let d = di(p, b, f, blocks, facts);
            let enc = dense_to_encoded(d, blocks, facts).unwrap();
            assert_eq!(decode_node(enc), (p, b, f));
            let back = encoded_to_dense(enc, blocks, facts).unwrap();
            assert_eq!(back, d, "roundtrip mismatch {p}/{b}/{f}");
        }
    }

    #[test]
    fn csr_gen_introduces_new_fact_flow_from_zero_fact() {
        // B0 → B1, GEN fact 2 at B0. Per IFDS 0-fact convention,
        // GEN emits edge (B0, 0) → (B1, 2). The intra loop still
        // propagates every non-killed fact (0..3), so total edges
        // are 4 (intra) + 1 (GEN from 0-fact) = 5. The GEN edge
        // specifically targets fact 2 at B1 even though fact 2 did
        // not flow in through any predecessor — that is the point.
        let (row_ptr, col_idx) = build_cpu_reference(1, 2, 4, &[(0, 0, 1)], &[], &[(0, 0, 2)], &[]);
        assert_eq!(col_idx.len(), 5);
        // Verify the GEN edge is attached to the 0-fact source, not
        // to fact-2 (which would be redundant with the intra edge).
        let zero_src = di(0, 0, 0, 2, 4) as usize;
        let fact2_dst = di(0, 1, 2, 2, 4);
        let zero_neighbours = &col_idx[row_ptr[zero_src] as usize..row_ptr[zero_src + 1] as usize];
        assert!(zero_neighbours.contains(&fact2_dst));
    }

    #[test]
    #[should_panic(expected = "exceed packed node-id limits")]
    fn csr_rejects_dimensions_overflowing_encoding() {
        // (MAX_PROC_ID + 2) × anything overflows PROC_BITS.
        let _ = build_cpu_reference(MAX_PROC_ID + 2, 1, 1, &[], &[], &[], &[]);
    }

    #[test]
    fn gpu_builder_rejects_row_ptr_count_overflow_without_panic() {
        let program = build_ifds_csr_program(u32::MAX, 1, 1, 0, 0, 0, 0, 0);

        assert!(program.stats().trap());
    }

    #[test]
    fn gpu_builder_source_has_checked_row_ptr_count_without_panics() {
        let source = include_str!("exploded.rs");
        let builder_source = source
            .split("pub fn build_ifds_csr_program(")
            .nth(1)
            .expect("exploded IFDS GPU builder source must be present")
            .split("/// Pack a `(proc_id, block_id, fact_id)` triple")
            .next()
            .expect("exploded IFDS GPU builder source must precede node packing");

        assert!(
            builder_source.contains("let Some(row_ptr_count)")
                && !builder_source.contains(concat!("panic", "!("))
                && !builder_source.contains(".unwrap_or_else("),
            "Fix: exploded IFDS GPU builder must check row_ptr count and avoid production panics."
        );
    }

    #[test]
    fn row_ptr_length_is_nodes_plus_one() {
        let procs = 3;
        let blocks = 4;
        let facts = 8;
        let (row_ptr, _) = build_cpu_reference(procs, blocks, facts, &[], &[], &[], &[]);
        assert_eq!(
            row_ptr.len(),
            (procs as usize * blocks as usize * facts as usize) + 1
        );
    }

    #[test]
    fn facts_per_workgroup_matches_max_fact_id_plus_one() {
        // G3 docstring claim: lane sizing matches NFA's.
        assert_eq!(FACTS_PER_WORKGROUP as u32, MAX_FACT_ID + 1);
    }

    #[test]
    fn reusable_layout_contract_sizes_dispatch_buffers() {
        let layout = validate_ifds_csr_layout(2, 3, 4, 5, 7, 11).unwrap();

        assert!(!layout.empty);
        assert_eq!(layout.num_procs, 2);
        assert_eq!(layout.blocks_per_proc, 3);
        assert_eq!(layout.facts_per_proc, 4);
        assert_eq!(layout.intra_count, 5);
        assert_eq!(layout.inter_count, 7);
        assert_eq!(layout.gen_count, 11);
        assert_eq!(layout.slots_per_proc, 12);
        assert_eq!(layout.total_nodes, 24);
        assert_eq!(layout.row_words, 25);
        assert_eq!(layout.row_cursor_words, 24);
        assert_eq!(layout.max_col_count, 5 * 4 + 5 * 11 + 7 * 4);
        assert_eq!(layout.col_buffer_words, layout.max_col_count as usize);
    }

    #[test]
    fn reusable_layout_contract_rejects_invalid_domains() {
        assert!(validate_ifds_csr_layout(0, 1, 1, 0, 0, 0).is_err());
        assert!(validate_ifds_csr_layout(MAX_PROC_ID + 2, 1, 1, 0, 0, 0).is_err());
        assert!(validate_ifds_csr_layout(
            MAX_PROC_ID + 1,
            MAX_BLOCK_ID + 1,
            MAX_FACT_ID + 1,
            0,
            0,
            0
        )
        .is_err());
        assert!(validate_ifds_csr_layout(u32::MAX, u32::MAX, 2, 0, 0, 0).is_err());
        assert!(validate_ifds_csr_layout(1, 1, 2, u32::MAX, 0, u32::MAX).is_err());
    }

    #[test]
    fn reusable_input_layout_contract_narrows_rule_counts_and_padding() {
        let layout = validate_ifds_csr_inputs(
            1,
            2,
            3,
            &[(0, 0, 1), (0, 1, 0)],
            &[(0, 0, 0, 1)],
            &[],
            &[(0, 0, 1)],
        )
        .unwrap();

        assert_eq!(layout.intra_count, 2);
        assert_eq!(layout.inter_count, 1);
        assert_eq!(layout.gen_count, 0);
        assert_eq!(layout.kill_count, 1);
        assert_eq!(layout.intra_storage_words, 2);
        assert_eq!(layout.inter_storage_words, 1);
        assert_eq!(layout.gen_storage_words, 1);
        assert_eq!(layout.kill_storage_words, 1);

        let empty = validate_ifds_csr_inputs(0, 0, 0, &[], &[], &[], &[]).unwrap();
        assert!(empty.empty);
        assert_eq!(empty.row_words, 1);

        let err = validate_ifds_csr_inputs(0, 0, 0, &[(0, 0, 0)], &[], &[], &[]).unwrap_err();
        assert!(err.contains("empty dimensions cannot carry rules"));
    }

    #[test]
    fn reusable_canonicalizer_sorts_rows_and_rejects_bad_ranges() {
        let row_ptr = vec![0, 3, 5];
        let mut col_idx = vec![9, 1, 4, 8, 2];
        canonicalize_csr_within_rows_in_place(&row_ptr, &mut col_idx).unwrap();
        assert_eq!(col_idx, vec![1, 4, 9, 2, 8]);

        let mut bad_col = vec![1, 2];
        let err = canonicalize_csr_within_rows_in_place(&[0, 3], &mut bad_col).unwrap_err();
        assert!(err.contains("exceeds col_idx.len()"));
    }
}
