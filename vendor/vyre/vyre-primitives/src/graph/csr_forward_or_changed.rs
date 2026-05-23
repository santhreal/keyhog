//! CSR frontier expansion over an in-place accumulator bitset.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::{GeneratorRef, Ident};
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

use crate::graph::program_graph::{
    ProgramGraphShape, BINDING_PRIMITIVE_START, NAME_EDGE_KIND_MASK, NAME_EDGE_OFFSETS,
    NAME_EDGE_TARGETS,
};

/// Canonical op id.
pub const OP_ID: &str = "vyre-primitives::graph::csr_forward_or_changed";

/// Build one in-place forward expansion pass over an accumulating frontier.
#[must_use]
pub fn csr_forward_or_changed_body(
    shape: ProgramGraphShape,
    frontier_out: &str,
    changed_var: &str,
    edge_kind_mask: u32,
) -> Vec<Node> {
    csr_forward_or_changed_body_prefixed(shape, frontier_out, changed_var, edge_kind_mask, "")
}

fn local(prefix: &str, name: &str) -> String {
    if prefix.is_empty() {
        name.to_string()
    } else {
        format!("{prefix}_{name}")
    }
}

/// Build one traversal pass with caller-provided local-name prefixing for
/// repeated inlining under validators that disallow shadowing.
#[must_use]
pub fn csr_forward_or_changed_body_prefixed(
    shape: ProgramGraphShape,
    frontier_out: &str,
    changed_var: &str,
    edge_kind_mask: u32,
    prefix: &str,
) -> Vec<Node> {
    let src = local(prefix, "src");
    let word_idx = local(prefix, "word_idx");
    let bit_mask = local(prefix, "bit_mask");
    let src_word = local(prefix, "src_word");
    let edge_start = local(prefix, "edge_start");
    let edge_end = local(prefix, "edge_end");
    let edge_iter = local(prefix, "e");
    let kind_mask = local(prefix, "kind_mask");
    let dst = local(prefix, "dst");
    let dst_word_idx = local(prefix, "dst_word_idx");
    let dst_bit = local(prefix, "dst_bit");
    let old = local(prefix, "old");

    let per_source = vec![
        Node::let_bind(
            word_idx.as_str(),
            Expr::shr(Expr::var(src.as_str()), Expr::u32(5)),
        ),
        Node::let_bind(
            bit_mask.as_str(),
            Expr::shl(
                Expr::u32(1),
                Expr::bitand(Expr::var(src.as_str()), Expr::u32(31)),
            ),
        ),
        Node::let_bind(
            src_word.as_str(),
            Expr::load(frontier_out, Expr::var(word_idx.as_str())),
        ),
        Node::if_then(
            Expr::ne(
                Expr::bitand(Expr::var(src_word.as_str()), Expr::var(bit_mask.as_str())),
                Expr::u32(0),
            ),
            vec![
                Node::let_bind(
                    edge_start.as_str(),
                    Expr::load(NAME_EDGE_OFFSETS, Expr::var(src.as_str())),
                ),
                Node::let_bind(
                    edge_end.as_str(),
                    Expr::load(
                        NAME_EDGE_OFFSETS,
                        Expr::add(Expr::var(src.as_str()), Expr::u32(1)),
                    ),
                ),
                Node::loop_for(
                    edge_iter.as_str(),
                    Expr::var(edge_start.as_str()),
                    Expr::var(edge_end.as_str()),
                    vec![
                        Node::let_bind(
                            kind_mask.as_str(),
                            Expr::load(NAME_EDGE_KIND_MASK, Expr::var(edge_iter.as_str())),
                        ),
                        Node::if_then(
                            Expr::ne(
                                Expr::bitand(
                                    Expr::var(kind_mask.as_str()),
                                    Expr::u32(edge_kind_mask),
                                ),
                                Expr::u32(0),
                            ),
                            vec![
                                Node::let_bind(
                                    dst.as_str(),
                                    Expr::load(NAME_EDGE_TARGETS, Expr::var(edge_iter.as_str())),
                                ),
                                Node::if_then(
                                    Expr::lt(Expr::var(dst.as_str()), Expr::u32(shape.node_count)),
                                    vec![
                                        Node::let_bind(
                                            dst_word_idx.as_str(),
                                            Expr::shr(Expr::var(dst.as_str()), Expr::u32(5)),
                                        ),
                                        Node::let_bind(
                                            dst_bit.as_str(),
                                            Expr::shl(
                                                Expr::u32(1),
                                                Expr::bitand(
                                                    Expr::var(dst.as_str()),
                                                    Expr::u32(31),
                                                ),
                                            ),
                                        ),
                                        Node::let_bind(
                                            old.as_str(),
                                            Expr::atomic_or(
                                                frontier_out,
                                                Expr::var(dst_word_idx.as_str()),
                                                Expr::var(dst_bit.as_str()),
                                            ),
                                        ),
                                        Node::if_then(
                                            Expr::eq(
                                                Expr::bitand(
                                                    Expr::var(old.as_str()),
                                                    Expr::var(dst_bit.as_str()),
                                                ),
                                                Expr::u32(0),
                                            ),
                                            vec![Node::assign(changed_var, Expr::u32(1))],
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

    vec![Node::if_then(
        Expr::eq(Expr::local_x(), Expr::u32(0)),
        vec![Node::loop_for(
            src.as_str(),
            Expr::u32(0),
            Expr::u32(shape.node_count),
            per_source,
        )],
    )]
}

/// Wrap one traversal pass as a child Region of `parent_op_id`.
#[must_use]
pub fn csr_forward_or_changed_child(
    parent_op_id: &str,
    shape: ProgramGraphShape,
    frontier_out: &str,
    changed_var: &str,
    edge_kind_mask: u32,
) -> Node {
    csr_forward_or_changed_child_prefixed(
        parent_op_id,
        shape,
        frontier_out,
        changed_var,
        edge_kind_mask,
        "",
    )
}

/// Wrap a traversal pass with a local-name prefix for repeated inlining.
#[must_use]
pub fn csr_forward_or_changed_child_prefixed(
    parent_op_id: &str,
    shape: ProgramGraphShape,
    frontier_out: &str,
    changed_var: &str,
    edge_kind_mask: u32,
    local_prefix: &str,
) -> Node {
    Node::Region {
        generator: Ident::from(OP_ID),
        source_region: Some(GeneratorRef {
            name: parent_op_id.to_string(),
        }),
        body: Arc::new(csr_forward_or_changed_body_prefixed(
            shape,
            frontier_out,
            changed_var,
            edge_kind_mask,
            local_prefix,
        )),
    }
}

/// Standalone in-place expansion program for primitive conformance.
#[must_use]
pub fn csr_forward_or_changed(
    shape: ProgramGraphShape,
    frontier_out: &str,
    changed: &str,
    edge_kind_mask: u32,
) -> Program {
    let words = crate::bitset::bitset_words(shape.node_count);
    let mut body = vec![Node::let_bind("local_changed", Expr::u32(0))];
    body.extend(csr_forward_or_changed_body(
        shape,
        frontier_out,
        "local_changed",
        edge_kind_mask,
    ));
    body.push(Node::if_then(
        Expr::eq(Expr::var("local_changed"), Expr::u32(1)),
        vec![Node::let_bind(
            "_changed",
            Expr::atomic_or(changed, Expr::u32(0), Expr::u32(1)),
        )],
    ));
    let mut buffers = shape.read_only_buffers();
    buffers.push(
        BufferDecl::storage(
            frontier_out,
            BINDING_PRIMITIVE_START,
            BufferAccess::ReadWrite,
            DataType::U32,
        )
        .with_count(words.max(1)),
    );
    buffers.push(
        BufferDecl::storage(
            changed,
            BINDING_PRIMITIVE_START + 1,
            BufferAccess::ReadWrite,
            DataType::U32,
        )
        .with_count(1),
    );
    Program::wrapped(
        buffers,
        [1, 1, 1],
        vec![Node::Region {
            generator: Ident::from(OP_ID),
            source_region: None,
            body: Arc::new(body),
        }],
    )
}

/// Parallel in-place expansion program for production fixed-point drivers.
///
/// Unlike [`csr_forward_or_changed`], this variant gives each source node its
/// own invocation instead of walking the whole CSR from one lane. The pass is
/// monotone: each dispatch may observe only the frontier bits visible at that
/// point in the dispatch, but every newly discovered destination is ORed into
/// the same resident accumulator and sets `changed[0]`. Re-dispatch until the
/// changed flag stays zero to compute the same reachability fixpoint without a
/// full frontier readback per iteration.
#[must_use]
pub fn csr_forward_or_changed_parallel(
    shape: ProgramGraphShape,
    frontier_out: &str,
    changed: &str,
    edge_kind_mask: u32,
) -> Program {
    let src = Expr::InvocationId { axis: 0 };
    let words = crate::bitset::bitset_words(shape.node_count);
    let body = vec![
        Node::let_bind("word_idx", Expr::shr(src.clone(), Expr::u32(5))),
        Node::let_bind(
            "bit_mask",
            Expr::shl(Expr::u32(1), Expr::bitand(src.clone(), Expr::u32(31))),
        ),
        Node::let_bind("src_word", Expr::load(frontier_out, Expr::var("word_idx"))),
        Node::if_then(
            Expr::ne(
                Expr::bitand(Expr::var("src_word"), Expr::var("bit_mask")),
                Expr::u32(0),
            ),
            vec![
                Node::let_bind("edge_start", Expr::load(NAME_EDGE_OFFSETS, src.clone())),
                Node::let_bind(
                    "edge_end",
                    Expr::load(NAME_EDGE_OFFSETS, Expr::add(src.clone(), Expr::u32(1))),
                ),
                Node::loop_for(
                    "e",
                    Expr::var("edge_start"),
                    Expr::var("edge_end"),
                    vec![
                        Node::let_bind(
                            "kind_mask",
                            Expr::load(NAME_EDGE_KIND_MASK, Expr::var("e")),
                        ),
                        Node::if_then(
                            Expr::ne(
                                Expr::bitand(Expr::var("kind_mask"), Expr::u32(edge_kind_mask)),
                                Expr::u32(0),
                            ),
                            vec![
                                Node::let_bind(
                                    "dst",
                                    Expr::load(NAME_EDGE_TARGETS, Expr::var("e")),
                                ),
                                Node::if_then(
                                    Expr::lt(Expr::var("dst"), Expr::u32(shape.node_count)),
                                    vec![
                                        Node::let_bind(
                                            "dst_word_idx",
                                            Expr::shr(Expr::var("dst"), Expr::u32(5)),
                                        ),
                                        Node::let_bind(
                                            "dst_bit",
                                            Expr::shl(
                                                Expr::u32(1),
                                                Expr::bitand(Expr::var("dst"), Expr::u32(31)),
                                            ),
                                        ),
                                        Node::let_bind(
                                            "old",
                                            Expr::atomic_or(
                                                frontier_out,
                                                Expr::var("dst_word_idx"),
                                                Expr::var("dst_bit"),
                                            ),
                                        ),
                                        Node::if_then(
                                            Expr::eq(
                                                Expr::bitand(
                                                    Expr::var("old"),
                                                    Expr::var("dst_bit"),
                                                ),
                                                Expr::u32(0),
                                            ),
                                            vec![Node::let_bind(
                                                "_changed",
                                                Expr::atomic_or(
                                                    changed,
                                                    Expr::u32(0),
                                                    Expr::u32(1),
                                                ),
                                            )],
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
    let mut buffers = shape.read_only_buffers();
    buffers.push(
        BufferDecl::storage(
            frontier_out,
            BINDING_PRIMITIVE_START,
            BufferAccess::ReadWrite,
            DataType::U32,
        )
        .with_count(words.max(1)),
    );
    buffers.push(
        BufferDecl::storage(
            changed,
            BINDING_PRIMITIVE_START + 1,
            BufferAccess::ReadWrite,
            DataType::U32,
        )
        .with_count(1),
    );
    Program::wrapped(
        buffers,
        [1, 1, 1],
        vec![Node::Region {
            generator: Ident::from(OP_ID),
            source_region: None,
            body: Arc::new(vec![Node::if_then(
                Expr::lt(src.clone(), Expr::u32(shape.node_count)),
                body,
            )]),
        }],
    )
}

/// Parallel in-place expansion for several frontier accumulators at once.
///
/// Invocation axis 0 is the source node and axis 1 is the query/frontier index.
/// `frontier_out` is laid out as `query_count` consecutive bitsets, each
/// containing `bitset_words(shape.node_count)` u32 words. `changed` contains
/// one u32 flag per query.
#[must_use]
pub fn csr_forward_or_changed_parallel_batch(
    shape: ProgramGraphShape,
    frontier_out: &str,
    changed: &str,
    edge_kind_mask: u32,
    query_count: u32,
) -> Program {
    match try_csr_forward_or_changed_parallel_batch(
        shape,
        frontier_out,
        changed,
        edge_kind_mask,
        query_count,
    ) {
        Ok(program) => program,
        Err(error) => {
            eprintln!("{error}");
            inert_csr_forward_or_changed_batch_program(shape, frontier_out, changed, 1)
        }
    }
}

/// Parallel in-place expansion for several frontier accumulators with checked
/// flat-frontier sizing.
pub fn try_csr_forward_or_changed_parallel_batch(
    shape: ProgramGraphShape,
    frontier_out: &str,
    changed: &str,
    edge_kind_mask: u32,
    query_count: u32,
) -> Result<Program, String> {
    if query_count == 0 {
        return Err(
            "Fix: csr_forward_or_changed_parallel_batch requires at least one query frontier."
                .to_string(),
        );
    }
    let src = Expr::InvocationId { axis: 0 };
    let query = Expr::InvocationId { axis: 1 };
    let words = crate::bitset::bitset_words(shape.node_count);
    let total_words = checked_batched_frontier_words(words, query_count)?;
    let query_word_base = Expr::mul(query.clone(), Expr::u32(words));
    let body = vec![
        Node::let_bind("query_word_base", query_word_base.clone()),
        Node::let_bind(
            "word_idx",
            Expr::add(
                Expr::var("query_word_base"),
                Expr::shr(src.clone(), Expr::u32(5)),
            ),
        ),
        Node::let_bind(
            "bit_mask",
            Expr::shl(Expr::u32(1), Expr::bitand(src.clone(), Expr::u32(31))),
        ),
        Node::let_bind("src_word", Expr::load(frontier_out, Expr::var("word_idx"))),
        Node::if_then(
            Expr::ne(
                Expr::bitand(Expr::var("src_word"), Expr::var("bit_mask")),
                Expr::u32(0),
            ),
            vec![
                Node::let_bind("edge_start", Expr::load(NAME_EDGE_OFFSETS, src.clone())),
                Node::let_bind(
                    "edge_end",
                    Expr::load(NAME_EDGE_OFFSETS, Expr::add(src.clone(), Expr::u32(1))),
                ),
                Node::loop_for(
                    "e",
                    Expr::var("edge_start"),
                    Expr::var("edge_end"),
                    vec![
                        Node::let_bind(
                            "kind_mask",
                            Expr::load(NAME_EDGE_KIND_MASK, Expr::var("e")),
                        ),
                        Node::if_then(
                            Expr::ne(
                                Expr::bitand(Expr::var("kind_mask"), Expr::u32(edge_kind_mask)),
                                Expr::u32(0),
                            ),
                            vec![
                                Node::let_bind(
                                    "dst",
                                    Expr::load(NAME_EDGE_TARGETS, Expr::var("e")),
                                ),
                                Node::if_then(
                                    Expr::lt(Expr::var("dst"), Expr::u32(shape.node_count)),
                                    vec![
                                        Node::let_bind(
                                            "dst_word_idx",
                                            Expr::add(
                                                Expr::var("query_word_base"),
                                                Expr::shr(Expr::var("dst"), Expr::u32(5)),
                                            ),
                                        ),
                                        Node::let_bind(
                                            "dst_bit",
                                            Expr::shl(
                                                Expr::u32(1),
                                                Expr::bitand(Expr::var("dst"), Expr::u32(31)),
                                            ),
                                        ),
                                        Node::let_bind(
                                            "old",
                                            Expr::atomic_or(
                                                frontier_out,
                                                Expr::var("dst_word_idx"),
                                                Expr::var("dst_bit"),
                                            ),
                                        ),
                                        Node::if_then(
                                            Expr::eq(
                                                Expr::bitand(
                                                    Expr::var("old"),
                                                    Expr::var("dst_bit"),
                                                ),
                                                Expr::u32(0),
                                            ),
                                            vec![Node::let_bind(
                                                "_changed",
                                                Expr::atomic_or(
                                                    changed,
                                                    query.clone(),
                                                    Expr::u32(1),
                                                ),
                                            )],
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
    let mut buffers = shape.read_only_buffers();
    buffers.push(
        BufferDecl::storage(
            frontier_out,
            BINDING_PRIMITIVE_START,
            BufferAccess::ReadWrite,
            DataType::U32,
        )
        .with_count(total_words.max(1)),
    );
    buffers.push(
        BufferDecl::storage(
            changed,
            BINDING_PRIMITIVE_START + 1,
            BufferAccess::ReadWrite,
            DataType::U32,
        )
        .with_count(query_count),
    );
    Ok(Program::wrapped(
        buffers,
        [1, 1, 1],
        vec![Node::Region {
            generator: Ident::from(OP_ID),
            source_region: None,
            body: Arc::new(vec![Node::if_then(
                Expr::lt(src.clone(), Expr::u32(shape.node_count)),
                body,
            )]),
        }],
    ))
}

/// Batched parallel expansion with one global convergence flag.
///
/// Same frontier layout as [`csr_forward_or_changed_parallel_batch`], but every
/// newly discovered bit ORs `changed[0]` instead of `changed[query]`. This is
/// the hot-path convergence primitive for callers that only need to know
/// whether the whole query batch changed.
#[must_use]
pub fn csr_forward_or_changed_parallel_batch_global(
    shape: ProgramGraphShape,
    frontier_out: &str,
    changed: &str,
    edge_kind_mask: u32,
    query_count: u32,
) -> Program {
    csr_forward_or_changed_parallel_batch_global_slot(
        shape,
        frontier_out,
        changed,
        edge_kind_mask,
        query_count,
        0,
        1,
    )
}

/// Batched parallel expansion with one global convergence slot.
///
/// This variant writes `changed[changed_slot]` instead of always writing
/// `changed[0]`. Resident fixed-point drivers can allocate one changed word
/// per iteration and avoid a host-to-device reset upload before every
/// dispatch. The slot must be inside `changed_slots`.
#[must_use]
pub fn csr_forward_or_changed_parallel_batch_global_slot(
    shape: ProgramGraphShape,
    frontier_out: &str,
    changed: &str,
    edge_kind_mask: u32,
    query_count: u32,
    changed_slot: u32,
    changed_slots: u32,
) -> Program {
    match try_csr_forward_or_changed_parallel_batch_global_slot(
        shape,
        frontier_out,
        changed,
        edge_kind_mask,
        query_count,
        changed_slot,
        changed_slots,
    ) {
        Ok(program) => program,
        Err(error) => {
            eprintln!("{error}");
            inert_csr_forward_or_changed_batch_program(
                shape,
                frontier_out,
                changed,
                changed_slots.max(1),
            )
        }
    }
}

/// Batched parallel expansion with one checked global convergence slot.
pub fn try_csr_forward_or_changed_parallel_batch_global_slot(
    shape: ProgramGraphShape,
    frontier_out: &str,
    changed: &str,
    edge_kind_mask: u32,
    query_count: u32,
    changed_slot: u32,
    changed_slots: u32,
) -> Result<Program, String> {
    if query_count == 0 {
        return Err(
            "Fix: csr_forward_or_changed_parallel_batch_global requires at least one query frontier."
                .to_string(),
        );
    }
    if changed_slot >= changed_slots {
        return Err(
            "Fix: changed_slot must be inside the allocated changed_slots buffer.".to_string(),
        );
    }
    let src = Expr::InvocationId { axis: 0 };
    let query = Expr::InvocationId { axis: 1 };
    let words = crate::bitset::bitset_words(shape.node_count);
    let total_words = checked_batched_frontier_words(words, query_count)?;
    let query_word_base = Expr::mul(query.clone(), Expr::u32(words));
    let body = vec![
        Node::let_bind("query_word_base", query_word_base.clone()),
        Node::let_bind(
            "word_idx",
            Expr::add(
                Expr::var("query_word_base"),
                Expr::shr(src.clone(), Expr::u32(5)),
            ),
        ),
        Node::let_bind(
            "bit_mask",
            Expr::shl(Expr::u32(1), Expr::bitand(src.clone(), Expr::u32(31))),
        ),
        Node::let_bind("src_word", Expr::load(frontier_out, Expr::var("word_idx"))),
        Node::if_then(
            Expr::ne(
                Expr::bitand(Expr::var("src_word"), Expr::var("bit_mask")),
                Expr::u32(0),
            ),
            vec![
                Node::let_bind("edge_start", Expr::load(NAME_EDGE_OFFSETS, src.clone())),
                Node::let_bind(
                    "edge_end",
                    Expr::load(NAME_EDGE_OFFSETS, Expr::add(src.clone(), Expr::u32(1))),
                ),
                Node::loop_for(
                    "e",
                    Expr::var("edge_start"),
                    Expr::var("edge_end"),
                    vec![
                        Node::let_bind(
                            "kind_mask",
                            Expr::load(NAME_EDGE_KIND_MASK, Expr::var("e")),
                        ),
                        Node::if_then(
                            Expr::ne(
                                Expr::bitand(Expr::var("kind_mask"), Expr::u32(edge_kind_mask)),
                                Expr::u32(0),
                            ),
                            vec![
                                Node::let_bind(
                                    "dst",
                                    Expr::load(NAME_EDGE_TARGETS, Expr::var("e")),
                                ),
                                Node::if_then(
                                    Expr::lt(Expr::var("dst"), Expr::u32(shape.node_count)),
                                    vec![
                                        Node::let_bind(
                                            "dst_word_idx",
                                            Expr::add(
                                                Expr::var("query_word_base"),
                                                Expr::shr(Expr::var("dst"), Expr::u32(5)),
                                            ),
                                        ),
                                        Node::let_bind(
                                            "dst_bit",
                                            Expr::shl(
                                                Expr::u32(1),
                                                Expr::bitand(Expr::var("dst"), Expr::u32(31)),
                                            ),
                                        ),
                                        Node::let_bind(
                                            "old",
                                            Expr::atomic_or(
                                                frontier_out,
                                                Expr::var("dst_word_idx"),
                                                Expr::var("dst_bit"),
                                            ),
                                        ),
                                        Node::if_then(
                                            Expr::eq(
                                                Expr::bitand(
                                                    Expr::var("old"),
                                                    Expr::var("dst_bit"),
                                                ),
                                                Expr::u32(0),
                                            ),
                                            vec![Node::let_bind(
                                                "_changed",
                                                Expr::atomic_or(
                                                    changed,
                                                    Expr::u32(changed_slot),
                                                    Expr::u32(1),
                                                ),
                                            )],
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
    let mut buffers = shape.read_only_buffers();
    buffers.push(
        BufferDecl::storage(
            frontier_out,
            BINDING_PRIMITIVE_START,
            BufferAccess::ReadWrite,
            DataType::U32,
        )
        .with_count(total_words.max(1)),
    );
    buffers.push(
        BufferDecl::storage(
            changed,
            BINDING_PRIMITIVE_START + 1,
            BufferAccess::ReadWrite,
            DataType::U32,
        )
        .with_count(changed_slots),
    );
    Ok(Program::wrapped(
        buffers,
        [1, 1, 1],
        vec![Node::Region {
            generator: Ident::from(OP_ID),
            source_region: None,
            body: Arc::new(vec![Node::if_then(
                Expr::lt(src.clone(), Expr::u32(shape.node_count)),
                body,
            )]),
        }],
    ))
}

fn checked_batched_frontier_words(words: u32, query_count: u32) -> Result<u32, String> {
    words.checked_mul(query_count).ok_or_else(|| {
        format!(
            "Fix: batched CSR frontier words overflow u32: words={words}, query_count={query_count}."
        )
    })
}

fn inert_csr_forward_or_changed_batch_program(
    shape: ProgramGraphShape,
    frontier_out: &str,
    changed: &str,
    changed_slots: u32,
) -> Program {
    let mut buffers = shape.read_only_buffers();
    buffers.push(
        BufferDecl::storage(
            frontier_out,
            BINDING_PRIMITIVE_START,
            BufferAccess::ReadWrite,
            DataType::U32,
        )
        .with_count(1),
    );
    buffers.push(
        BufferDecl::storage(
            changed,
            BINDING_PRIMITIVE_START + 1,
            BufferAccess::ReadWrite,
            DataType::U32,
        )
        .with_count(changed_slots.max(1)),
    );

    Program::wrapped(
        buffers,
        [1, 1, 1],
        vec![Node::Region {
            generator: Ident::from(OP_ID),
            source_region: None,
            body: Arc::new(vec![Node::return_()]),
        }],
    )
}

/// CPU reference for one in-place expansion pass.
#[must_use]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn cpu_ref(
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    frontier: &[u32],
    allow_mask: u32,
) -> (Vec<u32>, u32) {
    let mut out = Vec::new();
    let changed = cpu_ref_into(
        node_count,
        edge_offsets,
        edge_targets,
        edge_kind_mask,
        frontier,
        allow_mask,
        &mut out,
    );
    (out, changed)
}

/// CPU reference writing the expanded frontier into caller-owned storage.
#[cfg(any(test, feature = "cpu-parity"))]
pub fn cpu_ref_into(
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    frontier: &[u32],
    allow_mask: u32,
    out: &mut Vec<u32>,
) -> u32 {
    let words = crate::bitset::bitset_words(node_count) as usize;
    out.clear();
    out.extend_from_slice(frontier);
    out.resize(words, 0);
    validate_csr_inputs(node_count, edge_offsets, edge_targets, edge_kind_mask).unwrap_or_else(
        |err| panic!("csr_forward_or_changed CPU oracle received malformed CSR. {err}"),
    );
    if edge_offsets.is_empty() {
        return 0;
    }
    let mut changed = 0u32;
    for src in 0..node_count as usize {
        let src_word = src / 32;
        let src_bit = 1u32 << (src % 32);
        if out[src_word] & src_bit == 0 {
            continue;
        }
        let start = edge_offsets[src] as usize;
        let end = edge_offsets[src + 1] as usize;
        for edge in start..end.min(edge_targets.len()).min(edge_kind_mask.len()) {
            if edge_kind_mask[edge] & allow_mask == 0 {
                continue;
            }
            let dst = edge_targets[edge] as usize;
            if dst >= node_count as usize {
                continue;
            }
            let word = dst / 32;
            let bit = 1u32 << (dst % 32);
            let old = out[word];
            out[word] |= bit;
            if out[word] != old {
                changed = 1;
            }
        }
    }
    changed
}

/// Iterate [`cpu_ref_into`] until the change flag reaches zero or
/// `max_iters` is exhausted.
#[must_use]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn cpu_ref_closure(
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    seed: &[u32],
    allow_mask: u32,
    max_iters: u32,
) -> Vec<u32> {
    let mut current = Vec::new();
    let mut next = Vec::new();
    cpu_ref_closure_into(
        node_count,
        edge_offsets,
        edge_targets,
        edge_kind_mask,
        seed,
        allow_mask,
        max_iters,
        &mut current,
        &mut next,
    );
    current
}

/// Iterate [`cpu_ref_into`] using caller-owned frontier buffers.
#[allow(clippy::too_many_arguments)]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn cpu_ref_closure_into(
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    seed: &[u32],
    allow_mask: u32,
    max_iters: u32,
    current: &mut Vec<u32>,
    next: &mut Vec<u32>,
) {
    cpu_ref_closure_into_with_step_hook(
        node_count,
        edge_offsets,
        edge_targets,
        edge_kind_mask,
        seed,
        allow_mask,
        max_iters,
        current,
        next,
        |_| {},
    );
}

/// Iterate [`cpu_ref_into`] with a callback after each attempted expansion.
///
/// The hook lets consumers attach observability without owning the
/// fixed-point algorithm.
#[allow(clippy::too_many_arguments)]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn cpu_ref_closure_into_with_step_hook<F>(
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    seed: &[u32],
    allow_mask: u32,
    max_iters: u32,
    current: &mut Vec<u32>,
    next: &mut Vec<u32>,
    mut on_step: F,
) where
    F: FnMut(u32),
{
    current.clear();
    current.extend_from_slice(seed);
    for iteration in 0..max_iters {
        on_step(iteration);
        let changed = cpu_ref_into(
            node_count,
            edge_offsets,
            edge_targets,
            edge_kind_mask,
            current,
            allow_mask,
            next,
        );
        if changed == 0 {
            std::mem::swap(current, next);
            return;
        }
        std::mem::swap(current, next);
    }
}

/// Validated dispatch layout for the forward-or-changed CSR primitive.
///
/// The primitive owns these derived counts so dispatch wrappers do not fork CSR
/// offset, edge-array, frontier, or scratch sizing rules.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CsrForwardOrChangedLayout {
    /// Number of nodes accepted by the primitive.
    pub node_count: u32,
    /// Number of words required by node-indexed scratch buffers.
    pub node_words: usize,
    /// Number of words required by the edge-offset buffer.
    pub edge_offset_words: usize,
    /// Number of edge-array words supplied to the primitive.
    pub edge_storage_words: usize,
    /// Edge count used when constructing [`ProgramGraphShape`].
    pub shape_edge_count: u32,
    /// Number of frontier words used by the dispatch buffer.
    pub frontier_words: usize,
}

/// Validate the CSR inputs used by the forward-or-changed primitive.
///
/// # Errors
///
/// Returns an actionable diagnostic when offsets are missing, non-monotonic,
/// inconsistent with edge arrays, or when targets/kind masks have mismatched
/// lengths.
pub fn validate_csr_inputs(
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
) -> Result<CsrForwardOrChangedLayout, String> {
    let expected_offsets = (node_count as usize).checked_add(1).ok_or_else(|| {
        format!(
            "Fix: csr_forward_or_changed node_count + 1 overflows usize for node_count={node_count}."
        )
    })?;
    let frontier_words = (crate::bitset::bitset_words(node_count) as usize).max(1);
    if edge_offsets.is_empty() {
        if edge_targets.is_empty() && edge_kind_mask.is_empty() {
            return Ok(CsrForwardOrChangedLayout {
                node_count,
                node_words: (node_count as usize).max(1),
                edge_offset_words: expected_offsets,
                edge_storage_words: 1,
                shape_edge_count: 0,
                frontier_words,
            });
        }
        return Err(format!(
            "Fix: csr_forward_or_changed empty edge_offsets may only encode an empty edge set, got targets_len={} kind_mask_len={}.",
            edge_targets.len(),
            edge_kind_mask.len()
        ));
    }
    if edge_offsets.len() != expected_offsets {
        return Err(format!(
            "Fix: csr_forward_or_changed requires edge_offsets.len() == node_count + 1, got len={}, node_count={node_count}.",
            edge_offsets.len()
        ));
    }
    if edge_targets.len() != edge_kind_mask.len() {
        return Err(format!(
            "Fix: csr_forward_or_changed requires edge_targets.len() == edge_kind_mask.len(), got {} vs {}.",
            edge_targets.len(),
            edge_kind_mask.len()
        ));
    }
    let shape_edge_count = u32::try_from(edge_kind_mask.len()).map_err(|_| {
        format!(
            "Fix: csr_forward_or_changed edge count {} exceeds u32 index space.",
            edge_kind_mask.len()
        )
    })?;
    for (index, pair) in edge_offsets.windows(2).enumerate() {
        if pair[0] > pair[1] {
            return Err(format!(
                "Fix: csr_forward_or_changed offsets must be monotonic; offsets[{index}]={} > offsets[{}]={}.",
                pair[0],
                index + 1,
                pair[1]
            ));
        }
    }
    let edge_count = edge_offsets[expected_offsets - 1] as usize;
    if edge_targets.len() < edge_count {
        return Err(format!(
            "Fix: csr_forward_or_changed final offset declares edge_count={edge_count}, but targets_len={} and kind_mask_len={}.",
            edge_targets.len(),
            edge_kind_mask.len()
        ));
    }
    Ok(CsrForwardOrChangedLayout {
        node_count,
        node_words: (node_count as usize).max(1),
        edge_offset_words: expected_offsets,
        edge_storage_words: edge_kind_mask.len().max(1),
        shape_edge_count,
        frontier_words,
    })
}

#[cfg(feature = "inventory-registry")]
inventory::submit! {
    crate::harness::OpEntry::new(
        OP_ID,
        || csr_forward_or_changed(ProgramGraphShape::new(4, 4), "frontier", "changed", 1),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![
                to_bytes(&[0, 0, 0, 0]),
                to_bytes(&[0, 2, 3, 4, 4]),
                to_bytes(&[1, 2, 3, 3]),
                to_bytes(&[1, 1, 1, 1]),
                to_bytes(&[0, 0, 0, 0]),
                to_bytes(&[0b0001]),
                to_bytes(&[0]),
            ]]
        }),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![to_bytes(&[0b1111]), to_bytes(&[1])]]
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_ref_expands_in_place_frontier_pass() {
        let (frontier, changed) = cpu_ref(
            4,
            &[0, 2, 3, 4, 4],
            &[1, 2, 3, 3],
            &[1, 1, 1, 1],
            &[0b0001],
            1,
        );
        assert_eq!(frontier, vec![0b1111]);
        assert_eq!(changed, 1);
    }

    #[test]
    fn cpu_ref_closure_reaches_fixpoint() {
        let closure = cpu_ref_closure(
            4,
            &[0, 1, 2, 3, 3],
            &[1, 2, 3],
            &[1, 1, 1],
            &[0b0001],
            0xFFFF_FFFF,
            10,
        );
        assert_eq!(closure, vec![0b1111]);
    }

    #[test]
    fn cpu_ref_closure_into_reuses_buffers() {
        let mut current = Vec::with_capacity(8);
        let mut next = Vec::with_capacity(8);
        cpu_ref_closure_into(
            4,
            &[0, 1, 2, 3, 3],
            &[1, 2, 3],
            &[1, 1, 1],
            &[0b0001],
            0xFFFF_FFFF,
            10,
            &mut current,
            &mut next,
        );
        let current_capacity = current.capacity();
        let next_capacity = next.capacity();
        assert_eq!(current, vec![0b1111]);

        cpu_ref_closure_into(
            4,
            &[0, 1, 2, 3, 3],
            &[1, 2, 3],
            &[1, 1, 1],
            &[0],
            0xFFFF_FFFF,
            10,
            &mut current,
            &mut next,
        );
        assert_eq!(current.capacity(), current_capacity);
        assert_eq!(next.capacity(), next_capacity);
        assert_eq!(current, vec![0]);
    }

    #[test]
    fn validate_csr_inputs_rejects_mismatched_and_nonmonotonic_csr() {
        let err = validate_csr_inputs(2, &[0, 1, 1], &[1], &[]).unwrap_err();
        assert!(err.contains("edge_targets.len() == edge_kind_mask.len()"));

        let err = validate_csr_inputs(2, &[0, 2, 1], &[1, 0], &[1, 1]).unwrap_err();
        assert!(err.contains("offsets must be monotonic"));
    }

    #[test]
    fn empty_offsets_shorthand_is_empty_edge_set_only() {
        assert_eq!(
            validate_csr_inputs(64, &[], &[], &[]).expect("empty CSR shorthand is valid"),
            CsrForwardOrChangedLayout {
                node_count: 64,
                node_words: 64,
                edge_offset_words: 65,
                edge_storage_words: 1,
                shape_edge_count: 0,
                frontier_words: 2,
            }
        );

        let err = validate_csr_inputs(64, &[], &[1], &[]).unwrap_err();
        assert!(err.contains("empty edge_offsets may only encode an empty edge set"));

        let mut out = Vec::new();
        let changed = cpu_ref_into(64, &[], &[], &[], &[0b101], 0xFFFF_FFFF, &mut out);
        assert_eq!(changed, 0);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0], 0b101);
        assert_eq!(out[1], 0);
    }

    #[test]
    fn parallel_program_keeps_frontier_and_changed_resident() {
        let program = csr_forward_or_changed_parallel(
            ProgramGraphShape::new(65, 4),
            "frontier",
            "changed",
            0xFFFF_FFFF,
        );
        assert_eq!(program.workgroup_size, [1, 1, 1]);
        let names: Vec<&str> = program.buffers.iter().map(|buffer| buffer.name()).collect();
        assert!(names.contains(&"frontier"));
        assert!(names.contains(&"changed"));
        assert!(
            names.iter().any(|name| name.starts_with("pg_")),
            "parallel CSR expansion must keep ProgramGraph buffers resident"
        );
    }

    #[test]
    fn parallel_batch_program_packs_query_frontiers() {
        let program = csr_forward_or_changed_parallel_batch(
            ProgramGraphShape::new(65, 4),
            "frontiers",
            "changed",
            0xFFFF_FFFF,
            3,
        );
        assert_eq!(program.workgroup_size, [1, 1, 1]);
        let frontier = program
            .buffers
            .iter()
            .find(|buffer| buffer.name() == "frontiers")
            .expect("frontiers buffer must exist");
        let changed = program
            .buffers
            .iter()
            .find(|buffer| buffer.name() == "changed")
            .expect("changed buffer must exist");
        assert_eq!(frontier.count(), 9);
        assert_eq!(changed.count(), 3);
    }

    #[test]
    fn parallel_batch_global_program_uses_one_changed_flag() {
        let program = csr_forward_or_changed_parallel_batch_global(
            ProgramGraphShape::new(65, 4),
            "frontiers",
            "changed",
            0xFFFF_FFFF,
            3,
        );
        let frontier = program
            .buffers
            .iter()
            .find(|buffer| buffer.name() == "frontiers")
            .expect("frontiers buffer must exist");
        let changed = program
            .buffers
            .iter()
            .find(|buffer| buffer.name() == "changed")
            .expect("changed buffer must exist");
        assert_eq!(frontier.count(), 9);
        assert_eq!(changed.count(), 1);
    }

    #[test]
    fn parallel_batch_global_slot_program_uses_changed_history_buffer() {
        let program = csr_forward_or_changed_parallel_batch_global_slot(
            ProgramGraphShape::new(65, 4),
            "frontiers",
            "changed",
            0xFFFF_FFFF,
            3,
            5,
            8,
        );
        let frontier = program
            .buffers
            .iter()
            .find(|buffer| buffer.name() == "frontiers")
            .expect("frontiers buffer must exist");
        let changed = program
            .buffers
            .iter()
            .find(|buffer| buffer.name() == "changed")
            .expect("changed buffer must exist");
        assert_eq!(frontier.count(), 9);
        assert_eq!(changed.count(), 8);
    }

    #[test]
    fn checked_parallel_batch_rejects_zero_queries() {
        let error = try_csr_forward_or_changed_parallel_batch(
            ProgramGraphShape::new(65, 4),
            "frontiers",
            "changed",
            0xFFFF_FFFF,
            0,
        )
        .expect_err("checked CSR batch builder must reject empty query batches");

        assert!(
            error.contains("at least one query frontier"),
            "error should describe the invalid batch shape: {error}"
        );
    }

    #[test]
    fn checked_parallel_batch_rejects_flat_frontier_overflow() {
        let error = try_csr_forward_or_changed_parallel_batch(
            ProgramGraphShape::new(u32::MAX, 0),
            "frontiers",
            "changed",
            0xFFFF_FFFF,
            33,
        )
        .expect_err("checked CSR batch builder must reject flat frontier overflow");

        assert!(
            error.contains("frontier words overflow u32"),
            "error should describe the flat frontier overflow: {error}"
        );
    }

    #[test]
    fn legacy_parallel_batch_does_not_panic_on_flat_frontier_overflow() {
        let program = csr_forward_or_changed_parallel_batch(
            ProgramGraphShape::new(u32::MAX, 0),
            "frontiers",
            "changed",
            0xFFFF_FFFF,
            33,
        );
        let frontier = program
            .buffers
            .iter()
            .find(|buffer| buffer.name() == "frontiers")
            .expect("frontiers buffer must exist");
        let changed = program
            .buffers
            .iter()
            .find(|buffer| buffer.name() == "changed")
            .expect("changed buffer must exist");

        assert_eq!(frontier.count(), 1);
        assert_eq!(changed.count(), 1);
    }

    #[test]
    fn checked_parallel_global_slot_rejects_invalid_changed_slot() {
        let error = try_csr_forward_or_changed_parallel_batch_global_slot(
            ProgramGraphShape::new(65, 4),
            "frontiers",
            "changed",
            0xFFFF_FFFF,
            3,
            8,
            8,
        )
        .expect_err("checked CSR global-slot builder must reject out-of-range changed slot");

        assert!(
            error.contains("changed_slot must be inside"),
            "error should describe the invalid changed slot: {error}"
        );
    }

    #[test]
    fn legacy_parallel_global_slot_does_not_panic_on_invalid_changed_slot() {
        let program = csr_forward_or_changed_parallel_batch_global_slot(
            ProgramGraphShape::new(65, 4),
            "frontiers",
            "changed",
            0xFFFF_FFFF,
            3,
            8,
            8,
        );
        let changed = program
            .buffers
            .iter()
            .find(|buffer| buffer.name() == "changed")
            .expect("changed buffer must exist");

        assert_eq!(changed.count(), 8);
    }

    #[test]
    fn csr_forward_or_changed_batch_source_has_checked_api_without_panics() {
        let source = include_str!("csr_forward_or_changed.rs");
        let batch_source = source
            .split("/// Parallel in-place expansion for several frontier accumulators at once.")
            .nth(1)
            .expect("CSR batch builder source must be present")
            .split("/// CPU reference for one in-place expansion pass.")
            .next()
            .expect("CSR batch builder source must precede CPU oracle");

        assert!(
            batch_source.contains("pub fn try_csr_forward_or_changed_parallel_batch(")
                && batch_source
                    .contains("pub fn try_csr_forward_or_changed_parallel_batch_global_slot(")
                && !batch_source.contains(concat!("panic", "!("))
                && !batch_source.contains("assert!(")
                && !batch_source.contains(".unwrap_or_else("),
            "Fix: batched CSR forward-or-changed builders must expose checked release APIs and avoid production panics."
        );
    }
}
