use super::program_helpers::packed_byte_load;
use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

pub(super) fn simple_block_comment_marks_program(n: u32) -> Program {
    let i = Expr::var("i");
    let b0 = packed_byte_load("bytes_in", i.clone());
    let b1_addr = Expr::add(i.clone(), Expr::u32(1));
    let b1 = Expr::select(
        Expr::lt(b1_addr.clone(), Expr::load("block_n_real", Expr::u32(0))),
        packed_byte_load("bytes_in", b1_addr),
        Expr::u32(0),
    );
    let after_close = Expr::add(i.clone(), Expr::u32(2));
    let body = vec![
        Node::let_bind("i", Expr::InvocationId { axis: 0 }),
        Node::if_then(
            Expr::lt(i.clone(), Expr::u32(n)),
            vec![
                Node::let_bind("n_real", Expr::load("block_n_real", Expr::u32(0))),
                Node::let_bind(
                    "opens_block",
                    Expr::and(
                        Expr::lt(i.clone(), Expr::var("n_real")),
                        Expr::and(
                            Expr::eq(b0, Expr::u32(b'/' as u32)),
                            Expr::eq(b1.clone(), Expr::u32(b'*' as u32)),
                        ),
                    ),
                ),
                Node::store(
                    "block_open_flags",
                    i.clone(),
                    Expr::select(Expr::var("opens_block"), Expr::u32(1), Expr::u32(0)),
                ),
                Node::if_then(
                    Expr::and(
                        Expr::lt(after_close.clone(), Expr::u32(n)),
                        Expr::and(
                            Expr::lt(i.clone(), Expr::var("n_real")),
                            Expr::and(
                                Expr::eq(
                                    packed_byte_load("bytes_in", i.clone()),
                                    Expr::u32(b'*' as u32),
                                ),
                                Expr::eq(b1, Expr::u32(b'/' as u32)),
                            ),
                        ),
                    ),
                    vec![Node::store(
                        "block_close_after_flags",
                        after_close,
                        Expr::u32(1),
                    )],
                ),
            ],
        ),
    ];
    Program::wrapped(
        vec![
            BufferDecl::storage("bytes_in", 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(n.div_ceil(4).max(1)),
            BufferDecl::storage(
                "block_open_flags",
                1,
                BufferAccess::ReadWrite,
                DataType::U32,
            )
            .with_count(n.max(1)),
            BufferDecl::storage(
                "block_close_after_flags",
                2,
                BufferAccess::ReadWrite,
                DataType::U32,
            )
            .with_count(n.max(1)),
            BufferDecl::storage("block_n_real", 3, BufferAccess::ReadOnly, DataType::U32)
                .with_count(1),
        ],
        [256, 1, 1],
        body,
    )
    .with_entry_op_id("vyre-libs::parsing::c::preprocess::simple_block_comment_marks")
}

pub(super) fn simple_block_comment_topology_program(n: u32) -> Program {
    let i = Expr::var("i");
    let prev = Expr::saturating_sub(i.clone(), Expr::u32(1));
    let body = vec![
        Node::let_bind("i", Expr::InvocationId { axis: 0 }),
        Node::if_then(
            Expr::lt(i.clone(), Expr::load("block_n_real", Expr::u32(0))),
            vec![
                Node::let_bind("open_here", Expr::load("block_open_flags", i.clone())),
                Node::let_bind(
                    "open_before",
                    Expr::saturating_sub(
                        Expr::load("block_open_scan", i.clone()),
                        Expr::var("open_here"),
                    ),
                ),
                Node::let_bind(
                    "closed_before",
                    Expr::load("block_close_after_scan", i.clone()),
                ),
                Node::if_then(
                    Expr::and(
                        Expr::eq(Expr::var("open_here"), Expr::u32(1)),
                        Expr::gt(Expr::var("open_before"), Expr::var("closed_before")),
                    ),
                    vec![Node::let_bind(
                        "nested_block_open_old",
                        Expr::atomic_or("block_topology_invalid", Expr::u32(0), Expr::u32(1)),
                    )],
                ),
                Node::let_bind(
                    "close_after_here",
                    Expr::load("block_close_after_flags", i.clone()),
                ),
                Node::if_then(
                    Expr::eq(Expr::var("close_after_here"), Expr::u32(1)),
                    vec![
                        Node::let_bind(
                            "open_at_close",
                            Expr::load("block_open_scan", prev.clone()),
                        ),
                        Node::let_bind(
                            "closed_before_close",
                            Expr::load("block_close_after_scan", prev),
                        ),
                        Node::if_then(
                            Expr::le(Expr::var("open_at_close"), Expr::var("closed_before_close")),
                            vec![Node::let_bind(
                                "stray_block_close_old",
                                Expr::atomic_or(
                                    "block_topology_invalid",
                                    Expr::u32(0),
                                    Expr::u32(1),
                                ),
                            )],
                        ),
                    ],
                ),
            ],
        ),
    ];
    Program::wrapped(
        vec![
            BufferDecl::storage("block_open_flags", 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(n.max(1)),
            BufferDecl::storage(
                "block_close_after_flags",
                1,
                BufferAccess::ReadOnly,
                DataType::U32,
            )
            .with_count(n.max(1)),
            BufferDecl::storage("block_open_scan", 2, BufferAccess::ReadOnly, DataType::U32)
                .with_count(n.max(1)),
            BufferDecl::storage(
                "block_close_after_scan",
                3,
                BufferAccess::ReadOnly,
                DataType::U32,
            )
            .with_count(n.max(1)),
            BufferDecl::storage(
                "block_topology_invalid",
                4,
                BufferAccess::ReadWrite,
                DataType::U32,
            )
            .with_count(1),
            BufferDecl::storage("block_n_real", 5, BufferAccess::ReadOnly, DataType::U32)
                .with_count(1),
        ],
        [256, 1, 1],
        body,
    )
    .with_entry_op_id("vyre-libs::parsing::c::preprocess::simple_block_comment_topology")
}

pub(super) fn simple_block_comment_masks_program(n: u32) -> Program {
    let i = Expr::var("i");
    let body = vec![
        Node::let_bind("i", Expr::InvocationId { axis: 0 }),
        Node::if_then(
            Expr::lt(i.clone(), Expr::u32(n)),
            vec![
                Node::let_bind("n_real", Expr::load("block_n_real", Expr::u32(0))),
                Node::if_then_else(
                    Expr::lt(i.clone(), Expr::var("n_real")),
                    vec![
                        Node::let_bind("open_count", Expr::load("block_open_scan", i.clone())),
                        Node::let_bind(
                            "closed_before_count",
                            Expr::load("block_close_after_scan", i.clone()),
                        ),
                        Node::let_bind(
                            "inside_block",
                            Expr::gt(Expr::var("open_count"), Expr::var("closed_before_count")),
                        ),
                        Node::let_bind(
                            "comment_mask",
                            Expr::select(
                                Expr::var("inside_block"),
                                Expr::select(
                                    Expr::eq(
                                        Expr::load("block_open_flags", i.clone()),
                                        Expr::u32(1),
                                    ),
                                    Expr::u32(2),
                                    Expr::u32(1),
                                ),
                                Expr::u32(0),
                            ),
                        ),
                        Node::store("comment_mask_out", i.clone(), Expr::var("comment_mask")),
                        Node::store(
                            "final_keep",
                            i.clone(),
                            Expr::select(
                                Expr::ne(Expr::var("comment_mask"), Expr::u32(1)),
                                Expr::u32(1),
                                Expr::u32(0),
                            ),
                        ),
                    ],
                    vec![
                        Node::store("comment_mask_out", i.clone(), Expr::u32(0)),
                        Node::store("final_keep", i.clone(), Expr::u32(0)),
                    ],
                ),
            ],
        ),
    ];
    Program::wrapped(
        vec![
            BufferDecl::storage("block_open_flags", 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(n.max(1)),
            BufferDecl::storage("block_open_scan", 1, BufferAccess::ReadOnly, DataType::U32)
                .with_count(n.max(1)),
            BufferDecl::storage(
                "block_close_after_scan",
                2,
                BufferAccess::ReadOnly,
                DataType::U32,
            )
            .with_count(n.max(1)),
            BufferDecl::storage("final_keep", 3, BufferAccess::ReadWrite, DataType::U32)
                .with_count(n.max(1)),
            BufferDecl::storage(
                "comment_mask_out",
                4,
                BufferAccess::ReadWrite,
                DataType::U32,
            )
            .with_count(n.max(1)),
            BufferDecl::storage("block_n_real", 5, BufferAccess::ReadOnly, DataType::U32)
                .with_count(1),
        ],
        [256, 1, 1],
        body,
    )
    .with_entry_op_id("vyre-libs::parsing::c::preprocess::simple_block_comment_masks")
}
