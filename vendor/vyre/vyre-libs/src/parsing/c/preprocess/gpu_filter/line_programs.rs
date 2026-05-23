use super::program_helpers::packed_byte_load;
use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

pub(super) fn simple_line_newline_flags_program(n: u32) -> Program {
    let i = Expr::var("i");
    let byte = packed_byte_load("bytes_in", i.clone());
    let body = vec![
        Node::let_bind("i", Expr::InvocationId { axis: 0 }),
        Node::if_then(
            Expr::lt(i.clone(), Expr::u32(n)),
            vec![
                Node::let_bind("n_real", Expr::load("line_n_real", Expr::u32(0))),
                Node::store(
                    "newline_flags",
                    i.clone(),
                    Expr::select(
                        Expr::and(
                            Expr::lt(i.clone(), Expr::var("n_real")),
                            Expr::eq(byte, Expr::u32(b'\n' as u32)),
                        ),
                        Expr::u32(1),
                        Expr::u32(0),
                    ),
                ),
            ],
        ),
    ];
    Program::wrapped(
        vec![
            BufferDecl::storage("bytes_in", 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(n.div_ceil(4).max(1)),
            BufferDecl::storage("newline_flags", 1, BufferAccess::ReadWrite, DataType::U32)
                .with_count(n.max(1)),
            BufferDecl::storage("line_n_real", 2, BufferAccess::ReadOnly, DataType::U32)
                .with_count(1),
        ],
        [256, 1, 1],
        body,
    )
    .with_entry_op_id("vyre-libs::parsing::c::preprocess::simple_line_newline_flags")
}

pub(super) fn simple_line_comment_starts_program(n: u32) -> Program {
    let i = Expr::var("i");
    let b0 = packed_byte_load("bytes_in", i.clone());
    let b1_addr = Expr::add(i.clone(), Expr::u32(1));
    let b1 = Expr::select(
        Expr::lt(b1_addr.clone(), Expr::load("line_n_real", Expr::u32(0))),
        packed_byte_load("bytes_in", b1_addr),
        Expr::u32(0),
    );
    let row = Expr::saturating_sub(
        Expr::load("newline_scan", i.clone()),
        Expr::load("newline_flags", i.clone()),
    );
    let body = vec![
        Node::let_bind("i", Expr::InvocationId { axis: 0 }),
        Node::if_then(
            Expr::lt(i.clone(), Expr::load("line_n_real", Expr::u32(0))),
            vec![Node::if_then(
                Expr::and(
                    Expr::eq(b0, Expr::u32(b'/' as u32)),
                    Expr::eq(b1, Expr::u32(b'/' as u32)),
                ),
                vec![Node::let_bind(
                    "line_comment_start_old",
                    Expr::atomic_min("row_comment_starts", row, i.clone()),
                )],
            )],
        ),
    ];
    Program::wrapped(
        vec![
            BufferDecl::storage("bytes_in", 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(n.div_ceil(4).max(1)),
            BufferDecl::storage("newline_flags", 1, BufferAccess::ReadOnly, DataType::U32)
                .with_count(n.max(1)),
            BufferDecl::storage("newline_scan", 2, BufferAccess::ReadOnly, DataType::U32)
                .with_count(n.max(1)),
            BufferDecl::storage(
                "row_comment_starts",
                3,
                BufferAccess::ReadWrite,
                DataType::U32,
            )
            .with_count(n.max(1)),
            BufferDecl::storage("line_n_real", 4, BufferAccess::ReadOnly, DataType::U32)
                .with_count(1),
        ],
        [256, 1, 1],
        body,
    )
    .with_entry_op_id("vyre-libs::parsing::c::preprocess::simple_line_comment_starts")
}

pub(super) fn simple_line_comment_masks_program(n: u32) -> Program {
    let i = Expr::var("i");
    let b = packed_byte_load("bytes_in", i.clone());
    let row = Expr::saturating_sub(
        Expr::load("newline_scan", i.clone()),
        Expr::load("newline_flags", i.clone()),
    );
    let body = vec![
        Node::let_bind("i", Expr::InvocationId { axis: 0 }),
        Node::if_then(
            Expr::lt(i.clone(), Expr::u32(n)),
            vec![
                Node::let_bind("n_real", Expr::load("line_n_real", Expr::u32(0))),
                Node::if_then_else(
                    Expr::lt(i.clone(), Expr::var("n_real")),
                    vec![
                        Node::let_bind("is_newline", Expr::eq(b, Expr::u32(b'\n' as u32))),
                        Node::let_bind("row", row),
                        Node::let_bind("start", Expr::load("row_comment_starts", Expr::var("row"))),
                        Node::let_bind(
                            "comment_mask",
                            Expr::select(
                                Expr::and(
                                    Expr::ne(Expr::var("start"), Expr::u32(u32::MAX)),
                                    Expr::and(
                                        Expr::ge(i.clone(), Expr::var("start")),
                                        Expr::not(Expr::var("is_newline")),
                                    ),
                                ),
                                Expr::select(
                                    Expr::eq(i.clone(), Expr::var("start")),
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
            BufferDecl::storage("bytes_in", 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(n.div_ceil(4).max(1)),
            BufferDecl::storage("newline_flags", 1, BufferAccess::ReadOnly, DataType::U32)
                .with_count(n.max(1)),
            BufferDecl::storage("newline_scan", 2, BufferAccess::ReadOnly, DataType::U32)
                .with_count(n.max(1)),
            BufferDecl::storage(
                "row_comment_starts",
                3,
                BufferAccess::ReadOnly,
                DataType::U32,
            )
            .with_count(n.max(1)),
            BufferDecl::storage("final_keep", 4, BufferAccess::ReadWrite, DataType::U32)
                .with_count(n.max(1)),
            BufferDecl::storage(
                "comment_mask_out",
                5,
                BufferAccess::ReadWrite,
                DataType::U32,
            )
            .with_count(n.max(1)),
            BufferDecl::storage("line_n_real", 6, BufferAccess::ReadOnly, DataType::U32)
                .with_count(1),
        ],
        [256, 1, 1],
        body,
    )
    .with_entry_op_id("vyre-libs::parsing::c::preprocess::simple_line_comment_masks")
}
