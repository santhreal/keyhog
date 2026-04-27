use crate::parsing::c::lex::tokens::*;
use crate::parsing::core::ast::node::*;
use crate::region::wrap_anonymous;
use operator::{ast_opcode, is_binary_token, is_value_token, should_pop};
use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

mod operator;

const OP_ID: &str = "vyre-libs::parsing::ast_shunting_yard";
const MAX_TOK_SCAN: u32 = 65_536;
const STACK_SLOTS_PER_STATEMENT: u32 = 64;

fn emit_value_leaf(
    out_ast_nodes: &str,
    out_ast_count: &str,
    scratch_val_stack: &str,
    val_stack_base: Expr,
) -> Vec<Node> {
    vec![
        Node::let_bind(
            "ast_idx",
            Expr::atomic_add(out_ast_count, Expr::u32(0), Expr::u32(4)),
        ),
        Node::let_bind(
            "opcode",
            Expr::select(
                Expr::eq(Expr::var("tok"), Expr::u32(TOK_INTEGER)),
                Expr::u32(AST_CONST_INT),
                Expr::u32(AST_VAR),
            ),
        ),
        Node::store(out_ast_nodes, Expr::var("ast_idx"), Expr::var("opcode")),
        Node::store(
            out_ast_nodes,
            Expr::add(Expr::var("ast_idx"), Expr::u32(1)),
            Expr::u32(u32::MAX),
        ),
        Node::store(
            out_ast_nodes,
            Expr::add(Expr::var("ast_idx"), Expr::u32(2)),
            Expr::u32(u32::MAX),
        ),
        Node::store(
            out_ast_nodes,
            Expr::add(Expr::var("ast_idx"), Expr::u32(3)),
            Expr::var("tok_idx"),
        ),
        Node::store(
            scratch_val_stack,
            Expr::add(val_stack_base, Expr::var("v_sp")),
            Expr::var("ast_idx"),
        ),
        Node::assign("v_sp", Expr::add(Expr::var("v_sp"), Expr::u32(1))),
    ]
}

fn reduce_loaded_operator(
    out_ast_nodes: &str,
    out_ast_count: &str,
    scratch_val_stack: &str,
    val_stack_base: Expr,
) -> Vec<Node> {
    vec![
        Node::assign("v_sp", Expr::sub(Expr::var("v_sp"), Expr::u32(1))),
        Node::let_bind(
            "right_child",
            Expr::load(
                scratch_val_stack,
                Expr::add(val_stack_base.clone(), Expr::var("v_sp")),
            ),
        ),
        Node::assign("v_sp", Expr::sub(Expr::var("v_sp"), Expr::u32(1))),
        Node::let_bind(
            "left_child",
            Expr::load(
                scratch_val_stack,
                Expr::add(val_stack_base.clone(), Expr::var("v_sp")),
            ),
        ),
        Node::let_bind(
            "ast_idx",
            Expr::atomic_add(out_ast_count, Expr::u32(0), Expr::u32(4)),
        ),
        Node::store(
            out_ast_nodes,
            Expr::var("ast_idx"),
            ast_opcode(Expr::var("top_op")),
        ),
        Node::store(
            out_ast_nodes,
            Expr::add(Expr::var("ast_idx"), Expr::u32(1)),
            Expr::var("left_child"),
        ),
        Node::store(
            out_ast_nodes,
            Expr::add(Expr::var("ast_idx"), Expr::u32(2)),
            Expr::var("right_child"),
        ),
        Node::store(
            out_ast_nodes,
            Expr::add(Expr::var("ast_idx"), Expr::u32(3)),
            Expr::u32(u32::MAX),
        ),
        Node::store(
            scratch_val_stack,
            Expr::add(val_stack_base, Expr::var("v_sp")),
            Expr::var("ast_idx"),
        ),
        Node::assign("v_sp", Expr::add(Expr::var("v_sp"), Expr::u32(1))),
    ]
}

fn reduce_if_allowed(
    scratch_op_stack: &str,
    out_ast_nodes: &str,
    out_ast_count: &str,
    scratch_val_stack: &str,
    val_stack_base: Expr,
    op_stack_base: Expr,
) -> Vec<Node> {
    let mut body = vec![Node::assign(
        "o_sp",
        Expr::sub(Expr::var("o_sp"), Expr::u32(1)),
    )];
    body.extend(reduce_loaded_operator(
        out_ast_nodes,
        out_ast_count,
        scratch_val_stack,
        val_stack_base,
    ));

    vec![
        Node::let_bind(
            "top_op",
            Expr::load(
                scratch_op_stack,
                Expr::add(op_stack_base, Expr::sub(Expr::var("o_sp"), Expr::u32(1))),
            ),
        ),
        Node::let_bind(
            "reduce_now",
            Expr::and(
                should_pop(Expr::var("top_op"), Expr::var("tok")),
                Expr::ge(Expr::var("v_sp"), Expr::u32(2)),
            ),
        ),
        Node::if_then(Expr::var("reduce_now"), body),
        Node::if_then(
            Expr::not(Expr::var("reduce_now")),
            vec![Node::assign("done_bin", Expr::u32(1))],
        ),
    ]
}

fn binary_token_body(
    scratch_op_stack: &str,
    out_ast_nodes: &str,
    out_ast_count: &str,
    scratch_val_stack: &str,
    val_stack_base: Expr,
    op_stack_base: Expr,
) -> Vec<Node> {
    let reduce_one = reduce_if_allowed(
        scratch_op_stack,
        out_ast_nodes,
        out_ast_count,
        scratch_val_stack,
        val_stack_base,
        op_stack_base.clone(),
    );

    vec![
        Node::let_bind("done_bin", Expr::u32(0)),
        Node::loop_for(
            "pop",
            Expr::u32(0),
            Expr::u32(STACK_SLOTS_PER_STATEMENT),
            vec![Node::if_then(
                Expr::eq(Expr::var("done_bin"), Expr::u32(0)),
                vec![
                    Node::if_then(
                        Expr::eq(Expr::var("o_sp"), Expr::u32(0)),
                        vec![Node::assign("done_bin", Expr::u32(1))],
                    ),
                    Node::if_then(Expr::ne(Expr::var("o_sp"), Expr::u32(0)), reduce_one),
                ],
            )],
        ),
        Node::store(
            scratch_op_stack,
            Expr::add(op_stack_base, Expr::var("o_sp")),
            Expr::var("tok"),
        ),
        Node::assign("o_sp", Expr::add(Expr::var("o_sp"), Expr::u32(1))),
    ]
}

fn rparen_body(
    scratch_op_stack: &str,
    out_ast_nodes: &str,
    out_ast_count: &str,
    scratch_val_stack: &str,
    val_stack_base: Expr,
    op_stack_base: Expr,
) -> Vec<Node> {
    vec![
        Node::let_bind("done_rp", Expr::u32(0)),
        Node::loop_for(
            "pop",
            Expr::u32(0),
            Expr::u32(STACK_SLOTS_PER_STATEMENT),
            vec![Node::if_then(
                Expr::eq(Expr::var("done_rp"), Expr::u32(0)),
                vec![
                    Node::if_then(
                        Expr::eq(Expr::var("o_sp"), Expr::u32(0)),
                        vec![Node::assign("done_rp", Expr::u32(1))],
                    ),
                    Node::if_then(Expr::ne(Expr::var("o_sp"), Expr::u32(0)), {
                        let mut body = vec![
                            Node::assign("o_sp", Expr::sub(Expr::var("o_sp"), Expr::u32(1))),
                            Node::let_bind(
                                "top_op",
                                Expr::load(
                                    scratch_op_stack,
                                    Expr::add(op_stack_base.clone(), Expr::var("o_sp")),
                                ),
                            ),
                            Node::if_then(
                                Expr::eq(Expr::var("top_op"), Expr::u32(TOK_LPAREN)),
                                vec![Node::assign("done_rp", Expr::u32(1))],
                            ),
                        ];
                        body.push(Node::if_then(
                            Expr::and(
                                Expr::ne(Expr::var("top_op"), Expr::u32(TOK_LPAREN)),
                                Expr::ge(Expr::var("v_sp"), Expr::u32(2)),
                            ),
                            reduce_loaded_operator(
                                out_ast_nodes,
                                out_ast_count,
                                scratch_val_stack,
                                val_stack_base.clone(),
                            ),
                        ));
                        body
                    }),
                ],
            )],
        ),
    ]
}

fn final_sweep_body(
    scratch_op_stack: &str,
    out_ast_nodes: &str,
    out_ast_count: &str,
    scratch_val_stack: &str,
    val_stack_base: Expr,
    op_stack_base: Expr,
) -> Vec<Node> {
    vec![
        Node::let_bind("done_fs", Expr::u32(0)),
        Node::loop_for(
            "pop",
            Expr::u32(0),
            Expr::u32(STACK_SLOTS_PER_STATEMENT),
            vec![Node::if_then(
                Expr::eq(Expr::var("done_fs"), Expr::u32(0)),
                vec![
                    Node::if_then(
                        Expr::eq(Expr::var("o_sp"), Expr::u32(0)),
                        vec![Node::assign("done_fs", Expr::u32(1))],
                    ),
                    Node::if_then(Expr::ne(Expr::var("o_sp"), Expr::u32(0)), {
                        let mut body = vec![
                            Node::assign("o_sp", Expr::sub(Expr::var("o_sp"), Expr::u32(1))),
                            Node::let_bind(
                                "top_op",
                                Expr::load(
                                    scratch_op_stack,
                                    Expr::add(op_stack_base, Expr::var("o_sp")),
                                ),
                            ),
                        ];
                        body.push(Node::if_then(
                            Expr::and(
                                Expr::ne(Expr::var("top_op"), Expr::u32(TOK_LPAREN)),
                                Expr::ge(Expr::var("v_sp"), Expr::u32(2)),
                            ),
                            reduce_loaded_operator(
                                out_ast_nodes,
                                out_ast_count,
                                scratch_val_stack,
                                val_stack_base,
                            ),
                        ));
                        body
                    }),
                ],
            )],
        ),
    ]
}

/// Data-parallel shunting-yard AST builder.
///
/// Each invocation owns one statement boundary and emits a flat node stream
/// where every AST node is four `u32` words: `(opcode, left, right, value_ref)`.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn ast_shunting_yard(
    tok_types: &str,
    statements: &str,
    num_statements: Expr,
    out_ast_nodes: &str,
    out_ast_count: &str,
    out_statement_roots: &str,
    scratch_val_stack: &str,
    scratch_op_stack: &str,
) -> Program {
    let t = Expr::InvocationId { axis: 0 };
    let val_stack_base = Expr::mul(t.clone(), Expr::u32(STACK_SLOTS_PER_STATEMENT));
    let op_stack_base = Expr::mul(t.clone(), Expr::u32(STACK_SLOTS_PER_STATEMENT));

    let loop_body = vec![
        Node::let_bind(
            "stmt_start",
            Expr::load(statements, Expr::mul(t.clone(), Expr::u32(2))),
        ),
        Node::let_bind(
            "stmt_end",
            Expr::load(
                statements,
                Expr::add(Expr::mul(t.clone(), Expr::u32(2)), Expr::u32(1)),
            ),
        ),
        Node::let_bind("v_sp", Expr::u32(0)),
        Node::let_bind("o_sp", Expr::u32(0)),
        Node::loop_for(
            "tok_idx",
            Expr::var("stmt_start"),
            Expr::var("stmt_end"),
            vec![
                Node::let_bind("tok", Expr::load(tok_types, Expr::var("tok_idx"))),
                Node::if_then(
                    is_value_token(Expr::var("tok")),
                    emit_value_leaf(
                        out_ast_nodes,
                        out_ast_count,
                        scratch_val_stack,
                        val_stack_base.clone(),
                    ),
                ),
                Node::if_then(
                    is_binary_token(Expr::var("tok")),
                    binary_token_body(
                        scratch_op_stack,
                        out_ast_nodes,
                        out_ast_count,
                        scratch_val_stack,
                        val_stack_base.clone(),
                        op_stack_base.clone(),
                    ),
                ),
                Node::if_then(
                    Expr::eq(Expr::var("tok"), Expr::u32(TOK_LPAREN)),
                    vec![
                        Node::store(
                            scratch_op_stack,
                            Expr::add(op_stack_base.clone(), Expr::var("o_sp")),
                            Expr::var("tok"),
                        ),
                        Node::assign("o_sp", Expr::add(Expr::var("o_sp"), Expr::u32(1))),
                    ],
                ),
                Node::if_then(
                    Expr::eq(Expr::var("tok"), Expr::u32(TOK_RPAREN)),
                    rparen_body(
                        scratch_op_stack,
                        out_ast_nodes,
                        out_ast_count,
                        scratch_val_stack,
                        val_stack_base.clone(),
                        op_stack_base.clone(),
                    ),
                ),
            ],
        ),
        Node::Block(final_sweep_body(
            scratch_op_stack,
            out_ast_nodes,
            out_ast_count,
            scratch_val_stack,
            val_stack_base.clone(),
            op_stack_base,
        )),
        Node::if_then(
            Expr::gt(Expr::var("v_sp"), Expr::u32(0)),
            vec![Node::store(
                out_statement_roots,
                t.clone(),
                Expr::load(
                    scratch_val_stack,
                    Expr::add(val_stack_base, Expr::sub(Expr::var("v_sp"), Expr::u32(1))),
                ),
            )],
        ),
        Node::if_then(
            Expr::eq(Expr::var("v_sp"), Expr::u32(0)),
            vec![Node::store(
                out_statement_roots,
                t.clone(),
                Expr::u32(u32::MAX),
            )],
        ),
    ];

    let num_stmt = match &num_statements {
        Expr::LitU32(n) => *n,
        _ => 1,
    };
    let scratch_words = num_stmt.saturating_mul(STACK_SLOTS_PER_STATEMENT);
    Program::wrapped(
        vec![
            BufferDecl::storage(tok_types, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(MAX_TOK_SCAN),
            BufferDecl::storage(statements, 1, BufferAccess::ReadOnly, DataType::U32)
                .with_count(num_stmt.saturating_mul(2)),
            BufferDecl::storage(out_ast_nodes, 2, BufferAccess::ReadWrite, DataType::U32)
                .with_count(MAX_TOK_SCAN.saturating_mul(4)),
            BufferDecl::storage(out_ast_count, 3, BufferAccess::ReadWrite, DataType::U32)
                .with_count(1),
            BufferDecl::storage(
                out_statement_roots,
                4,
                BufferAccess::ReadWrite,
                DataType::U32,
            )
            .with_count(num_stmt),
            BufferDecl::storage(scratch_val_stack, 5, BufferAccess::ReadWrite, DataType::U32)
                .with_count(scratch_words),
            BufferDecl::storage(scratch_op_stack, 6, BufferAccess::ReadWrite, DataType::U32)
                .with_count(scratch_words),
        ],
        [256, 1, 1],
        vec![wrap_anonymous(
            OP_ID,
            vec![Node::if_then(
                Expr::lt(t.clone(), num_statements),
                loop_body,
            )],
        )],
    )
    .with_entry_op_id(OP_ID)
    .with_non_composable_with_self(true)
}

inventory::submit! {
    crate::harness::OpEntry {
        id: OP_ID,
        build: || ast_shunting_yard(
            "tok_types", "statements", Expr::u32(100),
            "out_ast_nodes", "out_ast_count", "out_statement_roots",
            "scratch_val_stack", "scratch_op_stack"
        ),
        test_inputs: Some(|| vec![vec![
            vec![0u8; MAX_TOK_SCAN as usize * 4],
            vec![0u8; 200 * 4],
            vec![0u8; MAX_TOK_SCAN as usize * 4 * 4],
            vec![0u8; 4],
            vec![0u8; 100 * 4],
            vec![0u8; 6_400 * 4],
            vec![0u8; 6_400 * 4],
        ]]),
        expected_output: Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![
                vec![0u8; MAX_TOK_SCAN as usize * 4 * 4],
                to_bytes(&[0u32]),
                to_bytes(&[u32::MAX; 100]),
                vec![0u8; 6_400 * 4],
                vec![0u8; 6_400 * 4],
            ]]
        }),
    }
}
