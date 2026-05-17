//! Audit-fix A36 `vast/build.rs` extract.

#![allow(missing_docs)] // c-parser feature: A33-A36 split lost some leading doc comments; lint loud, fix surgically when revisiting docs.
use crate::parsing::c::lex::tokens::*;
use crate::parsing::composition::child_phase;
use crate::region::wrap_anonymous;
use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

use super::build_declaration_kind_inner::emit_declaration_kind_for_index_inner;
use super::helpers::*;
use super::*;

pub fn c11_build_vast_nodes(
    tok_types: &str,
    tok_starts: &str,
    tok_lens: &str,
    num_tokens: Expr,
    out_vast_nodes: &str,
    out_count: &str,
) -> Program {
    let t = Expr::InvocationId { axis: 0 };

    let build_row = Expr::mul(Expr::var("build_i"), Expr::u32(VAST_NODE_STRIDE_U32));
    let parent_row = Expr::mul(Expr::var("parent_idx"), Expr::u32(VAST_NODE_STRIDE_U32));
    let previous_row = Expr::mul(
        Expr::var("previous_sibling"),
        Expr::u32(VAST_NODE_STRIDE_U32),
    );
    let stack_slot = Expr::add(
        Expr::mul(Expr::var("stack_depth"), Expr::u32(VAST_NODE_STRIDE_U32)),
        Expr::u32(9),
    );
    let top_slot = Expr::add(
        Expr::mul(
            Expr::sub(Expr::var("stack_depth"), Expr::u32(1)),
            Expr::u32(VAST_NODE_STRIDE_U32),
        ),
        Expr::u32(9),
    );

    let build_loop = vec![
        Node::let_bind("row", build_row),
        Node::let_bind("tok", Expr::load(tok_types, Expr::var("build_i"))),
        Node::let_bind("parent_idx", Expr::u32(SENTINEL)),
        Node::if_then(
            Expr::gt(Expr::var("stack_depth"), Expr::u32(0)),
            vec![Node::assign(
                "parent_idx",
                Expr::load(out_vast_nodes, top_slot.clone()),
            )],
        ),
        Node::store(out_vast_nodes, Expr::var("row"), Expr::var("tok")),
        Node::store(
            out_vast_nodes,
            Expr::add(Expr::var("row"), Expr::u32(1)),
            Expr::var("parent_idx"),
        ),
        Node::store(
            out_vast_nodes,
            Expr::add(Expr::var("row"), Expr::u32(2)),
            Expr::u32(SENTINEL),
        ),
        Node::store(
            out_vast_nodes,
            Expr::add(Expr::var("row"), Expr::u32(3)),
            Expr::u32(SENTINEL),
        ),
        Node::store(
            out_vast_nodes,
            Expr::add(Expr::var("row"), Expr::u32(4)),
            Expr::u32(SENTINEL),
        ),
        Node::store(
            out_vast_nodes,
            Expr::add(Expr::var("row"), Expr::u32(5)),
            Expr::load(tok_starts, Expr::var("build_i")),
        ),
        Node::store(
            out_vast_nodes,
            Expr::add(Expr::var("row"), Expr::u32(6)),
            Expr::load(tok_lens, Expr::var("build_i")),
        ),
        Node::store(
            out_vast_nodes,
            Expr::add(Expr::var("row"), Expr::u32(7)),
            Expr::u32(0),
        ),
        Node::store(
            out_vast_nodes,
            Expr::add(Expr::var("row"), Expr::u32(8)),
            Expr::u32(0),
        ),
        Node::store(
            out_vast_nodes,
            Expr::add(Expr::var("row"), Expr::u32(9)),
            Expr::u32(0),
        ),
        // Clamp parent_idx into a safe in-range slot (0) before the
        // speculative load. `Expr::select` evaluates both arms; on PTX the
        // load is unguarded, so feeding SENTINEL through `parent_row` reads
        // way out of bounds → CUDA_ERROR_ILLEGAL_ADDRESS. WGSL's bounds-check
        // policy clamps for us; PTX has no such policy. Clamping here keeps
        // both backends correct without requiring a backend-side bounds-check.
        Node::let_bind(
            "safe_parent_idx",
            Expr::select(
                Expr::lt(Expr::var("parent_idx"), num_tokens.clone()),
                Expr::var("parent_idx"),
                Expr::u32(0),
            ),
        ),
        Node::let_bind(
            "safe_parent_row",
            Expr::mul(Expr::var("safe_parent_idx"), Expr::u32(VAST_NODE_STRIDE_U32)),
        ),
        Node::let_bind(
            "previous_sibling",
            Expr::select(
                Expr::lt(Expr::var("parent_idx"), num_tokens.clone()),
                Expr::load(out_vast_nodes, Expr::add(Expr::var("safe_parent_row"), Expr::u32(4))),
                Expr::var("root_last_child"),
            ),
        ),
        Node::if_then_else(
            Expr::lt(Expr::var("previous_sibling"), num_tokens.clone()),
            vec![Node::store(
                out_vast_nodes,
                Expr::add(previous_row, Expr::u32(3)),
                Expr::var("build_i"),
            )],
            vec![Node::if_then(
                Expr::lt(Expr::var("parent_idx"), num_tokens.clone()),
                vec![Node::store(
                    out_vast_nodes,
                    Expr::add(parent_row.clone(), Expr::u32(2)),
                    Expr::var("build_i"),
                )],
            )],
        ),
        Node::if_then_else(
            Expr::lt(Expr::var("parent_idx"), num_tokens.clone()),
            vec![Node::store(
                out_vast_nodes,
                Expr::add(parent_row, Expr::u32(4)),
                Expr::var("build_i"),
            )],
            vec![Node::assign("root_last_child", Expr::var("build_i"))],
        ),
        Node::if_then(
            Expr::eq(Expr::var("tok"), Expr::u32(TOK_GNU_ATTRIBUTE)),
            vec![
                Node::let_bind(
                    "attr_next1",
                    Expr::load(tok_types, Expr::add(Expr::var("build_i"), Expr::u32(1))),
                ),
                Node::let_bind(
                    "attr_next2",
                    Expr::load(tok_types, Expr::add(Expr::var("build_i"), Expr::u32(2))),
                ),
                Node::if_then(
                    Expr::or(
                        Expr::ge(Expr::add(Expr::var("build_i"), Expr::u32(2)), num_tokens.clone()),
                        Expr::or(
                            Expr::ne(Expr::var("attr_next1"), Expr::u32(TOK_LPAREN)),
                            Expr::ne(Expr::var("attr_next2"), Expr::u32(TOK_LPAREN)),
                        ),
                    ),
                    vec![Node::trap(
                        Expr::var("build_i"),
                        "malformed-gnu-attribute-missing-double-paren",
                    )],
                ),
            ],
        ),
        Node::if_then(
            is_open_token(Expr::var("tok")),
            vec![
                Node::store(out_vast_nodes, stack_slot, Expr::var("build_i")),
                Node::assign(
                    "stack_depth",
                    Expr::add(Expr::var("stack_depth"), Expr::u32(1)),
                ),
            ],
        ),
        Node::let_bind("top_idx", Expr::u32(SENTINEL)),
        Node::if_then(
            Expr::gt(Expr::var("stack_depth"), Expr::u32(0)),
            vec![Node::assign(
                "top_idx",
                Expr::load(out_vast_nodes, top_slot),
            )],
        ),
        // Same OOB-on-PTX hazard as `safe_parent_idx`: top_idx is SENTINEL
        // when the stack is empty / hasn't been populated, and the speculative
        // tok_types load reads from u32::MAX on an unguarded backend.
        Node::let_bind(
            "safe_top_idx",
            Expr::select(
                Expr::lt(Expr::var("top_idx"), num_tokens.clone()),
                Expr::var("top_idx"),
                Expr::u32(0),
            ),
        ),
        Node::let_bind(
            "top_kind",
            Expr::select(
                Expr::lt(Expr::var("top_idx"), num_tokens.clone()),
                Expr::load(tok_types, Expr::var("safe_top_idx")),
                Expr::u32(0),
            ),
        ),
        Node::if_then(
            Expr::and(
                Expr::gt(Expr::var("stack_depth"), Expr::u32(0)),
                is_matching_close(Expr::var("top_kind"), Expr::var("tok")),
            ),
            vec![Node::assign(
                "stack_depth",
                Expr::sub(Expr::var("stack_depth"), Expr::u32(1)),
            )],
        ),
    ];

    let cleanup_loop = vec![
        Node::let_bind(
            "cleanup_row",
            Expr::mul(Expr::var("cleanup_i"), Expr::u32(VAST_NODE_STRIDE_U32)),
        ),
        Node::store(
            out_vast_nodes,
            Expr::add(Expr::var("cleanup_row"), Expr::u32(4)),
            Expr::u32(0),
        ),
        Node::store(
            out_vast_nodes,
            Expr::add(Expr::var("cleanup_row"), Expr::u32(7)),
            Expr::u32(0),
        ),
        Node::store(
            out_vast_nodes,
            Expr::add(Expr::var("cleanup_row"), Expr::u32(8)),
            Expr::u32(0),
        ),
        Node::store(
            out_vast_nodes,
            Expr::add(Expr::var("cleanup_row"), Expr::u32(9)),
            Expr::u32(0),
        ),
    ];

    let body = vec![Node::if_then(
        Expr::eq(t.clone(), Expr::u32(0)),
        vec![
            Node::store(out_count, Expr::u32(0), num_tokens.clone()),
            Node::let_bind("stack_depth", Expr::u32(0)),
            Node::let_bind("root_last_child", Expr::u32(SENTINEL)),
            Node::loop_for("build_i", Expr::u32(0), num_tokens.clone(), build_loop),
            Node::loop_for("cleanup_i", Expr::u32(0), num_tokens.clone(), cleanup_loop),
        ],
    )];

    let n = node_count(&num_tokens).max(1);
    Program::wrapped(
        vec![
            BufferDecl::storage(tok_types, 0, BufferAccess::ReadOnly, DataType::U32).with_count(n),
            BufferDecl::storage(tok_starts, 1, BufferAccess::ReadOnly, DataType::U32).with_count(n),
            BufferDecl::storage(tok_lens, 2, BufferAccess::ReadOnly, DataType::U32).with_count(n),
            BufferDecl::storage(out_vast_nodes, 3, BufferAccess::ReadWrite, DataType::U32)
                .with_count(n.saturating_mul(VAST_NODE_STRIDE_U32)),
            BufferDecl::storage(out_count, 4, BufferAccess::ReadWrite, DataType::U32).with_count(1),
        ],
        [1, 1, 1],
        vec![wrap_anonymous(
            BUILD_VAST_OP_ID,
            vec![child_phase(
                BUILD_VAST_OP_ID,
                vyre_primitives::parsing::ast_cse_structural_hash::OP_ID,
                body,
            )],
        )],
    )
    .with_entry_op_id(BUILD_VAST_OP_ID)
}

fn emit_identifier_hash_for_row(
    vast_nodes: &str,
    haystack: &str,
    haystack_len: &Expr,
    row_base: Expr,
    prefix: &str,
) -> Vec<Node> {
    let start = format!("{prefix}_start");
    let len = format!("{prefix}_len");
    let hash = format!("{prefix}_hash");
    let i = format!("{prefix}_i");
    let byte = format!("{prefix}_byte");

    vec![
        Node::let_bind(
            &start,
            Expr::load(vast_nodes, Expr::add(row_base.clone(), Expr::u32(5))),
        ),
        Node::let_bind(
            &len,
            Expr::load(vast_nodes, Expr::add(row_base, Expr::u32(6))),
        ),
        Node::let_bind(&hash, Expr::u32(0x811c9dc5)),
        Node::loop_for(
            &i,
            Expr::u32(0),
            Expr::var(&len),
            vec![Node::if_then(
                Expr::lt(
                    Expr::add(Expr::var(&start), Expr::var(&i)),
                    haystack_len.clone(),
                ),
                vec![
                    Node::let_bind(
                        &byte,
                        Expr::load(haystack, Expr::add(Expr::var(&start), Expr::var(&i))),
                    ),
                    Node::assign(&hash, Expr::bitxor(Expr::var(&hash), Expr::var(&byte))),
                    Node::assign(&hash, Expr::mul(Expr::var(&hash), Expr::u32(0x01000193))),
                ],
            )],
        ),
    ]
}

fn emit_scope_open_for_index(
    vast_nodes: &str,
    idx: Expr,
    out_name: &str,
    prefix: &str,
) -> Vec<Node> {
    let depth = format!("{prefix}_depth");
    let scan = format!("{prefix}_scan");
    let rev = format!("{prefix}_idx");
    let kind = format!("{prefix}_kind");

    vec![
        Node::let_bind(out_name, Expr::u32(SENTINEL)),
        Node::let_bind(&depth, Expr::u32(0)),
        Node::loop_for(
            &scan,
            Expr::u32(0),
            idx.clone(),
            vec![
                Node::let_bind(
                    &rev,
                    Expr::sub(Expr::sub(idx, Expr::u32(1)), Expr::var(&scan)),
                ),
                Node::let_bind(
                    &kind,
                    Expr::load(
                        vast_nodes,
                        Expr::mul(Expr::var(&rev), Expr::u32(VAST_NODE_STRIDE_U32)),
                    ),
                ),
                Node::if_then(
                    Expr::eq(Expr::var(&kind), Expr::u32(TOK_RBRACE)),
                    vec![Node::assign(
                        &depth,
                        Expr::add(Expr::var(&depth), Expr::u32(1)),
                    )],
                ),
                Node::if_then(
                    Expr::eq(Expr::var(out_name), Expr::u32(SENTINEL)),
                    vec![Node::if_then(
                        Expr::eq(Expr::var(&kind), Expr::u32(TOK_LBRACE)),
                        vec![Node::if_then_else(
                            Expr::eq(Expr::var(&depth), Expr::u32(0)),
                            vec![Node::assign(out_name, Expr::var(&rev))],
                            vec![Node::assign(
                                &depth,
                                Expr::sub(Expr::var(&depth), Expr::u32(1)),
                            )],
                        )],
                    )],
                ),
            ],
        ),
    ]
}

fn emit_enclosing_function_lparen_for_index(
    vast_nodes: &str,
    idx: Expr,
    out_name: &str,
    prefix: &str,
) -> Vec<Node> {
    let base = format!("{prefix}_base");
    let parent = format!("{prefix}_parent");
    let parent_walk = format!("{prefix}_parent_walk");
    let parent_base = format!("{prefix}_parent_base");
    let parent_kind = format!("{prefix}_parent_kind");
    let parent_prev_kind = format!("{prefix}_parent_prev_kind");
    let scope = format!("{prefix}_scope");
    let scope_walk = format!("{prefix}_scope_walk");
    let scope_base = format!("{prefix}_scope_base");
    let scope_kind = format!("{prefix}_scope_kind");
    let candidate = format!("{prefix}_candidate");
    let paren_depth = format!("{prefix}_paren_depth");
    let scan = format!("{prefix}_scan");
    let rev = format!("{prefix}_rev");
    let scan_kind = format!("{prefix}_scan_kind");
    let scan_prev_kind = format!("{prefix}_scan_prev_kind");

    let mut nodes = vec![
        Node::let_bind(out_name, Expr::u32(SENTINEL)),
        Node::let_bind(
            &base,
            Expr::mul(idx.clone(), Expr::u32(VAST_NODE_STRIDE_U32)),
        ),
        Node::let_bind(
            &parent,
            Expr::load(vast_nodes, Expr::add(Expr::var(&base), Expr::u32(1))),
        ),
        Node::loop_for(
            &parent_walk,
            Expr::u32(0),
            Expr::var("annot_num_nodes"),
            vec![Node::if_then(
                Expr::and(
                    Expr::eq(Expr::var(out_name), Expr::u32(SENTINEL)),
                    Expr::lt(Expr::var(&parent), Expr::var("annot_num_nodes")),
                ),
                vec![
                    Node::let_bind(
                        &parent_base,
                        Expr::mul(Expr::var(&parent), Expr::u32(VAST_NODE_STRIDE_U32)),
                    ),
                    Node::let_bind(
                        &parent_kind,
                        Expr::load(vast_nodes, Expr::var(&parent_base)),
                    ),
                    Node::let_bind(
                        &parent_prev_kind,
                        Expr::select(
                            Expr::gt(Expr::var(&parent), Expr::u32(0)),
                            Expr::load(
                                vast_nodes,
                                Expr::mul(
                                    Expr::sub(Expr::var(&parent), Expr::u32(1)),
                                    Expr::u32(VAST_NODE_STRIDE_U32),
                                ),
                            ),
                            Expr::u32(SENTINEL),
                        ),
                    ),
                    Node::if_then(
                        Expr::and(
                            Expr::eq(Expr::var(&parent_kind), Expr::u32(TOK_LPAREN)),
                            Expr::eq(Expr::var(&parent_prev_kind), Expr::u32(TOK_IDENTIFIER)),
                        ),
                        vec![Node::assign(out_name, Expr::var(&parent))],
                    ),
                    Node::assign(
                        &parent,
                        Expr::load(vast_nodes, Expr::add(Expr::var(&parent_base), Expr::u32(1))),
                    ),
                ],
            )],
        ),
    ];

    nodes.extend(emit_scope_open_for_index(
        vast_nodes,
        idx,
        &scope,
        &format!("{prefix}_scope_open"),
    ));
    nodes.push(Node::loop_for(
        &scope_walk,
        Expr::u32(0),
        Expr::var("annot_num_nodes"),
        vec![Node::if_then(
            Expr::and(
                Expr::eq(Expr::var(out_name), Expr::u32(SENTINEL)),
                Expr::lt(Expr::var(&scope), Expr::var("annot_num_nodes")),
            ),
            vec![
                Node::let_bind(
                    &scope_base,
                    Expr::mul(Expr::var(&scope), Expr::u32(VAST_NODE_STRIDE_U32)),
                ),
                Node::let_bind(&scope_kind, Expr::load(vast_nodes, Expr::var(&scope_base))),
                Node::if_then(
                    Expr::eq(Expr::var(&scope_kind), Expr::u32(TOK_LBRACE)),
                    vec![
                        Node::let_bind(&candidate, Expr::u32(SENTINEL)),
                        Node::let_bind(&paren_depth, Expr::u32(0)),
                        Node::loop_for(
                            &scan,
                            Expr::u32(0),
                            Expr::var(&scope),
                            vec![
                                Node::let_bind(
                                    &rev,
                                    Expr::sub(
                                        Expr::sub(Expr::var(&scope), Expr::u32(1)),
                                        Expr::var(&scan),
                                    ),
                                ),
                                Node::let_bind(
                                    &scan_kind,
                                    Expr::load(
                                        vast_nodes,
                                        Expr::mul(Expr::var(&rev), Expr::u32(VAST_NODE_STRIDE_U32)),
                                    ),
                                ),
                                Node::if_then(
                                    Expr::eq(Expr::var(&scan_kind), Expr::u32(TOK_RPAREN)),
                                    vec![Node::assign(
                                        &paren_depth,
                                        Expr::add(Expr::var(&paren_depth), Expr::u32(1)),
                                    )],
                                ),
                                Node::if_then(
                                    Expr::and(
                                        Expr::eq(Expr::var(&scan_kind), Expr::u32(TOK_LPAREN)),
                                        Expr::gt(Expr::var(&paren_depth), Expr::u32(0)),
                                    ),
                                    vec![
                                        Node::assign(
                                            &paren_depth,
                                            Expr::sub(Expr::var(&paren_depth), Expr::u32(1)),
                                        ),
                                        Node::if_then(
                                            Expr::and(
                                                Expr::eq(Expr::var(&paren_depth), Expr::u32(0)),
                                                Expr::eq(
                                                    Expr::var(&candidate),
                                                    Expr::u32(SENTINEL),
                                                ),
                                            ),
                                            vec![
                                                Node::let_bind(
                                                    &scan_prev_kind,
                                                    Expr::select(
                                                        Expr::gt(Expr::var(&rev), Expr::u32(0)),
                                                        Expr::load(
                                                            vast_nodes,
                                                            Expr::mul(
                                                                Expr::sub(
                                                                    Expr::var(&rev),
                                                                    Expr::u32(1),
                                                                ),
                                                                Expr::u32(VAST_NODE_STRIDE_U32),
                                                            ),
                                                        ),
                                                        Expr::u32(SENTINEL),
                                                    ),
                                                ),
                                                Node::if_then(
                                                    Expr::eq(
                                                        Expr::var(&scan_prev_kind),
                                                        Expr::u32(TOK_IDENTIFIER),
                                                    ),
                                                    vec![Node::assign(&candidate, Expr::var(&rev))],
                                                ),
                                            ],
                                        ),
                                    ],
                                ),
                            ],
                        ),
                        Node::if_then(
                            Expr::ne(Expr::var(&candidate), Expr::u32(SENTINEL)),
                            vec![Node::assign(out_name, Expr::var(&candidate))],
                        ),
                    ],
                ),
                Node::assign(
                    &scope,
                    Expr::load(vast_nodes, Expr::add(Expr::var(&scope_base), Expr::u32(1))),
                ),
            ],
        )],
    ));
    nodes
}

fn emit_declaration_kind_for_index(
    vast_nodes: &str,
    haystack: &str,
    haystack_len: &Expr,
    idx: Expr,
    out_name: &str,
    prefix: &str,
) -> Vec<Node> {
    emit_declaration_kind_for_index_inner(
        vast_nodes,
        idx,
        out_name,
        prefix,
        Some((haystack, haystack_len)),
    )
}

fn emit_builtin_declaration_kind_for_index(
    vast_nodes: &str,
    idx: Expr,
    out_name: &str,
    prefix: &str,
) -> Vec<Node> {
    emit_declaration_kind_for_index_inner(vast_nodes, idx, out_name, prefix, None)
}

pub(super) fn emit_identifier_source_hash_for_index(
    vast_nodes: &str,
    haystack: &str,
    haystack_len: &Expr,
    idx: Expr,
    out_name: &str,
    prefix: &str,
) -> Vec<Node> {
    let base = format!("{prefix}_hash_base");
    let start = format!("{prefix}_hash_start");
    let len = format!("{prefix}_hash_len");
    let cursor = format!("{prefix}_hash_i");
    let byte = format!("{prefix}_hash_byte");

    vec![
        Node::let_bind(out_name, Expr::u32(0x811c9dc5)),
        Node::let_bind(&base, Expr::mul(idx, Expr::u32(VAST_NODE_STRIDE_U32))),
        Node::let_bind(
            &start,
            Expr::load(vast_nodes, Expr::add(Expr::var(&base), Expr::u32(5))),
        ),
        Node::let_bind(
            &len,
            Expr::load(vast_nodes, Expr::add(Expr::var(&base), Expr::u32(6))),
        ),
        Node::loop_for(
            &cursor,
            Expr::u32(0),
            Expr::var(&len),
            vec![Node::if_then(
                Expr::lt(
                    Expr::add(Expr::var(&start), Expr::var(&cursor)),
                    haystack_len.clone(),
                ),
                vec![
                    Node::let_bind(
                        &byte,
                        Expr::load(haystack, Expr::add(Expr::var(&start), Expr::var(&cursor))),
                    ),
                    Node::assign(
                        out_name,
                        Expr::bitxor(Expr::var(out_name), Expr::var(&byte)),
                    ),
                    Node::assign(
                        out_name,
                        Expr::mul(Expr::var(out_name), Expr::u32(0x01000193)),
                    ),
                ],
            )],
        ),
    ]
}

pub(super) fn emit_visible_typedef_name_for_index(
    vast_nodes: &str,
    haystack: &str,
    haystack_len: &Expr,
    idx: Expr,
    out_name: &str,
    prefix: &str,
) -> Vec<Node> {
    let target_base = format!("{prefix}_target_base");
    let target_scope = format!("{prefix}_target_scope");
    let target_function = format!("{prefix}_target_function");
    let last_decl_kind = format!("{prefix}_last_decl_kind");
    let scan = format!("{prefix}_scan");
    let scan_base = format!("{prefix}_scan_base");
    let scan_kind = format!("{prefix}_scan_kind");
    let scan_scope = format!("{prefix}_scan_scope");
    let scan_function = format!("{prefix}_scan_function");
    let scan_decl_kind = format!("{prefix}_scan_decl_result_kind");
    let scope_walk = format!("{prefix}_scope_walk");
    let scope_walk_depth = format!("{prefix}_scope_walk_depth");
    let same_name = format!("{prefix}_same_name");
    let visible_scope = format!("{prefix}_visible_scope");
    let visible_function = format!("{prefix}_visible_function");

    let mut nodes = vec![
        Node::let_bind(out_name, Expr::u32(0)),
        Node::let_bind(
            &target_base,
            Expr::mul(idx.clone(), Expr::u32(VAST_NODE_STRIDE_U32)),
        ),
    ];
    nodes.extend(emit_identifier_hash_for_row(
        vast_nodes,
        haystack,
        haystack_len,
        Expr::var(&target_base),
        &format!("{prefix}_target"),
    ));
    nodes.extend(emit_scope_open_for_index(
        vast_nodes,
        idx.clone(),
        &target_scope,
        &format!("{prefix}_scope"),
    ));
    nodes.extend(emit_enclosing_function_lparen_for_index(
        vast_nodes,
        idx.clone(),
        &target_function,
        &format!("{prefix}_function"),
    ));
    nodes.push(Node::let_bind(&last_decl_kind, Expr::u32(0)));
    nodes.push(Node::loop_for(
        &scan,
        Expr::u32(0),
        idx,
        vec![
            Node::let_bind(
                &scan_base,
                Expr::mul(Expr::var(&scan), Expr::u32(VAST_NODE_STRIDE_U32)),
            ),
            Node::let_bind(&scan_kind, Expr::load(vast_nodes, Expr::var(&scan_base))),
            Node::if_then(
                Expr::eq(Expr::var(&scan_kind), Expr::u32(TOK_IDENTIFIER)),
                {
                    let scan_hash_prefix = format!("{prefix}_scan_hash");
                    let target_hash = format!("{prefix}_target_hash");
                    let target_len = format!("{prefix}_target_len");
                    let mut body = emit_identifier_hash_for_row(
                        vast_nodes,
                        haystack,
                        haystack_len,
                        Expr::var(&scan_base),
                        &scan_hash_prefix,
                    );
                    body.extend(emit_scope_open_for_index(
                        vast_nodes,
                        Expr::var(&scan),
                        &scan_scope,
                        &format!("{prefix}_scan_scope"),
                    ));
                    body.extend(emit_enclosing_function_lparen_for_index(
                        vast_nodes,
                        Expr::var(&scan),
                        &scan_function,
                        &format!("{prefix}_scan_function"),
                    ));
                    body.extend(emit_builtin_declaration_kind_for_index(
                        vast_nodes,
                        Expr::var(&scan),
                        &scan_decl_kind,
                        &format!("{prefix}_scan_decl"),
                    ));
                    body.push(Node::let_bind(
                        &same_name,
                        Expr::and(
                            Expr::eq(
                                Expr::var(format!("{scan_hash_prefix}_hash")),
                                Expr::var(&target_hash),
                            ),
                            Expr::eq(
                                Expr::var(format!("{scan_hash_prefix}_len")),
                                Expr::var(&target_len),
                            ),
                        ),
                    ));
                    body.push(Node::let_bind(
                        &visible_function,
                        Expr::or(
                            Expr::ne(Expr::var(&scan_decl_kind), Expr::u32(2)),
                            Expr::or(
                                Expr::eq(Expr::var(&scan_function), Expr::u32(SENTINEL)),
                                Expr::eq(Expr::var(&scan_function), Expr::var(&target_function)),
                            ),
                        ),
                    ));
                    body.push(Node::let_bind(
                        &visible_scope,
                        Expr::eq(Expr::var(&scan_scope), Expr::u32(SENTINEL)),
                    ));
                    body.push(Node::let_bind(&scope_walk, Expr::var(&target_scope)));
                    body.push(Node::loop_for(
                        &scope_walk_depth,
                        Expr::u32(0),
                        Expr::var("annot_num_nodes"),
                        vec![
                            Node::if_then(
                                Expr::eq(Expr::var(&scope_walk), Expr::var(&scan_scope)),
                                vec![Node::assign(&visible_scope, Expr::bool(true))],
                            ),
                            Node::if_then(
                                Expr::ne(Expr::var(&scope_walk), Expr::u32(SENTINEL)),
                                vec![Node::assign(
                                    &scope_walk,
                                    Expr::load(
                                        vast_nodes,
                                        Expr::add(
                                            Expr::mul(
                                                Expr::var(&scope_walk),
                                                Expr::u32(VAST_NODE_STRIDE_U32),
                                            ),
                                            Expr::u32(1),
                                        ),
                                    ),
                                )],
                            ),
                        ],
                    ));
                    body.push(Node::if_then(
                        Expr::and(
                            Expr::var(&same_name),
                            Expr::and(
                                Expr::var(&visible_scope),
                                Expr::and(
                                    Expr::var(&visible_function),
                                    Expr::ne(Expr::var(&scan_decl_kind), Expr::u32(0)),
                                ),
                            ),
                        ),
                        vec![Node::assign(&last_decl_kind, Expr::var(&scan_decl_kind))],
                    ));
                    body
                },
            ),
        ],
    ));
    nodes.push(Node::if_then(
        Expr::eq(Expr::var(&last_decl_kind), Expr::u32(1)),
        vec![Node::assign(out_name, Expr::u32(1))],
    ));
    nodes
}

pub(super) fn emit_typedef_visibility_scan(
    vast_nodes: &str,
    haystack: &str,
    haystack_len: &Expr,
    num_nodes: &Expr,
    t: Expr,
) -> Vec<Node> {
    let mut nodes = vec![Node::let_bind("annot_num_nodes", num_nodes.clone())];
    nodes.extend(emit_visible_typedef_name_for_index(
        vast_nodes,
        haystack,
        haystack_len,
        t,
        "current_visible_typedef_name",
        "current_visible_typedef",
    ));
    nodes.push(Node::assign(
        "last_decl_kind",
        Expr::select(
            Expr::eq(Expr::var("current_visible_typedef_name"), Expr::u32(1)),
            Expr::u32(1),
            Expr::u32(0),
        ),
    ));
    nodes
}

pub(super) fn emit_current_declaration_annotation(
    vast_nodes: &str,
    haystack: &str,
    haystack_len: &Expr,
    t: Expr,
    _num_nodes: &Expr,
) -> Vec<Node> {
    let mut nodes = Vec::new();
    nodes.extend(emit_declaration_kind_for_index(
        vast_nodes,
        haystack,
        haystack_len,
        t,
        "current_decl_result_kind",
        "current_decl",
    ));
    nodes.push(Node::let_bind(
        "current_decl_flags",
        Expr::select(
            Expr::eq(Expr::var("current_decl_result_kind"), Expr::u32(1)),
            Expr::u32(C_TYPEDEF_FLAG_TYPEDEF_DECLARATOR),
            Expr::select(
                Expr::eq(Expr::var("current_decl_result_kind"), Expr::u32(2)),
                Expr::u32(C_TYPEDEF_FLAG_ORDINARY_DECLARATOR),
                Expr::u32(0),
            ),
        ),
    ));
    nodes
}
