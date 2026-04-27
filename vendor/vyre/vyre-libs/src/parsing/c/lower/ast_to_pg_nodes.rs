use crate::harness::OpEntry;
use crate::parsing::c::lower::semantic_edges::{
    resolved_semantic_edges, semantic_resolution_nodes,
};
use crate::parsing::c::parse::vast::{
    C_AST_KIND_ALIGNOF_EXPR, C_AST_KIND_ARRAY_DECL, C_AST_KIND_ARRAY_SUBSCRIPT_EXPR,
    C_AST_KIND_ASM_CLOBBERS_LIST, C_AST_KIND_ASM_GOTO_LABELS, C_AST_KIND_ASM_INPUT_OPERAND,
    C_AST_KIND_ASM_OUTPUT_OPERAND, C_AST_KIND_ASM_QUALIFIER, C_AST_KIND_ASM_TEMPLATE,
    C_AST_KIND_ASSIGN_EXPR, C_AST_KIND_ATTRIBUTE_ALIAS, C_AST_KIND_ATTRIBUTE_ALIGNED,
    C_AST_KIND_ATTRIBUTE_ALWAYS_INLINE, C_AST_KIND_ATTRIBUTE_CLEANUP, C_AST_KIND_ATTRIBUTE_COLD,
    C_AST_KIND_ATTRIBUTE_CONST, C_AST_KIND_ATTRIBUTE_CONSTRUCTOR, C_AST_KIND_ATTRIBUTE_DESTRUCTOR,
    C_AST_KIND_ATTRIBUTE_FALLTHROUGH, C_AST_KIND_ATTRIBUTE_FORMAT, C_AST_KIND_ATTRIBUTE_HOT,
    C_AST_KIND_ATTRIBUTE_MODE, C_AST_KIND_ATTRIBUTE_NAKED, C_AST_KIND_ATTRIBUTE_NOINLINE,
    C_AST_KIND_ATTRIBUTE_PACKED, C_AST_KIND_ATTRIBUTE_PURE, C_AST_KIND_ATTRIBUTE_SECTION,
    C_AST_KIND_ATTRIBUTE_UNUSED, C_AST_KIND_ATTRIBUTE_USED, C_AST_KIND_ATTRIBUTE_VISIBILITY,
    C_AST_KIND_ATTRIBUTE_WEAK, C_AST_KIND_BIT_FIELD_DECL, C_AST_KIND_BREAK_STMT,
    C_AST_KIND_BUILTIN_CHOOSE_EXPR, C_AST_KIND_BUILTIN_CLASSIFY_TYPE_EXPR,
    C_AST_KIND_BUILTIN_CONSTANT_P_EXPR, C_AST_KIND_BUILTIN_EXPECT_EXPR,
    C_AST_KIND_BUILTIN_OBJECT_SIZE_EXPR, C_AST_KIND_BUILTIN_OFFSETOF_EXPR,
    C_AST_KIND_BUILTIN_OVERFLOW_EXPR, C_AST_KIND_BUILTIN_PREFETCH_EXPR,
    C_AST_KIND_BUILTIN_TYPES_COMPATIBLE_P_EXPR, C_AST_KIND_BUILTIN_UNREACHABLE_STMT,
    C_AST_KIND_CASE_STMT, C_AST_KIND_CAST_EXPR, C_AST_KIND_COMPOUND_LITERAL_EXPR,
    C_AST_KIND_CONDITIONAL_EXPR, C_AST_KIND_CONTINUE_STMT, C_AST_KIND_DEFAULT_STMT,
    C_AST_KIND_DO_STMT, C_AST_KIND_ELSE_STMT, C_AST_KIND_ENUMERATOR_DECL, C_AST_KIND_ENUM_DECL,
    C_AST_KIND_FIELD_DECL, C_AST_KIND_FOR_STMT, C_AST_KIND_FUNCTION_DECLARATOR,
    C_AST_KIND_FUNCTION_DEFINITION, C_AST_KIND_GENERIC_SELECTION_EXPR, C_AST_KIND_GNU_ATTRIBUTE,
    C_AST_KIND_GNU_LABEL_ADDRESS_EXPR, C_AST_KIND_GNU_LOCAL_LABEL_DECL,
    C_AST_KIND_GNU_STATEMENT_EXPR, C_AST_KIND_GOTO_STMT, C_AST_KIND_IF_STMT,
    C_AST_KIND_INITIALIZER_LIST, C_AST_KIND_INLINE_ASM, C_AST_KIND_LABEL_STMT,
    C_AST_KIND_MEMBER_ACCESS_EXPR, C_AST_KIND_POINTER_DECL, C_AST_KIND_RANGE_DESIGNATOR_EXPR,
    C_AST_KIND_RETURN_STMT, C_AST_KIND_SIZEOF_EXPR, C_AST_KIND_STATIC_ASSERT_DECL,
    C_AST_KIND_STRUCT_DECL, C_AST_KIND_SWITCH_STMT, C_AST_KIND_TYPEDEF_DECL, C_AST_KIND_UNARY_EXPR,
    C_AST_KIND_UNION_DECL, C_AST_KIND_WHILE_STMT,
};
use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};
use vyre_primitives::predicate::node_kind;

/// Number of `u32` words in one packed VAST node.
const VAST_NODE_STRIDE_U32: u32 = 10;
/// Number of `u32` words in one packed `PgNode`.
const PG_NODE_STRIDE_U32: u32 = 6;
/// Number of `u32` words in one semantic PG node witness row.
pub const C_AST_PG_SEMANTIC_NODE_STRIDE_U32: u32 = 10;
/// Number of `u32` words in one semantic PG edge witness row.
pub const C_AST_PG_EDGE_STRIDE_U32: u32 = 6;
/// Number of edge witness rows emitted per AST node.
pub const C_AST_PG_EDGE_ROWS_PER_NODE: u32 = 5;

/// No C AST semantic category was assigned.
pub const C_AST_PG_CATEGORY_NONE: u32 = 0;
/// Control-flow and label-like C AST node.
pub const C_AST_PG_CATEGORY_CONTROL: u32 = 1;
/// Expression, initializer, designator, or statement-expression node.
pub const C_AST_PG_CATEGORY_EXPRESSION: u32 = 2;
/// GNU extension node such as inline asm, attributes, or GNU builtins.
pub const C_AST_PG_CATEGORY_GNU: u32 = 3;
/// Declaration, declarator, type, or function-definition node.
pub const C_AST_PG_CATEGORY_DECLARATION: u32 = 4;

/// No specialized C AST role was assigned.
pub const C_AST_PG_ROLE_NONE: u32 = 0;
/// C/GNU label definition.
pub const C_AST_PG_ROLE_LABEL: u32 = 1;
/// `case` label.
pub const C_AST_PG_ROLE_CASE: u32 = 2;
/// `default` label.
pub const C_AST_PG_ROLE_DEFAULT: u32 = 3;
/// GNU statement expression `({ ... })`.
pub const C_AST_PG_ROLE_STATEMENT_EXPR: u32 = 4;
/// GNU inline asm statement or declarator asm suffix.
pub const C_AST_PG_ROLE_INLINE_ASM: u32 = 5;
/// GNU asm template string.
pub const C_AST_PG_ROLE_ASM_TEMPLATE: u32 = 6;
/// GNU asm output operand.
pub const C_AST_PG_ROLE_ASM_OUTPUT: u32 = 7;
/// GNU asm input operand.
pub const C_AST_PG_ROLE_ASM_INPUT: u32 = 8;
/// GNU asm clobber string.
pub const C_AST_PG_ROLE_ASM_CLOBBER: u32 = 9;
/// GNU asm-goto label operand.
pub const C_AST_PG_ROLE_ASM_GOTO_LABEL: u32 = 10;
/// GNU asm qualifier such as `volatile` or `goto`.
pub const C_AST_PG_ROLE_ASM_QUALIFIER: u32 = 11;
/// GNU `__attribute__` wrapper.
pub const C_AST_PG_ROLE_GNU_ATTRIBUTE: u32 = 12;
/// Specific GNU attribute payload such as `section`, `weak`, or `aligned`.
pub const C_AST_PG_ROLE_GNU_ATTRIBUTE_DETAIL: u32 = 13;
/// C initializer-list brace.
pub const C_AST_PG_ROLE_INITIALIZER_LIST: u32 = 14;
/// Field designator or member-access operator.
pub const C_AST_PG_ROLE_FIELD_DESIGNATOR_OR_MEMBER_ACCESS: u32 = 15;
/// Array designator or subscript operator.
pub const C_AST_PG_ROLE_ARRAY_DESIGNATOR_OR_SUBSCRIPT: u32 = 16;
/// GNU range designator ellipsis.
pub const C_AST_PG_ROLE_RANGE_DESIGNATOR: u32 = 17;
/// Assignment-expression node, including designator assignment witnesses.
pub const C_AST_PG_ROLE_ASSIGNMENT: u32 = 18;
/// Function definition declarator identifier.
pub const C_AST_PG_ROLE_FUNCTION_DEFINITION: u32 = 19;
/// Function declarator parameter-list node.
pub const C_AST_PG_ROLE_FUNCTION_DECLARATOR: u32 = 20;
/// Aggregate declaration/specifier node.
pub const C_AST_PG_ROLE_AGGREGATE_DECL: u32 = 21;
/// Field declarator identifier node.
pub const C_AST_PG_ROLE_FIELD_DECL: u32 = 22;
/// Typedef declarator node.
pub const C_AST_PG_ROLE_TYPEDEF_DECL: u32 = 23;
/// Enumerator declarator node.
pub const C_AST_PG_ROLE_ENUMERATOR_DECL: u32 = 24;
/// Pointer declarator node.
pub const C_AST_PG_ROLE_POINTER_DECL: u32 = 25;
/// Array declarator node.
pub const C_AST_PG_ROLE_ARRAY_DECL: u32 = 26;
/// Bit-field declarator node.
pub const C_AST_PG_ROLE_BIT_FIELD_DECL: u32 = 27;
/// `_Static_assert` declaration node.
pub const C_AST_PG_ROLE_STATIC_ASSERT_DECL: u32 = 28;
/// Generic expression operator or builtin expression witness.
pub const C_AST_PG_ROLE_EXPRESSION: u32 = 29;
/// Generic declaration witness from the shared predicate node-kind set.
pub const C_AST_PG_ROLE_DECLARATION: u32 = 30;
/// `goto` branch statement.
pub const C_AST_PG_ROLE_GOTO: u32 = 31;
/// `switch` selection statement.
pub const C_AST_PG_ROLE_SWITCH: u32 = 32;
/// `if` or `else` selection statement.
pub const C_AST_PG_ROLE_SELECTION: u32 = 33;
/// `for`, `while`, or `do` loop statement.
pub const C_AST_PG_ROLE_LOOP: u32 = 34;
/// `return` statement.
pub const C_AST_PG_ROLE_RETURN: u32 = 35;
/// `break` statement.
pub const C_AST_PG_ROLE_BREAK: u32 = 36;
/// `continue` statement.
pub const C_AST_PG_ROLE_CONTINUE: u32 = 37;
/// `__builtin_unreachable` terminator statement.
pub const C_AST_PG_ROLE_UNREACHABLE: u32 = 38;
/// `_Alignof` expression.
pub const C_AST_PG_ROLE_ALIGNOF: u32 = 39;
/// Pointer declarator participating in function-pointer declarator shape.
pub const C_AST_PG_ROLE_FUNCTION_POINTER_DECL: u32 = 40;

/// No semantic edge exists in this witness row.
pub const C_AST_PG_EDGE_NONE: u32 = 0;
/// Parent contains child.
pub const C_AST_PG_EDGE_PARENT: u32 = 1;
/// Node points to first child.
pub const C_AST_PG_EDGE_FIRST_CHILD: u32 = 2;
/// Node points to next sibling.
pub const C_AST_PG_EDGE_NEXT_SIBLING: u32 = 3;
/// `goto` statement points to the resolved label statement in the same root body.
pub const C_AST_PG_EDGE_GOTO_TARGET: u32 = 4;
/// `switch` statement points to the first selector expression node.
pub const C_AST_PG_EDGE_SWITCH_SELECTOR: u32 = 5;
/// Enclosing `switch` statement points to a `case` label.
pub const C_AST_PG_EDGE_SWITCH_CASE: u32 = 6;
/// Enclosing `switch` statement points to a `default` label.
pub const C_AST_PG_EDGE_SWITCH_DEFAULT: u32 = 7;
/// `case` label points to the first node of its value expression.
pub const C_AST_PG_EDGE_CASE_VALUE: u32 = 8;

const IDX_KIND: usize = 0;
const IDX_PARENT: usize = 1;
const IDX_FIRST_CHILD: usize = 2;
const IDX_NEXT_SIBLING: usize = 3;
const IDX_SRC_BYTE_OFF: usize = 5;
const IDX_SRC_BYTE_LEN: usize = 6;
const IDX_ATTR_OFF: usize = 7;
const IDX_ATTR_LEN: usize = 8;
const IDX_RESERVED: usize = 9;

const OP_ID: &str = "vyre-libs::parsing::c::lower::ast_to_pg_nodes";
const SEMANTIC_OP_ID: &str = "vyre-libs::parsing::c::lower::ast_to_pg_semantic_graph";

fn infer_node_count_words(node_count: &Expr) -> u32 {
    match node_count {
        Expr::LitU32(n) => *n,
        _ => 1,
    }
}

/// Lower structural VAST rows (`kind`, `span`, `parent`, `payload`) into
/// packed Program-Graph rows:
/// `(kind, span_start, span_end, parent_idx, first_child_idx, next_sibling_idx)`.
///
/// `num_nodes` controls both dispatch bounds and buffer sizing so this stays
/// composable with one-thread-per-node invocation. Inputs outside the declared
/// `num_nodes` range are masked by the dispatch bound.
#[must_use]
pub fn c_lower_ast_to_pg_nodes(vast_nodes: &str, num_nodes: Expr, out_pg_nodes: &str) -> Program {
    let t = Expr::InvocationId { axis: 0 };

    let vast_base = Expr::mul(t.clone(), Expr::u32(VAST_NODE_STRIDE_U32));
    let pg_base = Expr::mul(t.clone(), Expr::u32(PG_NODE_STRIDE_U32));

    let loop_body = vec![
        Node::let_bind("kind", Expr::load(vast_nodes, vast_base.clone())),
        Node::let_bind(
            "parent_idx",
            Expr::load(
                vast_nodes,
                Expr::add(vast_base.clone(), Expr::u32(IDX_PARENT as u32)),
            ),
        ),
        Node::let_bind(
            "first_child_idx",
            Expr::load(
                vast_nodes,
                Expr::add(vast_base.clone(), Expr::u32(IDX_FIRST_CHILD as u32)),
            ),
        ),
        Node::let_bind(
            "next_sibling_idx",
            Expr::load(
                vast_nodes,
                Expr::add(vast_base.clone(), Expr::u32(IDX_NEXT_SIBLING as u32)),
            ),
        ),
        Node::let_bind(
            "span_start",
            Expr::load(
                vast_nodes,
                Expr::add(vast_base.clone(), Expr::u32(IDX_SRC_BYTE_OFF as u32)),
            ),
        ),
        Node::let_bind(
            "span_len",
            Expr::load(
                vast_nodes,
                Expr::add(vast_base.clone(), Expr::u32(IDX_SRC_BYTE_LEN as u32)),
            ),
        ),
        Node::store(out_pg_nodes, pg_base.clone(), Expr::var("kind")),
        Node::store(
            out_pg_nodes,
            Expr::add(pg_base.clone(), Expr::u32(1)),
            Expr::var("span_start"),
        ),
        Node::store(
            out_pg_nodes,
            Expr::add(pg_base.clone(), Expr::u32(2)),
            Expr::add(Expr::var("span_start"), Expr::var("span_len")),
        ),
        Node::store(
            out_pg_nodes,
            Expr::add(pg_base.clone(), Expr::u32(3)),
            Expr::var("parent_idx"),
        ),
        Node::store(
            out_pg_nodes,
            Expr::add(pg_base.clone(), Expr::u32(4)),
            Expr::var("first_child_idx"),
        ),
        Node::store(
            out_pg_nodes,
            Expr::add(pg_base, Expr::u32(5)),
            Expr::var("next_sibling_idx"),
        ),
    ];

    let in_words = infer_node_count_words(&num_nodes)
        .saturating_mul(VAST_NODE_STRIDE_U32)
        .max(1);
    let out_words = infer_node_count_words(&num_nodes)
        .saturating_mul(PG_NODE_STRIDE_U32)
        .max(1);

    Program::wrapped(
        vec![
            BufferDecl::storage(vast_nodes, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(in_words),
            BufferDecl::storage(out_pg_nodes, 1, BufferAccess::ReadWrite, DataType::U32)
                .with_count(out_words),
        ],
        [256, 1, 1],
        vec![crate::region::wrap_anonymous(
            OP_ID,
            vec![Node::if_then(
                Expr::lt(t.clone(), num_nodes.clone()),
                loop_body,
            )],
        )],
    )
    .with_entry_op_id(OP_ID)
}

fn expr_is_kind(kind: Expr, expected: u32) -> Expr {
    Expr::eq(kind, Expr::u32(expected))
}

fn push_category_assignments(nodes: &mut Vec<Node>, kinds: &[u32], category: u32) {
    nodes.extend(kinds.iter().map(|kind| {
        Node::if_then(
            expr_is_kind(Expr::var("kind"), *kind),
            vec![Node::assign("semantic_category", Expr::u32(category))],
        )
    }));
}

fn semantic_classification_nodes() -> Vec<Node> {
    let mut nodes = vec![
        Node::let_bind("semantic_category", Expr::u32(C_AST_PG_CATEGORY_NONE)),
        Node::let_bind("semantic_role", Expr::u32(C_AST_PG_ROLE_NONE)),
    ];
    push_category_assignments(&mut nodes, CONTROL_KINDS, C_AST_PG_CATEGORY_CONTROL);
    push_category_assignments(&mut nodes, EXPRESSION_KINDS, C_AST_PG_CATEGORY_EXPRESSION);
    push_category_assignments(&mut nodes, DECLARATION_KINDS, C_AST_PG_CATEGORY_DECLARATION);
    push_category_assignments(&mut nodes, GNU_KINDS, C_AST_PG_CATEGORY_GNU);
    nodes.extend(ROLE_BY_KIND.iter().map(|(kind, role)| {
        Node::if_then(
            expr_is_kind(Expr::var("kind"), *kind),
            vec![Node::assign("semantic_role", Expr::u32(*role))],
        )
    }));
    nodes.push(Node::if_then(
        Expr::and(
            expr_is_kind(Expr::var("kind"), C_AST_KIND_POINTER_DECL),
            Expr::or(
                expr_is_kind(Expr::var("parent_kind"), C_AST_KIND_FUNCTION_DECLARATOR),
                Expr::or(
                    expr_is_kind(
                        Expr::var("first_child_kind"),
                        C_AST_KIND_FUNCTION_DECLARATOR,
                    ),
                    expr_is_kind(
                        Expr::var("next_sibling_kind"),
                        C_AST_KIND_FUNCTION_DECLARATOR,
                    ),
                ),
            ),
        ),
        vec![Node::assign(
            "semantic_role",
            Expr::u32(C_AST_PG_ROLE_FUNCTION_POINTER_DECL),
        )],
    ));
    nodes
}

fn load_related_kind_if_valid(
    nodes: &mut Vec<Node>,
    related_var: &str,
    related_kind_var: &str,
    vast_nodes: &str,
    num_nodes: &Expr,
) {
    nodes.push(Node::let_bind(related_kind_var, Expr::u32(0)));
    nodes.push(Node::if_then(
        Expr::and(
            Expr::ne(Expr::var(related_var), Expr::u32(u32::MAX)),
            Expr::lt(Expr::var(related_var), num_nodes.clone()),
        ),
        vec![Node::assign(
            related_kind_var,
            Expr::load(
                vast_nodes,
                Expr::mul(Expr::var(related_var), Expr::u32(VAST_NODE_STRIDE_U32)),
            ),
        )],
    ));
}

fn valid_node_ref_expr(idx: Expr, num_nodes: &Expr) -> Expr {
    Expr::and(
        Expr::ne(idx.clone(), Expr::u32(u32::MAX)),
        Expr::lt(idx, num_nodes.clone()),
    )
}

fn semantic_context_nodes(vast_nodes: &str, num_nodes: &Expr) -> Vec<Node> {
    let mut nodes = Vec::new();
    load_related_kind_if_valid(
        &mut nodes,
        "parent_idx",
        "parent_kind",
        vast_nodes,
        num_nodes,
    );
    load_related_kind_if_valid(
        &mut nodes,
        "first_child_idx",
        "first_child_kind",
        vast_nodes,
        num_nodes,
    );
    load_related_kind_if_valid(
        &mut nodes,
        "next_sibling_idx",
        "next_sibling_kind",
        vast_nodes,
        num_nodes,
    );
    nodes
}

fn store_semantic_edge(
    out_pg_edges: &str,
    edge_base: Expr,
    row_offset: u32,
    has_edge: Expr,
    edge_kind: u32,
    src_idx: Expr,
    dst_idx: Expr,
) -> Vec<Node> {
    let base = Expr::add(
        edge_base,
        Expr::u32(row_offset.saturating_mul(C_AST_PG_EDGE_STRIDE_U32)),
    );
    vec![
        Node::store(
            out_pg_edges,
            base.clone(),
            Expr::select(
                has_edge.clone(),
                Expr::u32(edge_kind),
                Expr::u32(C_AST_PG_EDGE_NONE),
            ),
        ),
        Node::store(
            out_pg_edges,
            Expr::add(base.clone(), Expr::u32(1)),
            Expr::select(has_edge.clone(), src_idx, Expr::u32(u32::MAX)),
        ),
        Node::store(
            out_pg_edges,
            Expr::add(base.clone(), Expr::u32(2)),
            Expr::select(has_edge.clone(), dst_idx, Expr::u32(u32::MAX)),
        ),
        Node::store(
            out_pg_edges,
            Expr::add(base.clone(), Expr::u32(3)),
            Expr::var("kind"),
        ),
        Node::store(
            out_pg_edges,
            Expr::add(base.clone(), Expr::u32(4)),
            Expr::var("semantic_role"),
        ),
        Node::store(
            out_pg_edges,
            Expr::add(base, Expr::u32(5)),
            Expr::var("semantic_category"),
        ),
    ]
}

fn store_semantic_edge_expr(
    out_pg_edges: &str,
    edge_base: Expr,
    row_offset: u32,
    has_edge: Expr,
    edge_kind: Expr,
    src_idx: Expr,
    dst_idx: Expr,
) -> Vec<Node> {
    let base = Expr::add(
        edge_base,
        Expr::u32(row_offset.saturating_mul(C_AST_PG_EDGE_STRIDE_U32)),
    );
    vec![
        Node::store(
            out_pg_edges,
            base.clone(),
            Expr::select(has_edge.clone(), edge_kind, Expr::u32(C_AST_PG_EDGE_NONE)),
        ),
        Node::store(
            out_pg_edges,
            Expr::add(base.clone(), Expr::u32(1)),
            Expr::select(has_edge.clone(), src_idx, Expr::u32(u32::MAX)),
        ),
        Node::store(
            out_pg_edges,
            Expr::add(base.clone(), Expr::u32(2)),
            Expr::select(has_edge.clone(), dst_idx, Expr::u32(u32::MAX)),
        ),
        Node::store(
            out_pg_edges,
            Expr::add(base.clone(), Expr::u32(3)),
            Expr::var("kind"),
        ),
        Node::store(
            out_pg_edges,
            Expr::add(base.clone(), Expr::u32(4)),
            Expr::var("semantic_role"),
        ),
        Node::store(
            out_pg_edges,
            Expr::add(base, Expr::u32(5)),
            Expr::var("semantic_category"),
        ),
    ]
}

/// Lower C VAST rows into semantic Program-Graph node and edge witnesses.
///
/// The first six semantic-node fields intentionally match
/// [`c_lower_ast_to_pg_nodes`]. Fields 6-9 add stable downstream witnesses:
/// `(category, role, attr_off, attr_len)`. The edge buffer emits five rows
/// per AST node: parent, first-child, next-sibling, and two resolved semantic
/// slots for `goto` targets plus `switch` selector/case/default relations.
/// Missing edges are explicit `C_AST_PG_EDGE_NONE` rows with sentinel
/// endpoints so downstream GPU passes can consume a fixed-stride table without
/// compaction.
#[must_use]
pub fn c_lower_ast_to_pg_semantic_graph(
    vast_nodes: &str,
    num_nodes: Expr,
    out_pg_nodes: &str,
    out_pg_edges: &str,
) -> Program {
    let t = Expr::InvocationId { axis: 0 };

    let vast_base = Expr::mul(t.clone(), Expr::u32(VAST_NODE_STRIDE_U32));
    let pg_base = Expr::mul(t.clone(), Expr::u32(C_AST_PG_SEMANTIC_NODE_STRIDE_U32));
    let edge_base = Expr::mul(
        t.clone(),
        Expr::u32(C_AST_PG_EDGE_ROWS_PER_NODE.saturating_mul(C_AST_PG_EDGE_STRIDE_U32)),
    );

    let mut loop_body = vec![
        Node::let_bind("kind", Expr::load(vast_nodes, vast_base.clone())),
        Node::let_bind(
            "parent_idx",
            Expr::load(
                vast_nodes,
                Expr::add(vast_base.clone(), Expr::u32(IDX_PARENT as u32)),
            ),
        ),
        Node::let_bind(
            "first_child_idx",
            Expr::load(
                vast_nodes,
                Expr::add(vast_base.clone(), Expr::u32(IDX_FIRST_CHILD as u32)),
            ),
        ),
        Node::let_bind(
            "next_sibling_idx",
            Expr::load(
                vast_nodes,
                Expr::add(vast_base.clone(), Expr::u32(IDX_NEXT_SIBLING as u32)),
            ),
        ),
        Node::let_bind(
            "span_start",
            Expr::load(
                vast_nodes,
                Expr::add(vast_base.clone(), Expr::u32(IDX_SRC_BYTE_OFF as u32)),
            ),
        ),
        Node::let_bind(
            "span_len",
            Expr::load(
                vast_nodes,
                Expr::add(vast_base.clone(), Expr::u32(IDX_SRC_BYTE_LEN as u32)),
            ),
        ),
        Node::let_bind(
            "attr_off",
            Expr::load(
                vast_nodes,
                Expr::add(vast_base.clone(), Expr::u32(IDX_ATTR_OFF as u32)),
            ),
        ),
        Node::let_bind(
            "attr_len",
            Expr::load(
                vast_nodes,
                Expr::add(vast_base.clone(), Expr::u32(IDX_ATTR_LEN as u32)),
            ),
        ),
    ];
    loop_body.extend(semantic_context_nodes(vast_nodes, &num_nodes));
    loop_body.extend(semantic_classification_nodes());
    loop_body.extend(semantic_resolution_nodes(vast_nodes, &num_nodes, t.clone()));
    loop_body.extend(vec![
        Node::store(out_pg_nodes, pg_base.clone(), Expr::var("kind")),
        Node::store(
            out_pg_nodes,
            Expr::add(pg_base.clone(), Expr::u32(1)),
            Expr::var("span_start"),
        ),
        Node::store(
            out_pg_nodes,
            Expr::add(pg_base.clone(), Expr::u32(2)),
            Expr::add(Expr::var("span_start"), Expr::var("span_len")),
        ),
        Node::store(
            out_pg_nodes,
            Expr::add(pg_base.clone(), Expr::u32(3)),
            Expr::var("parent_idx"),
        ),
        Node::store(
            out_pg_nodes,
            Expr::add(pg_base.clone(), Expr::u32(4)),
            Expr::var("first_child_idx"),
        ),
        Node::store(
            out_pg_nodes,
            Expr::add(pg_base.clone(), Expr::u32(5)),
            Expr::var("next_sibling_idx"),
        ),
        Node::store(
            out_pg_nodes,
            Expr::add(pg_base.clone(), Expr::u32(6)),
            Expr::var("semantic_category"),
        ),
        Node::store(
            out_pg_nodes,
            Expr::add(pg_base.clone(), Expr::u32(7)),
            Expr::var("semantic_role"),
        ),
        Node::store(
            out_pg_nodes,
            Expr::add(pg_base.clone(), Expr::u32(8)),
            Expr::var("attr_off"),
        ),
        Node::store(
            out_pg_nodes,
            Expr::add(pg_base, Expr::u32(9)),
            Expr::var("attr_len"),
        ),
    ]);

    loop_body.extend(store_semantic_edge(
        out_pg_edges,
        edge_base.clone(),
        0,
        valid_node_ref_expr(Expr::var("parent_idx"), &num_nodes),
        C_AST_PG_EDGE_PARENT,
        Expr::var("parent_idx"),
        t.clone(),
    ));
    loop_body.extend(store_semantic_edge(
        out_pg_edges,
        edge_base.clone(),
        1,
        valid_node_ref_expr(Expr::var("first_child_idx"), &num_nodes),
        C_AST_PG_EDGE_FIRST_CHILD,
        t.clone(),
        Expr::var("first_child_idx"),
    ));
    loop_body.extend(store_semantic_edge(
        out_pg_edges,
        edge_base.clone(),
        2,
        valid_node_ref_expr(Expr::var("next_sibling_idx"), &num_nodes),
        C_AST_PG_EDGE_NEXT_SIBLING,
        t.clone(),
        Expr::var("next_sibling_idx"),
    ));
    loop_body.extend(store_semantic_edge_expr(
        out_pg_edges,
        edge_base.clone(),
        3,
        Expr::var("semantic_edge3_has"),
        Expr::var("semantic_edge3_kind"),
        Expr::var("semantic_edge3_src"),
        Expr::var("semantic_edge3_dst"),
    ));
    loop_body.extend(store_semantic_edge_expr(
        out_pg_edges,
        edge_base,
        4,
        Expr::var("semantic_edge4_has"),
        Expr::var("semantic_edge4_kind"),
        Expr::var("semantic_edge4_src"),
        Expr::var("semantic_edge4_dst"),
    ));

    let in_words = infer_node_count_words(&num_nodes)
        .saturating_mul(VAST_NODE_STRIDE_U32)
        .max(1);
    let out_node_words = infer_node_count_words(&num_nodes)
        .saturating_mul(C_AST_PG_SEMANTIC_NODE_STRIDE_U32)
        .max(1);
    let out_edge_words = infer_node_count_words(&num_nodes)
        .saturating_mul(C_AST_PG_EDGE_ROWS_PER_NODE)
        .saturating_mul(C_AST_PG_EDGE_STRIDE_U32)
        .max(1);

    Program::wrapped(
        vec![
            BufferDecl::storage(vast_nodes, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(in_words),
            BufferDecl::storage(out_pg_nodes, 1, BufferAccess::ReadWrite, DataType::U32)
                .with_count(out_node_words),
            BufferDecl::storage(out_pg_edges, 2, BufferAccess::ReadWrite, DataType::U32)
                .with_count(out_edge_words),
        ],
        [256, 1, 1],
        vec![crate::region::wrap_anonymous(
            SEMANTIC_OP_ID,
            vec![Node::if_then(
                Expr::lt(t.clone(), num_nodes.clone()),
                loop_body,
            )],
        )],
    )
    .with_entry_op_id(SEMANTIC_OP_ID)
}

/// Malformed byte input for CPU oracle decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PgReferenceDecodeError {
    /// Input byte length is not a whole number of `u32` words.
    MisalignedBytes {
        /// Actual byte length.
        len: usize,
    },
    /// Input word count is not a whole number of VAST rows.
    PartialVastRow {
        /// Actual decoded word count.
        words: usize,
        /// Required row stride.
        stride: usize,
    },
}

/// Semantic PG witness rows computed by the CPU oracle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticPgReference {
    /// Semantic node rows.
    pub nodes: Vec<u8>,
    /// Semantic edge rows.
    pub edges: Vec<u8>,
}

impl std::fmt::Display for PgReferenceDecodeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MisalignedBytes { len } => write!(
                formatter,
                "VAST byte input has {len} bytes, which is not 4-byte aligned. Fix: pass complete u32 rows to the AST-to-PG reference oracle."
            ),
            Self::PartialVastRow { words, stride } => write!(
                formatter,
                "VAST word input has {words} words, which is not a multiple of row stride {stride}. Fix: pass complete VAST rows to the AST-to-PG reference oracle."
            ),
        }
    }
}

impl std::error::Error for PgReferenceDecodeError {}

fn try_u32_words_from_bytes(bytes: &[u8]) -> Result<Vec<u32>, PgReferenceDecodeError> {
    if bytes.len() % 4 != 0 {
        return Err(PgReferenceDecodeError::MisalignedBytes { len: bytes.len() });
    }
    Ok(bytes
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
        .collect())
}

fn u32_words_to_bytes(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}

/// Compute the same mapping as `c_lower_ast_to_pg_nodes` in pure-Rust for tests and fixtures.
///
/// # Errors
///
/// Returns [`PgReferenceDecodeError`] when the input is not aligned to `u32`
/// words or does not contain complete VAST rows.
pub fn try_reference_ast_to_pg_nodes(
    vast_node_bytes: &[u8],
) -> Result<Vec<u8>, PgReferenceDecodeError> {
    let vast_nodes = try_u32_words_from_bytes(vast_node_bytes)?;
    if vast_nodes.len() % VAST_NODE_STRIDE_U32 as usize != 0 {
        return Err(PgReferenceDecodeError::PartialVastRow {
            words: vast_nodes.len(),
            stride: VAST_NODE_STRIDE_U32 as usize,
        });
    }
    Ok(reference_ast_to_pg_nodes_from_words(&vast_nodes))
}

/// Compute semantic PG node and edge witnesses in pure Rust.
///
/// # Errors
///
/// Returns [`PgReferenceDecodeError`] when the input is not aligned to `u32`
/// words or does not contain complete VAST rows.
pub fn try_reference_ast_to_pg_semantic_graph(
    vast_node_bytes: &[u8],
) -> Result<SemanticPgReference, PgReferenceDecodeError> {
    let vast_nodes = try_u32_words_from_bytes(vast_node_bytes)?;
    if vast_nodes.len() % VAST_NODE_STRIDE_U32 as usize != 0 {
        return Err(PgReferenceDecodeError::PartialVastRow {
            words: vast_nodes.len(),
            stride: VAST_NODE_STRIDE_U32 as usize,
        });
    }
    Ok(reference_ast_to_pg_semantic_graph_from_words(&vast_nodes))
}

/// Compute the same mapping as `c_lower_ast_to_pg_nodes` in pure-Rust for tests and fixtures.
#[must_use]
pub fn reference_ast_to_pg_nodes(vast_node_bytes: &[u8]) -> Vec<u8> {
    try_reference_ast_to_pg_nodes(vast_node_bytes)
        .expect("Fix: pass complete u32-aligned VAST rows to reference_ast_to_pg_nodes")
}

/// Compute semantic PG node and edge witnesses in pure Rust.
#[must_use]
pub fn reference_ast_to_pg_semantic_graph(vast_node_bytes: &[u8]) -> SemanticPgReference {
    try_reference_ast_to_pg_semantic_graph(vast_node_bytes)
        .expect("Fix: pass complete u32-aligned VAST rows to reference_ast_to_pg_semantic_graph")
}

fn reference_ast_to_pg_nodes_from_words(vast_nodes: &[u32]) -> Vec<u8> {
    let mut out_nodes = Vec::with_capacity(
        vast_nodes.len() / VAST_NODE_STRIDE_U32 as usize * PG_NODE_STRIDE_U32 as usize,
    );

    let node_count = vast_nodes.len() / VAST_NODE_STRIDE_U32 as usize;
    for node_idx in 0..node_count {
        let base = node_idx * VAST_NODE_STRIDE_U32 as usize;
        let kind = vast_nodes.get(base + IDX_KIND).copied().unwrap_or_default();
        let parent_idx = vast_nodes
            .get(base + IDX_PARENT)
            .copied()
            .unwrap_or_default();
        let first_child_idx = vast_nodes
            .get(base + IDX_FIRST_CHILD)
            .copied()
            .unwrap_or_default();
        let next_sibling_idx = vast_nodes
            .get(base + IDX_NEXT_SIBLING)
            .copied()
            .unwrap_or_default();
        let span_start = vast_nodes
            .get(base + IDX_SRC_BYTE_OFF)
            .copied()
            .unwrap_or_default();
        let span_len = vast_nodes
            .get(base + IDX_SRC_BYTE_LEN)
            .copied()
            .unwrap_or_default();
        let span_end = span_start.wrapping_add(span_len);

        out_nodes.push(kind);
        out_nodes.push(span_start);
        out_nodes.push(span_end);
        out_nodes.push(parent_idx);
        out_nodes.push(first_child_idx);
        out_nodes.push(next_sibling_idx);
    }

    u32_words_to_bytes(&out_nodes)
}

fn reference_ast_to_pg_semantic_graph_from_words(vast_nodes: &[u32]) -> SemanticPgReference {
    let node_count = vast_nodes.len() / VAST_NODE_STRIDE_U32 as usize;
    let mut nodes = Vec::with_capacity(node_count * C_AST_PG_SEMANTIC_NODE_STRIDE_U32 as usize);
    let mut edges = Vec::with_capacity(
        node_count * C_AST_PG_EDGE_ROWS_PER_NODE as usize * C_AST_PG_EDGE_STRIDE_U32 as usize,
    );

    for node_idx in 0..node_count {
        let base = node_idx * VAST_NODE_STRIDE_U32 as usize;
        let kind = vast_nodes.get(base + IDX_KIND).copied().unwrap_or_default();
        let parent_idx = vast_nodes
            .get(base + IDX_PARENT)
            .copied()
            .unwrap_or_default();
        let first_child_idx = vast_nodes
            .get(base + IDX_FIRST_CHILD)
            .copied()
            .unwrap_or_default();
        let next_sibling_idx = vast_nodes
            .get(base + IDX_NEXT_SIBLING)
            .copied()
            .unwrap_or_default();
        let span_start = vast_nodes
            .get(base + IDX_SRC_BYTE_OFF)
            .copied()
            .unwrap_or_default();
        let span_len = vast_nodes
            .get(base + IDX_SRC_BYTE_LEN)
            .copied()
            .unwrap_or_default();
        let attr_off = vast_nodes
            .get(base + IDX_ATTR_OFF)
            .copied()
            .unwrap_or_default();
        let attr_len = vast_nodes
            .get(base + IDX_ATTR_LEN)
            .copied()
            .unwrap_or_default();
        let semantic_category = semantic_category(kind);
        let parent_kind = related_kind(vast_nodes, parent_idx, node_count);
        let first_child_kind = related_kind(vast_nodes, first_child_idx, node_count);
        let next_sibling_kind = related_kind(vast_nodes, next_sibling_idx, node_count);
        let semantic_role = semantic_role(kind, parent_kind, first_child_kind, next_sibling_kind);

        nodes.extend_from_slice(&[
            kind,
            span_start,
            span_start.wrapping_add(span_len),
            parent_idx,
            first_child_idx,
            next_sibling_idx,
            semantic_category,
            semantic_role,
            attr_off,
            attr_len,
        ]);

        let has_parent = valid_node_ref(parent_idx, node_count);
        let has_first_child = valid_node_ref(first_child_idx, node_count);
        let has_next_sibling = valid_node_ref(next_sibling_idx, node_count);
        append_edge_row(
            &mut edges,
            has_parent,
            C_AST_PG_EDGE_PARENT,
            parent_idx,
            node_idx as u32,
            kind,
            semantic_role,
            semantic_category,
        );
        append_edge_row(
            &mut edges,
            has_first_child,
            C_AST_PG_EDGE_FIRST_CHILD,
            node_idx as u32,
            first_child_idx,
            kind,
            semantic_role,
            semantic_category,
        );
        append_edge_row(
            &mut edges,
            has_next_sibling,
            C_AST_PG_EDGE_NEXT_SIBLING,
            node_idx as u32,
            next_sibling_idx,
            kind,
            semantic_role,
            semantic_category,
        );
        let (edge3, edge4) = resolved_semantic_edges(vast_nodes, node_idx, node_count, kind);
        append_edge_row(
            &mut edges,
            edge3.kind != C_AST_PG_EDGE_NONE,
            edge3.kind,
            edge3.src,
            edge3.dst,
            kind,
            semantic_role,
            semantic_category,
        );
        append_edge_row(
            &mut edges,
            edge4.kind != C_AST_PG_EDGE_NONE,
            edge4.kind,
            edge4.src,
            edge4.dst,
            kind,
            semantic_role,
            semantic_category,
        );
    }

    SemanticPgReference {
        nodes: u32_words_to_bytes(&nodes),
        edges: u32_words_to_bytes(&edges),
    }
}

fn append_edge_row(
    out: &mut Vec<u32>,
    has_edge: bool,
    edge_kind: u32,
    src_idx: u32,
    dst_idx: u32,
    ast_kind: u32,
    semantic_role: u32,
    semantic_category: u32,
) {
    out.extend_from_slice(&[
        if has_edge {
            edge_kind
        } else {
            C_AST_PG_EDGE_NONE
        },
        if has_edge { src_idx } else { u32::MAX },
        if has_edge { dst_idx } else { u32::MAX },
        ast_kind,
        semantic_role,
        semantic_category,
    ]);
}

fn valid_node_ref(idx: u32, node_count: usize) -> bool {
    if idx == u32::MAX {
        return false;
    }
    match usize::try_from(idx) {
        Ok(idx) => idx < node_count,
        Err(_) => false,
    }
}

fn semantic_category(kind: u32) -> u32 {
    if GNU_KINDS.contains(&kind) {
        C_AST_PG_CATEGORY_GNU
    } else if DECLARATION_KINDS.contains(&kind) {
        C_AST_PG_CATEGORY_DECLARATION
    } else if EXPRESSION_KINDS.contains(&kind) {
        C_AST_PG_CATEGORY_EXPRESSION
    } else if CONTROL_KINDS.contains(&kind) {
        C_AST_PG_CATEGORY_CONTROL
    } else {
        C_AST_PG_CATEGORY_NONE
    }
}

fn related_kind(vast_nodes: &[u32], related_idx: u32, node_count: usize) -> u32 {
    if related_idx == u32::MAX {
        return 0;
    }
    let Ok(related_idx) = usize::try_from(related_idx) else {
        return 0;
    };
    if related_idx >= node_count {
        return 0;
    }
    vast_nodes
        .get(related_idx * VAST_NODE_STRIDE_U32 as usize + IDX_KIND)
        .copied()
        .unwrap_or_default()
}

fn semantic_role(
    kind: u32,
    parent_kind: u32,
    first_child_kind: u32,
    next_sibling_kind: u32,
) -> u32 {
    let role = ROLE_BY_KIND
        .iter()
        .find_map(|(candidate, role)| (*candidate == kind).then_some(*role))
        .unwrap_or(C_AST_PG_ROLE_NONE);
    if kind == C_AST_KIND_POINTER_DECL
        && (parent_kind == C_AST_KIND_FUNCTION_DECLARATOR
            || first_child_kind == C_AST_KIND_FUNCTION_DECLARATOR
            || next_sibling_kind == C_AST_KIND_FUNCTION_DECLARATOR)
    {
        C_AST_PG_ROLE_FUNCTION_POINTER_DECL
    } else {
        role
    }
}

const CONTROL_KINDS: &[u32] = &[
    C_AST_KIND_LABEL_STMT,
    C_AST_KIND_CASE_STMT,
    C_AST_KIND_DEFAULT_STMT,
    C_AST_KIND_IF_STMT,
    C_AST_KIND_ELSE_STMT,
    C_AST_KIND_SWITCH_STMT,
    C_AST_KIND_FOR_STMT,
    C_AST_KIND_WHILE_STMT,
    C_AST_KIND_DO_STMT,
    C_AST_KIND_RETURN_STMT,
    C_AST_KIND_BREAK_STMT,
    C_AST_KIND_CONTINUE_STMT,
    C_AST_KIND_GOTO_STMT,
    C_AST_KIND_BUILTIN_UNREACHABLE_STMT,
];

const EXPRESSION_KINDS: &[u32] = &[
    C_AST_KIND_GNU_STATEMENT_EXPR,
    C_AST_KIND_ASSIGN_EXPR,
    C_AST_KIND_MEMBER_ACCESS_EXPR,
    C_AST_KIND_SIZEOF_EXPR,
    C_AST_KIND_ALIGNOF_EXPR,
    C_AST_KIND_CONDITIONAL_EXPR,
    C_AST_KIND_UNARY_EXPR,
    C_AST_KIND_ARRAY_SUBSCRIPT_EXPR,
    C_AST_KIND_GENERIC_SELECTION_EXPR,
    C_AST_KIND_RANGE_DESIGNATOR_EXPR,
    C_AST_KIND_CAST_EXPR,
    C_AST_KIND_COMPOUND_LITERAL_EXPR,
    C_AST_KIND_INITIALIZER_LIST,
];

const GNU_KINDS: &[u32] = &[
    C_AST_KIND_INLINE_ASM,
    C_AST_KIND_ASM_TEMPLATE,
    C_AST_KIND_ASM_OUTPUT_OPERAND,
    C_AST_KIND_ASM_INPUT_OPERAND,
    C_AST_KIND_ASM_CLOBBERS_LIST,
    C_AST_KIND_ASM_GOTO_LABELS,
    C_AST_KIND_ASM_QUALIFIER,
    C_AST_KIND_GNU_ATTRIBUTE,
    C_AST_KIND_ATTRIBUTE_SECTION,
    C_AST_KIND_ATTRIBUTE_WEAK,
    C_AST_KIND_ATTRIBUTE_ALIAS,
    C_AST_KIND_ATTRIBUTE_ALIGNED,
    C_AST_KIND_ATTRIBUTE_USED,
    C_AST_KIND_ATTRIBUTE_UNUSED,
    C_AST_KIND_ATTRIBUTE_NAKED,
    C_AST_KIND_ATTRIBUTE_VISIBILITY,
    C_AST_KIND_ATTRIBUTE_PACKED,
    C_AST_KIND_ATTRIBUTE_CLEANUP,
    C_AST_KIND_ATTRIBUTE_CONSTRUCTOR,
    C_AST_KIND_ATTRIBUTE_DESTRUCTOR,
    C_AST_KIND_ATTRIBUTE_MODE,
    C_AST_KIND_ATTRIBUTE_NOINLINE,
    C_AST_KIND_ATTRIBUTE_ALWAYS_INLINE,
    C_AST_KIND_ATTRIBUTE_COLD,
    C_AST_KIND_ATTRIBUTE_HOT,
    C_AST_KIND_ATTRIBUTE_PURE,
    C_AST_KIND_ATTRIBUTE_CONST,
    C_AST_KIND_ATTRIBUTE_FORMAT,
    C_AST_KIND_ATTRIBUTE_FALLTHROUGH,
    C_AST_KIND_GNU_LABEL_ADDRESS_EXPR,
    C_AST_KIND_BUILTIN_CONSTANT_P_EXPR,
    C_AST_KIND_BUILTIN_CHOOSE_EXPR,
    C_AST_KIND_BUILTIN_TYPES_COMPATIBLE_P_EXPR,
    C_AST_KIND_BUILTIN_EXPECT_EXPR,
    C_AST_KIND_BUILTIN_OFFSETOF_EXPR,
    C_AST_KIND_BUILTIN_OBJECT_SIZE_EXPR,
    C_AST_KIND_BUILTIN_PREFETCH_EXPR,
    C_AST_KIND_BUILTIN_OVERFLOW_EXPR,
    C_AST_KIND_BUILTIN_CLASSIFY_TYPE_EXPR,
    C_AST_KIND_GNU_LOCAL_LABEL_DECL,
];

const DECLARATION_KINDS: &[u32] = &[
    C_AST_KIND_POINTER_DECL,
    C_AST_KIND_ARRAY_DECL,
    C_AST_KIND_FUNCTION_DECLARATOR,
    C_AST_KIND_FIELD_DECL,
    C_AST_KIND_ENUMERATOR_DECL,
    C_AST_KIND_STRUCT_DECL,
    C_AST_KIND_UNION_DECL,
    C_AST_KIND_ENUM_DECL,
    C_AST_KIND_TYPEDEF_DECL,
    C_AST_KIND_FUNCTION_DEFINITION,
    C_AST_KIND_BIT_FIELD_DECL,
    C_AST_KIND_STATIC_ASSERT_DECL,
    node_kind::FUNCTION_DECL,
];

const ROLE_BY_KIND: &[(u32, u32)] = &[
    (C_AST_KIND_LABEL_STMT, C_AST_PG_ROLE_LABEL),
    (C_AST_KIND_CASE_STMT, C_AST_PG_ROLE_CASE),
    (C_AST_KIND_DEFAULT_STMT, C_AST_PG_ROLE_DEFAULT),
    (C_AST_KIND_GOTO_STMT, C_AST_PG_ROLE_GOTO),
    (C_AST_KIND_SWITCH_STMT, C_AST_PG_ROLE_SWITCH),
    (C_AST_KIND_IF_STMT, C_AST_PG_ROLE_SELECTION),
    (C_AST_KIND_ELSE_STMT, C_AST_PG_ROLE_SELECTION),
    (C_AST_KIND_FOR_STMT, C_AST_PG_ROLE_LOOP),
    (C_AST_KIND_WHILE_STMT, C_AST_PG_ROLE_LOOP),
    (C_AST_KIND_DO_STMT, C_AST_PG_ROLE_LOOP),
    (C_AST_KIND_RETURN_STMT, C_AST_PG_ROLE_RETURN),
    (C_AST_KIND_BREAK_STMT, C_AST_PG_ROLE_BREAK),
    (C_AST_KIND_CONTINUE_STMT, C_AST_PG_ROLE_CONTINUE),
    (
        C_AST_KIND_BUILTIN_UNREACHABLE_STMT,
        C_AST_PG_ROLE_UNREACHABLE,
    ),
    (C_AST_KIND_GNU_STATEMENT_EXPR, C_AST_PG_ROLE_STATEMENT_EXPR),
    (C_AST_KIND_INLINE_ASM, C_AST_PG_ROLE_INLINE_ASM),
    (C_AST_KIND_ASM_TEMPLATE, C_AST_PG_ROLE_ASM_TEMPLATE),
    (C_AST_KIND_ASM_OUTPUT_OPERAND, C_AST_PG_ROLE_ASM_OUTPUT),
    (C_AST_KIND_ASM_INPUT_OPERAND, C_AST_PG_ROLE_ASM_INPUT),
    (C_AST_KIND_ASM_CLOBBERS_LIST, C_AST_PG_ROLE_ASM_CLOBBER),
    (C_AST_KIND_ASM_GOTO_LABELS, C_AST_PG_ROLE_ASM_GOTO_LABEL),
    (C_AST_KIND_ASM_QUALIFIER, C_AST_PG_ROLE_ASM_QUALIFIER),
    (C_AST_KIND_GNU_ATTRIBUTE, C_AST_PG_ROLE_GNU_ATTRIBUTE),
    (
        C_AST_KIND_ATTRIBUTE_SECTION,
        C_AST_PG_ROLE_GNU_ATTRIBUTE_DETAIL,
    ),
    (
        C_AST_KIND_ATTRIBUTE_WEAK,
        C_AST_PG_ROLE_GNU_ATTRIBUTE_DETAIL,
    ),
    (
        C_AST_KIND_ATTRIBUTE_ALIAS,
        C_AST_PG_ROLE_GNU_ATTRIBUTE_DETAIL,
    ),
    (
        C_AST_KIND_ATTRIBUTE_ALIGNED,
        C_AST_PG_ROLE_GNU_ATTRIBUTE_DETAIL,
    ),
    (
        C_AST_KIND_ATTRIBUTE_USED,
        C_AST_PG_ROLE_GNU_ATTRIBUTE_DETAIL,
    ),
    (
        C_AST_KIND_ATTRIBUTE_UNUSED,
        C_AST_PG_ROLE_GNU_ATTRIBUTE_DETAIL,
    ),
    (
        C_AST_KIND_ATTRIBUTE_NAKED,
        C_AST_PG_ROLE_GNU_ATTRIBUTE_DETAIL,
    ),
    (
        C_AST_KIND_ATTRIBUTE_VISIBILITY,
        C_AST_PG_ROLE_GNU_ATTRIBUTE_DETAIL,
    ),
    (
        C_AST_KIND_ATTRIBUTE_PACKED,
        C_AST_PG_ROLE_GNU_ATTRIBUTE_DETAIL,
    ),
    (
        C_AST_KIND_ATTRIBUTE_CLEANUP,
        C_AST_PG_ROLE_GNU_ATTRIBUTE_DETAIL,
    ),
    (
        C_AST_KIND_ATTRIBUTE_CONSTRUCTOR,
        C_AST_PG_ROLE_GNU_ATTRIBUTE_DETAIL,
    ),
    (
        C_AST_KIND_ATTRIBUTE_DESTRUCTOR,
        C_AST_PG_ROLE_GNU_ATTRIBUTE_DETAIL,
    ),
    (
        C_AST_KIND_ATTRIBUTE_MODE,
        C_AST_PG_ROLE_GNU_ATTRIBUTE_DETAIL,
    ),
    (
        C_AST_KIND_ATTRIBUTE_NOINLINE,
        C_AST_PG_ROLE_GNU_ATTRIBUTE_DETAIL,
    ),
    (
        C_AST_KIND_ATTRIBUTE_ALWAYS_INLINE,
        C_AST_PG_ROLE_GNU_ATTRIBUTE_DETAIL,
    ),
    (
        C_AST_KIND_ATTRIBUTE_COLD,
        C_AST_PG_ROLE_GNU_ATTRIBUTE_DETAIL,
    ),
    (C_AST_KIND_ATTRIBUTE_HOT, C_AST_PG_ROLE_GNU_ATTRIBUTE_DETAIL),
    (
        C_AST_KIND_ATTRIBUTE_PURE,
        C_AST_PG_ROLE_GNU_ATTRIBUTE_DETAIL,
    ),
    (
        C_AST_KIND_ATTRIBUTE_CONST,
        C_AST_PG_ROLE_GNU_ATTRIBUTE_DETAIL,
    ),
    (
        C_AST_KIND_ATTRIBUTE_FORMAT,
        C_AST_PG_ROLE_GNU_ATTRIBUTE_DETAIL,
    ),
    (
        C_AST_KIND_ATTRIBUTE_FALLTHROUGH,
        C_AST_PG_ROLE_GNU_ATTRIBUTE_DETAIL,
    ),
    (C_AST_KIND_INITIALIZER_LIST, C_AST_PG_ROLE_INITIALIZER_LIST),
    (
        C_AST_KIND_MEMBER_ACCESS_EXPR,
        C_AST_PG_ROLE_FIELD_DESIGNATOR_OR_MEMBER_ACCESS,
    ),
    (
        C_AST_KIND_ARRAY_SUBSCRIPT_EXPR,
        C_AST_PG_ROLE_ARRAY_DESIGNATOR_OR_SUBSCRIPT,
    ),
    (
        C_AST_KIND_RANGE_DESIGNATOR_EXPR,
        C_AST_PG_ROLE_RANGE_DESIGNATOR,
    ),
    (C_AST_KIND_ASSIGN_EXPR, C_AST_PG_ROLE_ASSIGNMENT),
    (
        C_AST_KIND_FUNCTION_DEFINITION,
        C_AST_PG_ROLE_FUNCTION_DEFINITION,
    ),
    (
        C_AST_KIND_FUNCTION_DECLARATOR,
        C_AST_PG_ROLE_FUNCTION_DECLARATOR,
    ),
    (C_AST_KIND_STRUCT_DECL, C_AST_PG_ROLE_AGGREGATE_DECL),
    (C_AST_KIND_UNION_DECL, C_AST_PG_ROLE_AGGREGATE_DECL),
    (C_AST_KIND_ENUM_DECL, C_AST_PG_ROLE_AGGREGATE_DECL),
    (C_AST_KIND_FIELD_DECL, C_AST_PG_ROLE_FIELD_DECL),
    (C_AST_KIND_TYPEDEF_DECL, C_AST_PG_ROLE_TYPEDEF_DECL),
    (C_AST_KIND_ENUMERATOR_DECL, C_AST_PG_ROLE_ENUMERATOR_DECL),
    (C_AST_KIND_POINTER_DECL, C_AST_PG_ROLE_POINTER_DECL),
    (C_AST_KIND_ARRAY_DECL, C_AST_PG_ROLE_ARRAY_DECL),
    (C_AST_KIND_BIT_FIELD_DECL, C_AST_PG_ROLE_BIT_FIELD_DECL),
    (
        C_AST_KIND_STATIC_ASSERT_DECL,
        C_AST_PG_ROLE_STATIC_ASSERT_DECL,
    ),
    (node_kind::FUNCTION_DECL, C_AST_PG_ROLE_DECLARATION),
    (C_AST_KIND_CAST_EXPR, C_AST_PG_ROLE_EXPRESSION),
    (C_AST_KIND_COMPOUND_LITERAL_EXPR, C_AST_PG_ROLE_EXPRESSION),
    (C_AST_KIND_SIZEOF_EXPR, C_AST_PG_ROLE_EXPRESSION),
    (C_AST_KIND_ALIGNOF_EXPR, C_AST_PG_ROLE_ALIGNOF),
    (C_AST_KIND_CONDITIONAL_EXPR, C_AST_PG_ROLE_EXPRESSION),
    (C_AST_KIND_UNARY_EXPR, C_AST_PG_ROLE_EXPRESSION),
    (C_AST_KIND_GENERIC_SELECTION_EXPR, C_AST_PG_ROLE_EXPRESSION),
    (C_AST_KIND_BUILTIN_CONSTANT_P_EXPR, C_AST_PG_ROLE_EXPRESSION),
    (C_AST_KIND_BUILTIN_CHOOSE_EXPR, C_AST_PG_ROLE_EXPRESSION),
    (
        C_AST_KIND_BUILTIN_TYPES_COMPATIBLE_P_EXPR,
        C_AST_PG_ROLE_EXPRESSION,
    ),
    (C_AST_KIND_BUILTIN_EXPECT_EXPR, C_AST_PG_ROLE_EXPRESSION),
    (C_AST_KIND_BUILTIN_OFFSETOF_EXPR, C_AST_PG_ROLE_EXPRESSION),
    (
        C_AST_KIND_BUILTIN_OBJECT_SIZE_EXPR,
        C_AST_PG_ROLE_EXPRESSION,
    ),
    (C_AST_KIND_BUILTIN_PREFETCH_EXPR, C_AST_PG_ROLE_EXPRESSION),
    (C_AST_KIND_BUILTIN_OVERFLOW_EXPR, C_AST_PG_ROLE_EXPRESSION),
    (
        C_AST_KIND_BUILTIN_CLASSIFY_TYPE_EXPR,
        C_AST_PG_ROLE_EXPRESSION,
    ),
    (C_AST_KIND_GNU_LOCAL_LABEL_DECL, C_AST_PG_ROLE_DECLARATION),
    (C_AST_KIND_GNU_LABEL_ADDRESS_EXPR, C_AST_PG_ROLE_EXPRESSION),
];

fn append_vast_node(
    out: &mut Vec<u32>,
    kind: u32,
    parent_idx: u32,
    first_child_idx: u32,
    next_sibling_idx: u32,
    span_start: u32,
    span_len: u32,
) {
    out.extend_from_slice(&[
        kind,
        parent_idx,
        first_child_idx,
        next_sibling_idx,
        u32::MAX,
        span_start,
        span_len,
        kind.rotate_left(5),
        span_len,
        IDX_RESERVED as u32,
    ]);
}

fn witness_nodes() -> Vec<u32> {
    let mut vast_nodes = Vec::new();
    append_vast_node(
        &mut vast_nodes,
        node_kind::VARIABLE,
        u32::MAX,
        u32::MAX,
        1,
        0,
        11,
    );
    append_vast_node(&mut vast_nodes, node_kind::CALL, 0, 2, 5, 16, 9);
    append_vast_node(&mut vast_nodes, node_kind::LITERAL, 1, u32::MAX, 3, 32, 7);
    append_vast_node(&mut vast_nodes, node_kind::IMPORT, 1, 4, u32::MAX, 48, 13);
    append_vast_node(
        &mut vast_nodes,
        node_kind::SSA,
        3,
        u32::MAX,
        u32::MAX,
        62,
        3,
    );
    append_vast_node(
        &mut vast_nodes,
        node_kind::BASIC_BLOCK,
        u32::MAX,
        u32::MAX,
        u32::MAX,
        96,
        17,
    );
    append_vast_node(
        &mut vast_nodes,
        C_AST_KIND_LABEL_STMT,
        5,
        u32::MAX,
        7,
        128,
        5,
    );
    append_vast_node(
        &mut vast_nodes,
        C_AST_KIND_GNU_STATEMENT_EXPR,
        5,
        8,
        9,
        136,
        19,
    );
    append_vast_node(
        &mut vast_nodes,
        C_AST_KIND_ASM_QUALIFIER,
        8,
        u32::MAX,
        10,
        160,
        8,
    );
    append_vast_node(
        &mut vast_nodes,
        C_AST_KIND_ATTRIBUTE_FALLTHROUGH,
        5,
        u32::MAX,
        11,
        176,
        11,
    );
    append_vast_node(
        &mut vast_nodes,
        C_AST_KIND_BUILTIN_EXPECT_EXPR,
        7,
        u32::MAX,
        12,
        192,
        16,
    );
    append_vast_node(
        &mut vast_nodes,
        C_AST_KIND_SWITCH_STMT,
        5,
        u32::MAX,
        12,
        224,
        6,
    );
    append_vast_node(
        &mut vast_nodes,
        C_AST_KIND_CASE_STMT,
        11,
        u32::MAX,
        13,
        240,
        4,
    );
    append_vast_node(
        &mut vast_nodes,
        C_AST_KIND_DEFAULT_STMT,
        11,
        u32::MAX,
        14,
        248,
        7,
    );
    append_vast_node(
        &mut vast_nodes,
        C_AST_KIND_FOR_STMT,
        5,
        u32::MAX,
        15,
        264,
        3,
    );
    append_vast_node(
        &mut vast_nodes,
        C_AST_KIND_WHILE_STMT,
        5,
        u32::MAX,
        16,
        272,
        5,
    );
    append_vast_node(&mut vast_nodes, C_AST_KIND_DO_STMT, 5, u32::MAX, 17, 280, 2);
    append_vast_node(&mut vast_nodes, C_AST_KIND_IF_STMT, 5, u32::MAX, 18, 288, 2);
    append_vast_node(
        &mut vast_nodes,
        C_AST_KIND_GOTO_STMT,
        5,
        u32::MAX,
        19,
        296,
        4,
    );
    append_vast_node(
        &mut vast_nodes,
        C_AST_KIND_BREAK_STMT,
        5,
        u32::MAX,
        20,
        304,
        5,
    );
    append_vast_node(
        &mut vast_nodes,
        C_AST_KIND_CONTINUE_STMT,
        5,
        u32::MAX,
        21,
        312,
        8,
    );
    append_vast_node(
        &mut vast_nodes,
        C_AST_KIND_RETURN_STMT,
        5,
        u32::MAX,
        22,
        328,
        6,
    );
    append_vast_node(
        &mut vast_nodes,
        C_AST_KIND_CAST_EXPR,
        5,
        u32::MAX,
        u32::MAX,
        344,
        1,
    );
    vast_nodes
}

fn witness_node_count() -> u32 {
    u32::try_from(witness_nodes().len() / VAST_NODE_STRIDE_U32 as usize).unwrap_or_default()
}

fn witness_inputs() -> Vec<Vec<Vec<u8>>> {
    let nodes = witness_nodes();
    vec![vec![
        u32_words_to_bytes(&nodes),
        vec![0; witness_node_count() as usize * PG_NODE_STRIDE_U32 as usize * 4],
    ]]
}

fn semantic_witness_inputs() -> Vec<Vec<Vec<u8>>> {
    let nodes = witness_nodes();
    let node_count = witness_node_count() as usize;
    vec![vec![
        u32_words_to_bytes(&nodes),
        vec![0; node_count * C_AST_PG_SEMANTIC_NODE_STRIDE_U32 as usize * 4],
        vec![
            0;
            node_count
                * C_AST_PG_EDGE_ROWS_PER_NODE as usize
                * C_AST_PG_EDGE_STRIDE_U32 as usize
                * 4
        ],
    ]]
}

fn witness_expected() -> Vec<Vec<Vec<u8>>> {
    witness_inputs()
        .into_iter()
        .map(|input| vec![reference_ast_to_pg_nodes(&input[0])])
        .collect()
}

fn semantic_witness_expected() -> Vec<Vec<Vec<u8>>> {
    semantic_witness_inputs()
        .into_iter()
        .map(|input| {
            let semantic = reference_ast_to_pg_semantic_graph(&input[0]);
            vec![semantic.nodes, semantic.edges]
        })
        .collect()
}

inventory::submit! {
    OpEntry::new(
        OP_ID,
        || c_lower_ast_to_pg_nodes("vast_nodes", Expr::u32(witness_node_count()), "out_pg_nodes"),
        Some(witness_inputs),
        Some(witness_expected),
    )
}

inventory::submit! {
    OpEntry::new(
        SEMANTIC_OP_ID,
        || c_lower_ast_to_pg_semantic_graph(
            "vast_nodes",
            Expr::u32(witness_node_count()),
            "out_pg_nodes",
            "out_pg_edges",
        ),
        Some(semantic_witness_inputs),
        Some(semantic_witness_expected),
    )
}
