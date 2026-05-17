//! GPU IR builders: lower a C VAST node table into the property-graph
//! buffers that the dataflow analyzer consumes. Two entry points:
//! `c_lower_ast_to_pg_nodes` (node decode only) and
//! `c_lower_ast_to_pg_semantic_graph` (node + semantic edges).

use crate::parsing::c::lower::semantic_edges::*;
use crate::parsing::c::parse::vast::*;
use crate::parsing::composition::child_phase;
use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

use super::semantic::*;
use super::*;

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
                vec![child_phase(
                    SEMANTIC_OP_ID,
                    "vyre-libs::parsing::c::lower::ast_to_pg_semantic_graph::node_edge_pass",
                    loop_body,
                )],
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
