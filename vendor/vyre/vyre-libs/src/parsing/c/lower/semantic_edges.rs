use super::ast_to_pg_nodes::{
    C_AST_PG_EDGE_CASE_VALUE, C_AST_PG_EDGE_GOTO_TARGET, C_AST_PG_EDGE_NONE,
    C_AST_PG_EDGE_SWITCH_CASE, C_AST_PG_EDGE_SWITCH_DEFAULT, C_AST_PG_EDGE_SWITCH_SELECTOR,
};
use crate::parsing::c::parse::vast::{
    C_AST_KIND_CASE_STMT, C_AST_KIND_DEFAULT_STMT, C_AST_KIND_GOTO_STMT, C_AST_KIND_LABEL_STMT,
    C_AST_KIND_SWITCH_STMT,
};
use vyre::ir::{Expr, Node};

const VAST_NODE_STRIDE_U32: u32 = 10;
const IDX_KIND: usize = 0;
const IDX_PARENT: usize = 1;
const IDX_FIRST_CHILD: usize = 2;
const IDX_NEXT_SIBLING: usize = 3;
const IDX_SYMBOL_HASH: usize = 9;

#[derive(Clone, Copy)]
pub(super) struct SemanticEdge {
    pub(super) kind: u32,
    pub(super) src: u32,
    pub(super) dst: u32,
}

impl SemanticEdge {
    const NONE: Self = Self {
        kind: C_AST_PG_EDGE_NONE,
        src: u32::MAX,
        dst: u32::MAX,
    };

    const fn new(kind: u32, src: u32, dst: u32) -> Self {
        Self { kind, src, dst }
    }
}

fn expr_is_kind(kind: Expr, expected: u32) -> Expr {
    Expr::eq(kind, Expr::u32(expected))
}

fn valid_node_idx(idx: Expr, num_nodes: &Expr) -> Expr {
    Expr::and(
        Expr::ne(idx.clone(), Expr::u32(u32::MAX)),
        Expr::lt(idx, num_nodes.clone()),
    )
}

fn vast_field(vast_nodes: &str, idx: Expr, field: usize) -> Expr {
    Expr::load(
        vast_nodes,
        Expr::add(
            Expr::mul(idx, Expr::u32(VAST_NODE_STRIDE_U32)),
            Expr::u32(field as u32),
        ),
    )
}

fn resolve_root_nodes(
    vast_nodes: &str,
    num_nodes: &Expr,
    start_idx: Expr,
    root_var: &str,
    parent_var: &str,
    loop_var: &str,
) -> Vec<Node> {
    vec![
        Node::let_bind(root_var, start_idx.clone()),
        Node::let_bind(parent_var, Expr::u32(u32::MAX)),
        Node::if_then(
            valid_node_idx(start_idx.clone(), num_nodes),
            vec![Node::assign(
                parent_var,
                vast_field(vast_nodes, start_idx, IDX_PARENT),
            )],
        ),
        Node::loop_for(
            loop_var,
            Expr::u32(0),
            num_nodes.clone(),
            vec![Node::if_then(
                valid_node_idx(Expr::var(parent_var), num_nodes),
                vec![
                    Node::assign(root_var, Expr::var(parent_var)),
                    Node::assign(
                        parent_var,
                        vast_field(vast_nodes, Expr::var(parent_var), IDX_PARENT),
                    ),
                ],
            )],
        ),
    ]
}

pub(super) fn semantic_resolution_nodes(
    vast_nodes: &str,
    num_nodes: &Expr,
    node_idx: Expr,
) -> Vec<Node> {
    let mut nodes = vec![
        Node::let_bind("resolved_goto_target_idx", Expr::u32(u32::MAX)),
        Node::let_bind("switch_selector_idx", Expr::u32(u32::MAX)),
        Node::let_bind("case_value_idx", Expr::u32(u32::MAX)),
        Node::let_bind("enclosing_switch_idx", Expr::u32(u32::MAX)),
        Node::let_bind("enclosing_switch_distance", Expr::u32(u32::MAX)),
        Node::let_bind("goto_target_hash", Expr::u32(0)),
    ];

    nodes.extend(resolve_root_nodes(
        vast_nodes,
        num_nodes,
        node_idx.clone(),
        "current_root_idx",
        "current_root_parent_idx",
        "current_root_step",
    ));

    nodes.push(Node::if_then(
        Expr::and(
            expr_is_kind(Expr::var("kind"), C_AST_KIND_GOTO_STMT),
            valid_node_idx(Expr::var("next_sibling_idx"), num_nodes),
        ),
        vec![Node::assign(
            "goto_target_hash",
            vast_field(vast_nodes, Expr::var("next_sibling_idx"), IDX_SYMBOL_HASH),
        )],
    ));

    let mut label_scan_body = vec![
        Node::let_bind("label_scan_kind", Expr::u32(0)),
        Node::let_bind("label_scan_hash", Expr::u32(0)),
    ];
    label_scan_body.push(Node::if_then(
        valid_node_idx(Expr::var("label_scan_idx"), num_nodes),
        vec![
            Node::assign(
                "label_scan_kind",
                vast_field(vast_nodes, Expr::var("label_scan_idx"), IDX_KIND),
            ),
            Node::assign(
                "label_scan_hash",
                vast_field(vast_nodes, Expr::var("label_scan_idx"), IDX_SYMBOL_HASH),
            ),
        ],
    ));
    label_scan_body.extend(resolve_root_nodes(
        vast_nodes,
        num_nodes,
        Expr::var("label_scan_idx"),
        "label_scan_root_idx",
        "label_scan_parent_idx",
        "label_scan_root_step",
    ));
    label_scan_body.push(Node::if_then(
        Expr::and(
            expr_is_kind(Expr::var("kind"), C_AST_KIND_GOTO_STMT),
            Expr::and(
                Expr::eq(Expr::var("resolved_goto_target_idx"), Expr::u32(u32::MAX)),
                Expr::and(
                    Expr::eq(
                        Expr::var("label_scan_kind"),
                        Expr::u32(C_AST_KIND_LABEL_STMT),
                    ),
                    Expr::and(
                        Expr::ne(Expr::var("goto_target_hash"), Expr::u32(0)),
                        Expr::and(
                            Expr::eq(Expr::var("label_scan_hash"), Expr::var("goto_target_hash")),
                            Expr::eq(
                                Expr::var("label_scan_root_idx"),
                                Expr::var("current_root_idx"),
                            ),
                        ),
                    ),
                ),
            ),
        ),
        vec![Node::assign(
            "resolved_goto_target_idx",
            Expr::var("label_scan_idx"),
        )],
    ));
    nodes.push(Node::loop_for(
        "label_scan_idx",
        Expr::u32(0),
        num_nodes.clone(),
        label_scan_body,
    ));

    nodes.push(Node::if_then(
        Expr::and(
            expr_is_kind(Expr::var("kind"), C_AST_KIND_SWITCH_STMT),
            valid_node_idx(Expr::var("next_sibling_idx"), num_nodes),
        ),
        vec![
            Node::let_bind(
                "switch_selector_candidate",
                vast_field(vast_nodes, Expr::var("next_sibling_idx"), IDX_FIRST_CHILD),
            ),
            Node::let_bind("switch_selector_parent", Expr::u32(u32::MAX)),
            Node::if_then(
                valid_node_idx(Expr::var("switch_selector_candidate"), num_nodes),
                vec![Node::assign(
                    "switch_selector_parent",
                    vast_field(
                        vast_nodes,
                        Expr::var("switch_selector_candidate"),
                        IDX_PARENT,
                    ),
                )],
            ),
            Node::if_then(
                Expr::and(
                    valid_node_idx(Expr::var("switch_selector_candidate"), num_nodes),
                    Expr::eq(
                        Expr::var("switch_selector_parent"),
                        Expr::var("next_sibling_idx"),
                    ),
                ),
                vec![Node::assign(
                    "switch_selector_idx",
                    Expr::var("switch_selector_candidate"),
                )],
            ),
        ],
    ));

    nodes.push(Node::if_then(
        Expr::and(
            expr_is_kind(Expr::var("kind"), C_AST_KIND_CASE_STMT),
            Expr::and(
                valid_node_idx(Expr::var("next_sibling_idx"), num_nodes),
                Expr::eq(
                    vast_field(vast_nodes, Expr::var("next_sibling_idx"), IDX_PARENT),
                    Expr::var("parent_idx"),
                ),
            ),
        ),
        vec![Node::assign(
            "case_value_idx",
            Expr::var("next_sibling_idx"),
        )],
    ));

    let switch_scan_body = vec![
        Node::let_bind("switch_scan_kind", Expr::u32(0)),
        Node::let_bind("switch_scan_condition_group_idx", Expr::u32(u32::MAX)),
        Node::let_bind("switch_scan_body_idx", Expr::u32(u32::MAX)),
        Node::if_then(
            valid_node_idx(Expr::var("switch_scan_idx"), num_nodes),
            vec![
                Node::assign(
                    "switch_scan_kind",
                    vast_field(vast_nodes, Expr::var("switch_scan_idx"), IDX_KIND),
                ),
                Node::assign(
                    "switch_scan_condition_group_idx",
                    vast_field(vast_nodes, Expr::var("switch_scan_idx"), IDX_NEXT_SIBLING),
                ),
            ],
        ),
        Node::if_then(
            Expr::and(
                Expr::eq(
                    Expr::var("switch_scan_kind"),
                    Expr::u32(C_AST_KIND_SWITCH_STMT),
                ),
                valid_node_idx(Expr::var("switch_scan_condition_group_idx"), num_nodes),
            ),
            vec![Node::assign(
                "switch_scan_body_idx",
                vast_field(
                    vast_nodes,
                    Expr::var("switch_scan_condition_group_idx"),
                    IDX_NEXT_SIBLING,
                ),
            )],
        ),
        Node::if_then(
            Expr::and(
                Expr::or(
                    expr_is_kind(Expr::var("kind"), C_AST_KIND_CASE_STMT),
                    expr_is_kind(Expr::var("kind"), C_AST_KIND_DEFAULT_STMT),
                ),
                Expr::and(
                    valid_node_idx(Expr::var("switch_scan_idx"), num_nodes),
                    valid_node_idx(Expr::var("switch_scan_body_idx"), num_nodes),
                ),
            ),
            vec![
                Node::let_bind("switch_body_ancestor_idx", Expr::var("parent_idx")),
                Node::let_bind("switch_body_found", Expr::bool(false)),
                Node::let_bind("switch_body_distance", Expr::u32(u32::MAX)),
                Node::loop_for(
                    "switch_body_step",
                    Expr::u32(0),
                    num_nodes.clone(),
                    vec![
                        Node::if_then(
                            Expr::eq(
                                Expr::var("switch_body_ancestor_idx"),
                                Expr::var("switch_scan_body_idx"),
                            ),
                            vec![Node::if_then(
                                Expr::not(Expr::var("switch_body_found")),
                                vec![
                                    Node::assign("switch_body_found", Expr::bool(true)),
                                    Node::assign(
                                        "switch_body_distance",
                                        Expr::var("switch_body_step"),
                                    ),
                                ],
                            )],
                        ),
                        Node::if_then(
                            valid_node_idx(Expr::var("switch_body_ancestor_idx"), num_nodes),
                            vec![Node::assign(
                                "switch_body_ancestor_idx",
                                vast_field(
                                    vast_nodes,
                                    Expr::var("switch_body_ancestor_idx"),
                                    IDX_PARENT,
                                ),
                            )],
                        ),
                    ],
                ),
                Node::if_then(
                    Expr::and(
                        Expr::var("switch_body_found"),
                        Expr::lt(
                            Expr::var("switch_body_distance"),
                            Expr::var("enclosing_switch_distance"),
                        ),
                    ),
                    vec![
                        Node::assign("enclosing_switch_idx", Expr::var("switch_scan_idx")),
                        Node::assign(
                            "enclosing_switch_distance",
                            Expr::var("switch_body_distance"),
                        ),
                    ],
                ),
            ],
        ),
    ];
    nodes.push(Node::loop_for(
        "switch_scan_idx",
        Expr::u32(0),
        num_nodes.clone(),
        switch_scan_body,
    ));

    nodes.extend(vec![
        Node::let_bind("semantic_edge3_has", Expr::bool(false)),
        Node::let_bind("semantic_edge3_kind", Expr::u32(C_AST_PG_EDGE_NONE)),
        Node::let_bind("semantic_edge3_src", Expr::u32(u32::MAX)),
        Node::let_bind("semantic_edge3_dst", Expr::u32(u32::MAX)),
        Node::let_bind("semantic_edge4_has", Expr::bool(false)),
        Node::let_bind("semantic_edge4_kind", Expr::u32(C_AST_PG_EDGE_NONE)),
        Node::let_bind("semantic_edge4_src", Expr::u32(u32::MAX)),
        Node::let_bind("semantic_edge4_dst", Expr::u32(u32::MAX)),
    ]);

    nodes.push(Node::if_then(
        Expr::and(
            expr_is_kind(Expr::var("kind"), C_AST_KIND_GOTO_STMT),
            valid_node_idx(Expr::var("resolved_goto_target_idx"), num_nodes),
        ),
        vec![
            Node::assign("semantic_edge3_has", Expr::bool(true)),
            Node::assign("semantic_edge3_kind", Expr::u32(C_AST_PG_EDGE_GOTO_TARGET)),
            Node::assign("semantic_edge3_src", node_idx.clone()),
            Node::assign("semantic_edge3_dst", Expr::var("resolved_goto_target_idx")),
        ],
    ));
    nodes.push(Node::if_then(
        Expr::and(
            expr_is_kind(Expr::var("kind"), C_AST_KIND_SWITCH_STMT),
            valid_node_idx(Expr::var("switch_selector_idx"), num_nodes),
        ),
        vec![
            Node::assign("semantic_edge3_has", Expr::bool(true)),
            Node::assign(
                "semantic_edge3_kind",
                Expr::u32(C_AST_PG_EDGE_SWITCH_SELECTOR),
            ),
            Node::assign("semantic_edge3_src", node_idx.clone()),
            Node::assign("semantic_edge3_dst", Expr::var("switch_selector_idx")),
        ],
    ));
    nodes.push(Node::if_then(
        Expr::and(
            expr_is_kind(Expr::var("kind"), C_AST_KIND_CASE_STMT),
            valid_node_idx(Expr::var("case_value_idx"), num_nodes),
        ),
        vec![
            Node::assign("semantic_edge3_has", Expr::bool(true)),
            Node::assign("semantic_edge3_kind", Expr::u32(C_AST_PG_EDGE_CASE_VALUE)),
            Node::assign("semantic_edge3_src", node_idx.clone()),
            Node::assign("semantic_edge3_dst", Expr::var("case_value_idx")),
        ],
    ));
    nodes.push(Node::if_then(
        Expr::and(
            expr_is_kind(Expr::var("kind"), C_AST_KIND_DEFAULT_STMT),
            valid_node_idx(Expr::var("enclosing_switch_idx"), num_nodes),
        ),
        vec![
            Node::assign("semantic_edge3_has", Expr::bool(true)),
            Node::assign(
                "semantic_edge3_kind",
                Expr::u32(C_AST_PG_EDGE_SWITCH_DEFAULT),
            ),
            Node::assign("semantic_edge3_src", Expr::var("enclosing_switch_idx")),
            Node::assign("semantic_edge3_dst", node_idx.clone()),
        ],
    ));
    nodes.push(Node::if_then(
        Expr::and(
            expr_is_kind(Expr::var("kind"), C_AST_KIND_CASE_STMT),
            valid_node_idx(Expr::var("enclosing_switch_idx"), num_nodes),
        ),
        vec![
            Node::assign("semantic_edge4_has", Expr::bool(true)),
            Node::assign("semantic_edge4_kind", Expr::u32(C_AST_PG_EDGE_SWITCH_CASE)),
            Node::assign("semantic_edge4_src", Expr::var("enclosing_switch_idx")),
            Node::assign("semantic_edge4_dst", node_idx),
        ],
    ));

    nodes
}

pub(super) fn resolved_semantic_edges(
    vast_nodes: &[u32],
    node_idx: usize,
    node_count: usize,
    kind: u32,
) -> (SemanticEdge, SemanticEdge) {
    match kind {
        C_AST_KIND_GOTO_STMT => {
            let target = resolved_goto_target_label(vast_nodes, node_idx, node_count);
            if target == u32::MAX {
                (SemanticEdge::NONE, SemanticEdge::NONE)
            } else {
                (
                    SemanticEdge::new(C_AST_PG_EDGE_GOTO_TARGET, node_idx as u32, target),
                    SemanticEdge::NONE,
                )
            }
        }
        C_AST_KIND_SWITCH_STMT => {
            let selector = switch_selector_idx(vast_nodes, node_idx, node_count);
            if selector == u32::MAX {
                (SemanticEdge::NONE, SemanticEdge::NONE)
            } else {
                (
                    SemanticEdge::new(C_AST_PG_EDGE_SWITCH_SELECTOR, node_idx as u32, selector),
                    SemanticEdge::NONE,
                )
            }
        }
        C_AST_KIND_CASE_STMT => {
            let value = case_value_idx(vast_nodes, node_idx, node_count);
            let switch_idx = enclosing_switch_idx(vast_nodes, node_idx, node_count);
            let edge3 = if value == u32::MAX {
                SemanticEdge::NONE
            } else {
                SemanticEdge::new(C_AST_PG_EDGE_CASE_VALUE, node_idx as u32, value)
            };
            let edge4 = if switch_idx == u32::MAX {
                SemanticEdge::NONE
            } else {
                SemanticEdge::new(C_AST_PG_EDGE_SWITCH_CASE, switch_idx, node_idx as u32)
            };
            (edge3, edge4)
        }
        C_AST_KIND_DEFAULT_STMT => {
            let switch_idx = enclosing_switch_idx(vast_nodes, node_idx, node_count);
            if switch_idx == u32::MAX {
                (SemanticEdge::NONE, SemanticEdge::NONE)
            } else {
                (
                    SemanticEdge::new(C_AST_PG_EDGE_SWITCH_DEFAULT, switch_idx, node_idx as u32),
                    SemanticEdge::NONE,
                )
            }
        }
        _ => (SemanticEdge::NONE, SemanticEdge::NONE),
    }
}

fn field_if_valid(vast_nodes: &[u32], node_idx: usize, field: usize, node_count: usize) -> u32 {
    if node_idx >= node_count {
        return u32::MAX;
    }
    vast_nodes
        .get(node_idx * VAST_NODE_STRIDE_U32 as usize + field)
        .copied()
        .unwrap_or(u32::MAX)
}

fn root_idx(vast_nodes: &[u32], node_idx: usize, node_count: usize) -> u32 {
    if node_idx >= node_count {
        return u32::MAX;
    }
    let mut root = node_idx as u32;
    let mut parent = field_if_valid(vast_nodes, node_idx, IDX_PARENT, node_count);
    for _ in 0..node_count {
        let Ok(parent_idx) = usize::try_from(parent) else {
            break;
        };
        if parent_idx >= node_count {
            break;
        }
        root = parent;
        parent = field_if_valid(vast_nodes, parent_idx, IDX_PARENT, node_count);
    }
    root
}

fn resolved_goto_target_label(vast_nodes: &[u32], node_idx: usize, node_count: usize) -> u32 {
    let target_idx = field_if_valid(vast_nodes, node_idx, IDX_NEXT_SIBLING, node_count);
    let Ok(target_idx) = usize::try_from(target_idx) else {
        return u32::MAX;
    };
    if target_idx >= node_count {
        return u32::MAX;
    }
    let target_hash = field_if_valid(vast_nodes, target_idx, IDX_SYMBOL_HASH, node_count);
    if target_hash == 0 {
        return u32::MAX;
    }
    let current_root = root_idx(vast_nodes, node_idx, node_count);
    for candidate_idx in 0..node_count {
        let base = candidate_idx * VAST_NODE_STRIDE_U32 as usize;
        if vast_nodes.get(base + IDX_KIND).copied().unwrap_or_default() != C_AST_KIND_LABEL_STMT {
            continue;
        }
        if vast_nodes
            .get(base + IDX_SYMBOL_HASH)
            .copied()
            .unwrap_or_default()
            == target_hash
            && root_idx(vast_nodes, candidate_idx, node_count) == current_root
        {
            return candidate_idx as u32;
        }
    }
    u32::MAX
}

fn switch_selector_idx(vast_nodes: &[u32], node_idx: usize, node_count: usize) -> u32 {
    let condition_group = field_if_valid(vast_nodes, node_idx, IDX_NEXT_SIBLING, node_count);
    let Ok(condition_group) = usize::try_from(condition_group) else {
        return u32::MAX;
    };
    let selector = field_if_valid(vast_nodes, condition_group, IDX_FIRST_CHILD, node_count);
    let Ok(selector_idx) = usize::try_from(selector) else {
        return u32::MAX;
    };
    if selector_idx >= node_count {
        return u32::MAX;
    }
    if field_if_valid(vast_nodes, selector_idx, IDX_PARENT, node_count) != condition_group as u32 {
        return u32::MAX;
    }
    selector
}

fn switch_body_idx(vast_nodes: &[u32], switch_idx: usize, node_count: usize) -> u32 {
    let condition_group = field_if_valid(vast_nodes, switch_idx, IDX_NEXT_SIBLING, node_count);
    let Ok(condition_group) = usize::try_from(condition_group) else {
        return u32::MAX;
    };
    let body = field_if_valid(vast_nodes, condition_group, IDX_NEXT_SIBLING, node_count);
    let Ok(body_idx) = usize::try_from(body) else {
        return u32::MAX;
    };
    if body_idx >= node_count {
        return u32::MAX;
    }
    body
}

fn case_value_idx(vast_nodes: &[u32], node_idx: usize, node_count: usize) -> u32 {
    let value = field_if_valid(vast_nodes, node_idx, IDX_NEXT_SIBLING, node_count);
    let Ok(value_idx) = usize::try_from(value) else {
        return u32::MAX;
    };
    if value_idx >= node_count {
        return u32::MAX;
    }
    let case_parent = field_if_valid(vast_nodes, node_idx, IDX_PARENT, node_count);
    if case_parent == u32::MAX {
        return u32::MAX;
    }
    if field_if_valid(vast_nodes, value_idx, IDX_PARENT, node_count) != case_parent {
        return u32::MAX;
    }
    value
}

fn enclosing_switch_idx(vast_nodes: &[u32], node_idx: usize, node_count: usize) -> u32 {
    let mut resolved = u32::MAX;
    let mut best_distance = usize::MAX;
    let parent = field_if_valid(vast_nodes, node_idx, IDX_PARENT, node_count);
    for candidate_idx in 0..node_count {
        let base = candidate_idx * VAST_NODE_STRIDE_U32 as usize;
        if vast_nodes.get(base + IDX_KIND).copied().unwrap_or_default() != C_AST_KIND_SWITCH_STMT {
            continue;
        }
        let distance = ancestor_distance(
            vast_nodes,
            parent,
            switch_body_idx(vast_nodes, candidate_idx, node_count),
            node_count,
        );
        if let Some(distance) = distance {
            if distance < best_distance {
                best_distance = distance;
                resolved = candidate_idx as u32;
            }
        }
    }
    resolved
}

fn ancestor_distance(
    vast_nodes: &[u32],
    mut node: u32,
    ancestor: u32,
    node_count: usize,
) -> Option<usize> {
    if node == u32::MAX || ancestor == u32::MAX {
        return None;
    }
    for distance in 0..node_count {
        if node == ancestor {
            return Some(distance);
        }
        let Ok(node_idx) = usize::try_from(node) else {
            return None;
        };
        if node_idx >= node_count {
            return None;
        }
        node = field_if_valid(vast_nodes, node_idx, IDX_PARENT, node_count);
    }
    None
}
