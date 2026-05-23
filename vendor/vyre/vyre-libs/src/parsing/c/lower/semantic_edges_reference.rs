//! Test-only CPU oracle for semantic control-edge resolution.
//!
//! Production edge resolution is emitted by `semantic_edges.rs`; this module
//! exists under `#[cfg(test)]` for parity and hostile fixture coverage.

use super::ast_to_pg_nodes::{
    C_AST_PG_EDGE_CASE_VALUE, C_AST_PG_EDGE_GOTO_TARGET, C_AST_PG_EDGE_NONE,
    C_AST_PG_EDGE_SWITCH_CASE, C_AST_PG_EDGE_SWITCH_DEFAULT, C_AST_PG_EDGE_SWITCH_SELECTOR,
};
use crate::parsing::c::parse::vast::{
    C_AST_KIND_CASE_STMT, C_AST_KIND_DEFAULT_STMT, C_AST_KIND_GOTO_STMT, C_AST_KIND_LABEL_STMT,
    C_AST_KIND_SWITCH_STMT,
};

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
    let word_idx = node_idx
        .checked_mul(VAST_NODE_STRIDE_U32 as usize)
        .and_then(|base| base.checked_add(field))
        .unwrap_or_else(|| {
            panic!("vyre-libs semantic edge reference resolver VAST index overflow: node_idx={node_idx}, field={field}. Fix: bound VAST node counts before semantic lowering.")
        });
    *vast_nodes.get(word_idx).unwrap_or_else(|| {
        panic!(
            "vyre-libs semantic edge reference resolver received truncated VAST: node_idx={node_idx}, field={field}, word_idx={word_idx}, words={}. Fix: pass exactly node_count * {VAST_NODE_STRIDE_U32} VAST words.",
            vast_nodes.len()
        )
    })
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
        if field_if_valid(vast_nodes, candidate_idx, IDX_KIND, node_count) != C_AST_KIND_LABEL_STMT
        {
            continue;
        }
        if field_if_valid(vast_nodes, candidate_idx, IDX_SYMBOL_HASH, node_count) == target_hash
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
        if field_if_valid(vast_nodes, candidate_idx, IDX_KIND, node_count) != C_AST_KIND_SWITCH_STMT
        {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsing::c::parse::vast::{C_AST_KIND_GOTO_STMT, C_AST_KIND_LABEL_STMT};

    #[test]
    fn resolved_semantic_edges_reference_reads_goto_edge_fields() {
        let mut vast = vec![0u32; VAST_NODE_STRIDE_U32 as usize * 3];
        vast[IDX_KIND] = C_AST_KIND_GOTO_STMT;
        vast[IDX_PARENT] = u32::MAX;
        vast[IDX_NEXT_SIBLING] = 1;
        vast[VAST_NODE_STRIDE_U32 as usize + IDX_PARENT] = 0;
        vast[VAST_NODE_STRIDE_U32 as usize + IDX_SYMBOL_HASH] = 0xA11CE;
        let label_base = VAST_NODE_STRIDE_U32 as usize * 2;
        vast[label_base + IDX_KIND] = C_AST_KIND_LABEL_STMT;
        vast[label_base + IDX_PARENT] = 0;
        vast[label_base + IDX_SYMBOL_HASH] = 0xA11CE;

        let (edge, extra) = resolved_semantic_edges(&vast, 0, 3, C_AST_KIND_GOTO_STMT);

        assert_eq!(edge.kind, C_AST_PG_EDGE_GOTO_TARGET);
        assert_eq!(edge.src, 0);
        assert_eq!(edge.dst, 2);
        assert_eq!(extra.kind, C_AST_PG_EDGE_NONE);
    }

    #[test]
    #[should_panic(expected = "truncated VAST")]
    fn resolved_semantic_edges_reference_rejects_truncated_vast_rows() {
        let _ = resolved_semantic_edges(&[], 0, 1, C_AST_KIND_GOTO_STMT);
    }
}
