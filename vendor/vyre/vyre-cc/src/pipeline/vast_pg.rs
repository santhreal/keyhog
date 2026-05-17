#![allow(clippy::too_many_arguments, clippy::type_complexity)]

use std::path::Path;

use vyre::ir::Expr;
use vyre::{DispatchConfig, VyreBackend};
use vyre_driver_wgpu::WgpuBackend;
use vyre_libs::parsing::c::lower::ast_to_pg_nodes::{
    c_lower_ast_to_pg_nodes, c_lower_ast_to_pg_semantic_graph, C_AST_PG_EDGE_ROWS_PER_NODE,
    C_AST_PG_EDGE_STRIDE_U32, C_AST_PG_SEMANTIC_NODE_STRIDE_U32,
};
use vyre_libs::parsing::c::parse::vast::{
    c11_annotate_typedef_names, c11_build_expression_shape_nodes, c11_build_vast_nodes,
    c11_classify_vast_node_kinds,
};

use super::buffers::{read_u32_at, vec_u32_le_bytes};

pub(super) fn build_vast_and_pg(
    backend: &WgpuBackend,
    path: &Path,
    tok_types: &[u32],
    starts: &[u8],
    lens: &[u8],
    haystack: &[u8],
    haystack_len: u32,
    nt: u32,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>), String> {
    let vast_prog = c11_build_vast_nodes(
        "tok_types",
        "tok_starts",
        "tok_lens",
        Expr::u32(nt),
        "out_vast_nodes",
        "out_vast_count",
    );
    if !vyre::validate(&vast_prog).is_empty() {
        return Err("c11_build_vast_nodes IR validation failed".to_string());
    }
    let vast_init = vec![0u8; nt as usize * 10 * 4];
    let vast_count_init = vec![0u8; 4];
    let mut cfg = DispatchConfig::default();
    cfg.label = Some(format!("vyre-cc vast {}", path.display()));
    let vast_out = backend
        .dispatch(
            &vast_prog,
            &[
                vec_u32_le_bytes(tok_types),
                starts.to_vec(),
                lens.to_vec(),
                vast_init,
                vast_count_init,
            ],
            &cfg,
        )
        .map_err(|e| format!("c11_build_vast_nodes dispatch failed: {e}"))?;
    if vast_out.len() < 2 {
        return Err("c11_build_vast_nodes: expected node table and count outputs".to_string());
    }
    let raw_vast_blob = vast_out[0].clone();
    let vast_count = read_u32_at(&vast_out[1], 0).map_err(|e| format!("vast node count: {e}"))?;

    let annot_prog = c11_annotate_typedef_names(
        "vast_nodes",
        "haystack",
        Expr::u32(haystack_len.max(1)),
        Expr::u32(vast_count.max(1)),
        "annotated_vast",
    );
    if !vyre::validate(&annot_prog).is_empty() {
        return Err("c11_annotate_typedef_names IR validation failed".to_string());
    }
    cfg.label = Some(format!("vyre-cc vast-typedefs {}", path.display()));
    let annotated_out = backend
        .dispatch_borrowed(&annot_prog, &[&raw_vast_blob, haystack], &cfg)
        .map_err(|e| format!("c11_annotate_typedef_names dispatch failed: {e}"))?;
    let annotated_vast = annotated_out
        .first()
        .cloned()
        .ok_or_else(|| "c11_annotate_typedef_names: missing annotated VAST output".to_string())?;

    let classify_prog = c11_classify_vast_node_kinds(
        "vast_nodes",
        Expr::u32(vast_count.max(1)),
        "typed_vast_nodes",
    );
    if !vyre::validate(&classify_prog).is_empty() {
        return Err("c11_classify_vast_node_kinds IR validation failed".to_string());
    }
    cfg.label = Some(format!("vyre-cc vast-classify {}", path.display()));
    let typed_out = backend
        .dispatch_borrowed(&classify_prog, &[&annotated_vast], &cfg)
        .map_err(|e| format!("c11_classify_vast_node_kinds dispatch failed: {e}"))?;
    let typed_vast_blob = typed_out
        .first()
        .cloned()
        .ok_or_else(|| "c11_classify_vast_node_kinds: missing typed VAST output".to_string())?;

    let expr_prog = c11_build_expression_shape_nodes(
        "raw_vast_nodes",
        "typed_vast_nodes",
        Expr::u32(vast_count.max(1)),
        "expr_shape_nodes",
    );
    if !vyre::validate(&expr_prog).is_empty() {
        return Err("c11_build_expression_shape_nodes IR validation failed".to_string());
    }
    cfg.label = Some(format!("vyre-cc expr-shape {}", path.display()));
    let expr_out = backend
        .dispatch_borrowed(&expr_prog, &[&raw_vast_blob, &typed_vast_blob], &cfg)
        .map_err(|e| format!("c11_build_expression_shape_nodes dispatch failed: {e}"))?;
    let expr_shape_blob = expr_out.first().cloned().ok_or_else(|| {
        "c11_build_expression_shape_nodes: missing expression-shape output".to_string()
    })?;

    let pg_prog = c_lower_ast_to_pg_nodes("vast_nodes", Expr::u32(vast_count.max(1)), "pg_nodes");
    if !vyre::validate(&pg_prog).is_empty() {
        return Err("c_lower_ast_to_pg_nodes IR validation failed".to_string());
    }
    let pg_init = vec![0u8; vast_count.max(1) as usize * 6 * 4];
    cfg.label = Some(format!("vyre-cc pg {}", path.display()));
    let pg_out = backend
        .dispatch_borrowed(&pg_prog, &[&typed_vast_blob, &pg_init], &cfg)
        .map_err(|e| format!("c_lower_ast_to_pg_nodes dispatch failed: {e}"))?;
    let pg_blob = pg_out
        .first()
        .cloned()
        .ok_or_else(|| "c_lower_ast_to_pg_nodes: missing ProgramGraph node output".to_string())?;

    let semantic_pg_prog = c_lower_ast_to_pg_semantic_graph(
        "vast_nodes",
        Expr::u32(vast_count.max(1)),
        "semantic_pg_nodes",
        "semantic_pg_edges",
    );
    if !vyre::validate(&semantic_pg_prog).is_empty() {
        return Err("c_lower_ast_to_pg_semantic_graph IR validation failed".to_string());
    }
    let semantic_node_init =
        vec![0u8; vast_count.max(1) as usize * C_AST_PG_SEMANTIC_NODE_STRIDE_U32 as usize * 4];
    let semantic_edge_init = vec![
        0u8;
        vast_count.max(1) as usize
            * C_AST_PG_EDGE_ROWS_PER_NODE as usize
            * C_AST_PG_EDGE_STRIDE_U32 as usize
            * 4
    ];
    cfg.label = Some(format!("vyre-cc semantic-pg {}", path.display()));
    let semantic_pg_out = backend
        .dispatch_borrowed(
            &semantic_pg_prog,
            &[&typed_vast_blob, &semantic_node_init, &semantic_edge_init],
            &cfg,
        )
        .map_err(|e| format!("c_lower_ast_to_pg_semantic_graph dispatch failed: {e}"))?;
    if semantic_pg_out.len() < 2 {
        return Err(
            "c_lower_ast_to_pg_semantic_graph: missing semantic node/edge outputs".to_string(),
        );
    }
    let semantic_pg_nodes = semantic_pg_out[0].clone();
    let semantic_pg_edges = semantic_pg_out[1].clone();

    Ok((
        typed_vast_blob,
        expr_shape_blob,
        pg_blob,
        semantic_pg_nodes,
        semantic_pg_edges,
    ))
}
