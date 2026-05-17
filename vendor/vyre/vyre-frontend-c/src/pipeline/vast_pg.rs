#![allow(clippy::too_many_arguments, clippy::type_complexity)]

use std::path::Path;

use vyre::ir::Expr;
use vyre::{DispatchConfig, VyreBackend};

use vyre_libs::parsing::c::lower::ast_to_pg_nodes::{
    c_lower_ast_to_pg_nodes, c_lower_ast_to_pg_semantic_graph, C_AST_PG_EDGE_ROWS_PER_NODE,
    C_AST_PG_EDGE_STRIDE_U32, C_AST_PG_SEMANTIC_NODE_STRIDE_U32,
    reference_ast_to_pg_nodes, reference_ast_to_pg_semantic_graph,
};
use vyre_libs::parsing::c::parse::vast::{
    c11_annotate_typedef_names, c11_build_expression_shape_nodes, c11_build_vast_nodes,
    c11_classify_vast_node_kinds, reference_c11_annotate_typedef_names,
    reference_c11_build_expression_shape_nodes, reference_c11_classify_vast_node_kinds,
};

pub(super) fn build_vast_and_pg(
    backend: &dyn VyreBackend,
    path: &Path,
    tok_types_bytes: &[u8],
    starts: &[u8],
    lens: &[u8],
    source: &[u8],
    haystack: &[u8],
    haystack_len: u32,
    nt: u32,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>), String> {
    let trace = std::env::var_os("VYRE_STAGE_TRACE").is_some();
    let stage_start = std::time::Instant::now();
    let mut last_t = stage_start;
    let mut log = |label: &str| {
        if trace {
            let now = std::time::Instant::now();
            let stage = now.duration_since(last_t).as_micros();
            let total = now.duration_since(stage_start).as_micros();
            eprintln!("[stage-trace] +{stage}us (total {total}us): build_vast_and_pg {label}");
            last_t = now;
        }
    };

    let vast_prog = c11_build_vast_nodes(
        "tok_types",
        "tok_starts",
        "tok_lens",
        Expr::u32(nt),
        "out_vast_nodes",
        "out_vast_count",
    );
    super::validate_internal_stage(&vast_prog, "c11_build_vast_nodes")?;
    let vast_init = vec![0u8; nt as usize * 10 * 4];
    let vast_count_init = vec![0u8; 4];
    let mut cfg = DispatchConfig::default();
    cfg.label = Some(format!("vyre-frontend-c vast {}", path.display()));
    // Debug: when dispatch fails, dump the lowered descriptor shape so
    // we can compare against the standalone repro. nt = the actual
    // token count derived from the live lex output, not a hand-picked
    // synthetic.
    let mut vast_out = super::dispatch_borrowed_cached(
        backend,
            &vast_prog,
            &[
                tok_types_bytes,
                starts,
                lens,
                &vast_init,
                &vast_count_init,
            ],
            &cfg,
        )
        .map_err(|e| {
            eprintln!("=== VAST_DEBUG nt={nt} ===");
            let optimized = vyre::optimize(vast_prog.clone()).unwrap_or_else(|_| vast_prog.clone());
            match vyre_lower::lower_for_emit(&optimized) {
                Ok(_) => eprintln!("  standalone lower_for_emit OK (mismatch with backend dispatch path)"),
                Err(e) => eprintln!("  standalone lower_for_emit FAIL: {e}"),
            }
            format!("c11_build_vast_nodes dispatch failed: {e}")
        })?;
    log("dispatch c11_build_vast_nodes");
    if vast_out.len() < 2 {
        return Err("c11_build_vast_nodes: expected node table and count outputs".to_string());
    }
    let raw_vast_blob = vast_out.remove(0);
    let vast_count = nt.max(1);

    let annot_prog = c11_annotate_typedef_names(
        "vast_nodes",
        "haystack",
        Expr::u32(haystack_len.max(1)),
        Expr::u32(vast_count.max(1)),
        "annotated_vast",
    );
    super::validate_internal_stage(&annot_prog, "c11_annotate_typedef_names")?;

    let classify_prog = c11_classify_vast_node_kinds(
        "annotated_vast",
        Expr::u32(vast_count.max(1)),
        "typed_vast_nodes",
    );
    super::validate_internal_stage(&classify_prog, "c11_classify_vast_node_kinds")?;
    let annotated_init = vec![0u8; vast_count.max(1) as usize * 10 * 4];
    let typed_init = vec![0u8; vast_count.max(1) as usize * 10 * 4];
    let mut run_typedef_classify_unfused = |cfg: &mut DispatchConfig| -> Result<Vec<u8>, String> {
        cfg.label = Some(format!("vyre-frontend-c vast-typedefs {}", path.display()));
        let annotated_out = super::dispatch_borrowed_cached(
            backend,
                &annot_prog,
                &[&raw_vast_blob, haystack, &annotated_init],
                cfg,
            )
            .map_err(|e| format!("c11_annotate_typedef_names dispatch failed: {e}"))?;
        log("dispatch c11_annotate_typedef_names");
        let annotated_vast = annotated_out.into_iter().next().ok_or_else(|| {
            "c11_annotate_typedef_names: missing annotated VAST output".to_string()
        })?;
        cfg.label = Some(format!("vyre-frontend-c vast-classify {}", path.display()));
        let typed_out = super::dispatch_borrowed_cached(
            backend,
            &classify_prog,
            &[&annotated_vast, &typed_init],
            cfg,
        )
            .map_err(|e| format!("c11_classify_vast_node_kinds dispatch failed: {e}"))?;
        log("dispatch c11_classify_vast_node_kinds");
        typed_out.into_iter().next().ok_or_else(|| {
            "c11_classify_vast_node_kinds: missing typed VAST output".to_string()
        })
    };
    let typed_vast_blob = if vast_count <= 4096
        && std::env::var_os("VYRE_FRONTEND_C_FORCE_GPU_TYPEDEF_ANNOTATION").is_none()
    {
        let annotated_vast = reference_c11_annotate_typedef_names(&raw_vast_blob, source);
        log("host c11_annotate_typedef_names");
        let typed_vast = reference_c11_classify_vast_node_kinds(&annotated_vast);
        log("host c11_classify_vast_node_kinds");
        typed_vast
    } else if std::env::var_os("VYRE_FRONTEND_C_ENABLE_RUNTIME_FUSION").is_some() {
        match vyre_foundation::execution_plan::fusion::fuse_programs(&[
            annot_prog.clone(),
            classify_prog.clone(),
        ]) {
            Ok(fused) => {
            cfg.label = Some(format!(
                "vyre-frontend-c vast-typedefs+classify {}",
                path.display()
            ));
            match super::dispatch_borrowed_cached(
                    backend,
                    &fused,
                    &[&raw_vast_blob, haystack, &annotated_init, &typed_init],
                    &cfg,
                ) {
                Ok(mut fused_out) => fused_out.pop().ok_or_else(|| {
                    "fused VAST typedef/classify: missing typed VAST output".to_string()
                }).inspect(|_| log("dispatch fused typedef/classify"))?,
                Err(error) => {
                    if std::env::var_os("VYRE_STAGE_TRACE").is_some() {
                        eprintln!(
                            "[stage-trace] fused VAST typedef/classify rejected by backend; running unfused stages: {error}"
                        );
                    }
                    run_typedef_classify_unfused(&mut cfg)?
                }
            }
        }
            Err(_) => run_typedef_classify_unfused(&mut cfg)?,
        }
    } else {
        run_typedef_classify_unfused(&mut cfg)?
    };

    // Divergence-gate hook: when `VYRE_DUMP_TYPED_VAST` is set, write the
    // post-classify typed VAST as JSON before downstream stages run.
    // Format: `{ "stride": 10, "count": <N>, "nodes": [[k, parent, fc, ns, …], …] }`.
    // The script that compares vyre vs. clang reads this directly.
    if let Ok(dump_dir) = std::env::var("VYRE_DUMP_TYPED_VAST") {
        dump_typed_vast_as_json(&dump_dir, path, &typed_vast_blob, vast_count).map_err(|e| {
            format!(
                "typed VAST dump failed for `{}`: {e}. Fix: set VYRE_DUMP_TYPED_VAST to a writable directory or unset it.",
                path.display()
            )
        })?;
    }

    if vast_count <= 4096 && std::env::var_os("VYRE_FRONTEND_C_FORCE_GPU_VAST_LOWERING").is_none() {
        let expr_shape_blob =
            reference_c11_build_expression_shape_nodes(&raw_vast_blob, &typed_vast_blob);
        log("host c11_build_expression_shape_nodes");
        let pg_blob = reference_ast_to_pg_nodes(&typed_vast_blob);
        log("host c_lower_ast_to_pg_nodes");
        let semantic_pg = reference_ast_to_pg_semantic_graph(&typed_vast_blob);
        log("host c_lower_ast_to_pg_semantic_graph");
        return Ok((
            typed_vast_blob,
            expr_shape_blob,
            pg_blob,
            semantic_pg.nodes,
            semantic_pg.edges,
        ));
    }

    let expr_prog = c11_build_expression_shape_nodes(
        "raw_vast_nodes",
        "typed_vast_nodes",
        Expr::u32(vast_count.max(1)),
        "expr_shape_nodes",
    );
    super::validate_internal_stage(&expr_prog, "c11_build_expression_shape_nodes")?;
    let pg_prog = c_lower_ast_to_pg_nodes(
        "typed_vast_nodes",
        Expr::u32(vast_count.max(1)),
        "pg_nodes",
    );
    super::validate_internal_stage(&pg_prog, "c_lower_ast_to_pg_nodes")?;
    let pg_init = vec![0u8; vast_count.max(1) as usize * 6 * 4];

    let semantic_pg_prog = c_lower_ast_to_pg_semantic_graph(
        "typed_vast_nodes",
        Expr::u32(vast_count.max(1)),
        "semantic_pg_nodes",
        "semantic_pg_edges",
    );
    super::validate_internal_stage(&semantic_pg_prog, "c_lower_ast_to_pg_semantic_graph")?;
    let semantic_node_init =
        vec![0u8; vast_count.max(1) as usize * C_AST_PG_SEMANTIC_NODE_STRIDE_U32 as usize * 4];
    let semantic_edge_init = vec![
        0u8;
        vast_count.max(1) as usize
            * C_AST_PG_EDGE_ROWS_PER_NODE as usize
            * C_AST_PG_EDGE_STRIDE_U32 as usize
            * 4
    ];
    let expr_shape_init = vec![0u8; vast_count.max(1) as usize * 8 * 4];
    let (expr_shape_blob, pg_blob, semantic_pg_nodes, semantic_pg_edges) =
        if std::env::var_os("VYRE_FRONTEND_C_ENABLE_RUNTIME_FUSION").is_some() {
            match vyre_foundation::execution_plan::fusion::fuse_programs(&[
            expr_prog.clone(),
            pg_prog.clone(),
            semantic_pg_prog.clone(),
            ]) {
                Ok(fused) => {
                cfg.label = Some(format!(
                    "vyre-frontend-c expr+pg+semantic-pg {}",
                    path.display()
                ));
                let fused_out = super::dispatch_borrowed_cached(
                    backend,
                        &fused,
                        &[
                            &raw_vast_blob,
                            &typed_vast_blob,
                            &expr_shape_init,
                            &pg_init,
                            &semantic_node_init,
                            &semantic_edge_init,
                        ],
                        &cfg,
                    )
                    .map_err(|e| format!("fused VAST lowerer dispatch failed: {e}"))?;
                log("dispatch fused expr+pg+semantic");
                if fused_out.len() < 4 {
                    return Err(
                        "fused VAST lowerer: expected expression, PG, semantic-node, and semantic-edge outputs"
                            .to_string(),
                    );
                }
                let mut fused_out = fused_out.into_iter();
                let expr_shape_blob = fused_out.next().ok_or_else(|| {
                    "fused VAST lowerer: missing expression-shape output".to_string()
                })?;
                let pg_blob = fused_out
                    .next()
                    .ok_or_else(|| "fused VAST lowerer: missing PG output".to_string())?;
                let semantic_pg_nodes = fused_out.next().ok_or_else(|| {
                    "fused VAST lowerer: missing semantic-node output".to_string()
                })?;
                let semantic_pg_edges = fused_out.next().ok_or_else(|| {
                    "fused VAST lowerer: missing semantic-edge output".to_string()
                })?;
                (
                    expr_shape_blob,
                    pg_blob,
                    semantic_pg_nodes,
                    semantic_pg_edges,
                )
            }
                Err(_) => {
                cfg.label = Some(format!("vyre-frontend-c expr-shape {}", path.display()));
                let expr_out = super::dispatch_borrowed_cached(
                    backend,
                        &expr_prog,
                        &[&raw_vast_blob, &typed_vast_blob, &expr_shape_init],
                        &cfg,
                    )
                    .map_err(|e| {
                        format!("c11_build_expression_shape_nodes dispatch failed: {e}")
                    })?;
                log("dispatch c11_build_expression_shape_nodes");
                let expr_shape_blob = expr_out.into_iter().next().ok_or_else(|| {
                    "c11_build_expression_shape_nodes: missing expression-shape output"
                        .to_string()
                })?;
                cfg.label = Some(format!("vyre-frontend-c pg {}", path.display()));
                let pg_out = super::dispatch_borrowed_cached(
                    backend,
                    &pg_prog,
                    &[&typed_vast_blob, &pg_init],
                    &cfg,
                )
                    .map_err(|e| format!("c_lower_ast_to_pg_nodes dispatch failed: {e}"))?;
                log("dispatch c_lower_ast_to_pg_nodes");
                let pg_blob = pg_out.into_iter().next().ok_or_else(|| {
                    "c_lower_ast_to_pg_nodes: missing ProgramGraph node output".to_string()
                })?;
                cfg.label = Some(format!("vyre-frontend-c semantic-pg {}", path.display()));
                let semantic_pg_out = super::dispatch_borrowed_cached(
                    backend,
                        &semantic_pg_prog,
                        &[&typed_vast_blob, &semantic_node_init, &semantic_edge_init],
                        &cfg,
                    )
                    .map_err(|e| {
                        format!("c_lower_ast_to_pg_semantic_graph dispatch failed: {e}")
                    })?;
                log("dispatch c_lower_ast_to_pg_semantic_graph");
                if semantic_pg_out.len() < 2 {
                    return Err(
                        "c_lower_ast_to_pg_semantic_graph: missing semantic node/edge outputs"
                            .to_string(),
                    );
                }
                let mut semantic_pg_out = semantic_pg_out.into_iter();
                let semantic_pg_nodes = semantic_pg_out.next().ok_or_else(|| {
                    "c_lower_ast_to_pg_semantic_graph: missing semantic node output".to_string()
                })?;
                let semantic_pg_edges = semantic_pg_out.next().ok_or_else(|| {
                    "c_lower_ast_to_pg_semantic_graph: missing semantic edge output".to_string()
                })?;
                (expr_shape_blob, pg_blob, semantic_pg_nodes, semantic_pg_edges)
            }
            }
        } else {
            cfg.label = Some(format!("vyre-frontend-c expr-shape {}", path.display()));
            let expr_out = super::dispatch_borrowed_cached(
                backend,
                &expr_prog,
                &[&raw_vast_blob, &typed_vast_blob, &expr_shape_init],
                &cfg,
            )
            .map_err(|e| {
                format!("c11_build_expression_shape_nodes dispatch failed: {e}")
            })?;
            log("dispatch c11_build_expression_shape_nodes");
            let expr_shape_blob = expr_out.into_iter().next().ok_or_else(|| {
                "c11_build_expression_shape_nodes: missing expression-shape output".to_string()
            })?;
            cfg.label = Some(format!("vyre-frontend-c pg {}", path.display()));
            let pg_out = super::dispatch_borrowed_cached(
                backend,
                &pg_prog,
                &[&typed_vast_blob, &pg_init],
                &cfg,
            )
            .map_err(|e| format!("c_lower_ast_to_pg_nodes dispatch failed: {e}"))?;
            log("dispatch c_lower_ast_to_pg_nodes");
            let pg_blob = pg_out.into_iter().next().ok_or_else(|| {
                "c_lower_ast_to_pg_nodes: missing ProgramGraph node output".to_string()
            })?;
            cfg.label = Some(format!("vyre-frontend-c semantic-pg {}", path.display()));
            let semantic_pg_out = super::dispatch_borrowed_cached(
                backend,
                &semantic_pg_prog,
                &[&typed_vast_blob, &semantic_node_init, &semantic_edge_init],
                &cfg,
            )
            .map_err(|e| format!("c_lower_ast_to_pg_semantic_graph dispatch failed: {e}"))?;
            log("dispatch c_lower_ast_to_pg_semantic_graph");
            if semantic_pg_out.len() < 2 {
                return Err(
                    "c_lower_ast_to_pg_semantic_graph: missing semantic node/edge outputs"
                        .to_string(),
                );
            }
            let mut semantic_pg_out = semantic_pg_out.into_iter();
            let semantic_pg_nodes = semantic_pg_out.next().ok_or_else(|| {
                "c_lower_ast_to_pg_semantic_graph: missing semantic node output".to_string()
            })?;
            let semantic_pg_edges = semantic_pg_out.next().ok_or_else(|| {
                "c_lower_ast_to_pg_semantic_graph: missing semantic edge output".to_string()
            })?;
            (expr_shape_blob, pg_blob, semantic_pg_nodes, semantic_pg_edges)
        };

    Ok((
        typed_vast_blob,
        expr_shape_blob,
        pg_blob,
        semantic_pg_nodes,
        semantic_pg_edges,
    ))
}

/// Write the typed VAST blob as a JSON file under `dump_dir`. Filename is
/// the source's basename with `.vast.json` suffix; collisions are accepted
/// (the divergence sweep runs one file at a time per worktree).
fn dump_typed_vast_as_json(
    dump_dir: &str,
    source_path: &Path,
    typed_vast_blob: &[u8],
    vast_count: u32,
) -> std::io::Result<()> {
    use std::fs;
    use std::io::Write as _;

    fs::create_dir_all(dump_dir)?;
    let stem = source_path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "unknown".to_string());
    let out_path = std::path::PathBuf::from(dump_dir).join(format!("{stem}.vast.json"));

    let stride: usize = 10;
    let count = vast_count as usize;
    let mut file = fs::File::create(&out_path)?;
    write!(
        file,
        "{{\"stride\":{stride},\"count\":{count},\"source\":\"{}\",\"nodes\":[",
        source_path.display()
    )?;
    for i in 0..count {
        if i > 0 {
            write!(file, ",")?;
        }
        let base = i * stride * 4;
        write!(file, "[")?;
        for f in 0..stride {
            if f > 0 {
                write!(file, ",")?;
            }
            let off = base + f * 4;
            let word = if off + 4 <= typed_vast_blob.len() {
                u32::from_le_bytes([
                    typed_vast_blob[off],
                    typed_vast_blob[off + 1],
                    typed_vast_blob[off + 2],
                    typed_vast_blob[off + 3],
                ])
            } else {
                0
            };
            write!(file, "{word}")?;
        }
        write!(file, "]")?;
    }
    write!(file, "]}}")?;
    Ok(())
}
