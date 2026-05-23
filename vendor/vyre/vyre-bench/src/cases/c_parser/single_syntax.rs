use super::corpus::{CParserPrepared, LINUX_DRIVER_TU};
use super::support::{
    encode_parse_summary, require_encoded_syntax_surface, time_tree_sitter_c_baseline,
    time_tree_sitter_cold_baseline, tree_sitter_cold_speedup_metric, tree_sitter_speedup_metric,
};
use crate::api::case::{
    BenchCase, BenchContext, BenchError, BenchId, BenchLayer, BenchMetadata, BenchRequirements,
    BenchRun, Correctness, DeterminismClass, PerformanceContract, PreparedCase, WorkloadClass,
};
use crate::api::metric::{BenchMetrics, MetricPoint};
use vyre_frontend_c::api::parse_syntax_source;

pub(super) struct CParserSyntaxOnlyLinuxDriverPipeline;

impl BenchCase for CParserSyntaxOnlyLinuxDriverPipeline {
    fn id(&self) -> BenchId {
        BenchId("frontend.c.syntax_only.linux_driver_pipeline".to_string())
    }

    fn metadata(&self) -> BenchMetadata {
        BenchMetadata {
            id: self.id(),
            name: "Vyre-C Linux Driver Syntax Only".to_string(),
            description:
                "Vyre frontend C syntax-only GPU parser over a Linux-driver-shaped translation unit"
                    .to_string(),
            tags: vec![
                "frontend-c".to_string(),
                "parser".to_string(),
                "syntax".to_string(),
                "c_ast".to_string(),
                "token".to_string(),
                "linux".to_string(),
                "release".to_string(),
            ],
            layer: BenchLayer::Libs,
            workload: WorkloadClass::Macro,
            determinism: DeterminismClass::Deterministic,
            owner_crate: "vyre-frontend-c".to_string(),
        }
    }

    fn suites(&self) -> &'static [crate::api::suite::SuiteKind] {
        &[
            crate::api::suite::SuiteKind::Release,
            crate::api::suite::SuiteKind::Gpu,
            crate::api::suite::SuiteKind::Deep,
            crate::api::suite::SuiteKind::Honest,
        ]
    }

    fn requirements(&self) -> BenchRequirements {
        BenchRequirements {
            needs_gpu: true,
            needs_network: false,
            min_vram_bytes: None,
            min_input_bytes: Some(LINUX_DRIVER_TU.len() as u64),
            feature_set: vec![
                "vyre-frontend-c".to_string(),
                "c-parser".to_string(),
                "linux-tu".to_string(),
                "syntax-only".to_string(),
            ],
        }
    }

    fn performance_contract(&self) -> Option<PerformanceContract> {
        Some(PerformanceContract::cpu_sota_min_speedup(
            "C parser Linux translation-unit syntax-only",
            "vyre-frontend-c",
            "Tree-sitter C in-process parse + full AST traversal",
            10.0,
        ))
    }

    fn prepare(&self, _ctx: &mut BenchContext) -> Result<PreparedCase, BenchError> {
        Ok(Box::new(CParserPrepared {
            source: LINUX_DRIVER_TU.to_string(),
        }))
    }

    fn program<'a>(&self, _prepared: &'a PreparedCase) -> Option<&'a vyre_foundation::ir::Program> {
        None
    }

    fn run(
        &self,
        _ctx: &mut BenchContext,
        prepared: &mut PreparedCase,
    ) -> Result<BenchRun, BenchError> {
        let prepared = prepared.downcast_ref::<CParserPrepared>().ok_or_else(|| {
            BenchError::ExecutionFailed("C syntax-only prepared payload type mismatch".to_string())
        })?;
        let backend_acquire_ns = 0u64;
        let start = std::time::Instant::now();
        let summary = parse_syntax_source(&prepared.source).map_err(BenchError::BackendFailed)?;
        let wall_ns = start.elapsed().as_nanos() as u64;

        let tree_sitter_timed = time_tree_sitter_c_baseline(&prepared.source)?;
        let tree_sitter = tree_sitter_timed.baseline;
        let baseline_ns = tree_sitter_timed.wall_ns;
        let tree_sitter_cold = time_tree_sitter_cold_baseline(&prepared.source)?;
        let vyre_cold_ns = backend_acquire_ns.saturating_add(wall_ns);
        let output = encode_parse_summary(summary);

        Ok(BenchRun {
            metrics: BenchMetrics {
                wall_ns: Some(wall_ns),
                input_bytes: Some(prepared.source.len() as u64),
                output_bytes: Some(output.len() as u64),
                bytes_touched: Some(
                    (prepared.source.len() as u64).saturating_add(output.len() as u64),
                ),
                custom: vec![
                    MetricPoint {
                        name: "c_parser_source_bytes".to_string(),
                        value: summary.source_bytes,
                    },
                    MetricPoint {
                        name: "vyre_backend_acquire_ns".to_string(),
                        value: backend_acquire_ns,
                    },
                    MetricPoint {
                        name: "vyre_cold_wall_ns".to_string(),
                        value: vyre_cold_ns,
                    },
                    MetricPoint {
                        name: "tree_sitter_cold_wall_ns".to_string(),
                        value: tree_sitter_cold.wall_ns,
                    },
                    MetricPoint {
                        name: "c_parser_tokens".to_string(),
                        value: summary.token_count as u64,
                    },
                    MetricPoint {
                        name: "c_parser_ast_bytes".to_string(),
                        value: summary.ast_bytes,
                    },
                    MetricPoint {
                        name: "c_parser_vast_bytes".to_string(),
                        value: summary.vast_bytes,
                    },
                    MetricPoint {
                        name: "c_parser_abi_layout_bytes".to_string(),
                        value: summary.abi_layout_bytes,
                    },
                    MetricPoint {
                        name: "c_parser_expression_shape_bytes".to_string(),
                        value: summary.expression_shape_bytes,
                    },
                    MetricPoint {
                        name: "c_parser_program_graph_bytes".to_string(),
                        value: summary.program_graph_bytes,
                    },
                    MetricPoint {
                        name: "c_parser_semantic_node_bytes".to_string(),
                        value: summary.semantic_node_bytes,
                    },
                    MetricPoint {
                        name: "c_parser_semantic_edge_bytes".to_string(),
                        value: summary.semantic_edge_bytes,
                    },
                    MetricPoint {
                        name: "c_parser_sema_scope_bytes".to_string(),
                        value: summary.sema_scope_bytes,
                    },
                    MetricPoint {
                        name: "c_parser_function_record_bytes".to_string(),
                        value: summary.function_record_bytes,
                    },
                    MetricPoint {
                        name: "c_parser_call_record_bytes".to_string(),
                        value: summary.call_record_bytes,
                    },
                    MetricPoint {
                        name: "c_parser_function_records".to_string(),
                        value: summary.function_record_bytes / 12,
                    },
                    MetricPoint {
                        name: "c_parser_call_records".to_string(),
                        value: summary.call_record_bytes / 16,
                    },
                    MetricPoint {
                        name: "tree_sitter_c_ast_nodes".to_string(),
                        value: tree_sitter.nodes,
                    },
                    MetricPoint {
                        name: "tree_sitter_c_has_error".to_string(),
                        value: u64::from(tree_sitter.has_error),
                    },
                    tree_sitter_speedup_metric(baseline_ns, wall_ns),
                    tree_sitter_cold_speedup_metric(tree_sitter_cold.wall_ns, vyre_cold_ns),
                ],
                ..Default::default()
            },
            baseline_metrics: Some(BenchMetrics {
                wall_ns: Some(baseline_ns),
                input_bytes: Some(prepared.source.len() as u64),
                output_bytes: Some(tree_sitter.nodes),
                bytes_touched: Some(prepared.source.len() as u64),
                ..Default::default()
            }),
            outputs: vec![output],
            baseline_outputs: None,
        })
    }

    fn verify(&self, _ctx: &mut BenchContext, run: &BenchRun) -> Result<Correctness, BenchError> {
        let output = run.outputs.first().ok_or_else(|| {
            BenchError::CorrectnessViolation(
                "C syntax-only benchmark produced no summary bytes".to_string(),
            )
        })?;
        require_encoded_syntax_surface(output, "C syntax-only")?;
        Ok(Correctness::Certificate {
            digest: *blake3::hash(output).as_bytes(),
        })
    }

    fn bytes_touched(&self, _prepared: &PreparedCase) -> (u64, u64) {
        (LINUX_DRIVER_TU.len() as u64, 0)
    }
}

inventory::submit! {
    &CParserSyntaxOnlyLinuxDriverPipeline as &'static dyn BenchCase
}
