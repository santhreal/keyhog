use std::path::PathBuf;

use crate::api::case::{
    BenchCase, BenchContext, BenchError, BenchId, BenchLayer, BenchMetadata, BenchRequirements,
    BenchRun, Correctness, DeterminismClass, PerformanceContract, PreparedCase, WorkloadClass,
};
use crate::api::metric::{BenchMetrics, MetricPoint};
use vyre_frontend_c::api::{
    compile, parse_source, parse_syntax_source, CParseSummary, VyreCompileOptions,
};

pub struct CParserLinuxDriverPipeline;
pub struct CParserOnlyLinuxDriverPipeline;
pub struct CParserSyntaxOnlyLinuxDriverPipeline;
pub struct CParserSyntaxCorpusPipeline;
pub struct CParserSyntaxCorpus100Pipeline;

const LINUX_DRIVER_TU: &str = r#"
typedef unsigned long ulong_t;

struct file_operations {
    int (*read)(void *f, void *buf, ulong_t len);
    void (*release)(void *f);
};

struct file {
    struct file_operations *f_op;
    int f_flags;
};

static int demo_read(void *f, void *buf, ulong_t len)
{
    (void)f;
    (void)buf;
    (void)len;
    return 0;
}

static void demo_release(void *f)
{
    (void)f;
}

static struct file_operations demo_fops __attribute__((unused)) = {
    .read = demo_read,
    .release = demo_release,
};

static int linux_fop_open(struct file *filp)
{
    struct file local = (struct file){
        .f_op = &demo_fops,
        .f_flags = 0,
    };
    int bump = ({
        int t = local.f_flags;
        t + 3;
    });
    if (filp && filp->f_op && filp->f_op->read)
        bump += filp->f_op->read(filp, 0, 0);
    return bump;
}
"#;

struct CParserPrepared {
    source: String,
}

fn linux_driver_corpus(workloads: usize) -> String {
    let mut source = String::with_capacity(LINUX_DRIVER_TU.len().saturating_mul(workloads));
    source.push_str("typedef unsigned long ulong_t;\n");
    source.push_str("struct file_operations { int (*read)(void *f, void *buf, ulong_t len); void (*release)(void *f); };\n");
    source.push_str("struct file { struct file_operations *f_op; int f_flags; };\n");
    for idx in 0..workloads {
        source.push_str(&format!(
            r#"
static int demo_read_{idx}(void *f, void *buf, ulong_t len)
{{
    (void)f;
    (void)buf;
    (void)len;
    return {idx};
}}

static void demo_release_{idx}(void *f)
{{
    (void)f;
}}

static struct file_operations demo_fops_{idx} = {{
    .read = demo_read_{idx},
    .release = demo_release_{idx},
}};

static int linux_fop_open_{idx}(struct file *filp)
{{
    struct file local = (struct file){{
        .f_op = &demo_fops_{idx},
        .f_flags = {idx},
    }};
    int bump = local.f_flags + {idx};
    if (filp && filp->f_op && filp->f_op->read)
        bump += filp->f_op->read(filp, 0, 0);
    return bump;
}}
"#
        ));
    }
    source
}

impl BenchCase for CParserLinuxDriverPipeline {
    fn id(&self) -> BenchId {
        BenchId("frontend.c.parser.linux_driver_pipeline".to_string())
    }

    fn metadata(&self) -> BenchMetadata {
        BenchMetadata {
            id: self.id(),
            name: "Vyre-C Linux Driver Parser Pipeline".to_string(),
            description:
                "Vyre frontend C parser/preprocessor pipeline over a Linux-driver-shaped translation unit"
                    .to_string(),
            tags: vec![
                "frontend-c".to_string(),
                "parser".to_string(),
                "c_ast".to_string(),
                "preprocessor".to_string(),
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
            ],
        }
    }

    fn performance_contract(&self) -> Option<PerformanceContract> {
        Some(PerformanceContract::cpu_sota_min_speedup(
            "C parser Linux translation-unit parse/traverse",
            "vyre-frontend-c",
            "Tree-sitter C in-process parse + full AST traversal",
            1000.0,
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
            BenchError::ExecutionFailed("C parser prepared payload type mismatch".to_string())
        })?;
        let paths = TempCompilePaths::new("vyre-bench-c-parser-linux-driver");
        std::fs::write(&paths.source, prepared.source.as_bytes())
            .map_err(|error| BenchError::ExecutionFailed(format!("write C parser source: {error}")))?;

        let start = std::time::Instant::now();
        compile(VyreCompileOptions {
            is_compile_only: true,
            input_files: vec![paths.source.clone()],
            output_file: Some(paths.object.clone()),
            include_dirs: Vec::new(),
            forced_include_files: Vec::new(),
            macros: Vec::new(),
            undefs: Vec::new(),
        })
        .map_err(BenchError::BackendFailed)?;
        let wall_ns = start.elapsed().as_nanos() as u64;

        let baseline_start = std::time::Instant::now();
        let tree_sitter = run_tree_sitter_c_baseline(&prepared.source)?;
        let baseline_ns = baseline_start.elapsed().as_nanos() as u64;

        let object_bytes = std::fs::read(&paths.object)
            .map_err(|error| BenchError::ExecutionFailed(format!("read C parser object: {error}")))?;
        paths.cleanup();

        Ok(BenchRun {
            metrics: BenchMetrics {
                wall_ns: Some(wall_ns),
                input_bytes: Some(prepared.source.len() as u64),
                output_bytes: Some(object_bytes.len() as u64),
                bytes_touched: Some(
                    (prepared.source.len() as u64).saturating_add(object_bytes.len() as u64),
                ),
                custom: vec![
                    MetricPoint {
                        name: "c_parser_source_bytes".to_string(),
                        value: prepared.source.len() as u64,
                    },
                    MetricPoint {
                        name: "c_parser_object_bytes".to_string(),
                        value: object_bytes.len() as u64,
                    },
                    MetricPoint {
                        name: "tree_sitter_c_ast_nodes".to_string(),
                        value: tree_sitter.nodes,
                    },
                    MetricPoint {
                        name: "tree_sitter_c_has_error".to_string(),
                        value: u64::from(tree_sitter.has_error),
                    },
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
            outputs: vec![object_bytes],
            baseline_outputs: None,
        })
    }

    fn verify(&self, _ctx: &mut BenchContext, run: &BenchRun) -> Result<Correctness, BenchError> {
        let object = run.outputs.first().ok_or_else(|| {
            BenchError::CorrectnessViolation("C parser benchmark produced no object bytes".to_string())
        })?;
        if object.len() < 4 || &object[0..4] != b"\x7FELF" {
            return Err(BenchError::CorrectnessViolation(
                "C parser benchmark output is not an ELF object".to_string(),
            ));
        }
        Ok(Correctness::Certificate {
            digest: *blake3::hash(object).as_bytes(),
        })
    }

    fn bytes_touched(&self, _prepared: &PreparedCase) -> (u64, u64) {
        (LINUX_DRIVER_TU.len() as u64, 0)
    }
}

impl BenchCase for CParserOnlyLinuxDriverPipeline {
    fn id(&self) -> BenchId {
        BenchId("frontend.c.parser_only.linux_driver_pipeline".to_string())
    }

    fn metadata(&self) -> BenchMetadata {
        BenchMetadata {
            id: self.id(),
            name: "Vyre-C Linux Driver Parser Only".to_string(),
            description:
                "Vyre frontend C parser-only GPU pipeline over a Linux-driver-shaped translation unit"
                    .to_string(),
            tags: vec![
                "frontend-c".to_string(),
                "parser".to_string(),
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
                "parser-only".to_string(),
            ],
        }
    }

    fn performance_contract(&self) -> Option<PerformanceContract> {
        Some(PerformanceContract::cpu_sota_min_speedup(
            "C parser Linux translation-unit parser-only",
            "vyre-frontend-c",
            "Tree-sitter C in-process parse + full AST traversal",
            1.0,
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
            BenchError::ExecutionFailed("C parser prepared payload type mismatch".to_string())
        })?;

        let start = std::time::Instant::now();
        let summary = parse_source(&prepared.source).map_err(BenchError::BackendFailed)?;
        let wall_ns = start.elapsed().as_nanos() as u64;

        let baseline_start = std::time::Instant::now();
        let tree_sitter = run_tree_sitter_c_baseline(&prepared.source)?;
        let baseline_ns = baseline_start.elapsed().as_nanos() as u64;
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
                        name: "c_parser_tokens".to_string(),
                        value: summary.token_count as u64,
                    },
                    MetricPoint {
                        name: "c_parser_ast_bytes".to_string(),
                        value: summary.ast_bytes,
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
                        name: "tree_sitter_c_ast_nodes".to_string(),
                        value: tree_sitter.nodes,
                    },
                    MetricPoint {
                        name: "tree_sitter_c_has_error".to_string(),
                        value: u64::from(tree_sitter.has_error),
                    },
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
                "C parser-only benchmark produced no summary bytes".to_string(),
            )
        })?;
        if output.len() != 40 {
            return Err(BenchError::CorrectnessViolation(format!(
                "C parser-only summary has {} bytes, expected 40",
                output.len()
            )));
        }
        let token_count = u64::from_le_bytes(output[8..16].try_into().map_err(|_| {
            BenchError::CorrectnessViolation("invalid parser-only token field".to_string())
        })?);
        let ast_bytes = u64::from_le_bytes(output[16..24].try_into().map_err(|_| {
            BenchError::CorrectnessViolation("invalid parser-only AST field".to_string())
        })?);
        if token_count == 0 || ast_bytes == 0 {
            return Err(BenchError::CorrectnessViolation(
                "C parser-only summary must report nonzero token and AST evidence".to_string(),
            ));
        }
        Ok(Correctness::Certificate {
            digest: *blake3::hash(output).as_bytes(),
        })
    }

    fn bytes_touched(&self, _prepared: &PreparedCase) -> (u64, u64) {
        (LINUX_DRIVER_TU.len() as u64, 0)
    }
}

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
            1.0,
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

        let start = std::time::Instant::now();
        let summary = parse_syntax_source(&prepared.source).map_err(BenchError::BackendFailed)?;
        let wall_ns = start.elapsed().as_nanos() as u64;

        let baseline_start = std::time::Instant::now();
        let tree_sitter = run_tree_sitter_c_baseline(&prepared.source)?;
        let baseline_ns = baseline_start.elapsed().as_nanos() as u64;
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
                        name: "c_parser_tokens".to_string(),
                        value: summary.token_count as u64,
                    },
                    MetricPoint {
                        name: "c_parser_ast_bytes".to_string(),
                        value: summary.ast_bytes,
                    },
                    MetricPoint {
                        name: "tree_sitter_c_ast_nodes".to_string(),
                        value: tree_sitter.nodes,
                    },
                    MetricPoint {
                        name: "tree_sitter_c_has_error".to_string(),
                        value: u64::from(tree_sitter.has_error),
                    },
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
        if output.len() != 40 {
            return Err(BenchError::CorrectnessViolation(format!(
                "C syntax-only summary has {} bytes, expected 40",
                output.len()
            )));
        }
        let token_count = u64::from_le_bytes(output[8..16].try_into().map_err(|_| {
            BenchError::CorrectnessViolation("invalid syntax-only token field".to_string())
        })?);
        let ast_bytes = u64::from_le_bytes(output[16..24].try_into().map_err(|_| {
            BenchError::CorrectnessViolation("invalid syntax-only AST field".to_string())
        })?);
        if token_count == 0 || ast_bytes == 0 {
            return Err(BenchError::CorrectnessViolation(
                "C syntax-only summary must report nonzero token and AST evidence".to_string(),
            ));
        }
        Ok(Correctness::Certificate {
            digest: *blake3::hash(output).as_bytes(),
        })
    }

    fn bytes_touched(&self, _prepared: &PreparedCase) -> (u64, u64) {
        (LINUX_DRIVER_TU.len() as u64, 0)
    }
}

impl BenchCase for CParserSyntaxCorpusPipeline {
    fn id(&self) -> BenchId {
        BenchId("frontend.c.syntax_only.linux_driver_corpus10".to_string())
    }

    fn metadata(&self) -> BenchMetadata {
        BenchMetadata {
            id: self.id(),
            name: "Vyre-C Linux Driver Syntax Corpus 10".to_string(),
            description:
                "Vyre frontend C syntax-only GPU parser over ten Linux-driver-shaped workloads"
                    .to_string(),
            tags: vec![
                "frontend-c".to_string(),
                "parser".to_string(),
                "syntax".to_string(),
                "c_ast".to_string(),
                "token".to_string(),
                "linux".to_string(),
                "corpus10".to_string(),
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
            min_input_bytes: Some(linux_driver_corpus(10).len() as u64),
            feature_set: vec![
                "vyre-frontend-c".to_string(),
                "c-parser".to_string(),
                "linux-tu".to_string(),
                "syntax-only".to_string(),
                "corpus10".to_string(),
            ],
        }
    }

    fn performance_contract(&self) -> Option<PerformanceContract> {
        Some(PerformanceContract::cpu_sota_min_speedup(
            "C parser Linux corpus10 syntax-only",
            "vyre-frontend-c",
            "Tree-sitter C in-process parse + full AST traversal",
            1.0,
        ))
    }

    fn prepare(&self, _ctx: &mut BenchContext) -> Result<PreparedCase, BenchError> {
        Ok(Box::new(CParserPrepared {
            source: linux_driver_corpus(10),
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
            BenchError::ExecutionFailed("C syntax corpus prepared payload type mismatch".to_string())
        })?;

        let start = std::time::Instant::now();
        let summary = parse_syntax_source(&prepared.source).map_err(BenchError::BackendFailed)?;
        let wall_ns = start.elapsed().as_nanos() as u64;

        let baseline_start = std::time::Instant::now();
        let tree_sitter = run_tree_sitter_c_baseline(&prepared.source)?;
        let baseline_ns = baseline_start.elapsed().as_nanos() as u64;
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
                        name: "c_parser_tokens".to_string(),
                        value: summary.token_count as u64,
                    },
                    MetricPoint {
                        name: "c_parser_ast_bytes".to_string(),
                        value: summary.ast_bytes,
                    },
                    MetricPoint {
                        name: "tree_sitter_c_ast_nodes".to_string(),
                        value: tree_sitter.nodes,
                    },
                    MetricPoint {
                        name: "tree_sitter_c_has_error".to_string(),
                        value: u64::from(tree_sitter.has_error),
                    },
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
                "C syntax corpus benchmark produced no summary bytes".to_string(),
            )
        })?;
        if output.len() != 40 {
            return Err(BenchError::CorrectnessViolation(format!(
                "C syntax corpus summary has {} bytes, expected 40",
                output.len()
            )));
        }
        let token_count = u64::from_le_bytes(output[8..16].try_into().map_err(|_| {
            BenchError::CorrectnessViolation("invalid syntax corpus token field".to_string())
        })?);
        let ast_bytes = u64::from_le_bytes(output[16..24].try_into().map_err(|_| {
            BenchError::CorrectnessViolation("invalid syntax corpus AST field".to_string())
        })?);
        if token_count == 0 || ast_bytes == 0 {
            return Err(BenchError::CorrectnessViolation(
                "C syntax corpus summary must report nonzero token and AST evidence".to_string(),
            ));
        }
        Ok(Correctness::Certificate {
            digest: *blake3::hash(output).as_bytes(),
        })
    }

    fn bytes_touched(&self, prepared: &PreparedCase) -> (u64, u64) {
        let bytes = prepared
            .downcast_ref::<CParserPrepared>()
            .map(|prepared| prepared.source.len() as u64)
            .unwrap_or(0);
        (bytes, 0)
    }
}

impl BenchCase for CParserSyntaxCorpus100Pipeline {
    fn id(&self) -> BenchId {
        BenchId("frontend.c.syntax_only.linux_driver_corpus100".to_string())
    }

    fn metadata(&self) -> BenchMetadata {
        BenchMetadata {
            id: self.id(),
            name: "Vyre-C Linux Driver Syntax Corpus 100".to_string(),
            description:
                "Vyre frontend C syntax-only GPU parser over one hundred Linux-driver-shaped workloads"
                    .to_string(),
            tags: vec![
                "frontend-c".to_string(),
                "parser".to_string(),
                "syntax".to_string(),
                "c_ast".to_string(),
                "token".to_string(),
                "linux".to_string(),
                "corpus100".to_string(),
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
            min_input_bytes: Some(linux_driver_corpus(100).len() as u64),
            feature_set: vec![
                "vyre-frontend-c".to_string(),
                "c-parser".to_string(),
                "linux-tu".to_string(),
                "syntax-only".to_string(),
                "corpus100".to_string(),
            ],
        }
    }

    fn performance_contract(&self) -> Option<PerformanceContract> {
        Some(PerformanceContract::cpu_sota_min_speedup(
            "C parser Linux corpus100 syntax-only",
            "vyre-frontend-c",
            "Tree-sitter C in-process parse + full AST traversal",
            1.0,
        ))
    }

    fn prepare(&self, _ctx: &mut BenchContext) -> Result<PreparedCase, BenchError> {
        Ok(Box::new(CParserPrepared {
            source: linux_driver_corpus(100),
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
            BenchError::ExecutionFailed("C syntax corpus100 prepared payload type mismatch".to_string())
        })?;
        let start = std::time::Instant::now();
        let summary = parse_syntax_source(&prepared.source).map_err(BenchError::BackendFailed)?;
        let wall_ns = start.elapsed().as_nanos() as u64;
        let baseline_start = std::time::Instant::now();
        let tree_sitter = run_tree_sitter_c_baseline(&prepared.source)?;
        let baseline_ns = baseline_start.elapsed().as_nanos() as u64;
        let output = encode_parse_summary(summary);
        Ok(BenchRun {
            metrics: BenchMetrics {
                wall_ns: Some(wall_ns),
                input_bytes: Some(prepared.source.len() as u64),
                output_bytes: Some(output.len() as u64),
                bytes_touched: Some((prepared.source.len() as u64).saturating_add(output.len() as u64)),
                custom: vec![
                    MetricPoint { name: "c_parser_source_bytes".to_string(), value: summary.source_bytes },
                    MetricPoint { name: "c_parser_tokens".to_string(), value: summary.token_count as u64 },
                    MetricPoint { name: "c_parser_ast_bytes".to_string(), value: summary.ast_bytes },
                    MetricPoint { name: "tree_sitter_c_ast_nodes".to_string(), value: tree_sitter.nodes },
                    MetricPoint { name: "tree_sitter_c_has_error".to_string(), value: u64::from(tree_sitter.has_error) },
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
                "C syntax corpus100 benchmark produced no summary bytes".to_string(),
            )
        })?;
        if output.len() != 40 {
            return Err(BenchError::CorrectnessViolation(format!(
                "C syntax corpus100 summary has {} bytes, expected 40",
                output.len()
            )));
        }
        let token_count = u64::from_le_bytes(output[8..16].try_into().map_err(|_| {
            BenchError::CorrectnessViolation("invalid syntax corpus100 token field".to_string())
        })?);
        let ast_bytes = u64::from_le_bytes(output[16..24].try_into().map_err(|_| {
            BenchError::CorrectnessViolation("invalid syntax corpus100 AST field".to_string())
        })?);
        if token_count == 0 || ast_bytes == 0 {
            return Err(BenchError::CorrectnessViolation(
                "C syntax corpus100 summary must report nonzero token and AST evidence".to_string(),
            ));
        }
        Ok(Correctness::Certificate {
            digest: *blake3::hash(output).as_bytes(),
        })
    }

    fn bytes_touched(&self, prepared: &PreparedCase) -> (u64, u64) {
        let bytes = prepared
            .downcast_ref::<CParserPrepared>()
            .map(|prepared| prepared.source.len() as u64)
            .unwrap_or(0);
        (bytes, 0)
    }
}

struct TempCompilePaths {
    source: PathBuf,
    object: PathBuf,
}

impl TempCompilePaths {
    fn new(stem: &str) -> Self {
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let base = std::env::temp_dir().join(format!("{stem}-{pid}-{nanos}"));
        Self {
            source: base.with_extension("c"),
            object: base.with_extension("o"),
        }
    }

    fn cleanup(&self) {
        remove_compile_temp_file(&self.source);
        remove_compile_temp_file(&self.object);
    }
}

fn remove_compile_temp_file(path: &std::path::Path) {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => panic!("failed to remove C parser bench temp file {}: {error}", path.display()),
    }
}

struct TreeSitterBaseline {
    nodes: u64,
    has_error: bool,
}

fn encode_parse_summary(summary: CParseSummary) -> Vec<u8> {
    let mut out = Vec::with_capacity(40);
    out.extend_from_slice(&summary.source_bytes.to_le_bytes());
    out.extend_from_slice(&(summary.token_count as u64).to_le_bytes());
    out.extend_from_slice(&summary.ast_bytes.to_le_bytes());
    out.extend_from_slice(&summary.function_record_bytes.to_le_bytes());
    out.extend_from_slice(&summary.call_record_bytes.to_le_bytes());
    out
}

fn run_tree_sitter_c_baseline(source: &str) -> Result<TreeSitterBaseline, BenchError> {
    let mut parser = tree_sitter::Parser::new();
    let language: tree_sitter::Language = tree_sitter_c::LANGUAGE.into();
    parser.set_language(&language).map_err(|error| {
        BenchError::ExecutionFailed(format!(
            "failed to initialize Tree-sitter C parser baseline: {error}"
        ))
    })?;
    let tree = parser.parse(source, None).ok_or_else(|| {
        BenchError::ExecutionFailed(
            "Tree-sitter C parser baseline returned no parse tree".to_string(),
        )
    })?;
    let has_error = tree.root_node().has_error();

    let mut cursor = tree.walk();
    let mut nodes = 0u64;
    loop {
        nodes = nodes.saturating_add(1);
        if cursor.goto_first_child() {
            continue;
        }
        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                return Ok(TreeSitterBaseline { nodes, has_error });
            }
        }
    }
}

impl Drop for TempCompilePaths {
    fn drop(&mut self) {
        self.cleanup();
    }
}

inventory::submit! {
    &CParserLinuxDriverPipeline as &'static dyn BenchCase
}

inventory::submit! {
    &CParserOnlyLinuxDriverPipeline as &'static dyn BenchCase
}

inventory::submit! {
    &CParserSyntaxOnlyLinuxDriverPipeline as &'static dyn BenchCase
}

inventory::submit! {
    &CParserSyntaxCorpusPipeline as &'static dyn BenchCase
}

inventory::submit! {
    &CParserSyntaxCorpus100Pipeline as &'static dyn BenchCase
}
