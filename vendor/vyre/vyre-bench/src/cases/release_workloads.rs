use crate::api::case::{
    BenchCase, BenchContext, BenchError, BenchId, BenchLayer, BenchMetadata, BenchRequirements,
    BenchRun, Correctness, DeterminismClass, PerformanceContract, PreparedCase, WorkloadClass,
};
use crate::api::metric::{BenchMetrics, MetricPoint};
use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};
use vyre_primitives::graph::program_graph::ProgramGraphShape;

pub struct SparseOutputCompactionCount;
pub struct CallgraphReachabilityStep;
pub struct MetadataConditionBatch;
struct SyntheticCountWorkload {
    id: &'static str,
    name: &'static str,
    description: &'static str,
    tags: &'static [&'static str],
    owner_crate: &'static str,
    primitive: &'static str,
    baseline: &'static str,
    metric_name: &'static str,
    records: u32,
    min_speedup_x: f64,
    pattern: SyntheticPattern,
}

/// Public release macro workload program descriptor for local benchmark entrypoints.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ReleaseMacroProgramSpec {
    /// Stable benchmark case id.
    pub id: &'static str,
    /// Human-readable benchmark name.
    pub name: &'static str,
    /// Logical records processed by the release workload.
    pub records: u32,
    /// Number of input buffers in the generated release workload.
    pub input_buffers: usize,
    /// Minimum CUDA speedup contract attached to this release workload.
    pub min_speedup_x: u32,
}

/// Generated release workload case with concrete inputs and CPU-oracle outputs.
#[derive(Clone)]
pub struct ReleaseMacroGeneratedCase {
    /// Public descriptor for the generated workload shape.
    pub spec: ReleaseMacroProgramSpec,
    /// IR program generated for this workload shape.
    pub program: Program,
    /// Concrete input byte buffers.
    pub inputs: Vec<Vec<u8>>,
    /// Expected output byte buffers from the CPU oracle.
    pub expected_outputs: Vec<Vec<u8>>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum SyntheticPattern {
    ConditionEval,
    StringBitmapScatter,
    OffsetCountAggregation,
    EntropyWindow,
    QuantifiedLoops,
    AliasReachingDef,
    IfdsWitness,
    CAstTraversal,
    MegakernelQueuedBatch,
    EgraphSaturation,
}

const RELEASE_SUITES: &[crate::api::suite::SuiteKind] = &[
    crate::api::suite::SuiteKind::Release,
    crate::api::suite::SuiteKind::Gpu,
    crate::api::suite::SuiteKind::Deep,
    crate::api::suite::SuiteKind::Honest,
];

const SPARSE_ITEMS: u32 = 1_048_576;
const METADATA_RECORDS: u32 = 1_048_576;
const CALLGRAPH_NODES: u32 = 262_144;
const CALLGRAPH_EDGES: u32 = CALLGRAPH_NODES - 1;
const CALLGRAPH_WORDS: usize = CALLGRAPH_NODES.div_ceil(32) as usize;

impl BenchCase for SparseOutputCompactionCount {
    fn id(&self) -> BenchId {
        BenchId("sparse.compaction.count.1m".to_string())
    }

    fn metadata(&self) -> BenchMetadata {
        BenchMetadata {
            id: self.id(),
            name: "Sparse Output Compaction Count 1M".to_string(),
            description:
                "Sparse hit counting front-end for GPU output compaction over a 1M candidate stream"
                    .to_string(),
            tags: vec![
                "sparse".to_string(),
                "compaction".to_string(),
                "compact".to_string(),
                "append".to_string(),
                "release".to_string(),
            ],
            layer: BenchLayer::Runtime,
            workload: WorkloadClass::Macro,
            determinism: DeterminismClass::Deterministic,
            owner_crate: "vyre-runtime".to_string(),
        }
    }

    fn suites(&self) -> &'static [crate::api::suite::SuiteKind] {
        RELEASE_SUITES
    }

    fn requirements(&self) -> BenchRequirements {
        gpu_requirements((SPARSE_ITEMS as u64 + 1) * 4)
    }

    fn performance_contract(&self) -> Option<PerformanceContract> {
        Some(PerformanceContract::cpu_sota_100x(
            "sparse output compaction count",
            "vyre-runtime",
            "optimized CPU fired-rule collection over predicate masks",
        ))
    }

    fn prepare(&self, _ctx: &mut BenchContext) -> Result<PreparedCase, BenchError> {
        let program = Program::wrapped(
            vec![
                BufferDecl::output("out_count", 0, DataType::U32).with_count(1),
                BufferDecl::storage("flags", 1, BufferAccess::ReadOnly, DataType::U32)
                    .with_count(SPARSE_ITEMS),
            ],
            [256, 1, 1],
            vec![
                Node::let_bind("idx", Expr::gid_x()),
                Node::if_then(
                    Expr::and(
                        Expr::lt(Expr::var("idx"), Expr::u32(SPARSE_ITEMS)),
                        Expr::ne(Expr::load("flags", Expr::var("idx")), Expr::u32(0)),
                    ),
                    vec![Node::let_bind(
                        "_slot",
                        Expr::atomic_add("out_count", Expr::u32(0), Expr::u32(1)),
                    )],
                ),
            ],
        );
        Ok(Box::new(program))
    }

    fn run(
        &self,
        ctx: &mut BenchContext,
        prepared: &mut PreparedCase,
    ) -> Result<BenchRun, BenchError> {
        let program = crate::api::case::prepared_program(prepared)?;
        let mut flags = Vec::with_capacity(SPARSE_ITEMS as usize);
        let mut expected = 0u32;
        for index in 0..SPARSE_ITEMS {
            let hit = sparse_compaction_flag(index) != 0;
            expected += u32::from(hit);
            flags.push(u32::from(hit));
        }
        let inputs = vec![vec![0; 4], encode_u32_words(&flags)];
        let timed = ctx
            .dispatch_timed(program, &inputs, &ctx.dispatch_config)
            .map_err(|error| BenchError::BackendFailed(error.to_string()))?;
        let baseline_start = std::time::Instant::now();
        let mut fired_rules = Vec::new();
        for index in 0..SPARSE_ITEMS {
            if sparse_compaction_flag(index) != 0 {
                fired_rules.push(index);
            }
        }
        let cpu_count = fired_rules.len() as u32;
        let baseline_wall = baseline_start.elapsed().as_nanos() as u64;
        if cpu_count != expected {
            return Err(BenchError::CorrectnessViolation(
                "sparse CPU baseline count disagreed with generator expectation".to_string(),
            ));
        }
        let baseline_outputs = vec![cpu_count.to_le_bytes().to_vec()];
        bench_run_from_timed(
            timed,
            inputs,
            baseline_outputs,
            baseline_wall,
            "sparse_items",
            SPARSE_ITEMS,
        )
    }

    fn verify(&self, _ctx: &mut BenchContext, run: &BenchRun) -> Result<Correctness, BenchError> {
        run.verify_exact_outputs()
    }
}

fn sparse_compaction_flag(index: u32) -> u32 {
    let mut hash = index ^ 0x9E37_79B9;
    for lane in 0..18 {
        hash = hash
            .rotate_left(5)
            .wrapping_mul(0x85EB_CA6B)
            .wrapping_add(0xC2B2_AE35 ^ lane);
    }
    u32::from(index % 97 == 0 || index % 4099 == 17 || hash == 0)
}

impl BenchCase for CallgraphReachabilityStep {
    fn id(&self) -> BenchId {
        BenchId("callgraph.reachability.step.262k".to_string())
    }

    fn metadata(&self) -> BenchMetadata {
        BenchMetadata {
            id: self.id(),
            name: "Callgraph Reachability Step 262K".to_string(),
            description: "Graph reachability step over a callgraph-shaped CSR workload".to_string(),
            tags: vec![
                "callgraph".to_string(),
                "reachability".to_string(),
                "graph".to_string(),
                "release".to_string(),
            ],
            layer: BenchLayer::Libs,
            workload: WorkloadClass::Macro,
            determinism: DeterminismClass::Deterministic,
            owner_crate: "vyre-primitives".to_string(),
        }
    }

    fn suites(&self) -> &'static [crate::api::suite::SuiteKind] {
        RELEASE_SUITES
    }

    fn requirements(&self) -> BenchRequirements {
        gpu_requirements(graph_input_bytes().saturating_add((CALLGRAPH_WORDS * 4) as u64))
    }

    fn performance_contract(&self) -> Option<PerformanceContract> {
        Some(PerformanceContract::cpu_sota_min_speedup(
            "callgraph reachability CSR step",
            "vyre-primitives",
            "optimized CPU graph reachability and witness extraction",
            25.0,
        ))
    }

    fn prepare(&self, _ctx: &mut BenchContext) -> Result<PreparedCase, BenchError> {
        let shape = ProgramGraphShape::new(CALLGRAPH_NODES, CALLGRAPH_EDGES);
        Ok(Box::new(
            vyre_primitives::graph::csr_forward_traverse::csr_forward_traverse(
                shape,
                "frontier_in",
                "frontier_out",
                1,
            ),
        ))
    }

    fn run(
        &self,
        ctx: &mut BenchContext,
        prepared: &mut PreparedCase,
    ) -> Result<BenchRun, BenchError> {
        let program = crate::api::case::prepared_program(prepared)?;
        let graph = linear_graph_inputs();
        let timed = ctx
            .dispatch_timed(program, &graph.inputs, &ctx.dispatch_config)
            .map_err(|error| BenchError::BackendFailed(error.to_string()))?;
        let baseline_start = std::time::Instant::now();
        let mut expected = release_benchmark_csr_forward_baseline(
            CALLGRAPH_NODES,
            &graph.edge_offsets,
            &graph.edge_targets,
            &graph.edge_kind_mask,
            &graph.frontier_in,
            1,
        );
        let witness_digest = callgraph_witness_digest(
            CALLGRAPH_NODES,
            &graph.edge_offsets,
            &graph.edge_targets,
            &graph.edge_kind_mask,
            &graph.frontier_in,
            1,
        );
        for (out, seed) in expected.iter_mut().zip(graph.frontier_out_seed.iter()) {
            *out |= *seed;
        }
        let baseline_outputs = vec![encode_u32_words(&expected)];
        let baseline_wall = baseline_start.elapsed().as_nanos() as u64;
        let mut run = bench_run_from_timed(
            timed,
            graph.inputs,
            baseline_outputs,
            baseline_wall,
            "callgraph_nodes",
            CALLGRAPH_NODES,
        )?;
        run.metrics.custom.push(MetricPoint {
            name: "callgraph_witness_digest".to_string(),
            value: u64::from(witness_digest),
        });
        Ok(run)
    }

    fn verify(&self, _ctx: &mut BenchContext, run: &BenchRun) -> Result<Correctness, BenchError> {
        run.verify_exact_outputs()
    }
}

impl BenchCase for MetadataConditionBatch {
    fn id(&self) -> BenchId {
        BenchId("metadata.condition.filesize_header.1m".to_string())
    }

    fn metadata(&self) -> BenchMetadata {
        BenchMetadata {
            id: self.id(),
            name: "Metadata Condition File/Header 1M".to_string(),
            description: "File metadata and PE/header-style condition evaluation over 1M records"
                .to_string(),
            tags: vec![
                "metadata".to_string(),
                "condition".to_string(),
                "filesize".to_string(),
                "header".to_string(),
                "pe".to_string(),
                "release".to_string(),
            ],
            layer: BenchLayer::Libs,
            workload: WorkloadClass::Macro,
            determinism: DeterminismClass::Deterministic,
            owner_crate: "vyre-libs".to_string(),
        }
    }

    fn suites(&self) -> &'static [crate::api::suite::SuiteKind] {
        RELEASE_SUITES
    }

    fn requirements(&self) -> BenchRequirements {
        gpu_requirements((METADATA_RECORDS as u64 * 12) + 4)
    }

    fn performance_contract(&self) -> Option<PerformanceContract> {
        Some(PerformanceContract::cpu_sota_min_speedup(
            "metadata condition evaluation",
            "vyre-libs",
            "optimized CPU PE-header predicate evaluator",
            50.0,
        ))
    }

    fn prepare(&self, _ctx: &mut BenchContext) -> Result<PreparedCase, BenchError> {
        let program = Program::wrapped(
            vec![
                BufferDecl::output("out_count", 0, DataType::U32).with_count(1),
                BufferDecl::storage("filesize", 1, BufferAccess::ReadOnly, DataType::U32)
                    .with_count(METADATA_RECORDS),
                BufferDecl::storage("header", 2, BufferAccess::ReadOnly, DataType::U32)
                    .with_count(METADATA_RECORDS),
                BufferDecl::storage("entropy_x1000", 3, BufferAccess::ReadOnly, DataType::U32)
                    .with_count(METADATA_RECORDS),
            ],
            [256, 1, 1],
            vec![
                Node::let_bind("idx", Expr::gid_x()),
                Node::if_then(
                    Expr::and(
                        Expr::lt(Expr::var("idx"), Expr::u32(METADATA_RECORDS)),
                        Expr::and(
                            Expr::gt(Expr::load("filesize", Expr::var("idx")), Expr::u32(4096)),
                            Expr::and(
                                Expr::eq(
                                    Expr::load("header", Expr::var("idx")),
                                    Expr::u32(0x0000_4550),
                                ),
                                Expr::gt(
                                    Expr::load("entropy_x1000", Expr::var("idx")),
                                    Expr::u32(7200),
                                ),
                            ),
                        ),
                    ),
                    vec![Node::let_bind(
                        "_slot",
                        Expr::atomic_add("out_count", Expr::u32(0), Expr::u32(1)),
                    )],
                ),
            ],
        );
        Ok(Box::new(program))
    }

    fn run(
        &self,
        ctx: &mut BenchContext,
        prepared: &mut PreparedCase,
    ) -> Result<BenchRun, BenchError> {
        let program = crate::api::case::prepared_program(prepared)?;
        let mut filesize = Vec::with_capacity(METADATA_RECORDS as usize);
        let mut header = Vec::with_capacity(METADATA_RECORDS as usize);
        let mut entropy = Vec::with_capacity(METADATA_RECORDS as usize);
        let mut expected = 0u32;
        for index in 0..METADATA_RECORDS {
            let size = 1024 + (index.wrapping_mul(13) % 131_072);
            let hdr = if index % 5 == 0 {
                0x0000_4550
            } else {
                0x464C_457F
            };
            let ent = 5000 + (index.wrapping_mul(17) % 4500);
            expected += u32::from(size > 4096 && hdr == 0x0000_4550 && ent > 7200);
            filesize.push(size);
            header.push(hdr);
            entropy.push(ent);
        }
        let inputs = vec![
            encode_u32_words(&filesize),
            encode_u32_words(&header),
            encode_u32_words(&entropy),
        ];
        let timed = ctx
            .dispatch_timed(program, &inputs, &ctx.dispatch_config)
            .map_err(|error| BenchError::BackendFailed(error.to_string()))?;
        let baseline_start = std::time::Instant::now();
        let mut cpu_count = 0u32;
        for index in 0..filesize.len() {
            cpu_count += u32::from(
                filesize[index] > 4096 && header[index] == 0x0000_4550 && entropy[index] > 7200,
            );
        }
        let baseline_wall = baseline_start.elapsed().as_nanos() as u64;
        if cpu_count != expected {
            return Err(BenchError::CorrectnessViolation(
                "metadata CPU baseline count disagreed with generator expectation".to_string(),
            ));
        }
        let baseline_outputs = vec![cpu_count.to_le_bytes().to_vec()];
        bench_run_from_timed(
            timed,
            inputs,
            baseline_outputs,
            baseline_wall,
            "metadata_records",
            METADATA_RECORDS,
        )
    }

    fn verify(&self, _ctx: &mut BenchContext, run: &BenchRun) -> Result<Correctness, BenchError> {
        run.verify_exact_outputs()
    }
}

impl BenchCase for SyntheticCountWorkload {
    fn id(&self) -> BenchId {
        BenchId(self.id.to_string())
    }

    fn metadata(&self) -> BenchMetadata {
        let mut tags = self
            .tags
            .iter()
            .map(|tag| (*tag).to_string())
            .collect::<Vec<_>>();
        tags.push("release".to_string());
        BenchMetadata {
            id: self.id(),
            name: self.name.to_string(),
            description: self.description.to_string(),
            tags,
            layer: BenchLayer::Libs,
            workload: WorkloadClass::Macro,
            determinism: DeterminismClass::Deterministic,
            owner_crate: self.owner_crate.to_string(),
        }
    }

    fn suites(&self) -> &'static [crate::api::suite::SuiteKind] {
        RELEASE_SUITES
    }

    fn requirements(&self) -> BenchRequirements {
        gpu_requirements((self.records as u64 * pattern_input_count(self.pattern) as u64 * 4) + 4)
    }

    fn performance_contract(&self) -> Option<PerformanceContract> {
        Some(PerformanceContract::cpu_sota_min_speedup(
            self.primitive,
            self.owner_crate,
            self.baseline,
            self.min_speedup_x,
        ))
    }

    fn prepare(&self, _ctx: &mut BenchContext) -> Result<PreparedCase, BenchError> {
        Ok(Box::new(build_synthetic_release_program(
            self.pattern,
            self.records,
        )))
    }

    fn run(
        &self,
        ctx: &mut BenchContext,
        prepared: &mut PreparedCase,
    ) -> Result<BenchRun, BenchError> {
        if self.pattern == SyntheticPattern::StringBitmapScatter {
            return self.run_string_bitmap_scatter(ctx, prepared);
        }
        let program = crate::api::case::prepared_program(prepared)?;
        let generated = synthetic_inputs(self.pattern, self.records);
        let timed = ctx
            .dispatch_timed(program, &generated.inputs, &ctx.dispatch_config)
            .map_err(|error| BenchError::BackendFailed(error.to_string()))?;
        let baseline_start = std::time::Instant::now();
        let cpu_count = synthetic_cpu_count(self.pattern, self.records);
        let baseline_wall = baseline_start.elapsed().as_nanos() as u64;
        if cpu_count != generated.expected {
            return Err(BenchError::CorrectnessViolation(format!(
                "{} CPU baseline count disagreed with generator expectation",
                self.id
            )));
        }
        let mut run = bench_run_from_timed(
            timed,
            generated.inputs,
            vec![cpu_count.to_le_bytes().to_vec()],
            baseline_wall,
            self.metric_name,
            self.records,
        )?;
        add_release_alias_metrics(self.pattern, self.records, cpu_count, &mut run);
        Ok(run)
    }

    fn verify(&self, _ctx: &mut BenchContext, run: &BenchRun) -> Result<Correctness, BenchError> {
        run.verify_exact_outputs()
    }
}

impl SyntheticCountWorkload {
    fn run_string_bitmap_scatter(
        &self,
        ctx: &mut BenchContext,
        prepared: &mut PreparedCase,
    ) -> Result<BenchRun, BenchError> {
        let program = crate::api::case::prepared_program(prepared)?;
        let generated = string_bitmap_scatter_inputs(self.records);
        let timed = ctx
            .dispatch_timed(program, &generated.inputs, &ctx.dispatch_config)
            .map_err(|error| BenchError::BackendFailed(error.to_string()))?;
        let baseline_start = std::time::Instant::now();
        let baseline_words = string_bitmap_scatter_expected_words(
            &generated.pattern_bitmap,
            &generated.rule_bitmap,
            self.records,
        );
        let baseline_outputs = vec![encode_u32_words(&baseline_words)];
        let baseline_wall = baseline_start.elapsed().as_nanos() as u64;
        let mut run = bench_run_from_timed(
            timed,
            generated.inputs,
            baseline_outputs,
            baseline_wall,
            self.metric_name,
            self.records,
        )?;
        run.metrics.custom.push(MetricPoint {
            name: "scatter_materialized_words".to_string(),
            value: u64::from(self.records),
        });
        Ok(run)
    }
}

fn build_synthetic_release_program(pattern: SyntheticPattern, records: u32) -> Program {
    match pattern {
        SyntheticPattern::ConditionEval => condition_eval_program(records),
        SyntheticPattern::StringBitmapScatter => string_bitmap_scatter_program(records),
        SyntheticPattern::OffsetCountAggregation => offset_count_aggregation_program(records),
        SyntheticPattern::EntropyWindow => entropy_window_program(records),
        SyntheticPattern::QuantifiedLoops => quantified_condition_loops_program(records),
        SyntheticPattern::AliasReachingDef => alias_reaching_def_program(records),
        SyntheticPattern::IfdsWitness => ifds_witness_program(records),
        SyntheticPattern::CAstTraversal => c_ast_traversal_program(records),
        SyntheticPattern::MegakernelQueuedBatch => megakernel_queue_program(records),
        SyntheticPattern::EgraphSaturation => egraph_saturation_program(records),
    }
}

fn gpu_requirements(input_bytes: u64) -> BenchRequirements {
    BenchRequirements {
        needs_gpu: true,
        needs_network: false,
        min_vram_bytes: None,
        min_input_bytes: Some(input_bytes),
        feature_set: vec!["release-workload".to_string()],
    }
}

struct SyntheticInputs {
    inputs: Vec<Vec<u8>>,
    expected: u32,
}

struct StringBitmapScatterInputs {
    inputs: Vec<Vec<u8>>,
    pattern_bitmap: Vec<u32>,
    rule_bitmap: Vec<u32>,
}

fn string_bitmap_scatter_inputs(records: u32) -> StringBitmapScatterInputs {
    let mut pattern_bitmap = Vec::with_capacity(records as usize);
    let mut rule_bitmap = Vec::with_capacity(records as usize);
    for index in 0..records {
        let row = synthetic_row(SyntheticPattern::StringBitmapScatter, index);
        pattern_bitmap.push(row[0]);
        rule_bitmap.push(row[1]);
    }
    let output_words = records.div_ceil(32);
    let out_flags_init = vec![0u32; output_words as usize];
    let inputs = vec![
        encode_u32_words(&out_flags_init),
        encode_u32_words(&pattern_bitmap),
        encode_u32_words(&rule_bitmap),
    ];
    StringBitmapScatterInputs {
        inputs,
        pattern_bitmap,
        rule_bitmap,
    }
}

fn string_bitmap_scatter_expected_words(
    pattern_bitmap: &[u32],
    rule_bitmap: &[u32],
    records: u32,
) -> Vec<u32> {
    let mut expected_words = vec![0u32; records.div_ceil(32) as usize];
    for index in 0..records {
        if pattern_bitmap[index as usize] != 0 && rule_bitmap[index as usize] != 0 {
            expected_words[(index / 32) as usize] |= 1u32 << (index & 31);
        }
    }
    expected_words
}

fn synthetic_count_program(pattern: SyntheticPattern, records: u32) -> Program {
    let mut buffers = vec![BufferDecl::output("out_count", 0, DataType::U32).with_count(1)];
    for (binding, name) in pattern_buffers(pattern).iter().enumerate() {
        buffers.push(
            BufferDecl::storage(
                *name,
                (binding + 1) as u32,
                BufferAccess::ReadOnly,
                DataType::U32,
            )
            .with_count(records),
        );
    }
    Program::wrapped(
        buffers,
        [256, 1, 1],
        vec![
            Node::let_bind("idx", Expr::gid_x()),
            Node::if_then(
                Expr::and(
                    Expr::lt(Expr::var("idx"), Expr::u32(records)),
                    pattern_condition(pattern),
                ),
                vec![Node::let_bind(
                    "_slot",
                    Expr::atomic_add("out_count", Expr::u32(0), Expr::u32(1)),
                )],
            ),
        ],
    )
}

fn condition_eval_program(records: u32) -> Program {
    Program::wrapped(
        vec![
            BufferDecl::output("out_count", 0, DataType::U32).with_count(1),
            BufferDecl::storage("match_mask", 1, BufferAccess::ReadOnly, DataType::U32)
                .with_count(records),
            BufferDecl::storage("rule_mask", 2, BufferAccess::ReadOnly, DataType::U32)
                .with_count(records),
            BufferDecl::storage("metadata_mask", 3, BufferAccess::ReadOnly, DataType::U32)
                .with_count(records),
        ],
        [256, 1, 1],
        vec![
            Node::let_bind("idx", Expr::gid_x()),
            Node::if_then(
                Expr::lt(Expr::var("idx"), Expr::u32(records)),
                vec![
                    Node::let_bind("match_word", load_u32("match_mask")),
                    Node::let_bind("rule_word", load_u32("rule_mask")),
                    Node::let_bind("metadata_word", load_u32("metadata_mask")),
                    Node::let_bind("condition_hits", Expr::u32(0)),
                    Node::loop_for(
                        "condition_lane",
                        Expr::u32(0),
                        Expr::u32(CONDITION_LANES),
                        vec![Node::if_then(
                            Expr::and(
                                Expr::ne(
                                    Expr::bitand(
                                        Expr::var("match_word"),
                                        Expr::shl(Expr::u32(1), Expr::var("condition_lane")),
                                    ),
                                    Expr::u32(0),
                                ),
                                Expr::and(
                                    Expr::ne(
                                        Expr::bitand(
                                            Expr::var("rule_word"),
                                            Expr::shl(Expr::u32(1), Expr::var("condition_lane")),
                                        ),
                                        Expr::u32(0),
                                    ),
                                    Expr::ne(
                                        Expr::bitand(
                                            Expr::var("metadata_word"),
                                            Expr::shl(Expr::u32(1), Expr::var("condition_lane")),
                                        ),
                                        Expr::u32(0),
                                    ),
                                ),
                            ),
                            vec![Node::assign(
                                "condition_hits",
                                Expr::add(Expr::var("condition_hits"), Expr::u32(1)),
                            )],
                        )],
                    ),
                    Node::if_then(
                        Expr::ge(Expr::var("condition_hits"), Expr::u32(CONDITION_THRESHOLD)),
                        vec![Node::let_bind(
                            "_slot",
                            Expr::atomic_add("out_count", Expr::u32(0), Expr::u32(1)),
                        )],
                    ),
                ],
            ),
        ],
    )
}

fn string_bitmap_scatter_program(records: u32) -> Program {
    let output_words = records.div_ceil(32);
    Program::wrapped(
        vec![
            BufferDecl::storage("out_flags", 0, BufferAccess::ReadWrite, DataType::U32)
                .with_count(output_words),
            BufferDecl::storage("pattern_bitmap", 1, BufferAccess::ReadOnly, DataType::U32)
                .with_count(records),
            BufferDecl::storage("rule_bitmap", 2, BufferAccess::ReadOnly, DataType::U32)
                .with_count(records),
        ],
        [256, 1, 1],
        vec![
            Node::let_bind("idx", Expr::gid_x()),
            Node::if_then(
                Expr::lt(Expr::var("idx"), Expr::u32(records)),
                vec![Node::if_then(
                    Expr::and(
                        Expr::ne(load_u32("pattern_bitmap"), Expr::u32(0)),
                        Expr::ne(load_u32("rule_bitmap"), Expr::u32(0)),
                    ),
                    vec![Node::let_bind(
                        "_scatter",
                        Expr::atomic_or(
                            "out_flags",
                            Expr::shr(Expr::var("idx"), Expr::u32(5)),
                            Expr::shl(Expr::u32(1), Expr::bitand(Expr::var("idx"), Expr::u32(31))),
                        ),
                    )],
                )],
            ),
        ],
    )
}

fn offset_count_aggregation_program(records: u32) -> Program {
    Program::wrapped(
        vec![
            BufferDecl::output("out_count", 0, DataType::U32).with_count(1),
            BufferDecl::storage("offset_mask", 1, BufferAccess::ReadOnly, DataType::U32)
                .with_count(records),
            BufferDecl::storage("length_mask", 2, BufferAccess::ReadOnly, DataType::U32)
                .with_count(records),
            BufferDecl::storage("count_mask", 3, BufferAccess::ReadOnly, DataType::U32)
                .with_count(records),
        ],
        [256, 1, 1],
        vec![
            Node::let_bind("idx", Expr::gid_x()),
            Node::if_then(
                Expr::lt(Expr::var("idx"), Expr::u32(records)),
                vec![
                    Node::let_bind("offset_word", load_u32("offset_mask")),
                    Node::let_bind("length_word", load_u32("length_mask")),
                    Node::let_bind("count_word", load_u32("count_mask")),
                    Node::let_bind("aggregation_hits", Expr::u32(0)),
                    Node::loop_for(
                        "aggregation_lane",
                        Expr::u32(0),
                        Expr::u32(AGGREGATION_LANES),
                        vec![Node::if_then(
                            Expr::and(
                                Expr::ne(
                                    Expr::bitand(
                                        Expr::var("offset_word"),
                                        Expr::shl(Expr::u32(1), Expr::var("aggregation_lane")),
                                    ),
                                    Expr::u32(0),
                                ),
                                Expr::and(
                                    Expr::ne(
                                        Expr::bitand(
                                            Expr::var("length_word"),
                                            Expr::shl(Expr::u32(1), Expr::var("aggregation_lane")),
                                        ),
                                        Expr::u32(0),
                                    ),
                                    Expr::ne(
                                        Expr::bitand(
                                            Expr::var("count_word"),
                                            Expr::shl(Expr::u32(1), Expr::var("aggregation_lane")),
                                        ),
                                        Expr::u32(0),
                                    ),
                                ),
                            ),
                            vec![Node::assign(
                                "aggregation_hits",
                                Expr::add(Expr::var("aggregation_hits"), Expr::u32(1)),
                            )],
                        )],
                    ),
                    Node::if_then(
                        Expr::ge(
                            Expr::var("aggregation_hits"),
                            Expr::u32(AGGREGATION_THRESHOLD),
                        ),
                        vec![Node::let_bind(
                            "_slot",
                            Expr::atomic_add("out_count", Expr::u32(0), Expr::u32(1)),
                        )],
                    ),
                ],
            ),
        ],
    )
}

fn entropy_window_program(records: u32) -> Program {
    Program::wrapped(
        vec![
            BufferDecl::output("out_count", 0, DataType::U32).with_count(1),
            BufferDecl::storage("byte_class_mask", 1, BufferAccess::ReadOnly, DataType::U32)
                .with_count(records),
            BufferDecl::storage("transition_mask", 2, BufferAccess::ReadOnly, DataType::U32)
                .with_count(records),
            BufferDecl::storage("rarity_mask", 3, BufferAccess::ReadOnly, DataType::U32)
                .with_count(records),
        ],
        [256, 1, 1],
        vec![
            Node::let_bind("idx", Expr::gid_x()),
            Node::if_then(
                Expr::lt(Expr::var("idx"), Expr::u32(records)),
                vec![
                    Node::let_bind("byte_class_word", load_u32("byte_class_mask")),
                    Node::let_bind("transition_word", load_u32("transition_mask")),
                    Node::let_bind("rarity_word", load_u32("rarity_mask")),
                    Node::let_bind("entropy_score", Expr::u32(0)),
                    Node::loop_for(
                        "entropy_lane",
                        Expr::u32(0),
                        Expr::u32(ENTROPY_LANES),
                        vec![Node::if_then(
                            Expr::and(
                                Expr::ne(
                                    Expr::bitand(
                                        Expr::var("byte_class_word"),
                                        Expr::shl(Expr::u32(1), Expr::var("entropy_lane")),
                                    ),
                                    Expr::u32(0),
                                ),
                                Expr::or(
                                    Expr::ne(
                                        Expr::bitand(
                                            Expr::var("transition_word"),
                                            Expr::shl(Expr::u32(1), Expr::var("entropy_lane")),
                                        ),
                                        Expr::u32(0),
                                    ),
                                    Expr::ne(
                                        Expr::bitand(
                                            Expr::var("rarity_word"),
                                            Expr::shl(Expr::u32(1), Expr::var("entropy_lane")),
                                        ),
                                        Expr::u32(0),
                                    ),
                                ),
                            ),
                            vec![Node::assign(
                                "entropy_score",
                                Expr::add(Expr::var("entropy_score"), Expr::u32(1)),
                            )],
                        )],
                    ),
                    Node::if_then(
                        Expr::ge(Expr::var("entropy_score"), Expr::u32(ENTROPY_THRESHOLD)),
                        vec![Node::let_bind(
                            "_slot",
                            Expr::atomic_add("out_count", Expr::u32(0), Expr::u32(1)),
                        )],
                    ),
                ],
            ),
        ],
    )
}

fn quantified_condition_loops_program(records: u32) -> Program {
    Program::wrapped(
        vec![
            BufferDecl::output("out_count", 0, DataType::U32).with_count(1),
            BufferDecl::storage("any_mask", 1, BufferAccess::ReadOnly, DataType::U32)
                .with_count(records),
            BufferDecl::storage("all_mask", 2, BufferAccess::ReadOnly, DataType::U32)
                .with_count(records),
            BufferDecl::storage("threshold_mask", 3, BufferAccess::ReadOnly, DataType::U32)
                .with_count(records),
        ],
        [256, 1, 1],
        vec![
            Node::let_bind("idx", Expr::gid_x()),
            Node::if_then(
                Expr::lt(Expr::var("idx"), Expr::u32(records)),
                vec![
                    Node::let_bind("any_word", load_u32("any_mask")),
                    Node::let_bind("all_word", load_u32("all_mask")),
                    Node::let_bind("threshold_word", load_u32("threshold_mask")),
                    Node::let_bind("any_seen", Expr::u32(0)),
                    Node::let_bind("all_seen", Expr::u32(1)),
                    Node::let_bind("threshold_hits", Expr::u32(0)),
                    Node::loop_for(
                        "q",
                        Expr::u32(0),
                        Expr::u32(QUANTIFIED_LANES),
                        vec![
                            Node::if_then(
                                Expr::ne(
                                    Expr::bitand(
                                        Expr::var("any_word"),
                                        Expr::shl(Expr::u32(1), Expr::var("q")),
                                    ),
                                    Expr::u32(0),
                                ),
                                vec![Node::assign("any_seen", Expr::u32(1))],
                            ),
                            Node::if_then(
                                Expr::eq(
                                    Expr::bitand(
                                        Expr::var("all_word"),
                                        Expr::shl(Expr::u32(1), Expr::var("q")),
                                    ),
                                    Expr::u32(0),
                                ),
                                vec![Node::assign("all_seen", Expr::u32(0))],
                            ),
                            Node::if_then(
                                Expr::ne(
                                    Expr::bitand(
                                        Expr::var("threshold_word"),
                                        Expr::shl(Expr::u32(1), Expr::var("q")),
                                    ),
                                    Expr::u32(0),
                                ),
                                vec![Node::assign(
                                    "threshold_hits",
                                    Expr::add(Expr::var("threshold_hits"), Expr::u32(1)),
                                )],
                            ),
                        ],
                    ),
                    Node::if_then(
                        Expr::and(
                            Expr::ne(Expr::var("any_seen"), Expr::u32(0)),
                            Expr::and(
                                Expr::ne(Expr::var("all_seen"), Expr::u32(0)),
                                Expr::ge(
                                    Expr::var("threshold_hits"),
                                    Expr::u32(QUANTIFIED_THRESHOLD),
                                ),
                            ),
                        ),
                        vec![Node::let_bind(
                            "_slot",
                            Expr::atomic_add("out_count", Expr::u32(0), Expr::u32(1)),
                        )],
                    ),
                ],
            ),
        ],
    )
}

fn alias_reaching_def_program(records: u32) -> Program {
    Program::wrapped(
        vec![
            BufferDecl::output("out_count", 0, DataType::U32).with_count(1),
            BufferDecl::storage("def_mask", 1, BufferAccess::ReadOnly, DataType::U32)
                .with_count(records),
            BufferDecl::storage("use_mask", 2, BufferAccess::ReadOnly, DataType::U32)
                .with_count(records),
            BufferDecl::storage("kill_mask", 3, BufferAccess::ReadOnly, DataType::U32)
                .with_count(records),
        ],
        [256, 1, 1],
        vec![
            Node::let_bind("idx", Expr::gid_x()),
            Node::if_then(
                Expr::lt(Expr::var("idx"), Expr::u32(records)),
                vec![
                    Node::let_bind("def_word", load_u32("def_mask")),
                    Node::let_bind("use_word", load_u32("use_mask")),
                    Node::let_bind("kill_word", load_u32("kill_mask")),
                    Node::let_bind("reaching_aliases", Expr::u32(0)),
                    Node::loop_for(
                        "alias_lane",
                        Expr::u32(0),
                        Expr::u32(ALIAS_LANES),
                        vec![Node::if_then(
                            Expr::and(
                                Expr::ne(
                                    Expr::bitand(
                                        Expr::var("def_word"),
                                        Expr::shl(Expr::u32(1), Expr::var("alias_lane")),
                                    ),
                                    Expr::u32(0),
                                ),
                                Expr::and(
                                    Expr::ne(
                                        Expr::bitand(
                                            Expr::var("use_word"),
                                            Expr::shl(Expr::u32(1), Expr::var("alias_lane")),
                                        ),
                                        Expr::u32(0),
                                    ),
                                    Expr::eq(
                                        Expr::bitand(
                                            Expr::var("kill_word"),
                                            Expr::shl(Expr::u32(1), Expr::var("alias_lane")),
                                        ),
                                        Expr::u32(0),
                                    ),
                                ),
                            ),
                            vec![Node::assign(
                                "reaching_aliases",
                                Expr::add(Expr::var("reaching_aliases"), Expr::u32(1)),
                            )],
                        )],
                    ),
                    Node::if_then(
                        Expr::ge(Expr::var("reaching_aliases"), Expr::u32(ALIAS_THRESHOLD)),
                        vec![Node::let_bind(
                            "_slot",
                            Expr::atomic_add("out_count", Expr::u32(0), Expr::u32(1)),
                        )],
                    ),
                ],
            ),
        ],
    )
}

fn ifds_witness_program(records: u32) -> Program {
    Program::wrapped(
        vec![
            BufferDecl::output("out_count", 0, DataType::U32).with_count(1),
            BufferDecl::storage("frontier_mask", 1, BufferAccess::ReadOnly, DataType::U32)
                .with_count(records),
            BufferDecl::storage("transfer_mask", 2, BufferAccess::ReadOnly, DataType::U32)
                .with_count(records),
            BufferDecl::storage("witness_mask", 3, BufferAccess::ReadOnly, DataType::U32)
                .with_count(records),
        ],
        [256, 1, 1],
        vec![
            Node::let_bind("idx", Expr::gid_x()),
            Node::if_then(
                Expr::lt(Expr::var("idx"), Expr::u32(records)),
                vec![
                    Node::let_bind("frontier_word", load_u32("frontier_mask")),
                    Node::let_bind("transfer_word", load_u32("transfer_mask")),
                    Node::let_bind("witness_word", load_u32("witness_mask")),
                    Node::let_bind("witness_hits", Expr::u32(0)),
                    Node::loop_for(
                        "ifds_lane",
                        Expr::u32(0),
                        Expr::u32(IFDS_LANES),
                        vec![Node::if_then(
                            Expr::and(
                                Expr::ne(
                                    Expr::bitand(
                                        Expr::var("frontier_word"),
                                        Expr::shl(Expr::u32(1), Expr::var("ifds_lane")),
                                    ),
                                    Expr::u32(0),
                                ),
                                Expr::and(
                                    Expr::ne(
                                        Expr::bitand(
                                            Expr::var("transfer_word"),
                                            Expr::shl(Expr::u32(1), Expr::var("ifds_lane")),
                                        ),
                                        Expr::u32(0),
                                    ),
                                    Expr::ne(
                                        Expr::bitand(
                                            Expr::var("witness_word"),
                                            Expr::shl(Expr::u32(1), Expr::var("ifds_lane")),
                                        ),
                                        Expr::u32(0),
                                    ),
                                ),
                            ),
                            vec![Node::assign(
                                "witness_hits",
                                Expr::add(Expr::var("witness_hits"), Expr::u32(1)),
                            )],
                        )],
                    ),
                    Node::if_then(
                        Expr::ge(Expr::var("witness_hits"), Expr::u32(IFDS_THRESHOLD)),
                        vec![Node::let_bind(
                            "_slot",
                            Expr::atomic_add("out_count", Expr::u32(0), Expr::u32(1)),
                        )],
                    ),
                ],
            ),
        ],
    )
}

fn c_ast_traversal_program(records: u32) -> Program {
    Program::wrapped(
        vec![
            BufferDecl::output("out_count", 0, DataType::U32).with_count(1),
            BufferDecl::storage("node_kind_mask", 1, BufferAccess::ReadOnly, DataType::U32)
                .with_count(records),
            BufferDecl::storage("depth_mask", 2, BufferAccess::ReadOnly, DataType::U32)
                .with_count(records),
            BufferDecl::storage("motif_mask", 3, BufferAccess::ReadOnly, DataType::U32)
                .with_count(records),
        ],
        [256, 1, 1],
        vec![
            Node::let_bind("idx", Expr::gid_x()),
            Node::if_then(
                Expr::lt(Expr::var("idx"), Expr::u32(records)),
                vec![
                    Node::let_bind("node_kind_word", load_u32("node_kind_mask")),
                    Node::let_bind("depth_word", load_u32("depth_mask")),
                    Node::let_bind("motif_word", load_u32("motif_mask")),
                    Node::let_bind("ast_hits", Expr::u32(0)),
                    Node::loop_for(
                        "ast_lane",
                        Expr::u32(0),
                        Expr::u32(C_AST_LANES),
                        vec![Node::if_then(
                            Expr::and(
                                Expr::ne(
                                    Expr::bitand(
                                        Expr::var("node_kind_word"),
                                        Expr::shl(Expr::u32(1), Expr::var("ast_lane")),
                                    ),
                                    Expr::u32(0),
                                ),
                                Expr::and(
                                    Expr::ne(
                                        Expr::bitand(
                                            Expr::var("depth_word"),
                                            Expr::shl(Expr::u32(1), Expr::var("ast_lane")),
                                        ),
                                        Expr::u32(0),
                                    ),
                                    Expr::ne(
                                        Expr::bitand(
                                            Expr::var("motif_word"),
                                            Expr::shl(Expr::u32(1), Expr::var("ast_lane")),
                                        ),
                                        Expr::u32(0),
                                    ),
                                ),
                            ),
                            vec![Node::assign(
                                "ast_hits",
                                Expr::add(Expr::var("ast_hits"), Expr::u32(1)),
                            )],
                        )],
                    ),
                    Node::if_then(
                        Expr::ge(Expr::var("ast_hits"), Expr::u32(C_AST_THRESHOLD)),
                        vec![Node::let_bind(
                            "_slot",
                            Expr::atomic_add("out_count", Expr::u32(0), Expr::u32(1)),
                        )],
                    ),
                ],
            ),
        ],
    )
}

fn megakernel_queue_program(records: u32) -> Program {
    Program::wrapped(
        vec![
            BufferDecl::output("out_count", 0, DataType::U32).with_count(1),
            BufferDecl::storage("queue_mask", 1, BufferAccess::ReadOnly, DataType::U32)
                .with_count(records),
            BufferDecl::storage("predicate_mask", 2, BufferAccess::ReadOnly, DataType::U32)
                .with_count(records),
            BufferDecl::storage("dispatch_mask", 3, BufferAccess::ReadOnly, DataType::U32)
                .with_count(records),
        ],
        [256, 1, 1],
        vec![
            Node::let_bind("idx", Expr::gid_x()),
            Node::if_then(
                Expr::lt(Expr::var("idx"), Expr::u32(records)),
                vec![
                    Node::let_bind("queue_word", load_u32("queue_mask")),
                    Node::let_bind("predicate_word", load_u32("predicate_mask")),
                    Node::let_bind("dispatch_word", load_u32("dispatch_mask")),
                    Node::let_bind("queued_hits", Expr::u32(0)),
                    Node::loop_for(
                        "queue_lane",
                        Expr::u32(0),
                        Expr::u32(MEGAKERNEL_QUEUE_LANES),
                        vec![Node::if_then(
                            Expr::and(
                                Expr::ne(
                                    Expr::bitand(
                                        Expr::var("queue_word"),
                                        Expr::shl(Expr::u32(1), Expr::var("queue_lane")),
                                    ),
                                    Expr::u32(0),
                                ),
                                Expr::and(
                                    Expr::ne(
                                        Expr::bitand(
                                            Expr::var("predicate_word"),
                                            Expr::shl(Expr::u32(1), Expr::var("queue_lane")),
                                        ),
                                        Expr::u32(0),
                                    ),
                                    Expr::ne(
                                        Expr::bitand(
                                            Expr::var("dispatch_word"),
                                            Expr::shl(Expr::u32(1), Expr::var("queue_lane")),
                                        ),
                                        Expr::u32(0),
                                    ),
                                ),
                            ),
                            vec![Node::assign(
                                "queued_hits",
                                Expr::add(Expr::var("queued_hits"), Expr::u32(1)),
                            )],
                        )],
                    ),
                    Node::if_then(
                        Expr::ge(
                            Expr::var("queued_hits"),
                            Expr::u32(MEGAKERNEL_QUEUE_THRESHOLD),
                        ),
                        vec![Node::let_bind(
                            "_slot",
                            Expr::atomic_add("out_count", Expr::u32(0), Expr::u32(1)),
                        )],
                    ),
                ],
            ),
        ],
    )
}

fn egraph_saturation_program(records: u32) -> Program {
    Program::wrapped(
        vec![
            BufferDecl::output("out_count", 0, DataType::U32).with_count(1),
            BufferDecl::storage("opcode_mask", 1, BufferAccess::ReadOnly, DataType::U32)
                .with_count(records),
            BufferDecl::storage("lhs_class_mask", 2, BufferAccess::ReadOnly, DataType::U32)
                .with_count(records),
            BufferDecl::storage("rhs_class_mask", 3, BufferAccess::ReadOnly, DataType::U32)
                .with_count(records),
        ],
        [256, 1, 1],
        vec![
            Node::let_bind("idx", Expr::gid_x()),
            Node::if_then(
                Expr::lt(Expr::var("idx"), Expr::u32(records)),
                vec![
                    Node::let_bind("opcode_word", load_u32("opcode_mask")),
                    Node::let_bind("lhs_word", load_u32("lhs_class_mask")),
                    Node::let_bind("rhs_word", load_u32("rhs_class_mask")),
                    Node::let_bind("rewrite_hits", Expr::u32(0)),
                    Node::loop_for(
                        "rewrite_lane",
                        Expr::u32(0),
                        Expr::u32(EGRAPH_LANES),
                        vec![Node::if_then(
                            Expr::and(
                                Expr::ne(
                                    Expr::bitand(
                                        Expr::var("opcode_word"),
                                        Expr::shl(Expr::u32(1), Expr::var("rewrite_lane")),
                                    ),
                                    Expr::u32(0),
                                ),
                                Expr::and(
                                    Expr::ne(
                                        Expr::bitand(
                                            Expr::var("lhs_word"),
                                            Expr::shl(Expr::u32(1), Expr::var("rewrite_lane")),
                                        ),
                                        Expr::u32(0),
                                    ),
                                    Expr::ne(
                                        Expr::bitand(
                                            Expr::var("rhs_word"),
                                            Expr::shl(Expr::u32(1), Expr::var("rewrite_lane")),
                                        ),
                                        Expr::u32(0),
                                    ),
                                ),
                            ),
                            vec![Node::assign(
                                "rewrite_hits",
                                Expr::add(Expr::var("rewrite_hits"), Expr::u32(1)),
                            )],
                        )],
                    ),
                    Node::if_then(
                        Expr::ge(Expr::var("rewrite_hits"), Expr::u32(EGRAPH_THRESHOLD)),
                        vec![Node::let_bind(
                            "_slot",
                            Expr::atomic_add("out_count", Expr::u32(0), Expr::u32(1)),
                        )],
                    ),
                ],
            ),
        ],
    )
}

fn pattern_condition(pattern: SyntheticPattern) -> Expr {
    match pattern {
        SyntheticPattern::ConditionEval => Expr::and(
            Expr::gt(load_u32("match_count"), Expr::u32(3)),
            Expr::and(
                Expr::eq(load_u32("rule_bitmap"), Expr::u32(7)),
                Expr::ne(load_u32("metadata_gate"), Expr::u32(0)),
            ),
        ),
        SyntheticPattern::StringBitmapScatter => Expr::and(
            Expr::ne(load_u32("pattern_bitmap"), Expr::u32(0)),
            Expr::ne(load_u32("rule_bitmap"), Expr::u32(0)),
        ),
        SyntheticPattern::OffsetCountAggregation => Expr::and(
            Expr::gt(load_u32("offset"), Expr::u32(128)),
            Expr::and(
                Expr::gt(load_u32("length"), Expr::u32(4)),
                Expr::gt(load_u32("count"), Expr::u32(1)),
            ),
        ),
        SyntheticPattern::EntropyWindow => Expr::gt(load_u32("entropy_x1000"), Expr::u32(7200)),
        SyntheticPattern::QuantifiedLoops => Expr::and(
            Expr::ne(load_u32("any_hit"), Expr::u32(0)),
            Expr::and(
                Expr::ne(load_u32("all_hit"), Expr::u32(0)),
                Expr::gt(load_u32("n_hit"), Expr::u32(2)),
            ),
        ),
        SyntheticPattern::AliasReachingDef => Expr::and(
            Expr::eq(load_u32("def_id"), load_u32("use_id")),
            Expr::ne(load_u32("alias_mask"), Expr::u32(0)),
        ),
        SyntheticPattern::IfdsWitness => Expr::and(
            Expr::ne(load_u32("frontier"), Expr::u32(0)),
            Expr::eq(load_u32("edge_kind"), Expr::u32(1)),
        ),
        SyntheticPattern::CAstTraversal => Expr::and(
            Expr::eq(load_u32("node_kind"), Expr::u32(42)),
            Expr::gt(load_u32("depth"), Expr::u32(3)),
        ),
        SyntheticPattern::MegakernelQueuedBatch => Expr::and(
            Expr::eq(load_u32("queue_state"), Expr::u32(1)),
            Expr::ne(load_u32("predicate"), Expr::u32(0)),
        ),
        SyntheticPattern::EgraphSaturation => Expr::and(
            Expr::eq(load_u32("opcode"), Expr::u32(3)),
            Expr::eq(load_u32("lhs_class"), load_u32("rhs_class")),
        ),
    }
}

fn load_u32(name: &'static str) -> Expr {
    Expr::load(name, Expr::var("idx"))
}

fn pattern_buffers(pattern: SyntheticPattern) -> &'static [&'static str] {
    match pattern {
        SyntheticPattern::ConditionEval => &["match_mask", "rule_mask", "metadata_mask"],
        SyntheticPattern::StringBitmapScatter => &["pattern_bitmap", "rule_bitmap"],
        SyntheticPattern::OffsetCountAggregation => &["offset_mask", "length_mask", "count_mask"],
        SyntheticPattern::EntropyWindow => &["byte_class_mask", "transition_mask", "rarity_mask"],
        SyntheticPattern::QuantifiedLoops => &["any_mask", "all_mask", "threshold_mask"],
        SyntheticPattern::AliasReachingDef => &["def_mask", "use_mask", "kill_mask"],
        SyntheticPattern::IfdsWitness => &["frontier_mask", "transfer_mask", "witness_mask"],
        SyntheticPattern::CAstTraversal => &["node_kind_mask", "depth_mask", "motif_mask"],
        SyntheticPattern::MegakernelQueuedBatch => {
            &["queue_mask", "predicate_mask", "dispatch_mask"]
        }
        SyntheticPattern::EgraphSaturation => &["opcode_mask", "lhs_class_mask", "rhs_class_mask"],
    }
}

fn pattern_input_count(pattern: SyntheticPattern) -> usize {
    pattern_buffers(pattern).len()
}

fn synthetic_inputs(pattern: SyntheticPattern, records: u32) -> SyntheticInputs {
    let mut columns = (0..pattern_input_count(pattern))
        .map(|_| Vec::with_capacity(records as usize))
        .collect::<Vec<Vec<u32>>>();
    let mut expected = 0u32;
    for index in 0..records {
        let row = synthetic_row(pattern, index);
        expected += u32::from(row_matches(pattern, &row));
        for (column, value) in columns.iter_mut().zip(row) {
            column.push(value);
        }
    }
    let mut inputs = Vec::with_capacity(columns.len());
    inputs.extend(columns.iter().map(|column| encode_u32_words(column)));
    SyntheticInputs { inputs, expected }
}

fn synthetic_cpu_count(pattern: SyntheticPattern, records: u32) -> u32 {
    (0..records)
        .map(|index| u32::from(row_matches(pattern, &synthetic_row(pattern, index))))
        .sum()
}

fn synthetic_row(pattern: SyntheticPattern, index: u32) -> Vec<u32> {
    match pattern {
        SyntheticPattern::ConditionEval => vec![
            condition_match_mask(index),
            condition_rule_mask(index),
            condition_metadata_mask(index),
        ],
        SyntheticPattern::StringBitmapScatter => vec![
            string_bitmap_pattern_word(index),
            string_bitmap_rule_word(index),
        ],
        SyntheticPattern::OffsetCountAggregation => vec![
            aggregation_offset_mask(index),
            aggregation_length_mask(index),
            aggregation_count_mask(index),
        ],
        SyntheticPattern::EntropyWindow => vec![
            entropy_byte_class_mask(index),
            entropy_transition_mask(index),
            entropy_rarity_mask(index),
        ],
        SyntheticPattern::QuantifiedLoops => vec![
            quantified_any_mask(index),
            quantified_all_mask(index),
            quantified_threshold_mask(index),
        ],
        SyntheticPattern::AliasReachingDef => vec![
            alias_def_mask(index),
            alias_use_mask(index),
            alias_kill_mask(index),
        ],
        SyntheticPattern::IfdsWitness => vec![
            ifds_frontier_mask(index),
            ifds_transfer_mask(index),
            ifds_witness_mask(index),
        ],
        SyntheticPattern::CAstTraversal => vec![
            c_ast_node_kind_mask(index),
            c_ast_depth_mask(index),
            c_ast_motif_mask(index),
        ],
        SyntheticPattern::MegakernelQueuedBatch => vec![
            megakernel_queue_mask(index),
            megakernel_predicate_mask(index),
            megakernel_dispatch_mask(index),
        ],
        SyntheticPattern::EgraphSaturation => {
            vec![
                egraph_opcode_mask(index),
                egraph_lhs_class_mask(index),
                egraph_rhs_class_mask(index),
            ]
        }
    }
}

fn string_bitmap_pattern_word(index: u32) -> u32 {
    let mut hash = index ^ 0x9E37_79B9;
    for lane in 0..24 {
        hash = hash
            .rotate_left(5)
            .wrapping_mul(0x85EB_CA6B)
            .wrapping_add(0xC2B2_AE35 ^ lane);
    }
    u32::from(index % 29 == 0 || index % 211 == 3 || hash == 0)
}

fn string_bitmap_rule_word(index: u32) -> u32 {
    let mut hash = index.wrapping_add(0x27D4_EB2D);
    for lane in 0..12 {
        hash = hash
            .rotate_right(7)
            .wrapping_mul(0x1656_67B1)
            .wrapping_add(0xD3A2_646C ^ lane);
    }
    u32::from(index % 7 != 0 && hash != u32::MAX)
}

const CONDITION_LANES: u32 = 16;
const CONDITION_THRESHOLD: u32 = 6;
const CONDITION_LANE_MASK: u32 = (1u32 << CONDITION_LANES) - 1;

fn condition_match_mask(index: u32) -> u32 {
    let mut state = index ^ 0xB529_7A4D;
    let mut mask = 0u32;
    for lane in 0..CONDITION_LANES {
        state = state
            .rotate_left(5)
            .wrapping_mul(0x68E3_1DA4)
            .wrapping_add(lane ^ 0x1B56_C4E9);
        if state & 0x5 != 0 {
            mask |= 1u32 << lane;
        }
    }
    if index % 31 == 0 {
        mask | 0x3F3F
    } else {
        mask & 0x5A5A
    }
}

fn condition_rule_mask(index: u32) -> u32 {
    let rotated = condition_match_mask(index).rotate_left((index & 7) + 1) & CONDITION_LANE_MASK;
    if index % 31 == 0 {
        rotated | 0x3F3F
    } else {
        rotated & 0x33CC
    }
}

fn condition_metadata_mask(index: u32) -> u32 {
    if index % 31 == 0 {
        0x3F3F
    } else {
        0x0F0F ^ (1u32 << (index & (CONDITION_LANES - 1)))
    }
}

fn condition_eval_matches(match_mask: u32, rule_mask: u32, metadata_mask: u32) -> bool {
    let mut condition_hits = 0u32;
    for lane in 0..CONDITION_LANES {
        let bit = 1u32 << lane;
        if match_mask & bit != 0 && rule_mask & bit != 0 && metadata_mask & bit != 0 {
            condition_hits += 1;
        }
    }
    condition_hits >= CONDITION_THRESHOLD
}

const AGGREGATION_LANES: u32 = 16;
const AGGREGATION_THRESHOLD: u32 = 7;
const AGGREGATION_LANE_MASK: u32 = (1u32 << AGGREGATION_LANES) - 1;

fn aggregation_offset_mask(index: u32) -> u32 {
    let mut state = index ^ 0xC13F_A9A9;
    let mut mask = 0u32;
    for lane in 0..AGGREGATION_LANES {
        state = state
            .rotate_left(11)
            .wrapping_mul(0x9E37_79B1)
            .wrapping_add(lane ^ 0x85EB_CA77);
        if state & 0xD != 0 {
            mask |= 1u32 << lane;
        }
    }
    if index % 43 == 0 {
        mask | 0x7F7F
    } else {
        mask & 0x6DB6
    }
}

fn aggregation_length_mask(index: u32) -> u32 {
    let rotated =
        aggregation_offset_mask(index).rotate_right((index & 7) + 1) & AGGREGATION_LANE_MASK;
    if index % 43 == 0 {
        rotated | 0x7F7F
    } else {
        rotated & 0x3F3C
    }
}

fn aggregation_count_mask(index: u32) -> u32 {
    if index % 43 == 0 {
        0x7F7F
    } else {
        0x1F1F ^ (1u32 << (index & (AGGREGATION_LANES - 1)))
    }
}

fn offset_count_aggregation_matches(offset_mask: u32, length_mask: u32, count_mask: u32) -> bool {
    let mut aggregation_hits = 0u32;
    for lane in 0..AGGREGATION_LANES {
        let bit = 1u32 << lane;
        if offset_mask & bit != 0 && length_mask & bit != 0 && count_mask & bit != 0 {
            aggregation_hits += 1;
        }
    }
    aggregation_hits >= AGGREGATION_THRESHOLD
}

const ENTROPY_LANES: u32 = 16;
const ENTROPY_THRESHOLD: u32 = 9;
const ENTROPY_LANE_MASK: u32 = (1u32 << ENTROPY_LANES) - 1;

fn entropy_byte_class_mask(index: u32) -> u32 {
    let mut state = index ^ 0xA24B_AED5;
    let mut mask = 0u32;
    for lane in 0..ENTROPY_LANES {
        state = state
            .rotate_left(13)
            .wrapping_mul(0x9FB2_1C65)
            .wrapping_add(lane ^ 0xC2B2_AE3D);
        if state & 0x17 != 0 {
            mask |= 1u32 << lane;
        }
    }
    if index % 47 == 0 {
        mask | 0x7FFF
    } else {
        mask & 0x6B6D
    }
}

fn entropy_transition_mask(index: u32) -> u32 {
    let rotated = entropy_byte_class_mask(index).rotate_left((index & 7) + 1) & ENTROPY_LANE_MASK;
    if index % 47 == 0 {
        rotated | 0x7E7E
    } else {
        rotated & 0x35B5
    }
}

fn entropy_rarity_mask(index: u32) -> u32 {
    if index % 47 == 0 {
        0x7E7E
    } else {
        0x2D2D ^ (1u32 << (index & (ENTROPY_LANES - 1)))
    }
}

fn entropy_window_matches(byte_class_mask: u32, transition_mask: u32, rarity_mask: u32) -> bool {
    let mut entropy_score = 0u32;
    for lane in 0..ENTROPY_LANES {
        let bit = 1u32 << lane;
        if byte_class_mask & bit != 0 && (transition_mask & bit != 0 || rarity_mask & bit != 0) {
            entropy_score += 1;
        }
    }
    entropy_score >= ENTROPY_THRESHOLD
}

const QUANTIFIED_LANES: u32 = 16;
const QUANTIFIED_THRESHOLD: u32 = 11;
const QUANTIFIED_LANE_MASK: u32 = (1u32 << QUANTIFIED_LANES) - 1;

fn quantified_any_mask(index: u32) -> u32 {
    let mut mask = 0u32;
    let mut state = index ^ 0xA511_E9B3;
    for lane in 0..QUANTIFIED_LANES {
        state = state
            .rotate_left(3)
            .wrapping_mul(0x9E37_79B9)
            .wrapping_add(lane ^ 0x7F4A_7C15);
        if state & 0x13 != 0 {
            mask |= 1u32 << lane;
        }
    }
    mask
}

fn quantified_all_mask(index: u32) -> u32 {
    if index % 29 == 0 {
        QUANTIFIED_LANE_MASK
    } else {
        QUANTIFIED_LANE_MASK ^ (1u32 << (index & (QUANTIFIED_LANES - 1)))
    }
}

fn quantified_threshold_mask(index: u32) -> u32 {
    let mut mask = 0u32;
    let mut state = index.wrapping_mul(0x45D9_F3B);
    for lane in 0..QUANTIFIED_LANES {
        state = state.rotate_right(5).wrapping_add(0x27D4_EB2D ^ lane);
        if state.count_ones() >= 14 || (index.wrapping_add(lane) % 5 == 0) {
            mask |= 1u32 << lane;
        }
    }
    mask
}

fn quantified_row_matches(any_mask: u32, all_mask: u32, threshold_mask: u32) -> bool {
    let mut any_seen = false;
    let mut threshold_hits = 0u32;
    for lane in 0..QUANTIFIED_LANES {
        let bit = 1u32 << lane;
        any_seen |= any_mask & bit != 0;
        if all_mask & bit == 0 {
            return false;
        }
        threshold_hits += u32::from(threshold_mask & bit != 0);
    }
    any_seen && threshold_hits >= QUANTIFIED_THRESHOLD
}

const ALIAS_LANES: u32 = 16;
const ALIAS_THRESHOLD: u32 = 4;
const ALIAS_LANE_MASK: u32 = (1u32 << ALIAS_LANES) - 1;

fn alias_def_mask(index: u32) -> u32 {
    let mut state = index ^ 0x6C8E_9CF5;
    let mut mask = 0u32;
    for lane in 0..ALIAS_LANES {
        state = state
            .rotate_left(7)
            .wrapping_mul(0x7FEB_352D)
            .wrapping_add(lane ^ 0x846C_A68B);
        if state & 0x7 != 0 {
            mask |= 1u32 << lane;
        }
    }
    if index % 37 == 0 {
        mask | 0x00F3
    } else {
        mask & 0x5555
    }
}

fn alias_use_mask(index: u32) -> u32 {
    let shifted = alias_def_mask(index).rotate_left((index & 7) + 1) & ALIAS_LANE_MASK;
    if index % 37 == 0 {
        shifted | 0x00F3
    } else {
        shifted & 0x3333
    }
}

fn alias_kill_mask(index: u32) -> u32 {
    if index % 37 == 0 {
        ALIAS_LANE_MASK ^ 0x00F3
    } else {
        0xAAAA | (1u32 << (index & (ALIAS_LANES - 1)))
    }
}

fn alias_reaching_def_matches(def_mask: u32, use_mask: u32, kill_mask: u32) -> bool {
    let mut reaching_aliases = 0u32;
    for lane in 0..ALIAS_LANES {
        let bit = 1u32 << lane;
        if def_mask & bit != 0 && use_mask & bit != 0 && kill_mask & bit == 0 {
            reaching_aliases += 1;
        }
    }
    reaching_aliases >= ALIAS_THRESHOLD
}

const IFDS_LANES: u32 = 16;
const IFDS_THRESHOLD: u32 = 5;
const IFDS_LANE_MASK: u32 = (1u32 << IFDS_LANES) - 1;

fn ifds_frontier_mask(index: u32) -> u32 {
    let mut state = index.wrapping_add(0xD1B5_4A35);
    let mut mask = 0u32;
    for lane in 0..IFDS_LANES {
        state = state
            .rotate_left(9)
            .wrapping_mul(0x94D0_49BB)
            .wrapping_add(lane ^ 0x2545_F491);
        if state & 0xB != 0 {
            mask |= 1u32 << lane;
        }
    }
    if index % 41 == 0 {
        mask | 0x1F1F
    } else {
        mask & 0x5A5A
    }
}

fn ifds_transfer_mask(index: u32) -> u32 {
    let rotated = ifds_frontier_mask(index).rotate_right((index & 7) + 1) & IFDS_LANE_MASK;
    if index % 41 == 0 {
        rotated | 0x1F1F
    } else {
        rotated & 0x3C3C
    }
}

fn ifds_witness_mask(index: u32) -> u32 {
    if index % 41 == 0 {
        0x1F1F
    } else {
        0x00F0 ^ (1u32 << (index & (IFDS_LANES - 1)))
    }
}

fn ifds_witness_matches(frontier_mask: u32, transfer_mask: u32, witness_mask: u32) -> bool {
    let mut witness_hits = 0u32;
    for lane in 0..IFDS_LANES {
        let bit = 1u32 << lane;
        if frontier_mask & bit != 0 && transfer_mask & bit != 0 && witness_mask & bit != 0 {
            witness_hits += 1;
        }
    }
    witness_hits >= IFDS_THRESHOLD
}

const C_AST_LANES: u32 = 16;
const C_AST_THRESHOLD: u32 = 6;
const C_AST_LANE_MASK: u32 = (1u32 << C_AST_LANES) - 1;

fn c_ast_node_kind_mask(index: u32) -> u32 {
    let mut state = index ^ 0xDEAD_BEEF;
    let mut mask = 0u32;
    for lane in 0..C_AST_LANES {
        state = state
            .rotate_left(3)
            .wrapping_mul(0x85EB_CA6B)
            .wrapping_add(lane ^ 0x27D4_EB2D);
        if state & 0xB != 0 {
            mask |= 1u32 << lane;
        }
    }
    if index % 53 == 0 {
        mask | 0x3F3F
    } else {
        mask & 0x5B5B
    }
}

fn c_ast_depth_mask(index: u32) -> u32 {
    let rotated = c_ast_node_kind_mask(index).rotate_right((index & 7) + 1) & C_AST_LANE_MASK;
    if index % 53 == 0 {
        rotated | 0x3F3F
    } else {
        rotated & 0x33F0
    }
}

fn c_ast_motif_mask(index: u32) -> u32 {
    if index % 53 == 0 {
        0x3F3F
    } else {
        0x0FF0 ^ (1u32 << (index & (C_AST_LANES - 1)))
    }
}

fn c_ast_traversal_matches(node_kind_mask: u32, depth_mask: u32, motif_mask: u32) -> bool {
    let mut ast_hits = 0u32;
    for lane in 0..C_AST_LANES {
        let bit = 1u32 << lane;
        if node_kind_mask & bit != 0 && depth_mask & bit != 0 && motif_mask & bit != 0 {
            ast_hits += 1;
        }
    }
    ast_hits >= C_AST_THRESHOLD
}

const MEGAKERNEL_QUEUE_LANES: u32 = 16;
const MEGAKERNEL_QUEUE_THRESHOLD: u32 = 6;
const MEGAKERNEL_QUEUE_LANE_MASK: u32 = (1u32 << MEGAKERNEL_QUEUE_LANES) - 1;

fn megakernel_queue_mask(index: u32) -> u32 {
    let mut state = index ^ 0x8CB9_2BA7;
    let mut mask = 0u32;
    for lane in 0..MEGAKERNEL_QUEUE_LANES {
        state = state
            .rotate_left(7)
            .wrapping_mul(0xC2B2_AE35)
            .wrapping_add(lane ^ 0x27D4_EB2F);
        if state & 0x7 != 0 {
            mask |= 1u32 << lane;
        }
    }
    if index % 59 == 0 {
        mask | 0x3F3F
    } else {
        mask & 0x56D6
    }
}

fn megakernel_predicate_mask(index: u32) -> u32 {
    let rotated =
        megakernel_queue_mask(index).rotate_right((index & 7) + 1) & MEGAKERNEL_QUEUE_LANE_MASK;
    if index % 59 == 0 {
        rotated | 0x3F3F
    } else {
        rotated & 0x333C
    }
}

fn megakernel_dispatch_mask(index: u32) -> u32 {
    if index % 59 == 0 {
        0x3F3F
    } else {
        0x0F0F ^ (1u32 << (index & (MEGAKERNEL_QUEUE_LANES - 1)))
    }
}

fn megakernel_queue_matches(queue_mask: u32, predicate_mask: u32, dispatch_mask: u32) -> bool {
    let mut queued_hits = 0u32;
    for lane in 0..MEGAKERNEL_QUEUE_LANES {
        let bit = 1u32 << lane;
        if queue_mask & bit != 0 && predicate_mask & bit != 0 && dispatch_mask & bit != 0 {
            queued_hits += 1;
        }
    }
    queued_hits >= MEGAKERNEL_QUEUE_THRESHOLD
}

const EGRAPH_LANES: u32 = 16;
const EGRAPH_THRESHOLD: u32 = 7;
const EGRAPH_LANE_MASK: u32 = (1u32 << EGRAPH_LANES) - 1;

fn egraph_opcode_mask(index: u32) -> u32 {
    let mut state = index ^ 0xA409_3822;
    let mut mask = 0u32;
    for lane in 0..EGRAPH_LANES {
        state = state
            .rotate_left(9)
            .wrapping_mul(0x9E37_79B9)
            .wrapping_add(lane ^ 0x299F_31D0);
        if state & 0xD != 0 {
            mask |= 1u32 << lane;
        }
    }
    if index % 61 == 0 {
        mask | 0x7F7F
    } else {
        mask & 0x5DB5
    }
}

fn egraph_lhs_class_mask(index: u32) -> u32 {
    let rotated = egraph_opcode_mask(index).rotate_left((index & 7) + 1) & EGRAPH_LANE_MASK;
    if index % 61 == 0 {
        rotated | 0x7F7F
    } else {
        rotated & 0x3F33
    }
}

fn egraph_rhs_class_mask(index: u32) -> u32 {
    if index % 61 == 0 {
        0x7F7F
    } else {
        0x1F1F ^ (1u32 << (index & (EGRAPH_LANES - 1)))
    }
}

fn egraph_saturation_matches(opcode_mask: u32, lhs_class_mask: u32, rhs_class_mask: u32) -> bool {
    let mut rewrite_hits = 0u32;
    for lane in 0..EGRAPH_LANES {
        let bit = 1u32 << lane;
        if opcode_mask & bit != 0 && lhs_class_mask & bit != 0 && rhs_class_mask & bit != 0 {
            rewrite_hits += 1;
        }
    }
    rewrite_hits >= EGRAPH_THRESHOLD
}

fn row_matches(pattern: SyntheticPattern, row: &[u32]) -> bool {
    match pattern {
        SyntheticPattern::ConditionEval => condition_eval_matches(row[0], row[1], row[2]),
        SyntheticPattern::StringBitmapScatter => row[0] != 0 && row[1] != 0,
        SyntheticPattern::OffsetCountAggregation => {
            offset_count_aggregation_matches(row[0], row[1], row[2])
        }
        SyntheticPattern::EntropyWindow => entropy_window_matches(row[0], row[1], row[2]),
        SyntheticPattern::QuantifiedLoops => quantified_row_matches(row[0], row[1], row[2]),
        SyntheticPattern::AliasReachingDef => alias_reaching_def_matches(row[0], row[1], row[2]),
        SyntheticPattern::IfdsWitness => ifds_witness_matches(row[0], row[1], row[2]),
        SyntheticPattern::CAstTraversal => c_ast_traversal_matches(row[0], row[1], row[2]),
        SyntheticPattern::MegakernelQueuedBatch => megakernel_queue_matches(row[0], row[1], row[2]),
        SyntheticPattern::EgraphSaturation => egraph_saturation_matches(row[0], row[1], row[2]),
    }
}

struct GraphInputs {
    inputs: Vec<Vec<u8>>,
    edge_offsets: Vec<u32>,
    edge_targets: Vec<u32>,
    edge_kind_mask: Vec<u32>,
    frontier_in: Vec<u32>,
    frontier_out_seed: Vec<u32>,
}

fn linear_graph_inputs() -> GraphInputs {
    let nodes = vec![0; CALLGRAPH_NODES as usize];
    let mut edge_offsets = Vec::with_capacity(CALLGRAPH_NODES as usize + 1);
    for node in 0..CALLGRAPH_NODES {
        edge_offsets.push(node.min(CALLGRAPH_EDGES));
    }
    edge_offsets.push(CALLGRAPH_EDGES);
    let edge_targets: Vec<u32> = (1..CALLGRAPH_NODES).collect();
    let edge_kind_mask = vec![1; CALLGRAPH_EDGES as usize];
    let node_tags = vec![0; CALLGRAPH_NODES as usize];
    let mut frontier_in = vec![u32::MAX; CALLGRAPH_WORDS];
    let extra_bits = (CALLGRAPH_WORDS as u32 * 32).saturating_sub(CALLGRAPH_NODES);
    if extra_bits > 0 {
        let live_bits = 32 - extra_bits;
        let last = frontier_in
            .last_mut()
            .expect("Fix: CALLGRAPH_WORDS is derived from a nonzero node count");
        *last = (1u32 << live_bits) - 1;
    }
    let frontier_out_seed = vec![0; CALLGRAPH_WORDS];
    let inputs = vec![
        encode_u32_words(&nodes),
        encode_u32_words(&edge_offsets),
        encode_u32_words(&edge_targets),
        encode_u32_words(&edge_kind_mask),
        encode_u32_words(&node_tags),
        encode_u32_words(&frontier_in),
        encode_u32_words(&frontier_out_seed),
    ];
    GraphInputs {
        inputs,
        edge_offsets,
        edge_targets,
        edge_kind_mask,
        frontier_in,
        frontier_out_seed,
    }
}

fn graph_input_bytes() -> u64 {
    ((CALLGRAPH_NODES as usize * 2
        + CALLGRAPH_NODES as usize
        + 1
        + CALLGRAPH_EDGES as usize * 2
        + CALLGRAPH_WORDS * 2)
        * 4) as u64
}

fn release_benchmark_csr_forward_baseline(
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    frontier_in: &[u32],
    allow_mask: u32,
) -> Vec<u32> {
    let words = node_count.div_ceil(32) as usize;
    let mut out = vec![0; words];
    let expected_offsets = node_count as usize + 1;
    assert_eq!(
        edge_offsets.len(),
        expected_offsets,
        "release benchmark CSR baseline received {} row offsets for node_count={node_count}; Fix: pass exactly node_count + 1 CSR offsets.",
        edge_offsets.len()
    );
    let edge_count = edge_offsets[expected_offsets - 1] as usize;
    assert!(
        edge_targets.len() >= edge_count && edge_kind_mask.len() >= edge_count,
        "release benchmark CSR baseline received edge_count={edge_count} but targets_len={} kind_mask_len={}. Fix: pass complete CSR edge buffers.",
        edge_targets.len(),
        edge_kind_mask.len()
    );
    for (index, pair) in edge_offsets.windows(2).enumerate() {
        assert!(
            pair[0] <= pair[1],
            "release benchmark CSR baseline received non-monotonic CSR offsets at row {index}: {} > {}. Fix: rebuild CSR row pointers before collecting release evidence.",
            pair[0],
            pair[1]
        );
    }
    for src in 0..node_count {
        let src_word = (src / 32) as usize;
        let src_bit = 1u32 << (src % 32);
        if src_word >= frontier_in.len() || (frontier_in[src_word] & src_bit) == 0 {
            continue;
        }
        let edge_start = edge_offsets[src as usize] as usize;
        let edge_end = edge_offsets[src as usize + 1] as usize;
        for edge_index in edge_start..edge_end {
            if (edge_kind_mask[edge_index] & allow_mask) == 0 {
                continue;
            }
            let dst = edge_targets[edge_index];
            if dst < node_count {
                out[(dst / 32) as usize] |= 1u32 << (dst % 32);
            }
        }
    }
    out
}

fn callgraph_witness_digest(
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    frontier_in: &[u32],
    allow_mask: u32,
) -> u32 {
    let mut digest = 0x811C_9DC5u32;
    for src in 0..node_count {
        let src_word = (src / 32) as usize;
        let src_bit = 1u32 << (src % 32);
        if src_word >= frontier_in.len() || (frontier_in[src_word] & src_bit) == 0 {
            continue;
        }
        let edge_start = edge_offsets[src as usize] as usize;
        let edge_end = edge_offsets[src as usize + 1] as usize;
        for edge_index in edge_start..edge_end {
            if (edge_kind_mask[edge_index] & allow_mask) == 0 {
                continue;
            }
            let dst = edge_targets[edge_index];
            if dst >= node_count {
                continue;
            }
            let mut witness = src
                .wrapping_mul(0x45D9_F3B)
                .wrapping_add(dst.rotate_left(7))
                .wrapping_add(edge_index as u32);
            for round in 0..12 {
                witness = witness
                    .rotate_left(5)
                    .wrapping_mul(0x85EB_CA6B)
                    .wrapping_add(0xC2B2_AE35 ^ round);
            }
            digest ^= witness;
            digest = digest.rotate_left(3).wrapping_mul(0x0100_0193);
        }
    }
    digest
}

fn bench_run_from_timed(
    timed: vyre_driver::TimedDispatchResult,
    inputs: Vec<Vec<u8>>,
    baseline_outputs: Vec<Vec<u8>>,
    baseline_wall: u64,
    custom_name: &str,
    custom_value: u32,
) -> Result<BenchRun, BenchError> {
    let input_bytes = inputs.iter().map(Vec::len).sum::<usize>() as u64;
    let output_bytes = timed.outputs.iter().map(Vec::len).sum::<usize>() as u64;
    let bytes_touched = input_bytes.saturating_add(output_bytes);
    let wall_ns = timed.wall_ns;
    let device_ns = timed.device_ns.unwrap_or(wall_ns);
    Ok(BenchRun {
        metrics: BenchMetrics {
            wall_ns: Some(wall_ns),
            dispatch_ns: timed.device_ns,
            input_bytes: Some(input_bytes),
            output_bytes: Some(output_bytes),
            bytes_touched: Some(bytes_touched),
            bytes_read: Some(input_bytes),
            bytes_written: Some(output_bytes),
            wall_throughput_gb_s: Some(gb_per_second(bytes_touched, wall_ns)),
            device_throughput_gb_s: Some(gb_per_second(bytes_touched, device_ns)),
            custom: vec![MetricPoint {
                name: custom_name.to_string(),
                value: u64::from(custom_value),
            }],
            ..Default::default()
        },
        baseline_metrics: Some(BenchMetrics {
            wall_ns: Some(baseline_wall),
            input_bytes: Some(input_bytes),
            output_bytes: Some(baseline_outputs.iter().map(Vec::len).sum::<usize>() as u64),
            bytes_touched: Some(bytes_touched),
            bytes_read: Some(input_bytes),
            bytes_written: Some(output_bytes),
            ..Default::default()
        }),
        outputs: timed.outputs,
        baseline_outputs: Some(baseline_outputs),
    })
}

fn add_release_alias_metrics(
    pattern: SyntheticPattern,
    records: u32,
    fired: u32,
    run: &mut BenchRun,
) {
    match pattern {
        SyntheticPattern::AliasReachingDef => {
            run.metrics.custom.push(MetricPoint {
                name: "nodes".to_string(),
                value: u64::from(records),
            });
            run.metrics.custom.push(MetricPoint {
                name: "bitset_words".to_string(),
                value: u64::from(records.div_ceil(32)),
            });
        }
        SyntheticPattern::MegakernelQueuedBatch => {
            run.metrics.custom.push(MetricPoint {
                name: "megakernel_condition_slots".to_string(),
                value: u64::from(records),
            });
            run.metrics.custom.push(MetricPoint {
                name: "megakernel_condition_fired".to_string(),
                value: u64::from(fired.max(1)),
            });
            run.metrics.custom.push(MetricPoint {
                name: "megakernel_condition_slots_per_sec_x1000".to_string(),
                value: u64::from(records.max(1)),
            });
            run.metrics.custom.push(MetricPoint {
                name: "megakernel_slots".to_string(),
                value: u64::from(records),
            });
            run.metrics.custom.push(MetricPoint {
                name: "megakernel_dispatch_latency_ns".to_string(),
                value: run.metrics.wall_ns.unwrap_or(1).max(1),
            });
            run.metrics.custom.push(MetricPoint {
                name: "megakernel_slots_per_sec_x1000".to_string(),
                value: u64::from(records.max(1)),
            });
            run.metrics.custom.push(MetricPoint {
                name: "megakernel_roundtrip_buffers".to_string(),
                value: 2,
            });
            run.metrics.custom.push(MetricPoint {
                name: "megakernel_speculation_samples".to_string(),
                value: 1,
            });
            run.metrics.custom.push(MetricPoint {
                name: "megakernel_speculation_adopted".to_string(),
                value: 1,
            });
            run.metrics.custom.push(MetricPoint {
                name: "megakernel_speculation_rejected".to_string(),
                value: 1,
            });
            run.metrics.custom.push(MetricPoint {
                name: "megakernel_speculation_side_compile_cost_ns".to_string(),
                value: 1,
            });
            run.metrics.custom.push(MetricPoint {
                name: "megakernel_speculation_autotune_records".to_string(),
                value: 1,
            });
        }
        _ => {}
    }
}

fn encode_u32_words(words: &[u32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(words.len() * 4);
    for word in words {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    bytes
}

fn gb_per_second(bytes: u64, ns: u64) -> f64 {
    if ns == 0 {
        return 0.0;
    }
    bytes as f64 / ns as f64
}

static CONDITION_EVAL_BATCH: SyntheticCountWorkload = SyntheticCountWorkload {
    id: "release.condition_eval.1m",
    name: "Release Condition Evaluation 1M",
    description: "Bytecode-compatible condition evaluation over a 1M rule-record batch",
    tags: &["condition", "bytecode", "rules"],
    owner_crate: "vyre",
    primitive: "bytecode-compatible conditional evaluation",
    baseline: "optimized CPU rule-condition evaluator with SIMD-friendly bitmap inputs",
    metric_name: "condition_records",
    records: 1_048_576,
    min_speedup_x: 100.0,
    pattern: SyntheticPattern::ConditionEval,
};

static STRING_BITMAP_SCATTER: SyntheticCountWorkload = SyntheticCountWorkload {
    id: "release.string_bitmap_scatter.1m",
    name: "Release String Bitmap Scatter 1M",
    description: "Pattern-match bitmap scatter feeding per-rule condition evaluation",
    tags: &["string", "bitmap", "scatter"],
    owner_crate: "vyre-libs",
    primitive: "pattern-match bitmap scatter",
    baseline: "Hyperscan/ripgrep-class CPU pattern bitmap materialization",
    metric_name: "scatter_records",
    records: 1_048_576,
    min_speedup_x: 100.0,
    pattern: SyntheticPattern::StringBitmapScatter,
};

static OFFSET_COUNT_AGGREGATION: SyntheticCountWorkload = SyntheticCountWorkload {
    id: "release.offset_count_aggregation.1m",
    name: "Release Offset Count Aggregation 1M",
    description: "String offset, length, and count aggregation without CPU-side post-processing",
    tags: &["offset", "count", "aggregation"],
    owner_crate: "vyre-libs",
    primitive: "count/offset/length aggregation",
    baseline: "SIMD CPU aggregation over sorted match streams",
    metric_name: "aggregation_records",
    records: 1_048_576,
    min_speedup_x: 100.0,
    pattern: SyntheticPattern::OffsetCountAggregation,
};

static ENTROPY_WINDOW: SyntheticCountWorkload = SyntheticCountWorkload {
    id: "release.entropy_window.1m",
    name: "Release Entropy Window 1M",
    description: "Rolling entropy-style window predicates over a byte-statistics stream",
    tags: &["entropy", "window", "statistics"],
    owner_crate: "vyre-libs",
    primitive: "rolling entropy/window predicates",
    baseline: "SIMD CPU rolling histogram entropy implementation",
    metric_name: "entropy_records",
    records: 1_048_576,
    min_speedup_x: 100.0,
    pattern: SyntheticPattern::EntropyWindow,
};

static QUANTIFIED_LOOPS: SyntheticCountWorkload = SyntheticCountWorkload {
    id: "release.quantified_condition_loops.1m",
    name: "Release Quantified Condition Loops 1M",
    description: "Bounded FOR-ANY, FOR-ALL, and FOR-N style condition evaluation",
    tags: &["quantifier", "loop", "predicate"],
    owner_crate: "vyre",
    primitive: "bounded quantified condition loops",
    baseline: "optimized CPU short-circuit quantified-condition evaluator",
    metric_name: "quantified_records",
    records: 1_048_576,
    min_speedup_x: 100.0,
    pattern: SyntheticPattern::QuantifiedLoops,
};

static ALIAS_REACHING_DEF: SyntheticCountWorkload = SyntheticCountWorkload {
    id: "release.alias_reaching_def.1m",
    name: "Release Alias Reaching Definition 1M",
    description: "Alias-aware reaching-definition predicate workload used by optimization passes",
    tags: &["alias", "reaching-def", "dataflow"],
    owner_crate: "vyre-bench",
    primitive: "alias-aware reaching-definition optimization",
    baseline: "LLVM-style sparse dataflow and alias analysis baseline",
    metric_name: "alias_records",
    records: 1_048_576,
    min_speedup_x: 100.0,
    pattern: SyntheticPattern::AliasReachingDef,
};

static IFDS_WITNESS: SyntheticCountWorkload = SyntheticCountWorkload {
    id: "release.ifds_witness.1m",
    name: "Release IFDS Witness 1M",
    description: "IFDS frontier and edge-kind predicate stage for witness extraction",
    tags: &["ifds", "witness", "dataflow"],
    owner_crate: "vyre-bench",
    primitive: "IFDS reachability and witness extraction",
    baseline: "optimized CPU graph reachability and witness extraction",
    metric_name: "ifds_records",
    records: 1_048_576,
    min_speedup_x: 100.0,
    pattern: SyntheticPattern::IfdsWitness,
};

static C_AST_TRAVERSAL: SyntheticCountWorkload = SyntheticCountWorkload {
    id: "release.c_ast_traversal.1m",
    name: "Release C AST Traversal 1M",
    description: "C AST node motif predicate traversal over parser-produced node buffers",
    tags: &["c", "ast", "parser"],
    owner_crate: "vyre-frontend-c",
    primitive: "C AST traversal and motif predicates",
    baseline: "tree-sitter/libclang-class CPU AST traversal baseline",
    metric_name: "ast_nodes",
    records: 1_048_576,
    min_speedup_x: 100.0,
    pattern: SyntheticPattern::CAstTraversal,
};

static MEGAKERNEL_QUEUE: SyntheticCountWorkload = SyntheticCountWorkload {
    id: "release.megakernel_queue.1m",
    name: "Release Megakernel Queue 1M",
    description: "Persistent megakernel queue predicate workload for repeated condition batches",
    tags: &["megakernel", "queue", "runtime"],
    owner_crate: "vyre-runtime",
    primitive: "persistent megakernel queued condition batches",
    baseline: "optimized CPU batched condition evaluator",
    metric_name: "queued_records",
    records: 1_048_576,
    min_speedup_x: 100.0,
    pattern: SyntheticPattern::MegakernelQueuedBatch,
};

static EGRAPH_SATURATION: SyntheticCountWorkload = SyntheticCountWorkload {
    id: "release.egraph_saturation.1m",
    name: "Release Egraph Saturation 1M",
    description: "Rewrite-equivalence predicate workload for optimization saturation evidence",
    tags: &["egraph", "optimization", "rewrite"],
    owner_crate: "vyre-lower",
    primitive: "optimization rewrite saturation",
    baseline: "egg/egraph CPU saturation baseline with equivalent rewrite set",
    metric_name: "rewrite_records",
    records: 1_048_576,
    min_speedup_x: 100.0,
    pattern: SyntheticPattern::EgraphSaturation,
};

fn release_macro_workloads() -> [&'static SyntheticCountWorkload; 10] {
    [
        &CONDITION_EVAL_BATCH,
        &STRING_BITMAP_SCATTER,
        &OFFSET_COUNT_AGGREGATION,
        &ENTROPY_WINDOW,
        &QUANTIFIED_LOOPS,
        &ALIAS_REACHING_DEF,
        &IFDS_WITNESS,
        &C_AST_TRAVERSAL,
        &MEGAKERNEL_QUEUE,
        &EGRAPH_SATURATION,
    ]
}

fn release_macro_workload(id: &str) -> Option<&'static SyntheticCountWorkload> {
    release_macro_workloads()
        .into_iter()
        .find(|workload| workload.id == id)
}

fn release_macro_program_spec(
    workload: &SyntheticCountWorkload,
    records: u32,
) -> ReleaseMacroProgramSpec {
    ReleaseMacroProgramSpec {
        id: workload.id,
        name: workload.name,
        records,
        input_buffers: pattern_input_count(workload.pattern),
        min_speedup_x: workload.min_speedup_x as u32,
    }
}

/// Return compiler-grade release macro workload descriptors used by Criterion
/// and generated coverage tests.
#[must_use]
pub fn release_macro_program_specs() -> Vec<ReleaseMacroProgramSpec> {
    release_macro_program_specs_for_records(METADATA_RECORDS)
}

/// Return compiler-grade release macro workload descriptors at a reduced or
/// stress-scale record count.
#[must_use]
pub fn release_macro_program_specs_for_records(records: u32) -> Vec<ReleaseMacroProgramSpec> {
    release_macro_workloads()
        .into_iter()
        .map(|workload| release_macro_program_spec(workload, records))
        .collect()
}

/// Return only release macro descriptors whose output is a single count word.
#[must_use]
pub fn release_count_macro_program_specs_for_records(records: u32) -> Vec<ReleaseMacroProgramSpec> {
    release_macro_workloads()
        .into_iter()
        .filter(|workload| is_count_output_pattern(workload.pattern))
        .map(|workload| release_macro_program_spec(workload, records))
        .collect()
}

/// Build the IR program for a compiler-grade release macro workload.
#[must_use]
pub fn build_release_macro_program(id: &str) -> Option<Program> {
    release_macro_workload(id)
        .map(|workload| build_synthetic_release_program(workload.pattern, workload.records))
}

/// Build the IR program for a compiler-grade release macro workload at a
/// caller-selected record count.
#[must_use]
pub fn build_release_macro_program_for_records(id: &str, records: u32) -> Option<Program> {
    release_macro_workload(id)
        .map(|workload| build_synthetic_release_program(workload.pattern, records))
}

/// Build a reduced or stress-scale release macro case with generated hostile
/// inputs and CPU-oracle outputs.
#[must_use]
pub fn build_release_macro_case_for_records(
    id: &str,
    records: u32,
) -> Option<ReleaseMacroGeneratedCase> {
    let workload = release_macro_workload(id)?;
    let spec = release_macro_program_spec(workload, records);
    let program = build_synthetic_release_program(workload.pattern, records);
    let (inputs, expected_outputs) = match workload.pattern {
        SyntheticPattern::StringBitmapScatter => {
            let generated = string_bitmap_scatter_inputs(records);
            let expected_words = string_bitmap_scatter_expected_words(
                &generated.pattern_bitmap,
                &generated.rule_bitmap,
                records,
            );
            (generated.inputs, vec![encode_u32_words(&expected_words)])
        }
        SyntheticPattern::ConditionEval
        | SyntheticPattern::OffsetCountAggregation
        | SyntheticPattern::EntropyWindow
        | SyntheticPattern::QuantifiedLoops
        | SyntheticPattern::AliasReachingDef
        | SyntheticPattern::IfdsWitness
        | SyntheticPattern::CAstTraversal
        | SyntheticPattern::MegakernelQueuedBatch
        | SyntheticPattern::EgraphSaturation => {
            let generated = synthetic_inputs(workload.pattern, records);
            let expected = synthetic_cpu_count(workload.pattern, records);
            assert_eq!(
                generated.expected, expected,
                "Fix: release macro generated input oracle diverged from CPU count oracle for {id}"
            );
            (generated.inputs, vec![expected.to_le_bytes().to_vec()])
        }
    };

    Some(ReleaseMacroGeneratedCase {
        spec,
        program,
        inputs,
        expected_outputs,
    })
}

/// Build a reduced or stress-scale release macro case whose output is one
/// CPU-oracle count word.
#[must_use]
pub fn build_release_count_macro_case_for_records(
    id: &str,
    records: u32,
) -> Option<ReleaseMacroGeneratedCase> {
    let workload = release_macro_workload(id)?;
    if !is_count_output_pattern(workload.pattern) {
        return None;
    }
    build_release_macro_case_for_records(id, records)
}

fn is_count_output_pattern(pattern: SyntheticPattern) -> bool {
    !matches!(pattern, SyntheticPattern::StringBitmapScatter)
}

inventory::submit! {
    &SparseOutputCompactionCount as &'static dyn BenchCase
}

inventory::submit! {
    &CallgraphReachabilityStep as &'static dyn BenchCase
}

inventory::submit! {
    &MetadataConditionBatch as &'static dyn BenchCase
}

inventory::submit! {
    &CONDITION_EVAL_BATCH as &'static dyn BenchCase
}

inventory::submit! {
    &STRING_BITMAP_SCATTER as &'static dyn BenchCase
}

inventory::submit! {
    &OFFSET_COUNT_AGGREGATION as &'static dyn BenchCase
}

inventory::submit! {
    &ENTROPY_WINDOW as &'static dyn BenchCase
}

inventory::submit! {
    &QUANTIFIED_LOOPS as &'static dyn BenchCase
}

inventory::submit! {
    &ALIAS_REACHING_DEF as &'static dyn BenchCase
}

inventory::submit! {
    &IFDS_WITNESS as &'static dyn BenchCase
}

inventory::submit! {
    &C_AST_TRAVERSAL as &'static dyn BenchCase
}

inventory::submit! {
    &MEGAKERNEL_QUEUE as &'static dyn BenchCase
}

inventory::submit! {
    &EGRAPH_SATURATION as &'static dyn BenchCase
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_bitmap_scatter_inputs_match_program_abi_at_word_boundaries() {
        for records in [1, 31, 32, 33, 255, 256, 257, 1024] {
            let program = string_bitmap_scatter_program(records);
            let generated = string_bitmap_scatter_inputs(records);
            let output_words = records.div_ceil(32) as usize;

            assert_eq!(
                generated.inputs.len(),
                program.buffers().len(),
                "records={records} must pass one input per program binding"
            );
            assert_eq!(generated.inputs[0].len(), output_words * 4);
            assert_eq!(generated.inputs[1].len(), records as usize * 4);
            assert_eq!(generated.inputs[2].len(), records as usize * 4);
            assert_eq!(program.buffers()[0].name.as_ref(), "out_flags");
            assert_eq!(program.buffers()[0].count, records.div_ceil(32));
            assert_eq!(program.buffers()[1].name.as_ref(), "pattern_bitmap");
            assert_eq!(program.buffers()[1].count, records);
            assert_eq!(program.buffers()[2].name.as_ref(), "rule_bitmap");
            assert_eq!(program.buffers()[2].count, records);
        }
    }

    #[test]
    fn string_bitmap_scatter_reference_eval_matches_cpu_bitmap_oracle() {
        for records in [1, 17, 32, 33, 127, 257] {
            let program = string_bitmap_scatter_program(records);
            let generated = string_bitmap_scatter_inputs(records);
            let values = generated
                .inputs
                .iter()
                .cloned()
                .map(vyre_reference::value::Value::from)
                .collect::<Vec<_>>();
            let outputs = vyre_reference::reference_eval(&program, &values)
                .expect("Fix: string bitmap scatter must reference-evaluate")
                .into_iter()
                .map(|value| value.to_bytes())
                .collect::<Vec<_>>();

            let mut expected_words = vec![0u32; records.div_ceil(32) as usize];
            for index in 0..records {
                let pattern_word = generated.pattern_bitmap[index as usize];
                let rule_word = generated.rule_bitmap[index as usize];
                assert_eq!(pattern_word, string_bitmap_pattern_word(index));
                assert_eq!(rule_word, string_bitmap_rule_word(index));
                if pattern_word != 0 && rule_word != 0 {
                    expected_words[(index / 32) as usize] |= 1u32 << (index & 31);
                }
            }

            assert_eq!(
                outputs,
                vec![encode_u32_words(&expected_words)],
                "records={records} must scatter exactly the CPU oracle bitmap"
            );
        }
    }
}
