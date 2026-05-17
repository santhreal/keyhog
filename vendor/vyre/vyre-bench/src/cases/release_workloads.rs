use crate::api::case::{
    BenchCase, BenchContext, BenchError, BenchId, BenchLayer, BenchMetadata, BenchRequirements,
    BenchRun, Correctness, DeterminismClass, PerformanceContract, PreparedCase, WorkloadClass,
};
use crate::api::metric::{BenchMetrics, MetricPoint};
use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};
use vyre_primitives::graph::csr_forward_traverse::cpu_ref as csr_forward_cpu_ref;
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

#[derive(Clone, Copy)]
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
                BufferDecl::storage("out_count", 0, BufferAccess::ReadWrite, DataType::U32)
                    .with_count(1),
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
            let hit = index % 97 == 0 || index % 4099 == 17;
            expected += u32::from(hit);
            flags.push(u32::from(hit));
        }
        let inputs = vec![vec![0; 4], encode_u32_words(&flags)];
        let timed = ctx
            .dispatch_timed(program, &inputs, &ctx.dispatch_config)
            .map_err(|error| BenchError::BackendFailed(error.to_string()))?;
        let baseline_start = std::time::Instant::now();
        let cpu_count = flags.iter().copied().filter(|flag| *flag != 0).count() as u32;
        let baseline_wall = baseline_start.elapsed().as_nanos() as u64;
        if cpu_count != expected {
            return Err(BenchError::CorrectnessViolation(
                "sparse CPU baseline count disagreed with generator expectation".to_string(),
            ));
        }
        let baseline_outputs = vec![cpu_count.to_le_bytes().to_vec()];
        bench_run_from_timed(timed, inputs, baseline_outputs, baseline_wall, "sparse_items", SPARSE_ITEMS)
    }

    fn verify(&self, _ctx: &mut BenchContext, run: &BenchRun) -> Result<Correctness, BenchError> {
        run.verify_exact_outputs()
    }
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
            owner_crate: "weir".to_string(),
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
            "weir",
            "optimized CPU graph reachability and witness extraction",
            25.0,
        ))
    }

    fn prepare(&self, _ctx: &mut BenchContext) -> Result<PreparedCase, BenchError> {
        let shape = ProgramGraphShape::new(CALLGRAPH_NODES, CALLGRAPH_EDGES);
        Ok(Box::new(vyre_primitives::graph::csr_forward_traverse::csr_forward_traverse(
            shape,
            "frontier_in",
            "frontier_out",
            1,
        )))
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
        let mut expected = csr_forward_cpu_ref(
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
        bench_run_from_timed(
            timed,
            graph.inputs,
            baseline_outputs,
            baseline_wall,
            "callgraph_nodes",
            CALLGRAPH_NODES,
        )
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
            description: "File metadata and PE/header-style condition evaluation over 1M records".to_string(),
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
                BufferDecl::storage("out_count", 0, BufferAccess::ReadWrite, DataType::U32)
                    .with_count(1),
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
            let hdr = if index % 5 == 0 { 0x0000_4550 } else { 0x464C_457F };
            let ent = 5000 + (index.wrapping_mul(17) % 4500);
            expected += u32::from(size > 4096 && hdr == 0x0000_4550 && ent > 7200);
            filesize.push(size);
            header.push(hdr);
            entropy.push(ent);
        }
        let inputs = vec![
            vec![0; 4],
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
        Ok(Box::new(synthetic_count_program(self.pattern, self.records)))
    }

    fn run(
        &self,
        ctx: &mut BenchContext,
        prepared: &mut PreparedCase,
    ) -> Result<BenchRun, BenchError> {
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

fn synthetic_count_program(pattern: SyntheticPattern, records: u32) -> Program {
    let mut buffers = vec![
        BufferDecl::storage("out_count", 0, BufferAccess::ReadWrite, DataType::U32).with_count(1),
    ];
    for (binding, name) in pattern_buffers(pattern).iter().enumerate() {
        buffers.push(
            BufferDecl::storage(*name, (binding + 1) as u32, BufferAccess::ReadOnly, DataType::U32)
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
        SyntheticPattern::ConditionEval => &["match_count", "rule_bitmap", "metadata_gate"],
        SyntheticPattern::StringBitmapScatter => &["pattern_bitmap", "rule_bitmap"],
        SyntheticPattern::OffsetCountAggregation => &["offset", "length", "count"],
        SyntheticPattern::EntropyWindow => &["entropy_x1000"],
        SyntheticPattern::QuantifiedLoops => &["any_hit", "all_hit", "n_hit"],
        SyntheticPattern::AliasReachingDef => &["def_id", "use_id", "alias_mask"],
        SyntheticPattern::IfdsWitness => &["frontier", "edge_kind"],
        SyntheticPattern::CAstTraversal => &["node_kind", "depth"],
        SyntheticPattern::MegakernelQueuedBatch => &["queue_state", "predicate"],
        SyntheticPattern::EgraphSaturation => &["opcode", "lhs_class", "rhs_class"],
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
    let mut inputs = Vec::with_capacity(columns.len() + 1);
    inputs.push(vec![0; 4]);
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
            index.wrapping_mul(17) % 11,
            if index % 13 == 0 { 7 } else { 3 },
            u32::from(index % 5 != 0),
        ],
        SyntheticPattern::StringBitmapScatter => vec![
            u32::from(index % 29 == 0 || index % 211 == 3),
            u32::from(index % 7 != 0),
        ],
        SyntheticPattern::OffsetCountAggregation => vec![
            index.wrapping_mul(31) % 8192,
            1 + (index % 64),
            index % 5,
        ],
        SyntheticPattern::EntropyWindow => vec![5000 + (index.wrapping_mul(19) % 4500)],
        SyntheticPattern::QuantifiedLoops => vec![
            u32::from(index % 3 == 0),
            u32::from(index % 11 != 0),
            index % 8,
        ],
        SyntheticPattern::AliasReachingDef => {
            let def = index % 4096;
            let use_id = if index % 17 == 0 { def } else { def ^ 31 };
            vec![def, use_id, u32::from(index % 5 != 0)]
        }
        SyntheticPattern::IfdsWitness => vec![u32::from(index % 31 == 0), u32::from(index % 4 == 0)],
        SyntheticPattern::CAstTraversal => vec![
            if index % 97 == 0 { 42 } else { index % 64 },
            index % 12,
        ],
        SyntheticPattern::MegakernelQueuedBatch => vec![u32::from(index % 2 == 0), u32::from(index % 37 == 0)],
        SyntheticPattern::EgraphSaturation => {
            let lhs = index % 2048;
            let rhs = if index % 23 == 0 { lhs } else { lhs.wrapping_add(1) };
            vec![u32::from(index % 9 == 0) * 3, lhs, rhs]
        }
    }
}

fn row_matches(pattern: SyntheticPattern, row: &[u32]) -> bool {
    match pattern {
        SyntheticPattern::ConditionEval => row[0] > 3 && row[1] == 7 && row[2] != 0,
        SyntheticPattern::StringBitmapScatter => row[0] != 0 && row[1] != 0,
        SyntheticPattern::OffsetCountAggregation => row[0] > 128 && row[1] > 4 && row[2] > 1,
        SyntheticPattern::EntropyWindow => row[0] > 7200,
        SyntheticPattern::QuantifiedLoops => row[0] != 0 && row[1] != 0 && row[2] > 2,
        SyntheticPattern::AliasReachingDef => row[0] == row[1] && row[2] != 0,
        SyntheticPattern::IfdsWitness => row[0] != 0 && row[1] == 1,
        SyntheticPattern::CAstTraversal => row[0] == 42 && row[1] > 3,
        SyntheticPattern::MegakernelQueuedBatch => row[0] == 1 && row[1] != 0,
        SyntheticPattern::EgraphSaturation => row[0] == 3 && row[1] == row[2],
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
    let mut frontier_in = vec![0; CALLGRAPH_WORDS];
    frontier_in[0] = 1;
    let frontier_out_seed = frontier_in.clone();
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
                name: "weir_nodes".to_string(),
                value: u64::from(records),
            });
            run.metrics.custom.push(MetricPoint {
                name: "weir_bitset_words".to_string(),
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
    tags: &["alias", "reaching-def", "weir"],
    owner_crate: "weir",
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
    owner_crate: "weir",
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
