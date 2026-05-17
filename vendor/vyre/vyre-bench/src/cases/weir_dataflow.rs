use crate::api::case::{
    BenchCase, BenchContext, BenchError, BenchId, BenchLayer, BenchMetadata, BenchRequirements,
    BenchRun, Correctness, DeterminismClass, PerformanceContract, PreparedCase, WorkloadClass,
};
use crate::api::metric::{BenchMetrics, MetricPoint};
use vyre_primitives::graph::csr_forward_traverse::{bitset_words, cpu_ref as csr_step_cpu_ref};
use vyre_primitives::graph::program_graph::ProgramGraphShape;

pub struct WeirReachingDefBitset;
pub struct WeirIfdsStep;
pub struct WeirPointsToAliasStep;

const NODE_COUNT: u32 = 1_048_576;
const WORD_COUNT: usize = (NODE_COUNT as usize).div_ceil(32);
const GRAPH_NODE_COUNT: u32 = 262_144;
const GRAPH_EDGE_COUNT: u32 = GRAPH_NODE_COUNT - 1;
const GRAPH_WORD_COUNT: usize = bitset_words(GRAPH_NODE_COUNT) as usize;

struct WeirBitsetPrepared {
    program: vyre_foundation::ir::Program,
    gen_kill_in: Vec<u32>,
    use_set: Vec<u32>,
    out_seed: Vec<u32>,
}

struct WeirGraphPrepared {
    program: vyre_foundation::ir::Program,
    nodes: Vec<u32>,
    edge_offsets: Vec<u32>,
    edge_targets: Vec<u32>,
    edge_kind_mask: Vec<u32>,
    node_tags: Vec<u32>,
    frontier_in: Vec<u32>,
    frontier_out_seed: Vec<u32>,
    workload_name: &'static str,
}

impl BenchCase for WeirReachingDefBitset {
    fn id(&self) -> BenchId {
        BenchId("weir.reaching_def.bitset.1m".to_string())
    }

    fn metadata(&self) -> BenchMetadata {
        BenchMetadata {
            id: self.id(),
            name: "Weir Reaching-Def Bitset 1M".to_string(),
            description:
                "Weir reaching-definition query over a 1M-node packed bitset dataflow workload"
                    .to_string(),
            tags: vec![
                "weir".to_string(),
                "dataflow".to_string(),
                "reaching".to_string(),
                "reaching_def".to_string(),
                "bitset".to_string(),
                "release".to_string(),
            ],
            layer: BenchLayer::Libs,
            workload: WorkloadClass::Macro,
            determinism: DeterminismClass::Deterministic,
            owner_crate: "weir".to_string(),
        }
    }

    fn requirements(&self) -> BenchRequirements {
        BenchRequirements {
            needs_gpu: true,
            needs_network: false,
            min_vram_bytes: None,
            min_input_bytes: Some((WORD_COUNT * 12) as u64),
            feature_set: vec!["weir".to_string(), "bitset".to_string()],
        }
    }

    fn performance_contract(&self) -> Option<PerformanceContract> {
        Some(PerformanceContract::cpu_sota_100x(
            "weir reaching-def packed bitset",
            "weir",
            "single-threaded packed u32 bitset intersection",
        ))
    }

    fn suites(&self) -> &'static [crate::api::suite::SuiteKind] {
        &[
            crate::api::suite::SuiteKind::Release,
            crate::api::suite::SuiteKind::Gpu,
            crate::api::suite::SuiteKind::Deep,
            crate::api::suite::SuiteKind::Honest,
        ]
    }

    fn prepare(&self, _ctx: &mut BenchContext) -> Result<PreparedCase, BenchError> {
        let mut gen_kill_in = Vec::with_capacity(WORD_COUNT);
        let mut use_set = Vec::with_capacity(WORD_COUNT);
        for index in 0..WORD_COUNT {
            let x = index as u32;
            gen_kill_in.push(x.rotate_left(5) ^ 0xA5A5_5A5A);
            use_set.push(x.wrapping_mul(0x9E37_79B9).rotate_right(7) ^ 0x3C3C_C3C3);
        }
        let out_seed = vec![0; WORD_COUNT];
        let program =
            weir::reaching_def::reaching_def(NODE_COUNT, "gen_kill_in", "use_set", "out");
        Ok(Box::new(WeirBitsetPrepared {
            program,
            gen_kill_in,
            use_set,
            out_seed,
        }))
    }

    fn program<'a>(&self, prepared: &'a PreparedCase) -> Option<&'a vyre_foundation::ir::Program> {
        prepared
            .downcast_ref::<WeirBitsetPrepared>()
            .map(|prepared| &prepared.program)
    }

    fn run(
        &self,
        ctx: &mut BenchContext,
        prepared: &mut PreparedCase,
    ) -> Result<BenchRun, BenchError> {
        let prepared = prepared.downcast_ref::<WeirBitsetPrepared>().ok_or_else(|| {
            BenchError::ExecutionFailed(
                "weir reaching-def prepared payload type mismatch".to_string(),
            )
        })?;
        let inputs = vec![
            encode_u32_words(&prepared.gen_kill_in),
            encode_u32_words(&prepared.use_set),
            encode_u32_words(&prepared.out_seed),
        ];
        let timed = ctx
            .dispatch_timed(&prepared.program, &inputs, &ctx.dispatch_config)
            .map_err(|error| BenchError::BackendFailed(error.to_string()))?;

        let baseline_start = std::time::Instant::now();
        let baseline_words = weir::reaching_def::cpu_ref(&prepared.gen_kill_in, &prepared.use_set);
        let baseline_wall = baseline_start.elapsed().as_nanos() as u64;
        let baseline_outputs = vec![encode_u32_words(&baseline_words)];

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
                bytes_read: Some((WORD_COUNT * 8) as u64),
                bytes_written: Some((WORD_COUNT * 4) as u64),
                wall_throughput_gb_s: Some(gb_per_second(bytes_touched, wall_ns)),
                device_throughput_gb_s: Some(gb_per_second(bytes_touched, device_ns)),
                custom: vec![
                    MetricPoint {
                        name: "weir_nodes".to_string(),
                        value: u64::from(NODE_COUNT),
                    },
                    MetricPoint {
                        name: "weir_bitset_words".to_string(),
                        value: WORD_COUNT as u64,
                    },
                ],
                ..Default::default()
            },
            baseline_metrics: Some(BenchMetrics {
                wall_ns: Some(baseline_wall),
                input_bytes: Some((WORD_COUNT * 8) as u64),
                output_bytes: Some((WORD_COUNT * 4) as u64),
                bytes_touched: Some((WORD_COUNT * 12) as u64),
                bytes_read: Some((WORD_COUNT * 8) as u64),
                bytes_written: Some((WORD_COUNT * 4) as u64),
                ..Default::default()
            }),
            outputs: timed.outputs,
            baseline_outputs: Some(baseline_outputs),
        })
    }

    fn verify(&self, _ctx: &mut BenchContext, run: &BenchRun) -> Result<Correctness, BenchError> {
        run.verify_exact_outputs()
    }

    fn bytes_touched(&self, _prepared: &PreparedCase) -> (u64, u64) {
        ((WORD_COUNT * 8) as u64, (WORD_COUNT * 4) as u64)
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

inventory::submit! {
    &WeirReachingDefBitset as &'static dyn BenchCase
}

impl BenchCase for WeirIfdsStep {
    fn id(&self) -> BenchId {
        BenchId("weir.ifds.taint.step.262k".to_string())
    }

    fn metadata(&self) -> BenchMetadata {
        BenchMetadata {
            id: self.id(),
            name: "Weir IFDS Taint Step 262K".to_string(),
            description:
                "One IFDS taint propagation step over a 262K-node exploded-supergraph-shaped CSR"
                    .to_string(),
            tags: vec![
                "weir".to_string(),
                "ifds".to_string(),
                "taint".to_string(),
                "dataflow".to_string(),
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
        WEIR_RELEASE_SUITES
    }

    fn requirements(&self) -> BenchRequirements {
        weir_graph_requirements()
    }

    fn performance_contract(&self) -> Option<PerformanceContract> {
        Some(PerformanceContract::cpu_sota_10x(
            "weir IFDS taint propagation step",
            "weir",
            "single-threaded CSR frontier propagation",
        ))
    }

    fn prepare(&self, _ctx: &mut BenchContext) -> Result<PreparedCase, BenchError> {
        let shape = ProgramGraphShape::new(GRAPH_NODE_COUNT, GRAPH_EDGE_COUNT);
        Ok(Box::new(WeirGraphPrepared {
            program: weir::ifds::ifds_reach_step(shape, "frontier_in", "frontier_out"),
            workload_name: "weir_ifds_step",
            ..linear_graph_prepared_fields()
        }))
    }

    fn program<'a>(&self, prepared: &'a PreparedCase) -> Option<&'a vyre_foundation::ir::Program> {
        prepared
            .downcast_ref::<WeirGraphPrepared>()
            .map(|prepared| &prepared.program)
    }

    fn run(
        &self,
        ctx: &mut BenchContext,
        prepared: &mut PreparedCase,
    ) -> Result<BenchRun, BenchError> {
        run_graph_step(ctx, prepared)
    }

    fn verify(&self, _ctx: &mut BenchContext, run: &BenchRun) -> Result<Correctness, BenchError> {
        run.verify_exact_outputs()
    }

    fn bytes_touched(&self, _prepared: &PreparedCase) -> (u64, u64) {
        graph_bytes_touched()
    }
}

impl BenchCase for WeirPointsToAliasStep {
    fn id(&self) -> BenchId {
        BenchId("weir.points_to.alias.step.262k".to_string())
    }

    fn metadata(&self) -> BenchMetadata {
        BenchMetadata {
            id: self.id(),
            name: "Weir Points-To Alias Step 262K".to_string(),
            description:
                "One Andersen points-to alias propagation step over a 262K-node constraint CSR"
                    .to_string(),
            tags: vec![
                "weir".to_string(),
                "points_to".to_string(),
                "points-to".to_string(),
                "alias".to_string(),
                "may_alias".to_string(),
                "dataflow".to_string(),
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
        WEIR_RELEASE_SUITES
    }

    fn requirements(&self) -> BenchRequirements {
        weir_graph_requirements()
    }

    fn performance_contract(&self) -> Option<PerformanceContract> {
        Some(PerformanceContract::cpu_sota_10x(
            "weir points-to alias propagation step",
            "weir",
            "single-threaded Andersen subset frontier propagation",
        ))
    }

    fn prepare(&self, _ctx: &mut BenchContext) -> Result<PreparedCase, BenchError> {
        let shape = ProgramGraphShape::new(GRAPH_NODE_COUNT, GRAPH_EDGE_COUNT);
        Ok(Box::new(WeirGraphPrepared {
            program: weir::points_to::andersen_points_to(shape, "frontier_in", "frontier_out"),
            workload_name: "weir_points_to_alias_step",
            ..linear_graph_prepared_fields()
        }))
    }

    fn program<'a>(&self, prepared: &'a PreparedCase) -> Option<&'a vyre_foundation::ir::Program> {
        prepared
            .downcast_ref::<WeirGraphPrepared>()
            .map(|prepared| &prepared.program)
    }

    fn run(
        &self,
        ctx: &mut BenchContext,
        prepared: &mut PreparedCase,
    ) -> Result<BenchRun, BenchError> {
        run_graph_step(ctx, prepared)
    }

    fn verify(&self, _ctx: &mut BenchContext, run: &BenchRun) -> Result<Correctness, BenchError> {
        run.verify_exact_outputs()
    }

    fn bytes_touched(&self, _prepared: &PreparedCase) -> (u64, u64) {
        graph_bytes_touched()
    }
}

const WEIR_RELEASE_SUITES: &[crate::api::suite::SuiteKind] = &[
    crate::api::suite::SuiteKind::Release,
    crate::api::suite::SuiteKind::Gpu,
    crate::api::suite::SuiteKind::Deep,
    crate::api::suite::SuiteKind::Honest,
];

fn weir_graph_requirements() -> BenchRequirements {
    let (input_bytes, output_bytes) = graph_bytes_touched();
    BenchRequirements {
        needs_gpu: true,
        needs_network: false,
        min_vram_bytes: None,
        min_input_bytes: Some(input_bytes.saturating_add(output_bytes)),
        feature_set: vec!["weir".to_string(), "graph".to_string(), "dataflow".to_string()],
    }
}

fn linear_graph_prepared_fields() -> WeirGraphPrepared {
    let nodes = vec![0; GRAPH_NODE_COUNT as usize];
    let mut edge_offsets = Vec::with_capacity(GRAPH_NODE_COUNT as usize + 1);
    for node in 0..GRAPH_NODE_COUNT {
        edge_offsets.push(node.min(GRAPH_EDGE_COUNT));
    }
    edge_offsets.push(GRAPH_EDGE_COUNT);
    let edge_targets: Vec<u32> = (1..GRAPH_NODE_COUNT).collect();
    let edge_kind_mask = vec![1; GRAPH_EDGE_COUNT as usize];
    let node_tags = vec![0; GRAPH_NODE_COUNT as usize];
    let mut frontier_in = vec![0; GRAPH_WORD_COUNT];
    frontier_in[0] = 1;
    let frontier_out_seed = frontier_in.clone();
    WeirGraphPrepared {
        program: weir::ifds::ifds_reach_step(
            ProgramGraphShape::new(GRAPH_NODE_COUNT, GRAPH_EDGE_COUNT),
            "frontier_in",
            "frontier_out",
        ),
        nodes,
        edge_offsets,
        edge_targets,
        edge_kind_mask,
        node_tags,
        frontier_in,
        frontier_out_seed,
        workload_name: "weir_graph_step",
    }
}

fn run_graph_step(
    ctx: &mut BenchContext,
    prepared: &mut PreparedCase,
) -> Result<BenchRun, BenchError> {
    let prepared = prepared.downcast_ref::<WeirGraphPrepared>().ok_or_else(|| {
        BenchError::ExecutionFailed("weir graph prepared payload type mismatch".to_string())
    })?;
    let inputs = vec![
        encode_u32_words(&prepared.nodes),
        encode_u32_words(&prepared.edge_offsets),
        encode_u32_words(&prepared.edge_targets),
        encode_u32_words(&prepared.edge_kind_mask),
        encode_u32_words(&prepared.node_tags),
        encode_u32_words(&prepared.frontier_in),
        encode_u32_words(&prepared.frontier_out_seed),
    ];
    let timed = ctx
        .dispatch_timed(&prepared.program, &inputs, &ctx.dispatch_config)
        .map_err(|error| BenchError::BackendFailed(error.to_string()))?;

    let baseline_start = std::time::Instant::now();
    let mut baseline_words = csr_step_cpu_ref(
        GRAPH_NODE_COUNT,
        &prepared.edge_offsets,
        &prepared.edge_targets,
        &prepared.edge_kind_mask,
        &prepared.frontier_in,
        1,
    );
    for (out, seed) in baseline_words
        .iter_mut()
        .zip(prepared.frontier_out_seed.iter())
    {
        *out |= *seed;
    }
    let baseline_wall = baseline_start.elapsed().as_nanos() as u64;
    let baseline_outputs = vec![encode_u32_words(&baseline_words)];

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
            bytes_written: Some((GRAPH_WORD_COUNT * 4) as u64),
            wall_throughput_gb_s: Some(gb_per_second(bytes_touched, wall_ns)),
            device_throughput_gb_s: Some(gb_per_second(bytes_touched, device_ns)),
            custom: vec![
                MetricPoint {
                    name: "weir_graph_nodes".to_string(),
                    value: u64::from(GRAPH_NODE_COUNT),
                },
                MetricPoint {
                    name: "weir_graph_edges".to_string(),
                    value: u64::from(GRAPH_EDGE_COUNT),
                },
                MetricPoint {
                    name: prepared.workload_name.to_string(),
                    value: 1,
                },
            ],
            ..Default::default()
        },
        baseline_metrics: Some(BenchMetrics {
            wall_ns: Some(baseline_wall),
            input_bytes: Some(input_bytes),
            output_bytes: Some((GRAPH_WORD_COUNT * 4) as u64),
            bytes_touched: Some(bytes_touched),
            bytes_read: Some(input_bytes),
            bytes_written: Some((GRAPH_WORD_COUNT * 4) as u64),
            ..Default::default()
        }),
        outputs: timed.outputs,
        baseline_outputs: Some(baseline_outputs),
    })
}

fn graph_bytes_touched() -> (u64, u64) {
    let input_words = GRAPH_NODE_COUNT as usize
        + GRAPH_NODE_COUNT as usize
        + 1
        + GRAPH_EDGE_COUNT as usize
        + GRAPH_EDGE_COUNT as usize
        + GRAPH_NODE_COUNT as usize
        + GRAPH_WORD_COUNT
        + GRAPH_WORD_COUNT;
    ((input_words * 4) as u64, (GRAPH_WORD_COUNT * 4) as u64)
}

inventory::submit! {
    &WeirIfdsStep as &'static dyn BenchCase
}

inventory::submit! {
    &WeirPointsToAliasStep as &'static dyn BenchCase
}
