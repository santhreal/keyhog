use crate::api::case::{
    BenchCase, BenchContext, BenchError, BenchId, BenchLayer, BenchMetadata, BenchRequirements,
    BenchRun, Correctness, DeterminismClass, PerformanceContract, PreparedCase, WorkloadClass,
};
use crate::api::metric::{BenchMetrics, MetricPoint};
use crate::api::resident::{
    dispatch_program_timed, input_bytes_total, transfer_accounting, ResidentInputSet,
};
use external_dataflow_engine::{
    ifds as dataflow_ifds, points_to as dataflow_points_to, reaching_def as dataflow_reaching_def,
};
use vyre_primitives::bitset::and::cpu_ref as bitset_and_cpu_ref;
use vyre_primitives::graph::csr_forward_traverse::{bitset_words, cpu_ref as csr_step_cpu_ref};
use vyre_primitives::graph::program_graph::ProgramGraphShape;

pub struct DataflowReachingDefBitset;
pub struct DataflowIfdsStep;
pub struct DataflowPointsToAliasStep;

const NODE_COUNT: u32 = 1_048_576;
const WORD_COUNT: usize = (NODE_COUNT as usize).div_ceil(32);
const GRAPH_NODE_COUNT: u32 = 262_144;
const GRAPH_EDGE_COUNT: u32 = GRAPH_NODE_COUNT - 1;
const GRAPH_WORD_COUNT: usize = bitset_words(GRAPH_NODE_COUNT) as usize;

struct DataflowBitsetPrepared {
    program: vyre_foundation::ir::Program,
    encoded_inputs: Vec<Vec<u8>>,
    input_bytes_total: u64,
    baseline_output: Vec<u8>,
    baseline_wall_ns: u64,
    resident: Option<ResidentInputSet>,
}

struct DataflowGraphPrepared {
    program: vyre_foundation::ir::Program,
    encoded_inputs: Vec<Vec<u8>>,
    input_bytes_total: u64,
    baseline_output: Vec<u8>,
    baseline_wall_ns: u64,
    resident: Option<ResidentInputSet>,
    workload_name: &'static str,
}

impl BenchCase for DataflowReachingDefBitset {
    fn id(&self) -> BenchId {
        BenchId("dataflow.reaching_def.bitset.1m".to_string())
    }

    fn metadata(&self) -> BenchMetadata {
        BenchMetadata {
            id: self.id(),
            name: "Dataflow Reaching-Def Bitset 1M".to_string(),
            description: "Reaching-definition query over a 1M-node packed bitset dataflow workload"
                .to_string(),
            tags: vec![
                "dataflow".to_string(),
                "reaching".to_string(),
                "reaching_def".to_string(),
                "bitset".to_string(),
                "release".to_string(),
            ],
            layer: BenchLayer::Libs,
            workload: WorkloadClass::Macro,
            determinism: DeterminismClass::Deterministic,
            owner_crate: "vyre-primitives".to_string(),
        }
    }

    fn requirements(&self) -> BenchRequirements {
        BenchRequirements {
            needs_gpu: true,
            needs_network: false,
            min_vram_bytes: None,
            min_input_bytes: Some((WORD_COUNT * 12) as u64),
            feature_set: vec!["dataflow".to_string(), "bitset".to_string()],
        }
    }

    fn performance_contract(&self) -> Option<PerformanceContract> {
        Some(PerformanceContract::cpu_sota_100x(
            "dataflow reaching-def packed bitset",
            "dataflow",
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

    fn prepare(&self, ctx: &mut BenchContext) -> Result<PreparedCase, BenchError> {
        Ok(Box::new(prepare_reaching_def_bitset(Some(ctx))?))
    }

    fn program<'a>(&self, prepared: &'a PreparedCase) -> Option<&'a vyre_foundation::ir::Program> {
        prepared
            .downcast_ref::<DataflowBitsetPrepared>()
            .map(|prepared| &prepared.program)
    }

    fn run(
        &self,
        ctx: &mut BenchContext,
        prepared: &mut PreparedCase,
    ) -> Result<BenchRun, BenchError> {
        let prepared = prepared
            .downcast_ref::<DataflowBitsetPrepared>()
            .ok_or_else(|| {
                BenchError::ExecutionFailed(
                    "dataflow reaching-def prepared payload type mismatch".to_string(),
                )
            })?;
        let dispatch = dispatch_program_timed(
            ctx,
            &prepared.program,
            prepared.resident.as_ref(),
            &prepared.encoded_inputs,
            &ctx.dispatch_config,
        )?;
        let resident_used = dispatch.resident_used;
        let timed = dispatch.timed;

        let input_bytes = prepared.input_bytes_total;
        let output_bytes = timed.outputs.iter().map(Vec::len).sum::<usize>() as u64;
        let accounting = transfer_accounting(input_bytes, output_bytes, resident_used);
        let wall_ns = timed.wall_ns;
        let device_ns = timed.device_ns.unwrap_or(wall_ns);

        Ok(BenchRun {
            metrics: BenchMetrics {
                wall_ns: Some(wall_ns),
                dispatch_ns: timed.device_ns,
                input_bytes: Some(input_bytes),
                output_bytes: Some(output_bytes),
                bytes_touched: Some(accounting.bytes_touched),
                bytes_read: Some(accounting.bytes_read),
                bytes_written: Some(accounting.bytes_written),
                wall_throughput_gb_s: Some(gb_per_second(accounting.bytes_touched, wall_ns)),
                device_throughput_gb_s: Some(gb_per_second(accounting.bytes_touched, device_ns)),
                custom: vec![
                    MetricPoint {
                        name: "nodes".to_string(),
                        value: u64::from(NODE_COUNT),
                    },
                    MetricPoint {
                        name: "bitset_words".to_string(),
                        value: WORD_COUNT as u64,
                    },
                    MetricPoint {
                        name: "resident_buffers".to_string(),
                        value: u64::from(prepared.resident.is_some()),
                    },
                ],
                ..Default::default()
            },
            baseline_metrics: Some(BenchMetrics {
                wall_ns: Some(prepared.baseline_wall_ns),
                input_bytes: Some((WORD_COUNT * 8) as u64),
                output_bytes: Some(prepared.baseline_output.len() as u64),
                bytes_touched: Some((WORD_COUNT * 12) as u64),
                bytes_read: Some((WORD_COUNT * 8) as u64),
                bytes_written: Some((WORD_COUNT * 4) as u64),
                ..Default::default()
            }),
            outputs: timed.outputs,
            baseline_outputs: Some(vec![prepared.baseline_output.clone()]),
        })
    }

    fn verify(&self, _ctx: &mut BenchContext, run: &BenchRun) -> Result<Correctness, BenchError> {
        run.verify_exact_outputs()
    }

    fn bytes_touched(&self, _prepared: &PreparedCase) -> (u64, u64) {
        ((WORD_COUNT * 8) as u64, (WORD_COUNT * 4) as u64)
    }
}

fn prepare_reaching_def_bitset(
    ctx: Option<&BenchContext>,
) -> Result<DataflowBitsetPrepared, BenchError> {
    let (gen_kill_in, use_set, out_seed) = reaching_def_fixture_words();
    let encoded_inputs = vec![
        encode_u32_words(&gen_kill_in),
        encode_u32_words(&use_set),
        encode_u32_words(&out_seed),
    ];
    let input_bytes_total = input_bytes_total(&encoded_inputs);
    let program = dataflow_reaching_def::reaching_def(NODE_COUNT, "gen_kill_in", "use_set", "out");
    let baseline_start = std::time::Instant::now();
    let baseline_words = bitset_and_cpu_ref(&gen_kill_in, &use_set);
    let baseline_wall_ns = baseline_start
        .elapsed()
        .as_nanos()
        .min(u128::from(u64::MAX)) as u64;
    let baseline_output = encode_u32_words(&baseline_words);
    let resident = ctx
        .map(|ctx| ResidentInputSet::upload_optional(ctx, &encoded_inputs, "dataflow bitset"))
        .transpose()?
        .flatten();

    Ok(DataflowBitsetPrepared {
        program,
        encoded_inputs,
        input_bytes_total,
        baseline_output,
        baseline_wall_ns,
        resident,
    })
}

fn reaching_def_fixture_words() -> (Vec<u32>, Vec<u32>, Vec<u32>) {
    let mut gen_kill_in = Vec::with_capacity(WORD_COUNT);
    let mut use_set = Vec::with_capacity(WORD_COUNT);
    for index in 0..WORD_COUNT {
        let x = index as u32;
        gen_kill_in.push(x.rotate_left(5) ^ 0xA5A5_5A5A);
        use_set.push(x.wrapping_mul(0x9E37_79B9).rotate_right(7) ^ 0x3C3C_C3C3);
    }
    let out_seed = vec![0; WORD_COUNT];
    (gen_kill_in, use_set, out_seed)
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
    &DataflowReachingDefBitset as &'static dyn BenchCase
}

impl BenchCase for DataflowIfdsStep {
    fn id(&self) -> BenchId {
        BenchId("dataflow.ifds.step.262k".to_string())
    }

    fn metadata(&self) -> BenchMetadata {
        BenchMetadata {
            id: self.id(),
            name: "Dataflow IFDS Step 262K".to_string(),
            description:
                "One IFDS reachability step over a 262K-node exploded-supergraph-shaped CSR"
                    .to_string(),
            tags: vec![
                "dataflow".to_string(),
                "ifds".to_string(),
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
        DATAFLOW_RELEASE_SUITES
    }

    fn requirements(&self) -> BenchRequirements {
        graph_requirements()
    }

    fn performance_contract(&self) -> Option<PerformanceContract> {
        Some(PerformanceContract::cpu_sota_10x(
            "dataflow IFDS reachability step",
            "dataflow",
            "single-threaded CSR frontier propagation",
        ))
    }

    fn prepare(&self, ctx: &mut BenchContext) -> Result<PreparedCase, BenchError> {
        let shape = ProgramGraphShape::new(GRAPH_NODE_COUNT, GRAPH_EDGE_COUNT);
        Ok(Box::new(linear_graph_prepared(
            dataflow_ifds::ifds_reach_step(shape, "frontier_in", "frontier_out"),
            "ifds_step",
            Some(ctx),
        )?))
    }

    fn program<'a>(&self, prepared: &'a PreparedCase) -> Option<&'a vyre_foundation::ir::Program> {
        prepared
            .downcast_ref::<DataflowGraphPrepared>()
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

impl BenchCase for DataflowPointsToAliasStep {
    fn id(&self) -> BenchId {
        BenchId("dataflow.points_to.alias.step.262k".to_string())
    }

    fn metadata(&self) -> BenchMetadata {
        BenchMetadata {
            id: self.id(),
            name: "Dataflow Points-To Alias Step 262K".to_string(),
            description:
                "One Andersen points-to alias propagation step over a 262K-node constraint CSR"
                    .to_string(),
            tags: vec![
                "dataflow".to_string(),
                "points_to".to_string(),
                "points-to".to_string(),
                "alias".to_string(),
                "may_alias".to_string(),
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
        DATAFLOW_RELEASE_SUITES
    }

    fn requirements(&self) -> BenchRequirements {
        graph_requirements()
    }

    fn performance_contract(&self) -> Option<PerformanceContract> {
        Some(PerformanceContract::cpu_sota_10x(
            "dataflow points-to alias propagation step",
            "dataflow",
            "single-threaded Andersen subset frontier propagation",
        ))
    }

    fn prepare(&self, ctx: &mut BenchContext) -> Result<PreparedCase, BenchError> {
        let shape = ProgramGraphShape::new(GRAPH_NODE_COUNT, GRAPH_EDGE_COUNT);
        Ok(Box::new(linear_graph_prepared(
            dataflow_points_to::andersen_points_to(shape, "frontier_in", "frontier_out"),
            "points_to_alias_step",
            Some(ctx),
        )?))
    }

    fn program<'a>(&self, prepared: &'a PreparedCase) -> Option<&'a vyre_foundation::ir::Program> {
        prepared
            .downcast_ref::<DataflowGraphPrepared>()
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

const DATAFLOW_RELEASE_SUITES: &[crate::api::suite::SuiteKind] = &[
    crate::api::suite::SuiteKind::Release,
    crate::api::suite::SuiteKind::Gpu,
    crate::api::suite::SuiteKind::Deep,
    crate::api::suite::SuiteKind::Honest,
];

fn graph_requirements() -> BenchRequirements {
    let (input_bytes, output_bytes) = graph_bytes_touched();
    BenchRequirements {
        needs_gpu: true,
        needs_network: false,
        min_vram_bytes: None,
        min_input_bytes: Some(input_bytes.saturating_add(output_bytes)),
        feature_set: vec![
            "dataflow".to_string(),
            "graph".to_string(),
            "dataflow".to_string(),
        ],
    }
}

fn linear_graph_prepared(
    program: vyre_foundation::ir::Program,
    workload_name: &'static str,
    ctx: Option<&BenchContext>,
) -> Result<DataflowGraphPrepared, BenchError> {
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
    let encoded_inputs = vec![
        encode_u32_words(&nodes),
        encode_u32_words(&edge_offsets),
        encode_u32_words(&edge_targets),
        encode_u32_words(&edge_kind_mask),
        encode_u32_words(&node_tags),
        encode_u32_words(&frontier_in),
        encode_u32_words(&frontier_out_seed),
    ];
    let input_bytes_total = input_bytes_total(&encoded_inputs);
    let baseline_start = std::time::Instant::now();
    let mut baseline_words = csr_step_cpu_ref(
        GRAPH_NODE_COUNT,
        &edge_offsets,
        &edge_targets,
        &edge_kind_mask,
        &frontier_in,
        1,
    );
    for (out, seed) in baseline_words.iter_mut().zip(frontier_out_seed.iter()) {
        *out |= *seed;
    }
    let baseline_wall_ns = baseline_start
        .elapsed()
        .as_nanos()
        .min(u128::from(u64::MAX)) as u64;
    let baseline_output = encode_u32_words(&baseline_words);
    let resident = ctx
        .map(|ctx| ResidentInputSet::upload_optional(ctx, &encoded_inputs, "dataflow graph"))
        .transpose()?
        .flatten();

    Ok(DataflowGraphPrepared {
        program,
        encoded_inputs,
        input_bytes_total,
        baseline_output,
        baseline_wall_ns,
        resident,
        workload_name,
    })
}


fn run_graph_step(
    ctx: &mut BenchContext,
    prepared: &mut PreparedCase,
) -> Result<BenchRun, BenchError> {
    let prepared = prepared
        .downcast_ref::<DataflowGraphPrepared>()
        .ok_or_else(|| {
            BenchError::ExecutionFailed("graph prepared payload type mismatch".to_string())
        })?;
    let dispatch = dispatch_program_timed(
        ctx,
        &prepared.program,
        prepared.resident.as_ref(),
        &prepared.encoded_inputs,
        &ctx.dispatch_config,
    )?;
    let resident_used = dispatch.resident_used;
    let timed = dispatch.timed;

    let input_bytes = prepared.input_bytes_total;
    let output_bytes = timed.outputs.iter().map(Vec::len).sum::<usize>() as u64;
    let accounting = transfer_accounting(input_bytes, output_bytes, resident_used);
    let wall_ns = timed.wall_ns;
    let device_ns = timed.device_ns.unwrap_or(wall_ns);
    let baseline_output_bytes = prepared.baseline_output.len() as u64;

    Ok(BenchRun {
        metrics: BenchMetrics {
            wall_ns: Some(wall_ns),
            dispatch_ns: timed.device_ns,
            input_bytes: Some(input_bytes),
            output_bytes: Some(output_bytes),
            bytes_touched: Some(accounting.bytes_touched),
            bytes_read: Some(accounting.bytes_read),
            bytes_written: Some(accounting.bytes_written),
            wall_throughput_gb_s: Some(gb_per_second(accounting.bytes_touched, wall_ns)),
            device_throughput_gb_s: Some(gb_per_second(accounting.bytes_touched, device_ns)),
            custom: vec![
                MetricPoint {
                    name: "graph_nodes".to_string(),
                    value: u64::from(GRAPH_NODE_COUNT),
                },
                MetricPoint {
                    name: "graph_edges".to_string(),
                    value: u64::from(GRAPH_EDGE_COUNT),
                },
                MetricPoint {
                    name: prepared.workload_name.to_string(),
                    value: 1,
                },
                MetricPoint {
                    name: "resident_buffers".to_string(),
                    value: u64::from(prepared.resident.is_some()),
                },
            ],
            ..Default::default()
        },
        baseline_metrics: Some(BenchMetrics {
            wall_ns: Some(prepared.baseline_wall_ns),
            input_bytes: Some(input_bytes),
            output_bytes: Some(baseline_output_bytes),
            bytes_touched: Some(input_bytes.saturating_add(baseline_output_bytes)),
            bytes_read: Some(input_bytes),
            bytes_written: Some(baseline_output_bytes),
            ..Default::default()
        }),
        outputs: timed.outputs,
        baseline_outputs: Some(vec![prepared.baseline_output.clone()]),
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
    &DataflowIfdsStep as &'static dyn BenchCase
}

inventory::submit! {
    &DataflowPointsToAliasStep as &'static dyn BenchCase
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dataflow_benchmark_ids_are_consumer_neutral() {
        let cases: [(&dyn BenchCase, &str, &str); 3] = [
            (
                &DataflowReachingDefBitset,
                "dataflow.reaching_def.bitset.1m",
                "Dataflow Reaching-Def Bitset 1M",
            ),
            (
                &DataflowIfdsStep,
                "dataflow.ifds.step.262k",
                "Dataflow IFDS Step 262K",
            ),
            (
                &DataflowPointsToAliasStep,
                "dataflow.points_to.alias.step.262k",
                "Dataflow Points-To Alias Step 262K",
            ),
        ];
        for (case, expected_id, expected_name) in cases {
            let metadata = case.metadata();
            assert_eq!(metadata.id.0, expected_id);
            assert_eq!(metadata.name, expected_name);
        }
    }

    #[test]
    fn reaching_def_prepare_caches_encoded_inputs_and_baseline() {
        let prepared = prepare_reaching_def_bitset(None).unwrap();
        assert_eq!(prepared.encoded_inputs.len(), 3);
        assert_eq!(
            prepared.encoded_inputs.iter().map(Vec::len).sum::<usize>(),
            WORD_COUNT * 12
        );
        assert_eq!(prepared.baseline_output.len(), WORD_COUNT * 4);
        let (gen_kill_in, use_set, _) = reaching_def_fixture_words();
        assert_eq!(
            prepared.baseline_output,
            encode_u32_words(&bitset_and_cpu_ref(&gen_kill_in, &use_set))
        );
    }

    #[test]
    fn graph_prepare_caches_encoded_inputs_and_baseline() {
        let prepared = linear_graph_prepared(
            dataflow_ifds::ifds_reach_step(
                ProgramGraphShape::new(GRAPH_NODE_COUNT, GRAPH_EDGE_COUNT),
                "frontier_in",
                "frontier_out",
            ),
            "ifds_step",
            None,
        )
        .unwrap();
        assert_eq!(prepared.encoded_inputs.len(), 7);
        assert_eq!(prepared.baseline_output.len(), GRAPH_WORD_COUNT * 4);
        assert_eq!(
            prepared.encoded_inputs.iter().map(Vec::len).sum::<usize>() as u64,
            graph_bytes_touched().0
        );
    }
}

