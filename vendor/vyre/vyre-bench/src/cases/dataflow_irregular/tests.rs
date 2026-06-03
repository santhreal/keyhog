use super::fixture::{
    ifds_active_high_degree_sources, ifds_active_queue_inputs, ifds_queue_inputs,
};
use super::queue::{
    ifds_queue_closure_delta_lanes_per_source, ifds_queue_closure_inputs,
    ifds_queue_closure_reset_program, ifds_queue_materialize_sequence_fingerprint,
    ifds_queue_should_use_row_strided, ifds_queue_should_use_split_high_degree,
    ifds_queue_traverse_logical_lanes, ifds_sparse_queue_capacity,
    prepare_ifds_skewed_active_queue_step, prepare_ifds_skewed_queue_closure,
    prepare_ifds_skewed_queue_materialize_step, ACTIVE_QUEUE_ACTIVE_QUEUE_INDEX,
    ACTIVE_QUEUE_EDGE_KIND_INDEX, ACTIVE_QUEUE_EDGE_OFFSETS_INDEX, ACTIVE_QUEUE_EDGE_TARGETS_INDEX,
    ACTIVE_QUEUE_FRONTIER_OUT_INDEX, ACTIVE_QUEUE_LEN_INDEX, QUEUE_ACTIVE_QUEUE_INDEX,
    QUEUE_CLOSURE_ACCUMULATOR_INDEX, QUEUE_CLOSURE_EDGE_KIND_INDEX,
    QUEUE_CLOSURE_EDGE_OFFSETS_INDEX, QUEUE_CLOSURE_EDGE_TARGETS_INDEX, QUEUE_CLOSURE_LEN_A_INDEX,
    QUEUE_CLOSURE_LEN_B_INDEX, QUEUE_CLOSURE_QUEUE_A_INDEX, QUEUE_CLOSURE_QUEUE_B_INDEX,
    QUEUE_CLOSURE_SEED_FRONTIER_INDEX, QUEUE_CLOSURE_SEED_LEN_INDEX,
    QUEUE_CLOSURE_SEED_QUEUE_INDEX, QUEUE_FRONTIER_IN_INDEX, QUEUE_FRONTIER_OUT_INDEX,
    QUEUE_HIGH_LEN_INDEX, QUEUE_HIGH_QUEUE_INDEX, QUEUE_LEN_INDEX, QUEUE_RESET_GRID,
};
use super::*;
use vyre_primitives::graph::csr_queue_split::{
    csr_queue_split_low_dispatch_grid, csr_queue_split_mixed_logical_lanes,
    CSR_QUEUE_SPLIT_HIGH_DEGREE_THRESHOLD,
};

mod queue_closure_generated;

#[test]
fn ifds_skewed_fixture_has_filtered_edges_and_bitset_frontier() {
    let fixture = build_ifds_skewed_fixture(4096).unwrap();
    let oracle = ifds_skewed_cpu_oracle(&fixture);

    assert_eq!(fixture.edge_offsets.len(), 4097);
    assert!(fixture.edge_targets.len() > 4096);
    assert_eq!(fixture.stats.max_degree, UGLY_HUB_DEGREE);
    assert!(fixture.stats.high_degree_sources > 0);
    assert!(ifds_queue_should_use_row_strided(fixture.stats.max_degree));
    assert!(fixture.stats.active_sources > 0);
    assert!(oracle.allowed_edges_from_active > 0);
    assert!(oracle.filtered_edges_from_active > 0);
    assert_eq!(fixture.frontier_in.len(), 128);
}

#[test]
fn ifds_skewed_cpu_oracle_sets_packed_output_words() {
    let fixture = build_ifds_skewed_fixture(4096).unwrap();
    let oracle = ifds_skewed_cpu_oracle(&fixture);

    assert_eq!(oracle.output.len(), fixture.frontier_out_seed.len());
    assert!(oracle.output_words_set > 0);
    assert!(oracle.output.iter().any(|word| *word != 0));
}

#[test]
fn ifds_skewed_prepare_builds_vyre_program_and_oracle() {
    let prepared = prepare_ifds_skewed_step(None).unwrap();

    assert_eq!(prepared.program.workgroup_size(), [256, 1, 1]);
    assert_eq!(prepared.stats.nodes, NODE_COUNT);
    assert_eq!(prepared.baseline_output.len(), FRONTIER_WORDS * 4);
    assert_eq!(prepared.inputs.len(), 7);
    assert!(prepared.stats.filtered_edges_from_active > 0);
    assert!(prepared.input_bytes_total > u64::from(NODE_COUNT) * 20);
}

#[test]
fn ifds_queue_inputs_preserve_sparse_frontier_and_device_scratch() {
    let fixture = build_ifds_skewed_fixture(4096).unwrap();
    let capacity = ifds_sparse_queue_capacity(fixture.stats.active_sources).unwrap();
    let high_capacity =
        ifds_active_high_degree_sources(&fixture, CSR_QUEUE_SPLIT_HIGH_DEGREE_THRESHOLD).unwrap();
    let inputs = ifds_queue_inputs(&fixture, capacity, high_capacity).unwrap();

    assert_eq!(inputs.len(), 9);
    assert_eq!(
        inputs[QUEUE_FRONTIER_IN_INDEX],
        vyre_primitives::wire::pack_u32_slice(&fixture.frontier_in)
    );
    assert_eq!(
        inputs[QUEUE_ACTIVE_QUEUE_INDEX].len(),
        capacity as usize * std::mem::size_of::<u32>()
    );
    assert!(inputs[QUEUE_ACTIVE_QUEUE_INDEX]
        .iter()
        .all(|byte| *byte == 0));
    assert_eq!(
        inputs[QUEUE_LEN_INDEX],
        vyre_primitives::wire::pack_u32_slice(&[0])
    );
    assert_eq!(
        inputs[QUEUE_FRONTIER_OUT_INDEX],
        vyre_primitives::wire::pack_u32_slice(&fixture.frontier_out_seed)
    );
    assert_eq!(
        inputs[QUEUE_HIGH_QUEUE_INDEX].len(),
        high_capacity as usize * std::mem::size_of::<u32>()
    );
    assert!(inputs[QUEUE_HIGH_QUEUE_INDEX].iter().all(|byte| *byte == 0));
    assert_eq!(
        inputs[QUEUE_HIGH_LEN_INDEX],
        vyre_primitives::wire::pack_u32_slice(&[0])
    );
}

#[test]
fn ifds_queue_inputs_reject_capacity_below_active_sources() {
    let fixture = build_ifds_skewed_fixture(4096).unwrap();
    let undersized = fixture.stats.active_sources.saturating_sub(1) as u32;
    let high_capacity =
        ifds_active_high_degree_sources(&fixture, CSR_QUEUE_SPLIT_HIGH_DEGREE_THRESHOLD).unwrap();

    let err = ifds_queue_inputs(&fixture, undersized, high_capacity).unwrap_err();

    assert!(
        err.to_string().contains("queue_capacity >= active_sources"),
        "queue fixture errors must name the capacity invariant, got: {err}"
    );

    let high_err =
        ifds_queue_inputs(&fixture, fixture.stats.active_sources as u32, u32::MAX).unwrap_err();
    assert!(
        high_err
            .to_string()
            .contains("high_degree_queue_capacity <= queue_capacity"),
        "high queue capacity errors must name the split invariant, got: {high_err}"
    );
}

#[test]
fn ifds_active_queue_inputs_materialize_frontier_queue_once() {
    let fixture = build_ifds_skewed_fixture(4096).unwrap();
    let capacity = ifds_sparse_queue_capacity(fixture.stats.active_sources).unwrap();
    let inputs = ifds_active_queue_inputs(&fixture, capacity).unwrap();
    let mut active_queue = Vec::new();
    vyre_primitives::wire::unpack_u32_slice_into(
        &inputs[ACTIVE_QUEUE_ACTIVE_QUEUE_INDEX],
        capacity as usize,
        "active queue test",
        &mut active_queue,
    )
    .unwrap();
    let mut queue_len = Vec::new();
    vyre_primitives::wire::unpack_u32_slice_into(
        &inputs[ACTIVE_QUEUE_LEN_INDEX],
        1,
        "active queue len test",
        &mut queue_len,
    )
    .unwrap();

    assert_eq!(inputs.len(), 6);
    assert_eq!(queue_len, vec![fixture.stats.active_sources as u32]);
    assert_eq!(
        active_queue.len(),
        capacity as usize,
        "active queue buffer should be capacity-padded for stable resident dispatch"
    );
    assert_eq!(active_queue[0], 0);
    assert!(
        active_queue[..fixture.stats.active_sources as usize]
            .windows(2)
            .all(|pair| pair[0] < pair[1]),
        "pre-materialized active queue should preserve source order"
    );
    assert_eq!(
        inputs[ACTIVE_QUEUE_FRONTIER_OUT_INDEX],
        vyre_primitives::wire::pack_u32_slice(&fixture.frontier_out_seed)
    );
    assert_eq!(
        inputs[ACTIVE_QUEUE_EDGE_OFFSETS_INDEX],
        vyre_primitives::wire::pack_u32_slice(&fixture.edge_offsets)
    );
    assert_eq!(
        inputs[ACTIVE_QUEUE_EDGE_TARGETS_INDEX],
        vyre_primitives::wire::pack_u32_slice(&fixture.edge_targets)
    );
    assert_eq!(
        inputs[ACTIVE_QUEUE_EDGE_KIND_INDEX],
        vyre_primitives::wire::pack_u32_slice(&fixture.edge_kind_mask)
    );
}

#[test]
fn ifds_queue_materialize_prepare_builds_parallel_sparse_sequence() {
    let prepared = prepare_ifds_skewed_queue_materialize_step(None).unwrap();

    assert_eq!(prepared.reset_program.workgroup_size(), [1, 1, 1]);
    assert_eq!(QUEUE_RESET_GRID, [1, 1, 1]);
    assert_eq!(prepared.queue_program.workgroup_size(), [256, 1, 1]);
    assert_eq!(prepared.traverse_program.workgroup_size(), [256, 1, 1]);
    assert!(prepared.row_strided_traverse);
    assert!(prepared.split_high_degree_traverse);
    assert!(prepared.high_traverse_program.is_some());
    assert_eq!(prepared.high_degree_queue_capacity, 256);
    assert_eq!(
        prepared.traverse_grid,
        csr_queue_split_low_dispatch_grid(prepared.queue_capacity)
    );
    assert_eq!(prepared.high_traverse_grid, [32, 1, 1]);
    assert_eq!(
        prepared.traverse_logical_lanes,
        csr_queue_split_mixed_logical_lanes(
            prepared.queue_capacity,
            prepared.high_degree_queue_capacity,
        )
    );
    assert_eq!(
        prepared.queue_program.buffers()[0].name.as_ref(),
        "frontier_in"
    );
    assert_eq!(
        prepared.queue_program.buffers()[0].count as usize,
        FRONTIER_WORDS
    );
    assert_eq!(
        prepared.queue_program.buffers()[3].name.as_ref(),
        "frontier_out"
    );
    assert_eq!(
        prepared.queue_program.buffers()[3].count as usize,
        FRONTIER_WORDS
    );
    assert_eq!(prepared.stats.nodes, NODE_COUNT);
    assert_eq!(prepared.inputs.len(), 9);
    assert_eq!(
        prepared.inputs[QUEUE_FRONTIER_IN_INDEX].len(),
        FRONTIER_WORDS * 4
    );
    assert_eq!(
        prepared.inputs[QUEUE_ACTIVE_QUEUE_INDEX].len(),
        prepared.queue_capacity as usize * std::mem::size_of::<u32>()
    );
    assert_eq!(
        prepared.inputs[QUEUE_HIGH_QUEUE_INDEX].len(),
        prepared.high_degree_queue_capacity as usize * std::mem::size_of::<u32>()
    );
    assert_eq!(prepared.baseline_output.len(), FRONTIER_WORDS * 4);
    assert!(u64::from(prepared.queue_capacity) >= prepared.stats.active_sources);
    assert!(
        prepared.queue_capacity < prepared.stats.nodes / 32,
        "queue capacity should stay sparse relative to the full node-grid launch"
    );
    assert!(
        prepared.traverse_logical_lanes
            < ifds_queue_traverse_logical_lanes(prepared.queue_capacity, true) / 16,
        "split IFDS traversal should avoid assigning a row-strided team to every active source"
    );
    assert!(prepared.stats.allowed_edges_from_active > 0);
    assert!(prepared.input_bytes_total > u64::from(NODE_COUNT) * 12);
    assert_ne!(
        ifds_queue_materialize_sequence_fingerprint(&prepared),
        prepared.traverse_program.fingerprint()
    );
}

#[test]
fn generated_ifds_queue_split_targets_only_active_hub_rows() {
    const CASES: u32 = 10_000;

    let mut split_cases = 0_u32;
    let mut total_row_strided_lanes = 0_u128;
    let mut total_split_lanes = 0_u128;
    let mut total_high_capacity = 0_u64;

    for case in 0..CASES {
        let node_count = 32_u32 << (case % 8);
        let fixture = build_ifds_skewed_fixture(node_count).unwrap_or_else(|error| {
            panic!("generated IFDS split fixture case {case} failed: {error}")
        });
        let queue_capacity = ifds_sparse_queue_capacity(fixture.stats.active_sources)
            .unwrap_or_else(|error| panic!("generated IFDS queue capacity case {case}: {error}"));
        let high_capacity =
            ifds_active_high_degree_sources(&fixture, CSR_QUEUE_SPLIT_HIGH_DEGREE_THRESHOLD)
                .unwrap_or_else(|error| {
                    panic!("generated IFDS high capacity case {case}: {error}")
                });
        let inputs = ifds_queue_inputs(&fixture, queue_capacity, high_capacity)
            .unwrap_or_else(|error| panic!("generated IFDS queue inputs case {case}: {error}"));
        let row_strided_lanes = ifds_queue_traverse_logical_lanes(queue_capacity, true);
        let split_lanes = csr_queue_split_mixed_logical_lanes(queue_capacity, high_capacity);

        assert_eq!(
            inputs[QUEUE_ACTIVE_QUEUE_INDEX].len(),
            queue_capacity as usize * std::mem::size_of::<u32>(),
            "active queue bytes case {case}"
        );
        assert_eq!(
            inputs[QUEUE_HIGH_QUEUE_INDEX].len(),
            high_capacity as usize * std::mem::size_of::<u32>(),
            "high queue bytes case {case}"
        );
        let uses_split = ifds_queue_should_use_split_high_degree(queue_capacity, high_capacity);
        if uses_split {
            assert!(
                split_lanes < row_strided_lanes,
                "split lanes should beat all-row striding case {case}"
            );
        }
        split_cases += u32::from(uses_split);
        total_row_strided_lanes += u128::from(row_strided_lanes);
        total_split_lanes += u128::from(if uses_split {
            split_lanes
        } else {
            row_strided_lanes
        });
        total_high_capacity += u64::from(high_capacity);
    }

    assert!(split_cases > CASES / 2);
    assert!(total_high_capacity > 0);
    assert!(
        total_split_lanes * 8 < total_row_strided_lanes,
        "mixed IFDS traversal should keep generated lane pressure far below all-row striding"
    );
}

#[test]
fn generated_word_queue_materializer_launches_frontier_words_not_nodes() {
    const CASES: u32 = 10_000;

    let mut old_lanes = 0_u128;
    let mut new_lanes = 0_u128;
    for case in 0..CASES {
        let node_count = 65_536 + (mix32(case ^ 0xF901_DA7A) % 983_041);
        let frontier_words = node_count.div_ceil(32);
        let queue_capacity = 1 + (mix32(case ^ 0x51E5_4A11) % frontier_words.max(1));
        let program = vyre_primitives::graph::csr_frontier_queue::frontier_words_to_queue_parallel(
            "frontier_in",
            "active_queue",
            "queue_len",
            node_count,
            queue_capacity,
        );
        let inputs = vec![
            vec![0_u8; frontier_words as usize * std::mem::size_of::<u32>()],
            vec![0_u8; queue_capacity as usize * std::mem::size_of::<u32>()],
            vyre_primitives::wire::pack_u32_slice(&[0]),
        ];
        let grid = vyre_driver::infer_dispatch_grid(
            &program,
            &inputs,
            &vyre_driver::DispatchConfig::default(),
        )
        .unwrap_or_else(|error| {
            panic!("generated word queue materializer case {case} failed: {error}")
        });
        let word_grid_x = frontier_words.div_ceil(256).max(1);
        let node_grid_x = node_count.div_ceil(256).max(1);

        assert_eq!(grid, [word_grid_x, 1, 1], "case {case}");
        old_lanes += u128::from(node_grid_x) * 256;
        new_lanes += u128::from(word_grid_x) * 256;
    }

    assert!(
        old_lanes >= new_lanes * 31,
        "packed-word queue materialization should cut generated launch lanes by about 32x"
    );
}

#[test]
fn ifds_active_queue_prepare_builds_sparse_traversal_program() {
    let prepared = prepare_ifds_skewed_active_queue_step(None).unwrap();

    assert_eq!(prepared.traverse_program.workgroup_size(), [256, 1, 1]);
    assert!(prepared.row_strided_traverse);
    assert_eq!(
        prepared.traverse_grid,
        vyre_primitives::graph::csr_queue_strided::csr_queue_strided_forward_dispatch_grid(
            prepared.queue_capacity
        )
    );
    assert_eq!(
        prepared.traverse_logical_lanes,
        ifds_queue_traverse_logical_lanes(prepared.queue_capacity, prepared.row_strided_traverse)
    );
    assert_eq!(prepared.stats.nodes, NODE_COUNT);
    assert_eq!(prepared.inputs.len(), 6);
    assert_eq!(
        prepared.inputs[ACTIVE_QUEUE_ACTIVE_QUEUE_INDEX].len(),
        prepared.queue_capacity as usize * std::mem::size_of::<u32>()
    );
    assert_eq!(
        prepared.inputs[ACTIVE_QUEUE_LEN_INDEX],
        vyre_primitives::wire::pack_u32_slice(&[prepared.stats.active_sources as u32])
    );
    assert_eq!(prepared.baseline_output.len(), FRONTIER_WORDS * 4);
    assert!(u64::from(prepared.queue_capacity) >= prepared.stats.active_sources);
    assert!(prepared.queue_capacity < prepared.stats.nodes / 32);
    assert!(prepared.stats.allowed_edges_from_active > 0);
}

fn mix32(mut value: u32) -> u32 {
    value ^= value >> 16;
    value = value.wrapping_mul(0x7FEB_352D);
    value ^= value >> 15;
    value = value.wrapping_mul(0x846C_A68B);
    value ^ (value >> 16)
}

#[test]
fn ifds_queue_reset_only_clears_len_before_fused_queue_build() {
    let program = vyre_primitives::graph::csr_frontier_queue::frontier_queue_len_init("queue_len");

    assert_eq!(program.workgroup_size(), [1, 1, 1]);
    assert_eq!(program.buffers().len(), 1);
    assert_eq!(program.buffers()[0].name.as_ref(), "queue_len");
    assert_eq!(program.buffers()[0].binding, 0);
    assert_eq!(program.buffers()[0].count, 1);
}

#[test]
fn ifds_queue_closure_inputs_allocate_ping_pong_queues_and_seed_accumulator() {
    let fixture = build_ifds_skewed_fixture(4096).unwrap();
    let inputs = ifds_queue_closure_inputs(&fixture, fixture.stats.nodes).unwrap();

    assert_eq!(inputs.len(), 11);
    assert_eq!(
        inputs[QUEUE_CLOSURE_SEED_FRONTIER_INDEX],
        vyre_primitives::wire::pack_u32_slice(&fixture.frontier_in)
    );
    assert_eq!(
        inputs[QUEUE_CLOSURE_SEED_LEN_INDEX],
        vyre_primitives::wire::pack_u32_slice(&[fixture.stats.active_sources as u32])
    );
    let mut seed_queue = Vec::new();
    vyre_primitives::wire::unpack_u32_slice_into(
        &inputs[QUEUE_CLOSURE_SEED_QUEUE_INDEX],
        fixture.stats.active_sources as usize,
        "queue closure seed queue test",
        &mut seed_queue,
    )
    .unwrap();
    assert_eq!(seed_queue.len(), fixture.stats.active_sources as usize);
    assert_eq!(seed_queue[0], 0);
    assert!(
        seed_queue.windows(2).all(|pair| pair[0] < pair[1]),
        "pre-materialized queue closure seed queue should preserve source order"
    );
    assert_eq!(
        inputs[QUEUE_CLOSURE_ACCUMULATOR_INDEX],
        inputs[QUEUE_CLOSURE_SEED_FRONTIER_INDEX]
    );
    assert_eq!(
        inputs[QUEUE_CLOSURE_QUEUE_A_INDEX].len(),
        fixture.stats.nodes as usize * std::mem::size_of::<u32>()
    );
    assert_eq!(
        inputs[QUEUE_CLOSURE_QUEUE_B_INDEX].len(),
        fixture.stats.nodes as usize * std::mem::size_of::<u32>()
    );
    assert!(inputs[QUEUE_CLOSURE_QUEUE_A_INDEX]
        .iter()
        .all(|byte| *byte == 0));
    assert!(inputs[QUEUE_CLOSURE_QUEUE_B_INDEX]
        .iter()
        .all(|byte| *byte == 0));
    assert_eq!(
        inputs[QUEUE_CLOSURE_LEN_A_INDEX],
        vyre_primitives::wire::pack_u32_slice(&[0])
    );
    assert_eq!(
        inputs[QUEUE_CLOSURE_LEN_B_INDEX],
        vyre_primitives::wire::pack_u32_slice(&[0])
    );
    assert_eq!(
        inputs[QUEUE_CLOSURE_EDGE_OFFSETS_INDEX],
        vyre_primitives::wire::pack_u32_slice(&fixture.edge_offsets)
    );
    assert_eq!(
        inputs[QUEUE_CLOSURE_EDGE_TARGETS_INDEX],
        vyre_primitives::wire::pack_u32_slice(&fixture.edge_targets)
    );
    assert_eq!(
        inputs[QUEUE_CLOSURE_EDGE_KIND_INDEX],
        vyre_primitives::wire::pack_u32_slice(&fixture.edge_kind_mask)
    );
}

#[test]
fn ifds_queue_closure_reset_program_restores_accumulator_and_clears_lengths() {
    let program = ifds_queue_closure_reset_program(128, 7, 256);

    assert_eq!(program.workgroup_size(), [256, 1, 1]);
    assert_eq!(program.buffers().len(), 7);
    assert_eq!(program.buffers()[0].name.as_ref(), "frontier_seed");
    assert_eq!(program.buffers()[1].name.as_ref(), "seed_queue");
    assert_eq!(program.buffers()[2].name.as_ref(), "seed_len");
    assert_eq!(program.buffers()[3].name.as_ref(), "active_queue");
    assert_eq!(program.buffers()[4].name.as_ref(), "accumulator");
    assert_eq!(program.buffers()[5].name.as_ref(), "queue_a_len");
    assert_eq!(program.buffers()[6].name.as_ref(), "queue_b_len");
    assert_eq!(program.buffers()[1].count, 7);
    assert_eq!(program.buffers()[3].count, 256);
    assert_eq!(program.buffers()[4].count, 128);
}

#[test]
fn ifds_queue_closure_prepare_builds_delta_fixpoint_sequence() {
    let prepared = prepare_ifds_skewed_queue_closure(None).unwrap();

    assert_eq!(prepared.reset_program.workgroup_size(), [256, 1, 1]);
    assert_eq!(prepared.clear_len_program.workgroup_size(), [1, 1, 1]);
    assert_eq!(prepared.delta_program.workgroup_size(), [256, 1, 1]);
    assert!(prepared.row_strided_delta);
    assert_eq!(
        prepared.delta_grid,
        vyre_primitives::graph::csr_queue_delta::csr_queue_delta_strided_dispatch_grid(
            prepared.queue_capacity
        )
    );
    assert_eq!(
        prepared.delta_program.buffers()[0].name.as_ref(),
        "active_queue"
    );
    assert_eq!(
        prepared.delta_program.buffers()[6].name.as_ref(),
        "next_queue"
    );
    assert_eq!(
        prepared.reset_program.buffers()[0].name.as_ref(),
        "frontier_seed"
    );
    assert_eq!(
        prepared.reset_program.buffers()[0].count as usize,
        FRONTIER_WORDS
    );
    assert_eq!(prepared.stats.nodes, NODE_COUNT);
    assert_eq!(
        prepared.seed_queue_len,
        prepared.stats.active_sources as u32
    );
    assert_eq!(prepared.queue_capacity, prepared.max_wave_queue_len);
    assert!(prepared.queue_capacity < NODE_COUNT);
    assert_eq!(prepared.inputs.len(), 11);
    assert_eq!(
        prepared.inputs[QUEUE_CLOSURE_SEED_QUEUE_INDEX].len(),
        prepared.seed_queue_len as usize * std::mem::size_of::<u32>()
    );
    assert_eq!(
        prepared.inputs[QUEUE_CLOSURE_QUEUE_A_INDEX].len(),
        prepared.queue_capacity as usize * std::mem::size_of::<u32>()
    );
    assert_eq!(prepared.baseline_output.len(), FRONTIER_WORDS * 4);
    assert_eq!(prepared.closure_changed, 1);
    assert!(prepared.closure_iterations > 0);
    assert!(prepared.closure_iterations <= closure::CLOSURE_MAX_ITERS);
    assert!(prepared.total_queue_pops >= prepared.stats.active_sources);
    assert!(prepared.max_wave_queue_len >= prepared.stats.active_sources as u32);
    assert_eq!(
        prepared.wave_queue_lengths.len(),
        prepared.closure_iterations as usize
    );
    assert_eq!(
        prepared
            .wave_queue_lengths
            .iter()
            .map(|&len| u64::from(len))
            .sum::<u64>(),
        prepared.total_queue_pops
    );
    assert_eq!(
        prepared
            .wave_queue_lengths
            .iter()
            .copied()
            .max()
            .unwrap_or(0),
        prepared.max_wave_queue_len
    );
    let launch_lanes = crate::cases::queue_closure_profile::queue_closure_launch_lanes_per_wave(
        prepared.delta_grid,
        prepared.delta_program.workgroup_size(),
    );
    let lane_profile =
        crate::cases::queue_closure_profile::QueueClosureLaneProfile::from_wave_lengths_with_launch_lanes(
            prepared.queue_capacity,
            &prepared.wave_queue_lengths,
            ifds_queue_closure_delta_lanes_per_source(prepared.row_strided_delta),
            launch_lanes,
        );
    assert_eq!(
        lane_profile.profiled_delta_source_slots,
        prepared.total_queue_pops
    );
    assert!(lane_profile.elided_delta_lanes > 0);
    assert!(lane_profile.launch_elided_delta_lanes > 0);
    assert!(lane_profile.launch_lane_elision_x1000 > 800);
}

#[test]
fn ifds_skewed_closure_oracle_expands_seed_frontier() {
    let fixture = build_ifds_skewed_fixture(4096).unwrap();
    let oracle = ifds_skewed_closure_oracle(&fixture, closure::CLOSURE_MAX_ITERS);

    assert_eq!(oracle.output.len(), fixture.frontier_in.len());
    assert_eq!(oracle.changed, 1);
    assert!(oracle.iterations > 0);
    assert!(oracle.iterations <= closure::CLOSURE_MAX_ITERS);
    assert!(
        oracle.output_words_set
            >= fixture
                .frontier_in
                .iter()
                .filter(|word| **word != 0)
                .count() as u64
    );
    let launch_waves = ifds_skewed_launch_wave_iterations(&fixture, closure::CLOSURE_MAX_ITERS);
    assert!(launch_waves >= oracle.iterations);
    assert!(launch_waves <= closure::CLOSURE_MAX_ITERS);
}

#[test]
fn ifds_skewed_closure_resident_inputs_keep_immutable_seed() {
    let fixture = build_ifds_skewed_fixture(4096).unwrap();
    let inputs = super::fixture::ifds_closure_resident_inputs(&fixture);

    assert_eq!(inputs.len(), 8);
    assert_eq!(inputs[5].len(), fixture.frontier_in.len() * 4);
    assert_eq!(inputs[5], inputs[6]);
    assert_eq!(inputs[7], vyre_primitives::wire::pack_u32_slice(&[0]));
}

#[test]
fn ifds_skewed_closure_prepare_builds_resident_fixpoint_program() {
    let prepared = closure::prepare_ifds_skewed_closure(None).unwrap();

    assert_eq!(prepared.program.workgroup_size(), [256, 1, 1]);
    assert_eq!(prepared.reset_program.workgroup_size(), [256, 1, 1]);
    assert_eq!(prepared.stats.nodes, NODE_COUNT);
    assert_eq!(prepared.inputs.len(), 7);
    assert_eq!(prepared.inputs[5].len(), FRONTIER_WORDS * 4);
    assert_eq!(prepared.baseline_outputs.len(), 2);
    assert_eq!(prepared.baseline_outputs[0].len(), FRONTIER_WORDS * 4);
    assert_eq!(prepared.baseline_outputs[1].len(), 4);
    assert_eq!(prepared.closure_changed, 1);
    assert!(prepared.closure_iterations > 0);
    assert!(prepared.dispatch_iterations >= prepared.closure_iterations);
    assert!(prepared.dispatch_iterations < closure::CLOSURE_MAX_ITERS);
    assert!(prepared.input_bytes_total > u64::from(NODE_COUNT) * 20);
}
