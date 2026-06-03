//! CUDA parity for device-side active-frontier queue sparse traversal.

#![cfg(test)]

mod common;

use common::{bytes_u32, live_backend, u32_bytes};
use vyre_driver_cuda::CudaOptimizerDispatcher;
use vyre_primitives::bitset::bitset_words;
use vyre_primitives::graph::csr_frontier_queue::{
    csr_queue_forward_traverse, csr_queue_forward_traverse_cpu, frontier_to_queue,
    frontier_to_queue_cpu, frontier_to_queue_parallel,
};
use vyre_primitives::graph::csr_queue_delta::{
    csr_queue_delta_enqueue, csr_queue_delta_enqueue_cpu, csr_queue_delta_strided_dispatch_grid,
    csr_queue_delta_strided_enqueue,
};
use vyre_primitives::graph::csr_queue_split::CSR_QUEUE_SPLIT_HIGH_DEGREE_THRESHOLD;
use vyre_self_substrate::csr_frontier_queue_batch_resident::{
    run_resident_csr_queue_batch_budgeted_into, run_resident_csr_queue_batch_into,
    ResidentCsrQueueBatchScratch,
};
use vyre_self_substrate::csr_frontier_queue_resident::{
    run_resident_csr_queue_query_into, upload_resident_csr_queue_graph, ResidentCsrQueueScratch,
};
use vyre_self_substrate::optimizer::dispatcher::{
    OptimizerDispatcher, ResidentDispatchStep, ResidentReadRange,
};

fn pack_nodes(bits: &[u32], node_count: u32) -> Vec<u32> {
    let mut out = vec![0u32; bitset_words(node_count) as usize];
    for &bit in bits {
        out[bit as usize / 32] |= 1u32 << (bit % 32);
    }
    out
}

fn skewed_high_degree_graph(node_count: u32) -> (Vec<u32>, Vec<u32>, Vec<u32>) {
    assert!(
        node_count > 40,
        "Fix: skewed CUDA CSR queue parity graph needs enough target nodes."
    );
    let mut edge_offsets = Vec::with_capacity(node_count as usize + 1);
    let mut edge_targets = Vec::with_capacity(CSR_QUEUE_SPLIT_HIGH_DEGREE_THRESHOLD as usize + 8);
    let mut edge_kind_mask = Vec::with_capacity(edge_targets.capacity());
    edge_offsets.push(0);
    for src in 0..node_count {
        if src == 0 {
            for edge in 0..CSR_QUEUE_SPLIT_HIGH_DEGREE_THRESHOLD {
                edge_targets.push(edge.wrapping_mul(7).wrapping_add(11) % node_count);
                edge_kind_mask.push(if edge % 5 == 0 { 2 } else { 1 });
            }
        } else if (1..=8).contains(&src) {
            edge_targets.push((src + 23) % node_count);
            edge_kind_mask.push(if src % 3 == 0 { 2 } else { 1 });
        }
        edge_offsets.push(edge_targets.len() as u32);
    }
    (edge_offsets, edge_targets, edge_kind_mask)
}

#[test]
fn cuda_resident_frontier_queue_drives_sparse_csr_without_selector_readback() {
    let backend = live_backend();
    let dispatcher = CudaOptimizerDispatcher::new(&backend);
    let node_count = 8u32;
    let queue_capacity = 8u32;
    let frontier = pack_nodes(&[0, 3], node_count);
    let edge_offsets = vec![0, 2, 2, 2, 5, 5, 5, 5, 5];
    let edge_targets = vec![1, 2, 4, 5, 6];
    let edge_kind_mask = vec![1, 2, 1, 1, 2];
    let (expected_queue, expected_len) =
        frontier_to_queue_cpu(&frontier, node_count, queue_capacity as usize);
    let expected_out = csr_queue_forward_traverse_cpu(
        &expected_queue,
        expected_len,
        &edge_offsets,
        &edge_targets,
        &edge_kind_mask,
        node_count,
        1,
    );

    let frontier_handle = dispatcher
        .alloc_resident(frontier.len() * std::mem::size_of::<u32>())
        .expect("Fix: frontier resident allocation failed.");
    let queue_handle = dispatcher
        .alloc_resident(queue_capacity as usize * std::mem::size_of::<u32>())
        .expect("Fix: queue resident allocation failed.");
    let queue_len_handle = dispatcher
        .alloc_resident(std::mem::size_of::<u32>())
        .expect("Fix: queue_len resident allocation failed.");
    let edge_offsets_handle = dispatcher
        .alloc_resident(edge_offsets.len() * std::mem::size_of::<u32>())
        .expect("Fix: edge_offsets resident allocation failed.");
    let edge_targets_handle = dispatcher
        .alloc_resident(edge_targets.len() * std::mem::size_of::<u32>())
        .expect("Fix: edge_targets resident allocation failed.");
    let edge_kind_handle = dispatcher
        .alloc_resident(edge_kind_mask.len() * std::mem::size_of::<u32>())
        .expect("Fix: edge_kind_mask resident allocation failed.");
    let frontier_out_handle = dispatcher
        .alloc_resident(frontier.len() * std::mem::size_of::<u32>())
        .expect("Fix: frontier_out resident allocation failed.");

    let queue_program = frontier_to_queue(
        "frontier",
        "active_queue",
        "queue_len",
        node_count,
        queue_capacity,
    );
    let traverse_program = csr_queue_forward_traverse(
        "active_queue",
        "queue_len",
        "edge_offsets",
        "edge_targets",
        "edge_kind_mask",
        "frontier_out",
        node_count,
        edge_targets.len() as u32,
        queue_capacity,
        1,
    );
    let queue_handles = [frontier_handle, queue_handle, queue_len_handle];
    let traverse_handles = [
        queue_handle,
        queue_len_handle,
        edge_offsets_handle,
        edge_targets_handle,
        edge_kind_handle,
        frontier_out_handle,
    ];
    let steps = [
        ResidentDispatchStep {
            program: &queue_program,
            handle_ids: &queue_handles,
            grid_override: Some([node_count.div_ceil(256).max(1), 1, 1]),
        },
        ResidentDispatchStep {
            program: &traverse_program,
            handle_ids: &traverse_handles,
            grid_override: Some([queue_capacity.div_ceil(256).max(1), 1, 1]),
        },
    ];
    let zero_queue = vec![0u8; queue_capacity as usize * std::mem::size_of::<u32>()];
    let zero_count = vec![0u8; std::mem::size_of::<u32>()];
    let zero_frontier_out = vec![0u8; frontier.len() * std::mem::size_of::<u32>()];
    let frontier_bytes = u32_bytes(&frontier);
    let edge_offsets_bytes = u32_bytes(&edge_offsets);
    let edge_targets_bytes = u32_bytes(&edge_targets);
    let edge_kind_bytes = u32_bytes(&edge_kind_mask);
    let uploads = [
        (frontier_handle, frontier_bytes.as_slice()),
        (queue_handle, zero_queue.as_slice()),
        (queue_len_handle, zero_count.as_slice()),
        (edge_offsets_handle, edge_offsets_bytes.as_slice()),
        (edge_targets_handle, edge_targets_bytes.as_slice()),
        (edge_kind_handle, edge_kind_bytes.as_slice()),
        (frontier_out_handle, zero_frontier_out.as_slice()),
    ];

    backend.reset_telemetry();
    let read_ranges = [
        ResidentReadRange {
            handle_id: frontier_out_handle,
            byte_offset: 0,
            byte_len: frontier.len() * std::mem::size_of::<u32>(),
        },
        ResidentReadRange {
            handle_id: queue_len_handle,
            byte_offset: 0,
            byte_len: std::mem::size_of::<u32>(),
        },
    ];
    let outputs = dispatcher
        .upload_resident_many_sequence_read_ranges(&uploads, &steps, &read_ranges)
        .expect("Fix: resident queue sparse traversal sequence failed.");
    assert_eq!(bytes_u32(&outputs[0]), expected_out);
    assert_eq!(bytes_u32(&outputs[1]), vec![expected_len]);
    let telemetry = backend.telemetry_snapshot();
    assert_eq!(
        telemetry.kernel_launches, 2,
        "Fix: queue sparse traversal must be exactly queue-build + queue-consume kernels."
    );
    assert_eq!(
        telemetry.sync_points, 1,
        "Fix: resident queue sparse traversal must fence once for uploads, kernels, and compact readbacks."
    );
    assert_eq!(
        telemetry.readback_bytes,
        (frontier.len() * std::mem::size_of::<u32>() + std::mem::size_of::<u32>()) as u64,
        "Fix: queue sparse traversal readback must be compact and avoid queue payload D2H."
    );

    for handle in [
        frontier_handle,
        queue_handle,
        queue_len_handle,
        edge_offsets_handle,
        edge_targets_handle,
        edge_kind_handle,
        frontier_out_handle,
    ] {
        dispatcher
            .free_resident(handle)
            .expect("Fix: resident queue sparse traversal cleanup failed.");
    }
}

#[test]
fn cuda_resident_parallel_frontier_queue_scans_large_sparse_bitset() {
    let backend = live_backend();
    let dispatcher = CudaOptimizerDispatcher::new(&backend);
    let node_count = 1024u32;
    let queue_capacity = 16u32;
    let frontier = pack_nodes(&[0, 3, 511, 700], node_count);
    let mut edge_offsets = Vec::with_capacity(node_count as usize + 1);
    let mut edge_targets = Vec::with_capacity(node_count as usize);
    let mut edge_kind_mask = Vec::with_capacity(node_count as usize);
    edge_offsets.push(0);
    for src in 0..node_count {
        edge_targets.push((src.wrapping_mul(17).wrapping_add(9)) % node_count);
        edge_kind_mask.push(if src % 5 == 0 { 2 } else { 1 });
        edge_offsets.push(edge_targets.len() as u32);
    }
    let (expected_queue, expected_len) =
        frontier_to_queue_cpu(&frontier, node_count, queue_capacity as usize);
    let expected_out = csr_queue_forward_traverse_cpu(
        &expected_queue,
        expected_len,
        &edge_offsets,
        &edge_targets,
        &edge_kind_mask,
        node_count,
        1,
    );

    let frontier_handle = dispatcher
        .alloc_resident(frontier.len() * std::mem::size_of::<u32>())
        .expect("Fix: frontier resident allocation failed.");
    let queue_handle = dispatcher
        .alloc_resident(queue_capacity as usize * std::mem::size_of::<u32>())
        .expect("Fix: queue resident allocation failed.");
    let queue_len_handle = dispatcher
        .alloc_resident(std::mem::size_of::<u32>())
        .expect("Fix: queue_len resident allocation failed.");
    let edge_offsets_handle = dispatcher
        .alloc_resident(edge_offsets.len() * std::mem::size_of::<u32>())
        .expect("Fix: edge_offsets resident allocation failed.");
    let edge_targets_handle = dispatcher
        .alloc_resident(edge_targets.len() * std::mem::size_of::<u32>())
        .expect("Fix: edge_targets resident allocation failed.");
    let edge_kind_handle = dispatcher
        .alloc_resident(edge_kind_mask.len() * std::mem::size_of::<u32>())
        .expect("Fix: edge_kind_mask resident allocation failed.");
    let frontier_out_handle = dispatcher
        .alloc_resident(frontier.len() * std::mem::size_of::<u32>())
        .expect("Fix: frontier_out resident allocation failed.");

    let queue_program = frontier_to_queue_parallel(
        "frontier",
        "active_queue",
        "queue_len",
        node_count,
        queue_capacity,
    );
    let traverse_program = csr_queue_forward_traverse(
        "active_queue",
        "queue_len",
        "edge_offsets",
        "edge_targets",
        "edge_kind_mask",
        "frontier_out",
        node_count,
        edge_targets.len() as u32,
        queue_capacity,
        1,
    );
    let queue_handles = [frontier_handle, queue_handle, queue_len_handle];
    let traverse_handles = [
        queue_handle,
        queue_len_handle,
        edge_offsets_handle,
        edge_targets_handle,
        edge_kind_handle,
        frontier_out_handle,
    ];
    let steps = [
        ResidentDispatchStep {
            program: &queue_program,
            handle_ids: &queue_handles,
            grid_override: Some([node_count.div_ceil(256).max(1), 1, 1]),
        },
        ResidentDispatchStep {
            program: &traverse_program,
            handle_ids: &traverse_handles,
            grid_override: Some([queue_capacity.div_ceil(256).max(1), 1, 1]),
        },
    ];
    let zero_queue = vec![0u8; queue_capacity as usize * std::mem::size_of::<u32>()];
    let zero_count = vec![0u8; std::mem::size_of::<u32>()];
    let zero_frontier_out = vec![0u8; frontier.len() * std::mem::size_of::<u32>()];
    let frontier_bytes = u32_bytes(&frontier);
    let edge_offsets_bytes = u32_bytes(&edge_offsets);
    let edge_targets_bytes = u32_bytes(&edge_targets);
    let edge_kind_bytes = u32_bytes(&edge_kind_mask);
    let uploads = [
        (frontier_handle, frontier_bytes.as_slice()),
        (queue_handle, zero_queue.as_slice()),
        (queue_len_handle, zero_count.as_slice()),
        (edge_offsets_handle, edge_offsets_bytes.as_slice()),
        (edge_targets_handle, edge_targets_bytes.as_slice()),
        (edge_kind_handle, edge_kind_bytes.as_slice()),
        (frontier_out_handle, zero_frontier_out.as_slice()),
    ];
    let read_ranges = [
        ResidentReadRange {
            handle_id: frontier_out_handle,
            byte_offset: 0,
            byte_len: frontier.len() * std::mem::size_of::<u32>(),
        },
        ResidentReadRange {
            handle_id: queue_len_handle,
            byte_offset: 0,
            byte_len: std::mem::size_of::<u32>(),
        },
    ];

    backend.reset_telemetry();
    let outputs = dispatcher
        .upload_resident_many_sequence_read_ranges(&uploads, &steps, &read_ranges)
        .expect("Fix: resident parallel queue sparse traversal sequence failed.");

    assert_eq!(bytes_u32(&outputs[0]), expected_out);
    assert_eq!(bytes_u32(&outputs[1]), vec![expected_len]);
    let telemetry = backend.telemetry_snapshot();
    assert_eq!(
        telemetry.kernel_launches, 2,
        "Fix: parallel queue traversal should be queue-build + queue-consume kernels after setup uploads."
    );
    assert_eq!(
        telemetry.readback_bytes,
        (frontier.len() * std::mem::size_of::<u32>() + std::mem::size_of::<u32>()) as u64
    );

    for handle in [
        frontier_handle,
        queue_handle,
        queue_len_handle,
        edge_offsets_handle,
        edge_targets_handle,
        edge_kind_handle,
        frontier_out_handle,
    ] {
        dispatcher
            .free_resident(handle)
            .expect("Fix: resident parallel queue traversal cleanup failed.");
    }
}

#[test]
fn cuda_resident_queue_delta_enqueues_only_new_discoveries() {
    let backend = live_backend();
    let dispatcher = CudaOptimizerDispatcher::new(&backend);
    let node_count = 16u32;
    let active_queue_capacity = 8u32;
    let next_queue_capacity = 8u32;
    let active_queue = vec![0u32, 4, 0, 0, 0, 0, 0, 0];
    let active_len = vec![2u32];
    let edge_offsets = vec![0, 3, 3, 3, 3, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6];
    let edge_targets = vec![1, 2, 3, 2, 5, 6];
    let edge_kind_mask = vec![1, 1, 2, 1, 1, 1];
    let accumulator_seed = pack_nodes(&[0, 4], node_count);
    let (expected_accumulator, expected_next_queue, expected_next_len) =
        csr_queue_delta_enqueue_cpu(
            &active_queue,
            active_len[0],
            &edge_offsets,
            &edge_targets,
            &edge_kind_mask,
            &accumulator_seed,
            node_count,
            next_queue_capacity as usize,
            1,
        );

    let active_queue_handle = dispatcher
        .alloc_resident(active_queue.len() * std::mem::size_of::<u32>())
        .expect("Fix: active_queue resident allocation failed.");
    let active_len_handle = dispatcher
        .alloc_resident(std::mem::size_of::<u32>())
        .expect("Fix: active_len resident allocation failed.");
    let edge_offsets_handle = dispatcher
        .alloc_resident(edge_offsets.len() * std::mem::size_of::<u32>())
        .expect("Fix: edge_offsets resident allocation failed.");
    let edge_targets_handle = dispatcher
        .alloc_resident(edge_targets.len() * std::mem::size_of::<u32>())
        .expect("Fix: edge_targets resident allocation failed.");
    let edge_kind_handle = dispatcher
        .alloc_resident(edge_kind_mask.len() * std::mem::size_of::<u32>())
        .expect("Fix: edge_kind_mask resident allocation failed.");
    let accumulator_handle = dispatcher
        .alloc_resident(accumulator_seed.len() * std::mem::size_of::<u32>())
        .expect("Fix: accumulator resident allocation failed.");
    let next_queue_handle = dispatcher
        .alloc_resident(next_queue_capacity as usize * std::mem::size_of::<u32>())
        .expect("Fix: next_queue resident allocation failed.");
    let next_len_handle = dispatcher
        .alloc_resident(std::mem::size_of::<u32>())
        .expect("Fix: next_len resident allocation failed.");

    let program = csr_queue_delta_enqueue(
        "active_queue",
        "active_len",
        "edge_offsets",
        "edge_targets",
        "edge_kind_mask",
        "accumulator",
        "next_queue",
        "next_len",
        node_count,
        edge_targets.len() as u32,
        active_queue_capacity,
        next_queue_capacity,
        1,
    );
    let handles = [
        active_queue_handle,
        active_len_handle,
        edge_offsets_handle,
        edge_targets_handle,
        edge_kind_handle,
        accumulator_handle,
        next_queue_handle,
        next_len_handle,
    ];
    let steps = [ResidentDispatchStep {
        program: &program,
        handle_ids: &handles,
        grid_override: Some([active_queue_capacity.div_ceil(256).max(1), 1, 1]),
    }];

    let zero_next_queue = vec![0u8; next_queue_capacity as usize * std::mem::size_of::<u32>()];
    let active_queue_bytes = u32_bytes(&active_queue);
    let active_len_bytes = u32_bytes(&active_len);
    let edge_offsets_bytes = u32_bytes(&edge_offsets);
    let edge_targets_bytes = u32_bytes(&edge_targets);
    let edge_kind_bytes = u32_bytes(&edge_kind_mask);
    let accumulator_bytes = u32_bytes(&accumulator_seed);
    let zero_next_len = u32_bytes(&[0]);
    let uploads = [
        (active_queue_handle, active_queue_bytes.as_slice()),
        (active_len_handle, active_len_bytes.as_slice()),
        (edge_offsets_handle, edge_offsets_bytes.as_slice()),
        (edge_targets_handle, edge_targets_bytes.as_slice()),
        (edge_kind_handle, edge_kind_bytes.as_slice()),
        (accumulator_handle, accumulator_bytes.as_slice()),
        (next_queue_handle, zero_next_queue.as_slice()),
        (next_len_handle, zero_next_len.as_slice()),
    ];
    let read_ranges = [
        ResidentReadRange {
            handle_id: accumulator_handle,
            byte_offset: 0,
            byte_len: accumulator_seed.len() * std::mem::size_of::<u32>(),
        },
        ResidentReadRange {
            handle_id: next_queue_handle,
            byte_offset: 0,
            byte_len: next_queue_capacity as usize * std::mem::size_of::<u32>(),
        },
        ResidentReadRange {
            handle_id: next_len_handle,
            byte_offset: 0,
            byte_len: std::mem::size_of::<u32>(),
        },
    ];

    backend.reset_telemetry();
    let outputs = dispatcher
        .upload_resident_many_sequence_read_ranges(&uploads, &steps, &read_ranges)
        .expect("Fix: resident queue delta enqueue sequence failed.");

    assert_eq!(bytes_u32(&outputs[0]), expected_accumulator);
    let observed_next_len = bytes_u32(&outputs[2])[0];
    assert_eq!(observed_next_len, expected_next_len);
    let mut observed_queue = bytes_u32(&outputs[1]);
    observed_queue.truncate(observed_next_len as usize);
    observed_queue.sort_unstable();
    let mut expected_queue = expected_next_queue;
    expected_queue.sort_unstable();
    assert_eq!(observed_queue, expected_queue);

    let telemetry = backend.telemetry_snapshot();
    assert_eq!(
        telemetry.kernel_launches, 1,
        "Fix: queue delta enqueue must be one resident kernel over active nodes."
    );
    assert_eq!(
        telemetry.readback_bytes,
        (accumulator_seed.len() * std::mem::size_of::<u32>()
            + next_queue_capacity as usize * std::mem::size_of::<u32>()
            + std::mem::size_of::<u32>()) as u64
    );

    for handle in [
        active_queue_handle,
        active_len_handle,
        edge_offsets_handle,
        edge_targets_handle,
        edge_kind_handle,
        accumulator_handle,
        next_queue_handle,
        next_len_handle,
    ] {
        dispatcher
            .free_resident(handle)
            .expect("Fix: resident queue delta cleanup failed.");
    }
}

#[test]
fn cuda_resident_strided_queue_delta_matches_cpu_on_skewed_rows_and_pressure() {
    let backend = live_backend();
    let dispatcher = CudaOptimizerDispatcher::new(&backend);
    let node_count = 4096u32;
    let active_queue_capacity = 5u32;
    let active_queue = vec![0u32, 17, 2047, 0, 0];
    let active_len = vec![3u32];
    let accumulator_seed = pack_nodes(&[0, 17, 2047], node_count);
    let mut edge_offsets = Vec::with_capacity(node_count as usize + 1);
    let mut edge_targets = Vec::new();
    let mut edge_kind_mask = Vec::new();
    edge_offsets.push(0);
    for src in 0..node_count {
        let degree = match src {
            0 => 768,
            17 => 64,
            2047 => 9,
            _ => 0,
        };
        for edge in 0..degree {
            let target_base = match src {
                0 => 512,
                17 => 1536,
                2047 => 3000,
                _ => 0,
            };
            edge_targets.push(target_base + edge);
            edge_kind_mask.push(if edge % 5 == 0 { 2 } else { 1 });
        }
        edge_offsets.push(edge_targets.len() as u32);
    }
    let (expected_accumulator, full_expected_queue, full_expected_len) =
        csr_queue_delta_enqueue_cpu(
            &active_queue,
            active_len[0],
            &edge_offsets,
            &edge_targets,
            &edge_kind_mask,
            &accumulator_seed,
            node_count,
            node_count as usize,
            1,
        );
    let mut full_expected_sorted = full_expected_queue.clone();
    full_expected_sorted.sort_unstable();

    for next_queue_capacity in [full_expected_len, 32] {
        let active_queue_handle = dispatcher
            .alloc_resident(active_queue.len() * std::mem::size_of::<u32>())
            .expect("Fix: strided delta active_queue resident allocation failed.");
        let active_len_handle = dispatcher
            .alloc_resident(std::mem::size_of::<u32>())
            .expect("Fix: strided delta active_len resident allocation failed.");
        let edge_offsets_handle = dispatcher
            .alloc_resident(edge_offsets.len() * std::mem::size_of::<u32>())
            .expect("Fix: strided delta edge_offsets resident allocation failed.");
        let edge_targets_handle = dispatcher
            .alloc_resident(edge_targets.len() * std::mem::size_of::<u32>())
            .expect("Fix: strided delta edge_targets resident allocation failed.");
        let edge_kind_handle = dispatcher
            .alloc_resident(edge_kind_mask.len() * std::mem::size_of::<u32>())
            .expect("Fix: strided delta edge_kind_mask resident allocation failed.");
        let accumulator_handle = dispatcher
            .alloc_resident(accumulator_seed.len() * std::mem::size_of::<u32>())
            .expect("Fix: strided delta accumulator resident allocation failed.");
        let next_queue_handle = dispatcher
            .alloc_resident(next_queue_capacity as usize * std::mem::size_of::<u32>())
            .expect("Fix: strided delta next_queue resident allocation failed.");
        let next_len_handle = dispatcher
            .alloc_resident(std::mem::size_of::<u32>())
            .expect("Fix: strided delta next_len resident allocation failed.");

        let program = csr_queue_delta_strided_enqueue(
            "active_queue",
            "active_len",
            "edge_offsets",
            "edge_targets",
            "edge_kind_mask",
            "accumulator",
            "next_queue",
            "next_len",
            node_count,
            edge_targets.len() as u32,
            active_queue_capacity,
            next_queue_capacity,
            1,
        );
        let handles = [
            active_queue_handle,
            active_len_handle,
            edge_offsets_handle,
            edge_targets_handle,
            edge_kind_handle,
            accumulator_handle,
            next_queue_handle,
            next_len_handle,
        ];
        let steps = [ResidentDispatchStep {
            program: &program,
            handle_ids: &handles,
            grid_override: Some(csr_queue_delta_strided_dispatch_grid(active_queue_capacity)),
        }];

        let zero_next_queue = vec![0u8; next_queue_capacity as usize * std::mem::size_of::<u32>()];
        let active_queue_bytes = u32_bytes(&active_queue);
        let active_len_bytes = u32_bytes(&active_len);
        let edge_offsets_bytes = u32_bytes(&edge_offsets);
        let edge_targets_bytes = u32_bytes(&edge_targets);
        let edge_kind_bytes = u32_bytes(&edge_kind_mask);
        let accumulator_bytes = u32_bytes(&accumulator_seed);
        let zero_next_len = u32_bytes(&[0u32]);
        let uploads = [
            (active_queue_handle, active_queue_bytes.as_slice()),
            (active_len_handle, active_len_bytes.as_slice()),
            (edge_offsets_handle, edge_offsets_bytes.as_slice()),
            (edge_targets_handle, edge_targets_bytes.as_slice()),
            (edge_kind_handle, edge_kind_bytes.as_slice()),
            (accumulator_handle, accumulator_bytes.as_slice()),
            (next_queue_handle, zero_next_queue.as_slice()),
            (next_len_handle, zero_next_len.as_slice()),
        ];
        let read_ranges = [
            ResidentReadRange {
                handle_id: accumulator_handle,
                byte_offset: 0,
                byte_len: accumulator_seed.len() * std::mem::size_of::<u32>(),
            },
            ResidentReadRange {
                handle_id: next_queue_handle,
                byte_offset: 0,
                byte_len: next_queue_capacity as usize * std::mem::size_of::<u32>(),
            },
            ResidentReadRange {
                handle_id: next_len_handle,
                byte_offset: 0,
                byte_len: std::mem::size_of::<u32>(),
            },
        ];

        backend.reset_telemetry();
        let outputs = dispatcher
            .upload_resident_many_sequence_read_ranges(&uploads, &steps, &read_ranges)
            .expect("Fix: resident strided queue delta enqueue sequence failed.");

        assert_eq!(bytes_u32(&outputs[0]), expected_accumulator);
        let observed_next_len = bytes_u32(&outputs[2])[0];
        assert_eq!(observed_next_len, full_expected_len);
        let mut observed_queue = bytes_u32(&outputs[1]);
        observed_queue.truncate(next_queue_capacity.min(observed_next_len) as usize);
        observed_queue.sort_unstable();
        observed_queue.dedup();
        if next_queue_capacity >= full_expected_len {
            assert_eq!(observed_queue, full_expected_sorted);
        } else {
            assert_eq!(
                observed_queue.len(),
                next_queue_capacity as usize,
                "Fix: pressure case should fill every available next_queue slot."
            );
            assert!(
                observed_queue
                    .iter()
                    .all(|node| full_expected_sorted.binary_search(node).is_ok()),
                "Fix: pressure case stored a node outside the first-time discovery set: {:?}",
                observed_queue
            );
        }

        let telemetry = backend.telemetry_snapshot();
        assert_eq!(
            telemetry.kernel_launches, 1,
            "Fix: strided queue delta enqueue must remain one resident kernel."
        );
        assert_eq!(
            telemetry.readback_bytes,
            (accumulator_seed.len() * std::mem::size_of::<u32>()
                + next_queue_capacity as usize * std::mem::size_of::<u32>()
                + std::mem::size_of::<u32>()) as u64
        );

        for handle in [
            active_queue_handle,
            active_len_handle,
            edge_offsets_handle,
            edge_targets_handle,
            edge_kind_handle,
            accumulator_handle,
            next_queue_handle,
            next_len_handle,
        ] {
            dispatcher
                .free_resident(handle)
                .expect("Fix: resident strided queue delta cleanup failed.");
        }
    }
}

#[test]
fn cuda_resident_frontier_queue_reuses_static_graph_across_queries() {
    let backend = live_backend();
    let dispatcher = CudaOptimizerDispatcher::new(&backend);
    let node_count = 8u32;
    let queue_capacity = 8u32;
    let edge_offsets = vec![0, 2, 2, 2, 5, 5, 5, 5, 5];
    let edge_targets = vec![1, 2, 4, 5, 6];
    let edge_kind_mask = vec![1, 2, 1, 1, 2];
    let frontier_words = bitset_words(node_count) as usize;

    let frontier_handle = dispatcher
        .alloc_resident(frontier_words * std::mem::size_of::<u32>())
        .expect("Fix: resident queue reuse frontier allocation failed.");
    let queue_handle = dispatcher
        .alloc_resident(queue_capacity as usize * std::mem::size_of::<u32>())
        .expect("Fix: resident queue reuse queue allocation failed.");
    let queue_len_handle = dispatcher
        .alloc_resident(std::mem::size_of::<u32>())
        .expect("Fix: resident queue reuse queue_len allocation failed.");
    let edge_offsets_handle = dispatcher
        .alloc_resident(edge_offsets.len() * std::mem::size_of::<u32>())
        .expect("Fix: resident queue reuse edge_offsets allocation failed.");
    let edge_targets_handle = dispatcher
        .alloc_resident(edge_targets.len() * std::mem::size_of::<u32>())
        .expect("Fix: resident queue reuse edge_targets allocation failed.");
    let edge_kind_handle = dispatcher
        .alloc_resident(edge_kind_mask.len() * std::mem::size_of::<u32>())
        .expect("Fix: resident queue reuse edge_kind_mask allocation failed.");
    let frontier_out_handle = dispatcher
        .alloc_resident(frontier_words * std::mem::size_of::<u32>())
        .expect("Fix: resident queue reuse frontier_out allocation failed.");

    let edge_offsets_bytes = u32_bytes(&edge_offsets);
    let edge_targets_bytes = u32_bytes(&edge_targets);
    let edge_kind_bytes = u32_bytes(&edge_kind_mask);
    dispatcher
        .upload_resident_many(&[
            (edge_offsets_handle, edge_offsets_bytes.as_slice()),
            (edge_targets_handle, edge_targets_bytes.as_slice()),
            (edge_kind_handle, edge_kind_bytes.as_slice()),
        ])
        .expect("Fix: static CSR graph must upload once before repeated queue queries.");

    let queue_program = frontier_to_queue(
        "frontier",
        "active_queue",
        "queue_len",
        node_count,
        queue_capacity,
    );
    let traverse_program = csr_queue_forward_traverse(
        "active_queue",
        "queue_len",
        "edge_offsets",
        "edge_targets",
        "edge_kind_mask",
        "frontier_out",
        node_count,
        edge_targets.len() as u32,
        queue_capacity,
        1,
    );
    let queue_handles = [frontier_handle, queue_handle, queue_len_handle];
    let traverse_handles = [
        queue_handle,
        queue_len_handle,
        edge_offsets_handle,
        edge_targets_handle,
        edge_kind_handle,
        frontier_out_handle,
    ];
    let steps = [
        ResidentDispatchStep {
            program: &queue_program,
            handle_ids: &queue_handles,
            grid_override: Some([node_count.div_ceil(256).max(1), 1, 1]),
        },
        ResidentDispatchStep {
            program: &traverse_program,
            handle_ids: &traverse_handles,
            grid_override: Some([queue_capacity.div_ceil(256).max(1), 1, 1]),
        },
    ];
    let read_ranges = [ResidentReadRange {
        handle_id: frontier_out_handle,
        byte_offset: 0,
        byte_len: frontier_words * std::mem::size_of::<u32>(),
    }];
    let zero_count = vec![0u8; std::mem::size_of::<u32>()];
    let zero_frontier_out = vec![0u8; frontier_words * std::mem::size_of::<u32>()];

    for active_nodes in [&[0, 3][..], &[3][..]] {
        let frontier = pack_nodes(active_nodes, node_count);
        let (expected_queue, expected_len) =
            frontier_to_queue_cpu(&frontier, node_count, queue_capacity as usize);
        let expected_out = csr_queue_forward_traverse_cpu(
            &expected_queue,
            expected_len,
            &edge_offsets,
            &edge_targets,
            &edge_kind_mask,
            node_count,
            1,
        );
        let frontier_bytes = u32_bytes(&frontier);

        backend.reset_telemetry();
        let outputs = dispatcher
            .upload_resident_many_sequence_read_ranges(
                &[
                    (frontier_handle, frontier_bytes.as_slice()),
                    (queue_len_handle, zero_count.as_slice()),
                    (frontier_out_handle, zero_frontier_out.as_slice()),
                ],
                &steps,
                &read_ranges,
            )
            .expect("Fix: resident static-graph queue query must run without reuploading CSR graph state.");

        assert_eq!(bytes_u32(&outputs[0]), expected_out);
        let telemetry = backend.telemetry_snapshot();
        assert_eq!(telemetry.kernel_launches, 2);
        assert_eq!(telemetry.sync_points, 1);
        assert_eq!(
            telemetry.readback_bytes,
            (frontier_words * std::mem::size_of::<u32>()) as u64,
            "Fix: repeated resident queue query must read back only frontier_out, not queue payload or selector count."
        );
        assert_eq!(
            telemetry
                .host_to_device_bytes
                .saturating_sub(telemetry.param_upload_bytes),
            (frontier_bytes.len() + zero_count.len() + zero_frontier_out.len()) as u64,
            "Fix: repeated resident queue query must refresh only frontier/scratch/output buffers and keep CSR graph state resident."
        );
        assert!(
            telemetry.host_upload_operations <= 5,
            "Fix: repeated resident queue query must issue only frontier/scratch/output data uploads plus cached parameter uploads, not CSR graph uploads; observed {} upload operations.",
            telemetry.host_upload_operations
        );
    }

    for handle in [
        frontier_handle,
        queue_handle,
        queue_len_handle,
        edge_offsets_handle,
        edge_targets_handle,
        edge_kind_handle,
        frontier_out_handle,
    ] {
        dispatcher
            .free_resident(handle)
            .expect("Fix: resident queue reuse cleanup failed.");
    }
}

#[test]
fn cuda_resident_csr_queue_api_reuses_graph_and_scratch() {
    let backend = live_backend();
    let dispatcher = CudaOptimizerDispatcher::new(&backend);
    let node_count = 8u32;
    let queue_capacity = 8u32;
    let edge_offsets = vec![0, 2, 2, 2, 5, 5, 5, 5, 5];
    let edge_targets = vec![1, 2, 4, 5, 6];
    let edge_kind_mask = vec![1, 2, 1, 1, 2];
    let graph = upload_resident_csr_queue_graph(
        &dispatcher,
        node_count,
        &edge_offsets,
        &edge_targets,
        &edge_kind_mask,
    )
    .expect("Fix: reusable resident CSR queue graph upload failed.");
    let mut scratch = ResidentCsrQueueScratch::default();
    let mut output =
        Vec::with_capacity(bitset_words(node_count) as usize * std::mem::size_of::<u32>());
    let output_ptr = output.as_ptr();

    for active_nodes in [&[0, 3][..], &[3][..]] {
        let frontier = pack_nodes(active_nodes, node_count);
        let (expected_queue, expected_len) =
            frontier_to_queue_cpu(&frontier, node_count, queue_capacity as usize);
        let expected_out = csr_queue_forward_traverse_cpu(
            &expected_queue,
            expected_len,
            &edge_offsets,
            &edge_targets,
            &edge_kind_mask,
            node_count,
            1,
        );

        backend.reset_telemetry();
        run_resident_csr_queue_query_into(
            &dispatcher,
            &graph,
            &mut scratch,
            &frontier,
            queue_capacity,
            1,
            &mut output,
        )
        .expect("Fix: reusable resident CSR queue query failed on CUDA.");

        assert_eq!(bytes_u32(&output), expected_out);
        assert_eq!(
            output.as_ptr(),
            output_ptr,
            "Fix: resident CSR queue API must preserve caller-owned output capacity."
        );
        let telemetry = backend.telemetry_snapshot();
        assert_eq!(telemetry.kernel_launches, 3);
        assert_eq!(telemetry.sync_points, 1);
        assert_eq!(
            telemetry.readback_bytes,
            output.len() as u64,
            "Fix: resident CSR queue API must compact readback to frontier_out only."
        );
        assert_eq!(
            telemetry
                .host_to_device_bytes
                .saturating_sub(telemetry.param_upload_bytes),
            (frontier.len() * std::mem::size_of::<u32>()) as u64,
            "Fix: resident CSR queue API must upload only the frontier seed; queue length and frontier output are initialized on device."
        );
    }

    scratch
        .free(&dispatcher)
        .expect("Fix: resident CSR queue scratch cleanup failed.");
    graph
        .free(&dispatcher)
        .expect("Fix: resident CSR queue graph cleanup failed.");
}

#[test]
fn cuda_resident_csr_queue_uses_atomic_word_scan_for_large_sparse_frontier() {
    let backend = live_backend();
    let dispatcher = CudaOptimizerDispatcher::new(&backend);
    let node_count = 9_000u32;
    let queue_capacity = 16u32;
    let mut edge_offsets = Vec::with_capacity(node_count as usize + 1);
    let mut edge_targets = Vec::with_capacity(node_count as usize);
    let mut edge_kind_mask = Vec::with_capacity(node_count as usize);
    edge_offsets.push(0);
    for src in 0..node_count {
        edge_targets.push(src.wrapping_mul(17).wrapping_add(13) % node_count);
        edge_kind_mask.push(if src % 11 == 0 { 2 } else { 1 });
        edge_offsets.push(edge_targets.len() as u32);
    }
    let graph = upload_resident_csr_queue_graph(
        &dispatcher,
        node_count,
        &edge_offsets,
        &edge_targets,
        &edge_kind_mask,
    )
    .expect("Fix: large resident CSR queue graph upload failed.");
    let frontier = pack_nodes(&[0, 3, 511, 7_000, 8_999], node_count);
    let (expected_queue, expected_len) =
        frontier_to_queue_cpu(&frontier, node_count, queue_capacity as usize);
    let expected_out = csr_queue_forward_traverse_cpu(
        &expected_queue,
        expected_len,
        &edge_offsets,
        &edge_targets,
        &edge_kind_mask,
        node_count,
        1,
    );
    let mut scratch = ResidentCsrQueueScratch::default();
    let mut output =
        Vec::with_capacity(bitset_words(node_count) as usize * std::mem::size_of::<u32>());

    backend.reset_telemetry();
    run_resident_csr_queue_query_into(
        &dispatcher,
        &graph,
        &mut scratch,
        &frontier,
        queue_capacity,
        1,
        &mut output,
    )
    .expect("Fix: large sparse resident CSR queue query failed on CUDA.");

    assert_eq!(bytes_u32(&output), expected_out);
    let telemetry = backend.telemetry_snapshot();
    assert_eq!(
        telemetry.kernel_launches, 3,
        "Fix: sparse resident CSR queue should run clear, atomic word queue-build, and traverse kernels; deterministic word-prefix is reserved for dense high-capacity frontiers."
    );
    assert_eq!(
        telemetry
            .host_to_device_bytes
            .saturating_sub(telemetry.param_upload_bytes),
        (frontier.len() * std::mem::size_of::<u32>()) as u64,
        "Fix: large sparse resident CSR queue must upload only the packed frontier; queue scratch stays device-side."
    );

    scratch
        .free(&dispatcher)
        .expect("Fix: large sparse resident CSR queue scratch cleanup failed.");
    graph
        .free(&dispatcher)
        .expect("Fix: large sparse resident CSR queue graph cleanup failed.");
}

#[test]
fn cuda_resident_csr_queue_api_splits_skewed_high_degree_rows() {
    let backend = live_backend();
    let dispatcher = CudaOptimizerDispatcher::new(&backend);
    let node_count = 64u32;
    let queue_capacity = 1024u32;
    let (edge_offsets, edge_targets, edge_kind_mask) = skewed_high_degree_graph(node_count);
    let graph = upload_resident_csr_queue_graph(
        &dispatcher,
        node_count,
        &edge_offsets,
        &edge_targets,
        &edge_kind_mask,
    )
    .expect("Fix: skewed high-degree resident CSR queue graph upload failed.");
    let frontier = pack_nodes(&[0, 1, 2, 3, 4, 5, 6, 7, 8], node_count);
    let (expected_queue, expected_len) =
        frontier_to_queue_cpu(&frontier, node_count, queue_capacity as usize);
    let expected_out = csr_queue_forward_traverse_cpu(
        &expected_queue,
        expected_len,
        &edge_offsets,
        &edge_targets,
        &edge_kind_mask,
        node_count,
        1,
    );
    let mut scratch = ResidentCsrQueueScratch::default();
    let mut output =
        Vec::with_capacity(bitset_words(node_count) as usize * std::mem::size_of::<u32>());

    backend.reset_telemetry();
    run_resident_csr_queue_query_into(
        &dispatcher,
        &graph,
        &mut scratch,
        &frontier,
        queue_capacity,
        1,
        &mut output,
    )
    .expect("Fix: skewed high-degree resident CSR queue query failed on CUDA.");

    assert_eq!(bytes_u32(&output), expected_out);
    let telemetry = backend.telemetry_snapshot();
    assert_eq!(
        telemetry.kernel_launches, 5,
        "Fix: skewed resident CSR queue query must run queue_len init, queue build, high_len init, split-low, and bounded high-row traverse."
    );
    assert_eq!(telemetry.sync_points, 1);
    assert_eq!(
        telemetry.readback_bytes,
        output.len() as u64,
        "Fix: skewed resident CSR queue query must read back only frontier_out."
    );
    assert_eq!(
        telemetry
            .host_to_device_bytes
            .saturating_sub(telemetry.param_upload_bytes),
        (frontier.len() * std::mem::size_of::<u32>()) as u64,
        "Fix: skewed resident CSR queue query must upload only the packed frontier seed."
    );

    scratch
        .free(&dispatcher)
        .expect("Fix: skewed resident CSR queue scratch cleanup failed.");
    graph
        .free(&dispatcher)
        .expect("Fix: skewed resident CSR queue graph cleanup failed.");
}

#[test]
fn cuda_resident_csr_queue_batch_runs_many_queries_with_one_sync() {
    let backend = live_backend();
    let dispatcher = CudaOptimizerDispatcher::new(&backend);
    let node_count = 8u32;
    let queue_capacity = 8u32;
    let edge_offsets = vec![0, 2, 2, 2, 5, 5, 5, 5, 5];
    let edge_targets = vec![1, 2, 4, 5, 6];
    let edge_kind_mask = vec![1, 2, 1, 1, 2];
    let graph = upload_resident_csr_queue_graph(
        &dispatcher,
        node_count,
        &edge_offsets,
        &edge_targets,
        &edge_kind_mask,
    )
    .expect("Fix: batched resident CSR queue graph upload failed.");
    let frontiers = [
        pack_nodes(&[0, 3], node_count),
        pack_nodes(&[3], node_count),
        pack_nodes(&[7], node_count),
    ];
    let frontier_refs: Vec<&[u32]> = frontiers.iter().map(Vec::as_slice).collect();
    let mut expected = Vec::new();
    for frontier in &frontiers {
        let (expected_queue, expected_len) =
            frontier_to_queue_cpu(frontier, node_count, queue_capacity as usize);
        expected.push(csr_queue_forward_traverse_cpu(
            &expected_queue,
            expected_len,
            &edge_offsets,
            &edge_targets,
            &edge_kind_mask,
            node_count,
            1,
        ));
    }

    let mut scratch = ResidentCsrQueueBatchScratch::default();
    let output_bytes = bitset_words(node_count) as usize * std::mem::size_of::<u32>();
    let mut outputs = vec![
        Vec::with_capacity(output_bytes),
        Vec::with_capacity(output_bytes),
        Vec::with_capacity(output_bytes),
    ];
    let output_ptrs: Vec<*const u8> = outputs.iter().map(Vec::as_ptr).collect();

    backend.reset_telemetry();
    run_resident_csr_queue_batch_into(
        &dispatcher,
        &graph,
        &mut scratch,
        &frontier_refs,
        queue_capacity,
        1,
        &mut outputs,
    )
    .expect("Fix: batched resident CSR queue execution failed on CUDA.");

    for ((output, expected_words), ptr) in outputs.iter().zip(&expected).zip(&output_ptrs) {
        assert_eq!(bytes_u32(output), *expected_words);
        assert_eq!(
            output.as_ptr(),
            *ptr,
            "Fix: batched resident CSR queue must preserve caller-owned output slots."
        );
    }
    let telemetry = backend.telemetry_snapshot();
    assert_eq!(
        telemetry.kernel_launches,
        (frontiers.len() * 3) as u64,
        "Fix: each batched CSR queue query should submit frontier clear, queue-build, and queue-consume kernels; frontier_to_queue clears queue_len itself."
    );
    assert_eq!(
        telemetry.sync_points, 1,
        "Fix: batched resident CSR queue must use one host fence for all queries."
    );
    assert_eq!(
        telemetry.readback_bytes,
        (frontiers.len() * output_bytes) as u64,
        "Fix: batched resident CSR queue must read only compact frontier outputs."
    );
    assert_eq!(
            telemetry
                .host_to_device_bytes
                .saturating_sub(telemetry.param_upload_bytes),
        (frontiers.len() * output_bytes) as u64,
        "Fix: batched resident CSR queue must upload only each frontier seed; queue length and frontier output are initialized on device."
    );
    assert_eq!(scratch.resident_query_slots(), frontiers.len());
    let retained_frontier_payload_capacity = scratch.frontier_payload_capacity();

    backend.reset_telemetry();
    run_resident_csr_queue_batch_into(
        &dispatcher,
        &graph,
        &mut scratch,
        &frontier_refs,
        queue_capacity,
        1,
        &mut outputs,
    )
    .expect("Fix: repeated batched resident CSR queue execution failed on CUDA.");
    assert_eq!(
        scratch.resident_query_slots(),
        frontiers.len(),
        "Fix: repeated batch execution must reuse resident per-query scratch slots."
    );
    assert_eq!(
        scratch.frontier_payload_capacity(),
        retained_frontier_payload_capacity,
        "Fix: repeated batch execution must reuse host frontier staging capacity."
    );
    for (output, ptr) in outputs.iter().zip(&output_ptrs) {
        assert_eq!(
            output.as_ptr(),
            *ptr,
            "Fix: repeated batched resident CSR queue must preserve caller-owned output slots."
        );
    }
    let telemetry = backend.telemetry_snapshot();
    assert_eq!(
        telemetry.sync_points, 1,
        "Fix: repeated batched resident CSR queue must still use one host fence."
    );
    assert_eq!(
        telemetry.readback_bytes,
        (frontiers.len() * output_bytes) as u64,
        "Fix: repeated batched resident CSR queue must read only compact frontier outputs."
    );

    scratch
        .free(&dispatcher)
        .expect("Fix: batched resident CSR queue scratch cleanup failed.");
    graph
        .free(&dispatcher)
        .expect("Fix: batched resident CSR queue graph cleanup failed.");
}

#[test]
fn cuda_resident_csr_queue_batch_splits_skewed_high_degree_rows() {
    let backend = live_backend();
    let dispatcher = CudaOptimizerDispatcher::new(&backend);
    let node_count = 64u32;
    let queue_capacity = 1024u32;
    let (edge_offsets, edge_targets, edge_kind_mask) = skewed_high_degree_graph(node_count);
    let graph = upload_resident_csr_queue_graph(
        &dispatcher,
        node_count,
        &edge_offsets,
        &edge_targets,
        &edge_kind_mask,
    )
    .expect("Fix: skewed high-degree batched resident CSR queue graph upload failed.");
    let frontiers = [
        pack_nodes(&[0, 1, 2, 3, 4, 5, 6, 7, 8], node_count),
        pack_nodes(&[0, 2, 5, 8], node_count),
    ];
    let frontier_refs: Vec<&[u32]> = frontiers.iter().map(Vec::as_slice).collect();
    let mut expected = Vec::new();
    for frontier in &frontiers {
        let (expected_queue, expected_len) =
            frontier_to_queue_cpu(frontier, node_count, queue_capacity as usize);
        expected.push(csr_queue_forward_traverse_cpu(
            &expected_queue,
            expected_len,
            &edge_offsets,
            &edge_targets,
            &edge_kind_mask,
            node_count,
            1,
        ));
    }

    let mut scratch = ResidentCsrQueueBatchScratch::default();
    let output_bytes = bitset_words(node_count) as usize * std::mem::size_of::<u32>();
    let mut outputs = vec![
        Vec::with_capacity(output_bytes),
        Vec::with_capacity(output_bytes),
    ];
    let output_ptrs: Vec<*const u8> = outputs.iter().map(Vec::as_ptr).collect();

    backend.reset_telemetry();
    run_resident_csr_queue_batch_into(
        &dispatcher,
        &graph,
        &mut scratch,
        &frontier_refs,
        queue_capacity,
        1,
        &mut outputs,
    )
    .expect("Fix: skewed high-degree batched resident CSR queue execution failed on CUDA.");

    for ((output, expected_words), ptr) in outputs.iter().zip(&expected).zip(&output_ptrs) {
        assert_eq!(bytes_u32(output), *expected_words);
        assert_eq!(
            output.as_ptr(),
            *ptr,
            "Fix: skewed batched resident CSR queue must preserve caller-owned output slots."
        );
    }
    let telemetry = backend.telemetry_snapshot();
    assert_eq!(
        telemetry.kernel_launches,
        (frontiers.len() * 5) as u64,
        "Fix: each skewed batched CSR query must run queue_len init, queue build, high_len init, split-low, and bounded high-row traverse."
    );
    assert_eq!(
        telemetry.sync_points, 1,
        "Fix: skewed batched resident CSR queue must use one host fence for all queries."
    );
    assert_eq!(
        telemetry.readback_bytes,
        (frontiers.len() * output_bytes) as u64,
        "Fix: skewed batched resident CSR queue must read only compact frontier outputs."
    );
    assert_eq!(
        telemetry
            .host_to_device_bytes
            .saturating_sub(telemetry.param_upload_bytes),
        (frontiers.len() * output_bytes) as u64,
        "Fix: skewed batched resident CSR queue must upload only each frontier seed."
    );

    scratch
        .free(&dispatcher)
        .expect("Fix: skewed batched resident CSR queue scratch cleanup failed.");
    graph
        .free(&dispatcher)
        .expect("Fix: skewed batched resident CSR queue graph cleanup failed.");
}

#[test]
fn cuda_resident_csr_queue_budgeted_batch_shards_before_allocation() {
    let backend = live_backend();
    let dispatcher = CudaOptimizerDispatcher::new(&backend);
    let node_count = 8u32;
    let queue_capacity = 8u32;
    let edge_offsets = vec![0, 2, 2, 2, 5, 5, 5, 5, 5];
    let edge_targets = vec![1, 2, 4, 5, 6];
    let edge_kind_mask = vec![1, 2, 1, 1, 2];
    let graph = upload_resident_csr_queue_graph(
        &dispatcher,
        node_count,
        &edge_offsets,
        &edge_targets,
        &edge_kind_mask,
    )
    .expect("Fix: budgeted resident CSR queue graph upload failed.");
    let frontiers = [
        pack_nodes(&[0, 3], node_count),
        pack_nodes(&[3], node_count),
        pack_nodes(&[7], node_count),
    ];
    let frontier_refs: Vec<&[u32]> = frontiers.iter().map(Vec::as_slice).collect();
    let mut scratch = ResidentCsrQueueBatchScratch::default();
    let output_bytes = bitset_words(node_count) as usize * std::mem::size_of::<u32>();
    let two_active_query_bytes =
        output_bytes + 2 * std::mem::size_of::<u32>() + std::mem::size_of::<u32>() + output_bytes;
    let mut outputs = Vec::new();

    backend.reset_telemetry();
    let plan = run_resident_csr_queue_batch_budgeted_into(
        &dispatcher,
        &graph,
        &mut scratch,
        &frontier_refs,
        queue_capacity,
        1,
        two_active_query_bytes * 2,
        &mut outputs,
    )
    .expect("Fix: budgeted resident CSR queue batch failed on CUDA.");

    assert_eq!(plan.max_queries_per_dispatch, 2);
    assert_eq!(plan.dispatch_batches, 2);
    assert_eq!(
        scratch.resident_query_slots(),
        2,
        "Fix: budgeted resident CSR queue must retain the larger scratch shard for the final smaller shard."
    );
    assert_eq!(
        outputs.len(),
        frontiers.len(),
        "Fix: budgeted resident CSR queue must preserve one output slot per query."
    );
    let telemetry = backend.telemetry_snapshot();
    assert_eq!(
        telemetry.sync_points, 2,
        "Fix: budgeted resident CSR queue must shard into exactly two host fences for this budget."
    );
    assert_eq!(
        telemetry.kernel_launches,
        (frontiers.len() * 3) as u64,
        "Fix: budgeted resident CSR queue must still run frontier clear, queue-build, and queue-consume per query."
    );
    assert_eq!(
        telemetry.readback_bytes,
        (frontiers.len() * output_bytes) as u64,
        "Fix: budgeted resident CSR queue must read only compact frontier outputs across shards."
    );

    scratch
        .free(&dispatcher)
        .expect("Fix: budgeted resident CSR queue scratch cleanup failed.");
    graph
        .free(&dispatcher)
        .expect("Fix: budgeted resident CSR queue graph cleanup failed.");
}
