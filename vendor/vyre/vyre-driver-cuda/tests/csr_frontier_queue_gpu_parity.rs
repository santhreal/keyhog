//! CUDA parity for device-side active-frontier queue sparse traversal.

#![cfg(test)]

mod common;

use common::{bytes_u32, live_backend, u32_bytes};
use vyre_driver_cuda::CudaOptimizerDispatcher;
use vyre_primitives::bitset::bitset_words;
use vyre_primitives::graph::csr_frontier_queue::{
    csr_queue_forward_traverse, csr_queue_forward_traverse_cpu, frontier_to_queue,
    frontier_to_queue_cpu,
};
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
        assert_eq!(telemetry.kernel_launches, 4);
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
        (frontiers.len() * 4) as u64,
        "Fix: each batched CSR queue query should submit queue-len init, frontier clear, queue-build, and queue-consume kernels."
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
    let bytes_per_query = output_bytes
        + queue_capacity as usize * std::mem::size_of::<u32>()
        + std::mem::size_of::<u32>()
        + output_bytes;
    let mut outputs = Vec::new();

    backend.reset_telemetry();
    let plan = run_resident_csr_queue_batch_budgeted_into(
        &dispatcher,
        &graph,
        &mut scratch,
        &frontier_refs,
        queue_capacity,
        1,
        bytes_per_query * 2,
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
        (frontiers.len() * 4) as u64,
        "Fix: budgeted resident CSR queue must still run queue-len init, frontier clear, queue-build, and queue-consume per query."
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

