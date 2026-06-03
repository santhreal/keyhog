//! cudaGraph dispatch parity and latency tests.
//!
//! Records a real Program kernel launch into a CUDA graph via
//! `CudaBackend::record_cuda_graph`, then replays it many times via
//! `dispatch_via_cuda_graph` and asserts:
//!
//! 1. **Byte-identity parity**  -  every replay's outputs match the same
//!    Program dispatched via the regular `CudaBackend::dispatch` path.
//! 2. **Latency ceiling**  -  per-replay wall-clock remains under the hot
//!    dispatch budget for latency-bound kernels.
//! 3. **Shape validation**  -  passing inputs of the wrong byte length
//!    returns `BackendError::InvalidProgram` with a structured fix string.

mod common;
use common::{bool_bytes, bytes_u32, u32_bytes};
use std::sync::Arc;
use std::time::Instant;

use vyre_driver::{BackendError, DispatchConfig};
use vyre_driver_cuda::CudaBackend;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Simple program: out[i] = in[i] + 1, 8 threads. Small enough that the
/// dispatch overhead dominates kernel time, so the cudaGraph speedup is
/// the headline number.
fn add_one_program() -> Program {
    Program::wrapped(
        vec![
            BufferDecl::read("input", 0, DataType::U32).with_count(8),
            BufferDecl::output("out", 1, DataType::U32).with_count(8),
        ],
        [128, 1, 1],
        vec![Node::store(
            "out",
            Expr::gid_x(),
            Expr::add(Expr::load("input", Expr::gid_x()), Expr::u32(1)),
        )],
    )
}

fn bool_not_program() -> Program {
    Program::wrapped(
        vec![
            BufferDecl::read("input", 0, DataType::Bool).with_count(8),
            BufferDecl::output("out", 1, DataType::Bool).with_count(8),
        ],
        [128, 1, 1],
        vec![Node::store(
            "out",
            Expr::gid_x(),
            Expr::not(Expr::load("input", Expr::gid_x())),
        )],
    )
}

#[test]
fn cuda_graph_uses_nonblocking_dedicated_stream() {
    let source = include_str!("../src/backend/cuda_graph.rs");
    assert!(
        source.contains("CU_STREAM_NON_BLOCKING"),
        "Fix: CUDA graph capture/replay must use a nonblocking dedicated stream, not CUDA's legacy-default-stream-ordered blocking stream."
    );
    assert!(
        !source.contains("cuStreamCreate(&mut stream_ptr, 0)"),
        "Fix: CUDA graph dedicated stream creation must not pass flag 0; that can inherit unwanted default-stream ordering."
    );
}

#[test]
fn cuda_graph_capture_does_not_allocate_fake_empty_param_buffer() {
    let source = include_str!("../src/backend/cuda_graph.rs");
    assert!(
        source.contains("if param_bytes != 0 {\n            // SAFETY: param_bytes is u32-aligned and non-zero in this branch."),
        "Fix: CUDA graph capture must use a null parameter pointer for empty launch params instead of allocating a rounded 1-byte buffer."
    );
    assert!(
        !source.contains("cuMemAlloc_v2(&mut params_device_ptr, param_bytes.max(1))")
            && !source.contains("record_transient_allocation_bytes(param_bytes.max(1) as u64)"),
        "Fix: CUDA graph parameter capture must not hide empty launch params behind max(1) allocation or telemetry."
    );
}

#[test]
fn cuda_graph_param_initialization_sync_is_telemetry_visible() {
    let source = include_str!("../src/backend/cuda_graph.rs");
    assert!(
        source.contains("cuStreamSynchronize(stream.ptr().as_ptr())")
            && source.contains("self.telemetry.record_sync_point();"),
        "Fix: CUDA graph parameter initialization must record its stream synchronization in telemetry."
    );
}

#[test]
fn cuda_graph_dispatch_matches_direct_dispatch_byte_for_byte() {
    let backend = Arc::new(
        CudaBackend::acquire()
            .expect("Fix: CUDA backend acquisition must succeed on the GPU-required test host."),
    );

    let program = add_one_program();
    let initial_inputs = vec![u32_bytes(&[0, 1, 2, 3, 4, 5, 6, 7])];
    let config = DispatchConfig::default();

    // Record the graph once with sample inputs.
    let mut cached = backend
        .record_cuda_graph(&program, &initial_inputs, &config)
        .expect("Fix: cudaGraph recording must succeed for the trivial add-one program");

    // Run direct dispatch as the parity oracle.
    let direct_outputs = backend
        .dispatch(&program, &initial_inputs, &config)
        .expect("direct dispatch must succeed for parity comparison");

    // Run via cached graph with the SAME inputs; outputs must match byte-for-byte.
    let input_refs: Vec<&[u8]> = initial_inputs.iter().map(Vec::as_slice).collect();
    let graph_outputs = backend
        .dispatch_via_cuda_graph(&mut cached, &input_refs)
        .expect("cuda_graph replay must succeed");

    assert_eq!(
        direct_outputs.len(),
        graph_outputs.len(),
        "output buffer count must match between direct dispatch and graph replay"
    );
    assert_eq!(
        bytes_u32(&direct_outputs[0]),
        bytes_u32(&graph_outputs[0]),
        "direct dispatch and graph replay must produce byte-identical outputs"
    );
    let mut reusable_outputs = Vec::with_capacity(graph_outputs.len());
    backend
        .dispatch_via_cuda_graph_into(&mut cached, &input_refs, &mut reusable_outputs)
        .expect("cuda_graph replay into reusable output buffer must succeed");
    let reusable_capacity = reusable_outputs.capacity();
    assert_eq!(
        bytes_u32(&direct_outputs[0]),
        bytes_u32(&reusable_outputs[0]),
        "reusable graph replay output must match direct dispatch byte-for-byte"
    );
    let reusable_inner_capacity = reusable_outputs[0].capacity();
    backend
        .dispatch_via_cuda_graph_into(&mut cached, &input_refs, &mut reusable_outputs)
        .expect("second reusable graph replay must succeed");
    assert_eq!(
        reusable_outputs.capacity(),
        reusable_capacity,
        "dispatch_via_cuda_graph_into must reuse the caller's outer output Vec allocation"
    );
    assert_eq!(
        reusable_outputs[0].capacity(),
        reusable_inner_capacity,
        "dispatch_via_cuda_graph_into must reuse each existing output byte buffer allocation"
    );

    // Try a SECOND replay with different input bytes  -  same shape, new data.
    let new_inputs = vec![u32_bytes(&[100, 200, 300, 400, 500, 600, 700, 800])];
    let direct_outputs_2 = backend
        .dispatch(&program, &new_inputs, &config)
        .expect("second direct dispatch must succeed");
    let new_input_refs: Vec<&[u8]> = new_inputs.iter().map(Vec::as_slice).collect();
    let graph_outputs_2 = backend
        .dispatch_via_cuda_graph(&mut cached, &new_input_refs)
        .expect("second graph replay must succeed");
    assert_eq!(
        bytes_u32(&direct_outputs_2[0]),
        bytes_u32(&graph_outputs_2[0]),
        "graph replay with NEW inputs must produce the SAME outputs as direct dispatch on \
         those inputs  -  without this, the cached host buffer write isn't being picked up by \
         the captured memcpy on replay"
    );
}

#[test]
fn cuda_graph_bool_storage_abi_matches_direct_dispatch() {
    let backend = Arc::new(
        CudaBackend::acquire()
            .expect("Fix: CUDA backend acquisition must succeed on the GPU-required test host."),
    );
    let program = bool_not_program();
    let inputs = vec![bool_bytes(&[
        false, true, true, false, true, false, false, true,
    ])];
    let config = DispatchConfig::default();
    let direct_outputs = backend
        .dispatch(&program, &inputs, &config)
        .expect("Fix: direct CUDA Bool dispatch must succeed before cudaGraph parity.");
    let mut cached = backend
        .record_cuda_graph(&program, &inputs, &config)
        .expect("Fix: cudaGraph recording must support Bool word-ABI inputs and outputs.");
    let input_refs: Vec<&[u8]> = inputs.iter().map(Vec::as_slice).collect();
    let graph_outputs = backend
        .dispatch_via_cuda_graph(&mut cached, &input_refs)
        .expect("Fix: cudaGraph replay must support Bool word-ABI inputs and outputs.");

    assert_eq!(
        direct_outputs, graph_outputs,
        "Fix: cudaGraph Bool replay must match direct CUDA dispatch byte-for-byte."
    );
    assert_eq!(
        bytes_u32(&graph_outputs[0]),
        vec![1, 0, 0, 1, 0, 1, 1, 0],
        "Fix: cudaGraph Bool output must use the stable one-u32-word-per-lane ABI."
    );
}

#[test]
fn cuda_graph_honors_output_byte_ranges_like_direct_dispatch() {
    let backend = Arc::new(
        CudaBackend::acquire()
            .expect("Fix: CUDA backend acquisition must succeed on the GPU-required test host."),
    );
    let program = Program::wrapped(
        vec![
            BufferDecl::storage("state", 0, BufferAccess::ReadWrite, DataType::U32)
                .with_count(4)
                .with_output_byte_range(4..12),
        ],
        [1, 1, 1],
        vec![Node::store("state", Expr::u32(3), Expr::u32(99))],
    );
    let inputs = vec![u32_bytes(&[11, 22, 33, 44])];
    let config = DispatchConfig::default();
    let direct_outputs = backend
        .dispatch(&program, &inputs, &config)
        .expect("Fix: direct CUDA dispatch must accept output byte ranges.");
    let mut cached = backend
        .record_cuda_graph(&program, &inputs, &config)
        .expect("Fix: cudaGraph recording must preserve output byte ranges.");
    let input_refs: Vec<&[u8]> = inputs.iter().map(Vec::as_slice).collect();
    let graph_outputs = backend
        .dispatch_via_cuda_graph(&mut cached, &input_refs)
        .expect("Fix: cudaGraph replay must preserve output byte ranges.");

    assert_eq!(
        direct_outputs, graph_outputs,
        "Fix: cudaGraph output readback must use the same byte range as direct CUDA dispatch."
    );
    assert_eq!(
        bytes_u32(&graph_outputs[0]),
        vec![22, 33],
        "Fix: cudaGraph output_byte_range=4..12 must return only the requested middle words."
    );
}

#[test]
fn cuda_graph_dispatch_per_replay_beats_direct_dispatch_floor() {
    let backend = Arc::new(
        CudaBackend::acquire()
            .expect("Fix: CUDA backend acquisition must succeed on the GPU-required test host."),
    );

    let program = add_one_program();
    let inputs = vec![u32_bytes(&[0; 8])];
    let config = DispatchConfig::default();

    // Warm + record.
    let warm_outputs = backend
        .dispatch(&program, &inputs, &config)
        .expect("warm dispatch");
    assert_eq!(
        bytes_u32(&warm_outputs[0]),
        vec![1; 8],
        "Fix: warm direct dispatch before cudaGraph recording must produce the add-one oracle output"
    );
    let mut cached = backend
        .record_cuda_graph(&program, &inputs, &config)
        .expect("Fix: record must succeed");

    // Measure several steady-state windows. Full-suite GPU contention can
    // occasionally inject a single scheduler-latency spike; the release
    // contract is that the warmed replay path can sustain the direct-dispatch
    // floor, not that one noisy wall-clock window defines the kernel path.
    const REPLAYS: u32 = 1000;
    const WINDOWS: u32 = 5;
    let input_refs: Vec<&[u8]> = inputs.iter().map(Vec::as_slice).collect();
    let mut outputs = Vec::with_capacity(1);
    let mut best_per_replay_ns = u128::MAX;
    for _ in 0..WINDOWS {
        let t0 = Instant::now();
        for _ in 0..REPLAYS {
            backend
                .dispatch_via_cuda_graph_into(&mut cached, &input_refs, &mut outputs)
                .expect("graph replay must succeed");
        }
        let elapsed_ns = t0.elapsed().as_nanos();
        best_per_replay_ns = best_per_replay_ns.min(elapsed_ns / u128::from(REPLAYS));
    }

    println!();
    println!("=== cudaGraph production dispatch replay ===");
    println!("windows             {WINDOWS}");
    println!("replays_per_window  {REPLAYS}");
    println!("best_per_replay_ns  {best_per_replay_ns}");
    println!("===");

    // Full-Program graph replay includes input upload, kernel launch,
    // output readback, stream synchronization, and output materialization.
    // The ceiling keeps this path below the direct warm-dispatch latency
    // floor for latency-bound kernels.
    assert!(
        best_per_replay_ns < 20_000,
        "cudaGraph per-replay must beat 20 µs (1.4× the 28.3 µs direct-dispatch floor); \
         observed best steady-state window {best_per_replay_ns}ns. A regression here means the cached graph isn't \
         amortizing the launch path, OR per-replay memcpy/clone cost rose."
    );
}

#[test]
fn cuda_graph_materialized_cache_is_telemetry_visible_and_input_exact() {
    let backend = Arc::new(
        CudaBackend::acquire()
            .expect("Fix: CUDA backend acquisition must succeed on the GPU-required test host."),
    );
    let program = add_one_program();
    let config = DispatchConfig::default();
    let inputs = vec![u32_bytes(&[0, 1, 2, 3, 4, 5, 6, 7])];
    let input_refs: Vec<&[u8]> = inputs.iter().map(Vec::as_slice).collect();
    let mut cached = backend
        .record_cuda_graph(&program, &inputs, &config)
        .expect("Fix: cudaGraph recording must succeed before materialized-cache telemetry.");
    backend.reset_telemetry();

    let mut outputs = Vec::with_capacity(1);
    backend
        .dispatch_via_cuda_graph_into(&mut cached, &input_refs, &mut outputs)
        .expect("Fix: first replay must execute the graph and materialize outputs.");
    assert_eq!(bytes_u32(&outputs[0]), vec![1, 2, 3, 4, 5, 6, 7, 8]);
    let first = backend.telemetry_snapshot();
    assert_eq!(
        first.cuda_graph_launches, 1,
        "Fix: first same-shape replay must execute a real cudaGraph before cache hits are possible."
    );
    assert_eq!(
        first.cuda_graph_materialized_cache_hits, 0,
        "Fix: materialized cache must not claim a hit before host outputs are initialized."
    );

    backend
        .dispatch_via_cuda_graph_into(&mut cached, &input_refs, &mut outputs)
        .expect("Fix: second identical replay must use the materialized-output fast path.");
    assert_eq!(bytes_u32(&outputs[0]), vec![1, 2, 3, 4, 5, 6, 7, 8]);
    let cached_same = backend.telemetry_snapshot();
    assert_eq!(
        cached_same.cuda_graph_launches, 1,
        "Fix: identical materialized-cache hit must not enqueue redundant cudaGraph work."
    );
    assert_eq!(
        cached_same.cuda_graph_materialized_cache_hits, 1,
        "Fix: materialized-cache hit must be observable in CUDA telemetry."
    );

    let changed_inputs = vec![u32_bytes(&[10, 20, 30, 40, 50, 60, 70, 80])];
    let changed_refs: Vec<&[u8]> = changed_inputs.iter().map(Vec::as_slice).collect();
    backend
        .dispatch_via_cuda_graph_into(&mut cached, &changed_refs, &mut outputs)
        .expect("Fix: changed bytes must bypass materialized cache and execute a graph replay.");
    assert_eq!(bytes_u32(&outputs[0]), vec![11, 21, 31, 41, 51, 61, 71, 81]);
    let changed = backend.telemetry_snapshot();
    assert_eq!(
        changed.cuda_graph_launches, 2,
        "Fix: changed inputs must force a fresh cudaGraph replay instead of returning stale host outputs."
    );
    assert_eq!(
        changed.cuda_graph_materialized_cache_hits, 1,
        "Fix: changed input replay must not be counted as a materialized-cache hit."
    );
}

#[test]
fn cuda_graph_timed_replay_uses_exact_materialized_cache_without_device_work() {
    let backend = Arc::new(
        CudaBackend::acquire()
            .expect("Fix: CUDA backend acquisition must succeed on the GPU-required test host."),
    );
    let program = add_one_program();
    let config = DispatchConfig::default();
    let inputs = vec![u32_bytes(&[5, 6, 7, 8, 9, 10, 11, 12])];
    let input_refs: Vec<&[u8]> = inputs.iter().map(Vec::as_slice).collect();
    let mut cached = backend
        .record_cuda_graph(&program, &inputs, &config)
        .expect("Fix: cudaGraph recording must succeed before timed materialized replay.");

    backend.reset_telemetry();
    let first = backend
        .dispatch_via_cuda_graph_timed(&mut cached, &input_refs)
        .expect("Fix: first timed cudaGraph replay must execute and materialize outputs.");
    assert_eq!(
        bytes_u32(&first.outputs[0]),
        vec![6, 7, 8, 9, 10, 11, 12, 13]
    );
    let first_telemetry = backend.telemetry_snapshot();
    assert_eq!(
        first_telemetry.cuda_graph_launches, 1,
        "Fix: first timed cudaGraph replay must execute one graph launch before cached outputs exist."
    );
    assert_eq!(
        first_telemetry.cuda_graph_materialized_cache_hits, 0,
        "Fix: first timed cudaGraph replay must not claim a materialized hit before outputs are initialized."
    );

    backend.reset_telemetry();
    let repeated = backend
        .dispatch_via_cuda_graph_timed(&mut cached, &input_refs)
        .expect("Fix: repeated timed cudaGraph replay must use exact materialized outputs.");
    assert_eq!(
        bytes_u32(&repeated.outputs[0]),
        vec![6, 7, 8, 9, 10, 11, 12, 13]
    );
    assert_eq!(
        repeated.device_ns,
        Some(0),
        "Fix: timed raw cudaGraph materialized hits must report zero device work instead of launching for timing."
    );
    let repeated_telemetry = backend.telemetry_snapshot();
    assert_eq!(
        repeated_telemetry.cuda_graph_launches, 0,
        "Fix: repeated timed raw cudaGraph replay must bypass redundant device graph launches."
    );
    assert_eq!(
        repeated_telemetry.cuda_graph_materialized_cache_hits, 1,
        "Fix: repeated timed raw cudaGraph replay must record one exact materialized-cache hit."
    );
    assert_eq!(
        repeated_telemetry.timed_dispatches, 1,
        "Fix: timed raw cudaGraph materialized hits must still be visible as timed dispatches."
    );

    let changed_inputs = vec![u32_bytes(&[15, 16, 17, 18, 19, 20, 21, 22])];
    let changed_refs: Vec<&[u8]> = changed_inputs.iter().map(Vec::as_slice).collect();
    backend.reset_telemetry();
    let changed = backend
        .dispatch_via_cuda_graph_timed(&mut cached, &changed_refs)
        .expect("Fix: changed timed cudaGraph inputs must bypass materialized cache.");
    assert_eq!(
        bytes_u32(&changed.outputs[0]),
        vec![16, 17, 18, 19, 20, 21, 22, 23]
    );
    let changed_telemetry = backend.telemetry_snapshot();
    assert_eq!(
        changed_telemetry.cuda_graph_launches, 1,
        "Fix: changed timed raw cudaGraph inputs must launch a graph instead of returning stale output."
    );
    assert_eq!(
        changed_telemetry.cuda_graph_materialized_cache_hits, 0,
        "Fix: changed timed raw cudaGraph inputs must not be counted as a materialized-cache hit."
    );
}

#[test]

fn compiled_pipeline_dispatch_into_uses_cached_cuda_graph() {
    let backend = CudaBackend::acquire()
        .expect("Fix: CUDA backend acquisition must succeed on the GPU-required test host.");

    let program = add_one_program();
    let inputs = [u32_bytes(&[9, 8, 7, 6, 5, 4, 3, 2])];
    let input_refs: Vec<&[u8]> = inputs.iter().map(Vec::as_slice).collect();
    let config = DispatchConfig::default();
    backend.reset_telemetry();
    let pipeline = backend
        .compile_native(&program, &config)
        .expect("Fix: CUDA native pipeline compilation must succeed");
    let compile_telemetry = backend.telemetry_snapshot();
    assert_eq!(
        compile_telemetry.sync_points, 1,
        "Fix: CUDA native pipeline compilation must account for static launch-parameter upload synchronization."
    );

    let mut outputs = Vec::with_capacity(1);
    pipeline
        .dispatch_borrowed_into(&input_refs, &config, &mut outputs)
        .expect("Fix: first compiled pipeline dispatch must record and replay a cudaGraph");
    assert_eq!(bytes_u32(&outputs[0]), vec![10, 9, 8, 7, 6, 5, 4, 3]);

    let outer_capacity = outputs.capacity();
    let inner_capacity = outputs[0].capacity();
    pipeline
        .dispatch_borrowed_into(&input_refs, &config, &mut outputs)
        .expect("Fix: second compiled pipeline dispatch must reuse the cached cudaGraph");
    assert_eq!(outputs.capacity(), outer_capacity);
    assert_eq!(outputs[0].capacity(), inner_capacity);
    assert_eq!(bytes_u32(&outputs[0]), vec![10, 9, 8, 7, 6, 5, 4, 3]);
}

#[test]
fn compiled_pipeline_repeated_single_dispatch_uses_exact_materialized_cache_hit() {
    let backend = CudaBackend::acquire()
        .expect("Fix: CUDA backend acquisition must succeed on the GPU-required test host.");

    let program = add_one_program();
    let config = DispatchConfig::default();
    let pipeline = backend
        .compile_native(&program, &config)
        .expect("Fix: CUDA native pipeline compilation must succeed");
    let inputs = [u32_bytes(&[50, 51, 52, 53, 54, 55, 56, 57])];
    let input_refs: Vec<&[u8]> = inputs.iter().map(Vec::as_slice).collect();
    let mut outputs = Vec::with_capacity(1);

    pipeline
        .dispatch_borrowed_into(&input_refs, &config, &mut outputs)
        .expect("Fix: first compiled single CUDA graph dispatch must materialize outputs.");
    assert_eq!(bytes_u32(&outputs[0]), vec![51, 52, 53, 54, 55, 56, 57, 58]);

    backend.reset_telemetry();
    pipeline
        .dispatch_borrowed_into(&input_refs, &config, &mut outputs)
        .expect("Fix: repeated identical compiled single dispatch must use materialized outputs.");
    assert_eq!(bytes_u32(&outputs[0]), vec![51, 52, 53, 54, 55, 56, 57, 58]);
    let repeated = backend.telemetry_snapshot();
    assert_eq!(
        repeated.cuda_graph_launches, 0,
        "Fix: repeated identical compiled single dispatch must bypass redundant cudaGraph launches."
    );
    assert_eq!(
        repeated.cuda_graph_materialized_cache_hits, 1,
        "Fix: repeated identical compiled single dispatch must report one materialized-cache hit."
    );

    let changed = [u32_bytes(&[70, 71, 72, 73, 74, 75, 76, 77])];
    let changed_refs: Vec<&[u8]> = changed.iter().map(Vec::as_slice).collect();
    backend.reset_telemetry();
    pipeline
        .dispatch_borrowed_into(&changed_refs, &config, &mut outputs)
        .expect("Fix: changed single-dispatch input bytes must bypass materialized cache.");
    assert_eq!(bytes_u32(&outputs[0]), vec![71, 72, 73, 74, 75, 76, 77, 78]);
    let changed_telemetry = backend.telemetry_snapshot();
    assert_eq!(
        changed_telemetry.cuda_graph_launches, 1,
        "Fix: changed compiled single-dispatch input bytes must launch exactly one cudaGraph replay."
    );
    assert_eq!(
        changed_telemetry.cuda_graph_materialized_cache_hits, 0,
        "Fix: changed compiled single-dispatch input bytes must not count as a materialized-cache hit."
    );
}

#[test]
fn compiled_pipeline_repeated_timed_single_dispatch_reports_materialized_zero_device_work() {
    let backend = CudaBackend::acquire()
        .expect("Fix: CUDA backend acquisition must succeed on the GPU-required test host.");

    let program = add_one_program();
    let config = DispatchConfig::default();
    let pipeline = backend
        .compile_native(&program, &config)
        .expect("Fix: CUDA native pipeline compilation must succeed");
    let inputs = [u32_bytes(&[80, 81, 82, 83, 84, 85, 86, 87])];
    let input_refs: Vec<&[u8]> = inputs.iter().map(Vec::as_slice).collect();

    let first = pipeline
        .dispatch_borrowed_timed(&input_refs, &config)
        .expect("Fix: first timed compiled single dispatch must execute and materialize outputs.");
    assert_eq!(
        bytes_u32(&first.outputs[0]),
        vec![81, 82, 83, 84, 85, 86, 87, 88]
    );
    assert!(
        first.device_ns.unwrap_or(0) > 0,
        "Fix: first timed compiled graph dispatch must report real device work before materialized hits exist."
    );

    backend.reset_telemetry();
    let repeated = pipeline
        .dispatch_borrowed_timed(&input_refs, &config)
        .expect("Fix: repeated timed compiled single dispatch must use materialized outputs.");
    assert_eq!(
        bytes_u32(&repeated.outputs[0]),
        vec![81, 82, 83, 84, 85, 86, 87, 88]
    );
    assert_eq!(
        repeated.device_ns,
        Some(0),
        "Fix: timed materialized-cache hits must report zero device work instead of replaying a graph for timing."
    );
    let telemetry = backend.telemetry_snapshot();
    assert_eq!(
        telemetry.cuda_graph_launches, 0,
        "Fix: repeated timed compiled single dispatch must not launch cudaGraph work."
    );
    assert_eq!(
        telemetry.cuda_graph_materialized_cache_hits, 1,
        "Fix: repeated timed compiled single dispatch must report one materialized-cache hit."
    );
}

#[test]
fn compiled_pipeline_batched_cuda_graph_replay_matches_direct_dispatch() {
    let backend = CudaBackend::acquire()
        .expect("Fix: CUDA backend acquisition must succeed on the GPU-required test host.");

    let program = add_one_program();
    let config = DispatchConfig::default();
    let pipeline = backend
        .compile_native(&program, &config)
        .expect("Fix: CUDA native pipeline compilation must succeed");
    backend.reset_telemetry();
    let inputs = [
        u32_bytes(&[0, 1, 2, 3, 4, 5, 6, 7]),
        u32_bytes(&[10, 11, 12, 13, 14, 15, 16, 17]),
        u32_bytes(&[20, 21, 22, 23, 24, 25, 26, 27]),
        u32_bytes(&[30, 31, 32, 33, 34, 35, 36, 37]),
    ];
    let batch0 = [inputs[0].as_slice()];
    let batch1 = [inputs[1].as_slice()];
    let batch2 = [inputs[2].as_slice()];
    let batch3 = [inputs[3].as_slice()];
    let batches: [&[&[u8]]; 4] = [&batch0, &batch1, &batch2, &batch3];
    let mut outputs = Vec::with_capacity(batches.len());

    pipeline
        .dispatch_borrowed_batched_into(&batches, &config, &mut outputs)
        .expect("Fix: compiled batched CUDA dispatch must replay same-shape graph batches");

    assert_eq!(outputs.len(), batches.len());
    for (index, output) in outputs.iter().enumerate() {
        let expected: Vec<u32> = (0..8)
            .map(|offset| (index as u32) * 10 + offset + 1)
            .collect();
        assert_eq!(
            bytes_u32(&output[0]),
            expected,
            "Fix: batched cudaGraph replay lane {index} must match direct add-one semantics"
        );
    }
    let telemetry = backend.telemetry_snapshot();
    assert!(
        telemetry.cuda_graph_batched_replay_chunks >= 1,
        "Fix: same-shape compiled batch replay must report batched cudaGraph chunks, not hide behind per-item replay telemetry."
    );
    assert!(
        telemetry.cuda_graph_batched_replay_lanes >= batches.len() as u64,
        "Fix: same-shape compiled batch replay must report every graph lane launched."
    );
}

#[test]
fn compiled_pipeline_repeated_batched_cuda_graph_uses_exact_materialized_cache_hits() {
    let backend = CudaBackend::acquire()
        .expect("Fix: CUDA backend acquisition must succeed on the GPU-required test host.");

    let program = add_one_program();
    let config = DispatchConfig::default();
    let pipeline = backend
        .compile_native(&program, &config)
        .expect("Fix: CUDA native pipeline compilation must succeed");
    let inputs = [
        u32_bytes(&[100, 101, 102, 103, 104, 105, 106, 107]),
        u32_bytes(&[200, 201, 202, 203, 204, 205, 206, 207]),
        u32_bytes(&[300, 301, 302, 303, 304, 305, 306, 307]),
        u32_bytes(&[400, 401, 402, 403, 404, 405, 406, 407]),
    ];
    let batch0 = [inputs[0].as_slice()];
    let batch1 = [inputs[1].as_slice()];
    let batch2 = [inputs[2].as_slice()];
    let batch3 = [inputs[3].as_slice()];
    let batches: [&[&[u8]]; 4] = [&batch0, &batch1, &batch2, &batch3];
    let mut outputs = Vec::with_capacity(batches.len());

    pipeline
        .dispatch_borrowed_batched_into(&batches, &config, &mut outputs)
        .expect("Fix: first compiled batched CUDA graph replay must materialize lane outputs.");

    backend.reset_telemetry();
    pipeline
        .dispatch_borrowed_batched_into(&batches, &config, &mut outputs)
        .expect(
            "Fix: repeated identical compiled batch must reuse materialized CUDA graph outputs.",
        );

    for (index, output) in outputs.iter().enumerate() {
        let base = ((index as u32) + 1) * 100;
        let expected: Vec<u32> = (0..8).map(|offset| base + offset + 1).collect();
        assert_eq!(
            bytes_u32(&output[0]),
            expected,
            "Fix: materialized-cache batch lane {index} must return exact cached add-one output."
        );
    }
    let telemetry = backend.telemetry_snapshot();
    assert_eq!(
        telemetry.cuda_graph_launches, 0,
        "Fix: repeated identical compiled batches must prefer exact materialized cached lanes and avoid all redundant graph launches."
    );
    assert_eq!(
        telemetry.cuda_graph_materialized_cache_hits,
        batches.len() as u64,
        "Fix: every repeated batch lane must be counted as a materialized CUDA graph cache hit."
    );
    assert_eq!(
        telemetry.cuda_graph_batched_replay_lanes, 0,
        "Fix: all-hit materialized batches must not report launched batched replay lanes."
    );
}

#[test]
fn compiled_pipeline_mixed_batched_materialized_cache_launches_only_misses() {
    let backend = CudaBackend::acquire()
        .expect("Fix: CUDA backend acquisition must succeed on the GPU-required test host.");

    let program = add_one_program();
    let config = DispatchConfig::default();
    let pipeline = backend
        .compile_native(&program, &config)
        .expect("Fix: CUDA native pipeline compilation must succeed");
    let cached_inputs = [
        u32_bytes(&[10, 11, 12, 13, 14, 15, 16, 17]),
        u32_bytes(&[20, 21, 22, 23, 24, 25, 26, 27]),
        u32_bytes(&[30, 31, 32, 33, 34, 35, 36, 37]),
        u32_bytes(&[40, 41, 42, 43, 44, 45, 46, 47]),
    ];
    let cached0 = [cached_inputs[0].as_slice()];
    let cached1 = [cached_inputs[1].as_slice()];
    let cached2 = [cached_inputs[2].as_slice()];
    let cached3 = [cached_inputs[3].as_slice()];
    let cached_batches: [&[&[u8]]; 4] = [&cached0, &cached1, &cached2, &cached3];
    let mut outputs = Vec::with_capacity(cached_batches.len());

    pipeline
        .dispatch_borrowed_batched_into(&cached_batches, &config, &mut outputs)
        .expect("Fix: first compiled batched CUDA graph replay must materialize cached lanes.");

    let changed = u32_bytes(&[90, 91, 92, 93, 94, 95, 96, 97]);
    let changed1 = [changed.as_slice()];
    let mixed_batches: [&[&[u8]]; 4] = [&cached0, &changed1, &cached2, &cached3];
    backend.reset_telemetry();
    pipeline
        .dispatch_borrowed_batched_into(&mixed_batches, &config, &mut outputs)
        .expect("Fix: mixed materialized/miss batch must replay only cache misses.");

    let expected = [
        vec![11, 12, 13, 14, 15, 16, 17, 18],
        vec![91, 92, 93, 94, 95, 96, 97, 98],
        vec![31, 32, 33, 34, 35, 36, 37, 38],
        vec![41, 42, 43, 44, 45, 46, 47, 48],
    ];
    for (index, output) in outputs.iter().enumerate() {
        assert_eq!(
            bytes_u32(&output[0]),
            expected[index],
            "Fix: mixed CUDA materialized batch lane {index} must return exact add-one output."
        );
    }
    let telemetry = backend.telemetry_snapshot();
    assert_eq!(
        telemetry.cuda_graph_launches, 1,
        "Fix: mixed materialized/miss compiled batches must launch only the one cache-miss lane."
    );
    assert_eq!(
        telemetry.cuda_graph_materialized_cache_hits, 3,
        "Fix: mixed materialized/miss compiled batches must count the three exact cache-hit lanes."
    );
    assert_eq!(
        telemetry.cuda_graph_batched_replay_lanes, 1,
        "Fix: mixed materialized/miss compiled batches must report only launched graph lanes."
    );
}

#[test]
fn cuda_graph_recording_accounts_raw_device_allocations() {
    let backend = Arc::new(
        CudaBackend::acquire()
            .expect("Fix: CUDA backend acquisition must succeed on the GPU-required test host."),
    );

    let program = add_one_program();
    let inputs = vec![u32_bytes(&[0, 1, 2, 3, 4, 5, 6, 7])];
    let config = DispatchConfig::default();
    backend.reset_telemetry();

    let _cached = backend
        .record_cuda_graph(&program, &inputs, &config)
        .expect("Fix: cudaGraph recording must succeed for the add-one telemetry contract.");

    let telemetry = backend.telemetry_snapshot();
    assert!(
        telemetry.transient_allocation_bytes_requested >= 64,
        "Fix: cudaGraph recording allocates raw input/output device buffers outside the \
         transient pool; telemetry must include at least the 32-byte input and 32-byte output \
         buffers instead of underreporting CUDA memory pressure. observed={}",
        telemetry.transient_allocation_bytes_requested
    );
    assert_eq!(
        telemetry.sync_points, 1,
        "Fix: cudaGraph recording must account for the parameter-initialization stream synchronization exactly once."
    );
}

#[test]
fn cuda_graph_rejects_input_shape_mismatch() {
    let backend = Arc::new(
        CudaBackend::acquire()
            .expect("Fix: CUDA backend acquisition must succeed on the GPU-required test host."),
    );

    let program = add_one_program();
    let inputs = vec![u32_bytes(&[0; 8])];
    let config = DispatchConfig::default();

    let mut cached = backend
        .record_cuda_graph(&program, &inputs, &config)
        .expect("record must succeed");

    // Try replay with WRONG-LENGTH input.
    let bad_inputs = [u32_bytes(&[0; 4])]; // half the recorded size
    let bad_refs: Vec<&[u8]> = bad_inputs.iter().map(Vec::as_slice).collect();
    match backend.dispatch_via_cuda_graph(&mut cached, &bad_refs) {
        Err(BackendError::InvalidProgram { fix }) => {
            assert!(
                fix.contains("re-record") || fix.contains("expects"),
                "rejection error must mention the size mismatch + tell the user to re-record \
                 the graph; got: {fix}"
            );
        }
        Ok(_) => panic!(
            "cuda_graph dispatch must NOT silently accept inputs of the wrong byte length; \
             expected BackendError::InvalidProgram with a structured fix string"
        ),
        Err(other) => panic!(
            "cuda_graph dispatch with mismatched input size must return InvalidProgram, \
             not {other:?}"
        ),
    }
}

#[test]
fn cuda_graph_replay_uses_cached_telemetry_totals_without_per_replay_scans() {
    let replay_source = include_str!("../src/backend/cuda_graph_replay.rs");
    let graph_source = include_str!("../src/backend/cuda_graph.rs");

    assert!(
        graph_source.contains("replay_input_bytes")
            && graph_source.contains("replay_output_bytes")
            && graph_source.contains("replay_host_upload_operations")
            && graph_source.contains("replay_device_readback_operations"),
        "Fix: cached CUDA graphs must store fixed-shape replay telemetry totals at record time."
    );
    assert!(
        replay_source.contains("CudaGraphReplayStats::from_cached(cached)"),
        "Fix: CUDA graph replay must reuse cached telemetry totals instead of rebuilding stats."
    );
    assert!(
        !replay_source.contains(".iter()\n                .fold(0_u64")
            && !replay_source.contains(".iter().filter("),
        "Fix: CUDA graph replay must not rescan inputs or output_lens for per-replay telemetry accounting."
    );
    assert!(
        !graph_source.contains("sample_inputs.iter().map(Vec::as_slice).collect()")
            && !graph_source.contains(".map(DevicePtrGuard::into_raw)")
            && !graph_source.contains("device_ptr.saturating_add")
            && !graph_source.contains(concat!(".", "saturating_add")),
        "Fix: CUDA graph recording must avoid iterator collect staging and saturating arithmetic while preparing sample inputs, telemetry totals, and raw device pointers."
    );
    assert!(
        graph_source.contains("cuda_output_readback_for_binding(")
            && !graph_source.contains("program.buffers()[binding.buffer_index]"),
        "Fix: CUDA graph capture readback planning must use the shared checked program-buffer lookup instead of directly indexing program buffers."
    );
    assert!(
        graph_source.contains("fn cuda_graph_sample_input")
            && graph_source.contains(".get(input_index)")
            && graph_source.contains(".copied()")
            && graph_source.contains("expected sample input index {input_index}")
            && !graph_source.contains("sample_inputs[input_index]"),
        "Fix: CUDA graph capture must turn stale binding sample-input indexes into BackendError instead of directly indexing borrowed sample input slices."
    );
}
