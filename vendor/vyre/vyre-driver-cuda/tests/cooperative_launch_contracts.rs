//! Cooperative-launch dispatch contracts.
//!
//! Verifies that the public `DispatchConfig::cooperative` flag routes
//! `vyre-driver-cuda` through `cuLaunchCooperativeKernel` and that:
//!   - On hardware that supports cooperative launch, output is byte-identical
//!     to the same Program dispatched via the regular `cuLaunchKernel` path.
//!   - On hardware that does NOT support cooperative launch (or when the
//!     device's `cooperative_launch` capability is false), the backend
//!     returns `BackendError::UnsupportedFeature` instead of silently falling
//!     back. Hardware-fail mode is the explicit, structured signal the runtime
//!     needs to make the kernel-split-fallback decision in
//!     `vyre_driver::grid_sync::dispatch_with_grid_sync_split`.
//!
//! These tests require a CUDA device. Backend acquisition failure is a test
//! failure on the GPU-required Vyre test hosts.

mod common;
use common::{bytes_u32, u32_bytes};
use vyre_driver::{BackendError, DispatchConfig};
use vyre_driver_cuda::occupancy::cooperative_thread_residency_block_limit;
use vyre_driver_cuda::CudaBackend;
use vyre_foundation::ir::{BufferDecl, DataType, Expr, Node, Program};

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

#[test]
fn cooperative_dispatch_matches_regular_dispatch_on_supported_hardware() {
    let backend = CudaBackend::acquire()
        .expect("Fix: CUDA backend acquisition must succeed on the GPU-required test host.");
    if !backend.hardware_supports_grid_sync() {
        // Hardware doesn't expose cooperative launch; the request-rejection
        // contract is covered by `cooperative_dispatch_rejected_on_unsupported_hardware`.
        return;
    }

    let program = add_one_program();
    let inputs = [u32_bytes(&[0, 1, 2, 3, 9, 10, 99, u32::MAX - 1])];

    let regular_outputs = backend
        .dispatch(&program, &inputs, &DispatchConfig::default())
        .expect("regular cuLaunchKernel dispatch must succeed for the trivial add-one program");

    let mut cooperative_config = DispatchConfig::default();
    cooperative_config.cooperative = true;
    let cooperative_outputs = backend
        .dispatch(&program, &inputs, &cooperative_config)
        .expect(
            "cuLaunchCooperativeKernel dispatch must succeed when the device reports \
             cooperative_launch support; a failure here means cooperative launch is \
             refused even though hardware_supports_grid_sync() returned true",
        );

    assert_eq!(
        regular_outputs.len(),
        cooperative_outputs.len(),
        "cooperative dispatch must produce the same output buffer count as regular dispatch"
    );
    assert_eq!(
        bytes_u32(&regular_outputs[0]),
        bytes_u32(&cooperative_outputs[0]),
        "cooperative + regular dispatch must produce byte-identical output for the \
         same Program; any divergence means the cooperative-launch path is not parity-clean"
    );
    assert_eq!(
        bytes_u32(&cooperative_outputs[0]),
        vec![1, 2, 3, 4, 10, 11, 100, u32::MAX],
        "cooperative-launch output must be byte-exact for u32 add-one"
    );
}

#[test]
fn cooperative_dispatch_rejected_on_unsupported_hardware() {
    let backend = CudaBackend::acquire()
        .expect("Fix: CUDA backend acquisition must succeed on the GPU-required test host.");
    if backend.hardware_supports_grid_sync() {
        // Hardware DOES support cooperative launch; the rejection-contract test
        // does not apply on this device.
        return;
    }

    let program = add_one_program();
    let inputs = [u32_bytes(&[0; 8])];
    let mut cooperative_config = DispatchConfig::default();
    cooperative_config.cooperative = true;

    match backend.dispatch(&program, &inputs, &cooperative_config) {
        Ok(_) => panic!(
            "cooperative dispatch must NOT silently succeed on hardware that doesn't \
             support cooperative launch; expected BackendError::UnsupportedFeature so \
             the runtime can drive the kernel-split-fallback decision explicitly"
        ),
        Err(BackendError::UnsupportedFeature { name, backend: _ }) => {
            assert!(
                name.contains("cooperative"),
                "rejection error name must mention cooperative launch so the diagnostic is searchable; got: {name}"
            );
        }
        Err(other) => panic!(
            "cooperative dispatch on unsupported hardware must return UnsupportedFeature, \
             not {other:?}"
        ),
    }
}

#[test]
fn cooperative_dispatch_rejects_non_resident_grid_before_driver_launch() {
    let backend = CudaBackend::acquire()
        .expect("Fix: CUDA backend acquisition must succeed on the GPU-required test host.");
    if !backend.hardware_supports_grid_sync() {
        return;
    }

    let program = add_one_program();
    let inputs = [u32_bytes(&[0; 8])];
    let workgroup = program.workgroup_size();
    let threads_per_block = workgroup[0]
        .checked_mul(workgroup[1])
        .and_then(|xy| xy.checked_mul(workgroup[2]))
        .expect("test workgroup product must fit u32");
    let resident_blocks =
        cooperative_thread_residency_block_limit(&backend.caps, threads_per_block);
    assert!(
        resident_blocks > 0,
        "Fix: cooperative launch contract test requires a positive resident-block limit on supported hardware."
    );

    let mut cooperative_config = DispatchConfig::default();
    cooperative_config.cooperative = true;
    cooperative_config.grid_override = Some([
        u32::try_from(resident_blocks + 1)
            .expect("test resident-block limit must fit in a 1D CUDA grid"),
        1,
        1,
    ]);

    let cache_before = backend.pipeline_cache_snapshot();
    match backend.dispatch(&program, &inputs, &cooperative_config) {
        Ok(_) => panic!(
            "oversized cooperative grid must be rejected before cuLaunchCooperativeKernel; \
             silently launching here would make grid-sync correctness depend on opaque driver failure"
        ),
        Err(BackendError::InvalidProgram { fix }) => {
            assert!(
                fix.contains("every block to be resident") && fix.contains("split"),
                "cooperative-grid residency error must explain the resident-grid invariant and the split remedy; got: {fix}"
            );
        }
        Err(other) => panic!(
            "oversized cooperative grid must return InvalidProgram with an actionable residency fix, not {other:?}"
        ),
    }
    let cache_after = backend.pipeline_cache_snapshot();
    assert_eq!(
        cache_after.hits, cache_before.hits,
        "Fix: oversized cooperative grids must be rejected before CUDA module-cache lookup; a cache hit here means the hot path still did avoidable launch prep."
    );
    assert_eq!(
        cache_after.misses, cache_before.misses,
        "Fix: oversized cooperative grids must be rejected before CUDA module load/JIT; a cache miss here means invalid cooperative dispatch still paid compile-path cost."
    );
}

#[test]
fn cooperative_compiled_pipeline_does_not_use_regular_cuda_graph_replay() {
    let compiled_dispatch_source = include_str!("../src/pipeline/compiled_dispatch.rs");
    let graph_source = include_str!("../src/backend/cuda_graph.rs");

    assert!(
        compiled_dispatch_source.contains("|| self.prepared.cooperative")
            && compiled_dispatch_source.contains("&& !self.prepared.cooperative"),
        "Fix: cooperative CUDA compiled pipelines must bypass regular CUDA graph replay until cooperative graph capture explicitly records the cooperative launch ABI."
    );
    assert!(
        graph_source.contains("super::launch::launch_cuda_function(")
            && graph_source.contains(
                "false,\n                self.ptx_target_sm(),\n                \"cuLaunchKernel (capture)\","
            )
            && graph_source.contains(
                "false,\n                self.ptx_target_sm(),\n                \"cuLaunchKernel (resident input capture)\","
            )
            && !graph_source.contains(concat!("cuLaunchCooperativeKernel", "(")),
        "Fix: this contract assumes CUDA graph capture still records regular non-cooperative launches through launch_cuda_function(..., cooperative=false); update the replay gate only when cooperative graph capture is implemented explicitly."
    );
}

#[test]
fn cooperative_cuda_graph_recording_is_rejected_explicitly() {
    let backend = CudaBackend::acquire()
        .expect("Fix: CUDA backend acquisition must succeed on the GPU-required test host.");
    let program = add_one_program();
    let input = u32_bytes(&[0, 1, 2, 3, 4, 5, 6, 7]);
    let inputs = [input.as_slice()];
    let mut cooperative_config = DispatchConfig::default();
    cooperative_config.cooperative = true;

    match backend.record_cuda_graph_borrowed(&program, &inputs, &cooperative_config) {
        Ok(_) => panic!(
            "cooperative CUDA graph recording must not silently capture cuLaunchKernel; expected explicit UnsupportedFeature until cooperative graph capture records cuLaunchCooperativeKernel."
        ),
        Err(BackendError::UnsupportedFeature { name, backend: _ }) => {
            assert!(
                name.contains("cooperative") && name.contains("cuLaunchCooperativeKernel"),
                "Fix: cooperative graph rejection must name the missing cooperative launch ABI; got: {name}"
            );
        }
        Err(other) => panic!(
            "cooperative CUDA graph recording must return UnsupportedFeature, not {other:?}"
        ),
    }
}

#[test]
fn cooperative_default_is_false_so_existing_callers_unchanged() {
    // The DispatchConfig::default() field must be `cooperative: false` so every
    // existing call site (which constructs DispatchConfig::default() and never
    // sets cooperative) continues to use cuLaunchKernel exactly as before.
    // This test guards the additive-only contract of the field addition.
    let config = DispatchConfig::default();
    assert!(
        !config.cooperative,
        "DispatchConfig::default().cooperative must be false; flipping it would silently \
         opt every existing dispatch into cooperative launch and change behaviour on every \
         consumer of the API"
    );
}
