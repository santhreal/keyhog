//! Integration test for the CUDA backend.

mod common;
use common::{bytes_u32, u32_bytes};
use std::sync::Arc;

use vyre_driver::{DispatchConfig, VyreBackend};
use vyre_driver_cuda::{CudaBackend, CudaBackendRegistration, CudaOptimizerDispatcher};
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};
use vyre_self_substrate::optimizer::dispatcher::{
    OptimizerDispatcher, ResidentDispatchStep, ResidentReadRange,
};

fn cuda_resident_borrowed_fallback_active() -> bool {
    if std::env::var_os("VYRE_CUDA_RESIDENT_BORROWED_FALLBACK").is_none() {
        return false;
    }
    #[cfg(debug_assertions)]
    {
        return true;
    }
    #[cfg(not(debug_assertions))]
    {
        std::env::var("VYRE_CUDA_ALLOW_BORROWED_FALLBACK")
            .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "on" | "ON"))
            .unwrap_or(false)
    }
}

fn expected_readback_bytes(native_resident: u64, fallback_resident: u64) -> u64 {
    if cuda_resident_borrowed_fallback_active() {
        fallback_resident
    } else {
        native_resident
    }
}

#[test]
fn resident_dispatch_runs_without_host_buffer_arguments() {
    let backend =
        CudaBackend::acquire().expect("Fix: CUDA backend acquire failed on a GPU-required host.");
    let program = Program::wrapped(
        vec![
            BufferDecl::read("input", 0, DataType::U32).with_count(4),
            BufferDecl::output("out", 1, DataType::U32).with_count(4),
        ],
        [1, 1, 1],
        vec![Node::store(
            "out",
            Expr::gid_x(),
            Expr::mul(Expr::load("input", Expr::gid_x()), Expr::u32(3)),
        )],
    );

    let input = backend
        .allocate_resident(16)
        .expect("Fix: CUDA resident input allocation failed.");
    let output = backend
        .allocate_resident(16)
        .expect("Fix: CUDA resident output allocation failed.");
    backend
        .upload_resident(input, &u32_bytes(&[1, 2, 3, 4]))
        .expect("Fix: CUDA resident input upload failed.");

    backend
        .dispatch_resident(&program, &[input, output], &DispatchConfig::default())
        .expect("Fix: CUDA resident dispatch must execute the scalar trainer-safe subset.");

    let output_bytes = backend
        .download_resident(output)
        .expect("Fix: CUDA resident output download failed.");
    assert_eq!(bytes_u32(&output_bytes), vec![3, 6, 9, 12]);

    backend
        .free_resident(input)
        .expect("Fix: CUDA resident input free failed.");
    backend
        .free_resident(output)
        .expect("Fix: CUDA resident output free failed.");
}

#[test]
fn resident_dispatch_preserves_plain_read_write_state() {
    let backend =
        CudaBackend::acquire().expect("Fix: CUDA backend acquire failed on a GPU-required host.");
    let program = Program::wrapped(
        vec![BufferDecl::storage("state", 0, BufferAccess::ReadWrite, DataType::U32).with_count(4)],
        [1, 1, 1],
        vec![Node::store(
            "state",
            Expr::gid_x(),
            Expr::add(Expr::load("state", Expr::gid_x()), Expr::u32(7)),
        )],
    );

    let state = backend
        .allocate_resident(16)
        .expect("Fix: CUDA resident state allocation failed.");
    backend
        .upload_resident(state, &u32_bytes(&[1, 2, 3, 4]))
        .expect("Fix: CUDA resident state upload failed.");

    backend
        .dispatch_resident(&program, &[state], &DispatchConfig::default())
        .expect("Fix: CUDA resident dispatch must update plain read-write state in place.");

    let output_bytes = backend
        .download_resident(state)
        .expect("Fix: CUDA resident state download failed.");
    assert_eq!(bytes_u32(&output_bytes), vec![8, 9, 10, 11]);

    backend
        .free_resident(state)
        .expect("Fix: CUDA resident state free failed.");
}

#[test]
fn async_resident_dispatch_holds_handles_until_awaited() {
    let backend =
        CudaBackend::acquire().expect("Fix: CUDA backend acquire failed on a GPU-required host.");
    let program = Program::wrapped(
        vec![
            BufferDecl::read("input", 0, DataType::U32).with_count(4),
            BufferDecl::output("out", 1, DataType::U32).with_count(4),
        ],
        [1, 1, 1],
        vec![Node::store(
            "out",
            Expr::gid_x(),
            Expr::add(Expr::load("input", Expr::gid_x()), Expr::u32(5)),
        )],
    );

    let input = backend
        .allocate_resident(16)
        .expect("Fix: CUDA resident input allocation failed.");
    let output = backend
        .allocate_resident(16)
        .expect("Fix: CUDA resident output allocation failed.");
    backend
        .upload_resident(input, &u32_bytes(&[10, 20, 30, 40]))
        .expect("Fix: CUDA resident input upload failed.");

    let pending = backend
        .dispatch_resident_async(&program, &[input, output], &DispatchConfig::default())
        .expect("Fix: CUDA resident async dispatch must enqueue without host buffer arguments.");
    pending
        .await_result()
        .expect("Fix: CUDA resident async dispatch must complete successfully.");

    let output_bytes = backend
        .download_resident(output)
        .expect("Fix: CUDA resident output download failed.");
    assert_eq!(bytes_u32(&output_bytes), vec![15, 25, 35, 45]);

    backend
        .free_resident(input)
        .expect("Fix: CUDA resident input free failed after await.");
    backend
        .free_resident(output)
        .expect("Fix: CUDA resident output free failed after await.");
}

#[test]
fn timed_resident_dispatch_reports_device_time_and_outputs() {
    let backend =
        CudaBackend::acquire().expect("Fix: CUDA backend acquire failed on a GPU-required host.");
    let program = Program::wrapped(
        vec![
            BufferDecl::read("input", 0, DataType::U32).with_count(4),
            BufferDecl::output("out", 1, DataType::U32).with_count(4),
        ],
        [1, 1, 1],
        vec![Node::store(
            "out",
            Expr::gid_x(),
            Expr::mul(Expr::load("input", Expr::gid_x()), Expr::u32(2)),
        )],
    );

    let input = backend
        .allocate_resident(16)
        .expect("Fix: CUDA resident input allocation failed.");
    let output = backend
        .allocate_resident(16)
        .expect("Fix: CUDA resident output allocation failed.");
    backend
        .upload_resident(input, &u32_bytes(&[2, 4, 6, 8]))
        .expect("Fix: CUDA resident input upload failed.");

    let timed = backend
        .dispatch_resident_timed(&program, &[input, output], &DispatchConfig::default())
        .expect("Fix: timed CUDA resident dispatch must complete successfully.");
    assert_eq!(bytes_u32(&timed.outputs[0]), vec![4, 8, 12, 16]);
    assert!(
        timed.wall_ns > 0,
        "Fix: CUDA resident timing fallback must return wall-clock timing."
    );

    backend
        .free_resident(input)
        .expect("Fix: CUDA resident input free failed after timed dispatch.");
    backend
        .free_resident(output)
        .expect("Fix: CUDA resident output free failed after timed dispatch.");
}

#[test]
fn compiled_resident_dispatch_into_reuses_output_slot() {
    let backend = Arc::new(CudaBackendRegistration::new(
        CudaBackend::acquire().expect("Fix: CUDA backend acquire failed on a GPU-required host."),
    ));
    let program = Program::wrapped(
        vec![
            BufferDecl::read("input", 0, DataType::U32).with_count(4),
            BufferDecl::output("out", 1, DataType::U32).with_count(4),
        ],
        [1, 1, 1],
        vec![Node::store(
            "out",
            Expr::gid_x(),
            Expr::add(Expr::load("input", Expr::gid_x()), Expr::u32(11)),
        )],
    );
    let config = DispatchConfig::default();
    let pipeline = vyre_driver::pipeline::compile(backend.clone(), &program, &config)
        .expect("Fix: CUDA compiled pipeline creation failed for resident dispatch.");
    let input = VyreBackend::allocate_resident(backend.as_ref(), 16)
        .expect("Fix: CUDA trait resident input allocation failed.");
    let output = VyreBackend::allocate_resident(backend.as_ref(), 16)
        .expect("Fix: CUDA trait resident output allocation failed.");
    VyreBackend::upload_resident(backend.as_ref(), &input, &u32_bytes(&[1, 2, 3, 4]))
        .expect("Fix: CUDA trait resident input upload failed.");

    let mut outputs = vec![Vec::with_capacity(64)];
    let outer_ptr = outputs.as_ptr();
    let first_slot_ptr = outputs[0].as_ptr();

    backend.reset_telemetry();
    pipeline
        .dispatch_persistent_handles_into(&[input.clone(), output.clone()], &config, &mut outputs)
        .expect("Fix: CUDA compiled resident dispatch must support caller-owned output slots.");

    assert_eq!(bytes_u32(&outputs[0]), vec![12, 13, 14, 15]);
    assert_eq!(outputs.as_ptr(), outer_ptr);
    assert_eq!(outputs[0].as_ptr(), first_slot_ptr);
    let telemetry = backend.telemetry_snapshot();
    assert_eq!(
        telemetry.param_upload_bytes, 0,
        "Fix: same-shape compiled resident dispatch must reuse static CUDA launch params instead of re-uploading params through the borrowed fallback."
    );
    assert_eq!(
        telemetry.readback_bytes, 16,
        "Fix: same-shape compiled resident dispatch must read back only requested output bytes, not resident inputs."
    );

    VyreBackend::free_resident(backend.as_ref(), input)
        .expect("Fix: CUDA trait resident input free failed.");
    VyreBackend::free_resident(backend.as_ref(), output)
        .expect("Fix: CUDA trait resident output free failed.");
}

#[test]
fn compiled_resident_dispatch_skips_zero_length_output_writeback() {
    let backend = Arc::new(CudaBackendRegistration::new(
        CudaBackend::acquire().expect("Fix: CUDA backend acquire failed on a GPU-required host."),
    ));
    let program = Program::wrapped(
        vec![BufferDecl::read_write("state", 0, DataType::U32)
            .with_count(4)
            .with_output_byte_range(0..0)],
        [1, 1, 1],
        vec![Node::store("state", Expr::gid_x(), Expr::u32(99))],
    );
    let config = DispatchConfig::default();
    let pipeline = vyre_driver::pipeline::compile(backend.clone(), &program, &config)
        .expect("Fix: CUDA compiled pipeline creation failed for zero-readback resident dispatch.");
    let state = VyreBackend::allocate_resident(backend.as_ref(), 16)
        .expect("Fix: CUDA trait resident state allocation failed.");
    VyreBackend::upload_resident(backend.as_ref(), &state, &u32_bytes(&[1, 2, 3, 4]))
        .expect("Fix: CUDA trait resident state upload failed.");

    let mut outputs = Vec::new();
    pipeline
        .dispatch_persistent_handles_into(&[state.clone()], &config, &mut outputs)
        .expect(
            "Fix: CUDA compiled resident dispatch must skip writeback for output_byte_range=0..0.",
        );

    assert_eq!(outputs, vec![Vec::<u8>::new()]);
    VyreBackend::free_resident(backend.as_ref(), state)
        .expect("Fix: CUDA trait resident state free failed.");
}

#[test]
fn compiled_resource_output_dispatch_reuses_static_launch_params() {
    let backend = Arc::new(CudaBackendRegistration::new(
        CudaBackend::acquire().expect("Fix: CUDA backend acquire failed on a GPU-required host."),
    ));
    let program = Program::wrapped(
        vec![
            BufferDecl::read("input", 0, DataType::U32).with_count(4),
            BufferDecl::output("out", 1, DataType::U32).with_count(4),
        ],
        [1, 1, 1],
        vec![Node::store(
            "out",
            Expr::gid_x(),
            Expr::add(Expr::load("input", Expr::gid_x()), Expr::u32(17)),
        )],
    );
    let config = DispatchConfig::default();
    let pipeline = vyre_driver::pipeline::compile(backend.clone(), &program, &config)
        .expect("Fix: CUDA compiled pipeline creation failed for resident resource outputs.");
    let input = VyreBackend::allocate_resident(backend.as_ref(), 16)
        .expect("Fix: CUDA trait resident input allocation failed.");
    let output = VyreBackend::allocate_resident(backend.as_ref(), 16)
        .expect("Fix: CUDA trait resident output allocation failed.");
    VyreBackend::upload_resident(backend.as_ref(), &input, &u32_bytes(&[1, 2, 3, 4]))
        .expect("Fix: CUDA trait resident input upload failed.");

    backend.reset_telemetry();
    let resources = pipeline
        .dispatch_persistent_resource_outputs(&[input.clone(), output.clone()], &config)
        .expect("Fix: CUDA compiled persistent resource-output dispatch must stay resident.");

    assert_eq!(
        resources.len(),
        1,
        "Fix: CUDA compiled persistent resource-output dispatch must return resident output resources only."
    );
    let telemetry = backend.telemetry_snapshot();
    assert_eq!(
        telemetry.param_upload_bytes, 0,
        "Fix: compiled persistent resource-output dispatch must reuse static CUDA launch params instead of re-uploading params through a fallback."
    );
    assert_eq!(
        telemetry.readback_bytes, 0,
        "Fix: resource-output dispatch must stay resident and avoid host readback before the caller asks for bytes."
    );
    let output_bytes = VyreBackend::download_resident(backend.as_ref(), &output)
        .expect("Fix: CUDA compiled resource-output dispatch must leave computed bytes resident.");
    assert_eq!(bytes_u32(&output_bytes), vec![18, 19, 20, 21]);

    VyreBackend::free_resident(backend.as_ref(), input)
        .expect("Fix: CUDA trait resident input free failed.");
    VyreBackend::free_resident(backend.as_ref(), output)
        .expect("Fix: CUDA trait resident output free failed.");
}

#[test]
fn backend_sequence_read_ranges_runs_dependent_steps_with_one_fence() {
    let backend = CudaBackendRegistration::new(
        CudaBackend::acquire().expect("Fix: CUDA backend acquire failed on a GPU-required host."),
    );
    let add_seven = Program::wrapped(
        vec![
            BufferDecl::read("input", 0, DataType::U32).with_count(4),
            BufferDecl::output("tmp", 1, DataType::U32).with_count(4),
        ],
        [1, 1, 1],
        vec![Node::store(
            "tmp",
            Expr::gid_x(),
            Expr::add(Expr::load("input", Expr::gid_x()), Expr::u32(7)),
        )],
    );
    let double = Program::wrapped(
        vec![
            BufferDecl::read("tmp", 0, DataType::U32).with_count(4),
            BufferDecl::output("out", 1, DataType::U32).with_count(4),
        ],
        [1, 1, 1],
        vec![Node::store(
            "out",
            Expr::gid_x(),
            Expr::mul(Expr::load("tmp", Expr::gid_x()), Expr::u32(2)),
        )],
    );
    let input = VyreBackend::allocate_resident(&backend, 16)
        .expect("Fix: CUDA sequence resident input allocation failed.");
    let tmp = VyreBackend::allocate_resident(&backend, 16)
        .expect("Fix: CUDA sequence resident tmp allocation failed.");
    let output = VyreBackend::allocate_resident(&backend, 16)
        .expect("Fix: CUDA sequence resident output allocation failed.");
    VyreBackend::upload_resident(&backend, &input, &u32_bytes(&[1, 2, 3, 4]))
        .expect("Fix: CUDA sequence resident input upload failed.");

    let first_resources = [input.clone(), tmp.clone()];
    let second_resources = [tmp.clone(), output.clone()];
    let steps = [
        vyre_driver::backend::ResidentDispatchStep {
            program: &add_seven,
            resources: &first_resources,
            grid_override: None,
        },
        vyre_driver::backend::ResidentDispatchStep {
            program: &add_seven,
            resources: &first_resources,
            grid_override: None,
        },
        vyre_driver::backend::ResidentDispatchStep {
            program: &double,
            resources: &second_resources,
            grid_override: None,
        },
    ];
    let read_ranges = [vyre_driver::backend::ResidentReadRange {
        resource: &output,
        byte_offset: 4,
        byte_len: 8,
    }];
    let mut compact = Vec::with_capacity(64);
    let compact_ptr = compact.as_ptr();

    backend.reset_telemetry();
    VyreBackend::dispatch_resident_sequence_read_ranges_into(
        &backend,
        &steps,
        &read_ranges,
        &mut [&mut compact],
    )
    .expect("Fix: CUDA backend resident sequence-read API must execute dependent kernels.");

    assert_eq!(bytes_u32(&compact), vec![18, 20]);
    assert_eq!(
        compact.as_ptr(),
        compact_ptr,
        "Fix: CUDA backend resident sequence-read API must preserve caller-owned output capacity."
    );
    let telemetry = backend.telemetry_snapshot();
    assert_eq!(
        telemetry.kernel_launches, 3,
        "Fix: CUDA backend resident sequence-read API must launch every dependent sequence step."
    );
    assert!(telemetry.sync_points > 0, "Fix: CUDA backend resident sequence-read API must fence once for the whole dependent window plus readback.");
    assert_eq!(
        telemetry.readback_bytes,
        expected_readback_bytes(8, 104),
        "Fix: CUDA backend resident sequence-read API must compact readback to the requested byte range."
    );
    assert!(
        telemetry.param_upload_bytes <= 128,
        "Fix: CUDA backend resident sequence-read API must hoist duplicate launch parameter blocks instead of uploading parameters once per sequence step; observed {} bytes.",
        telemetry.param_upload_bytes
    );

    VyreBackend::free_resident(&backend, input)
        .expect("Fix: CUDA sequence resident input free failed.");
    VyreBackend::free_resident(&backend, tmp)
        .expect("Fix: CUDA sequence resident tmp free failed.");
    VyreBackend::free_resident(&backend, output)
        .expect("Fix: CUDA sequence resident output free failed.");
}

#[test]
fn backend_sequence_read_ranges_coalesces_duplicate_d2h_copies() {
    let backend = CudaBackendRegistration::new(
        CudaBackend::acquire().expect("Fix: CUDA backend acquire failed on a GPU-required host."),
    );
    let add_seven = Program::wrapped(
        vec![
            BufferDecl::read("input", 0, DataType::U32).with_count(4),
            BufferDecl::output("out", 1, DataType::U32).with_count(4),
        ],
        [1, 1, 1],
        vec![Node::store(
            "out",
            Expr::gid_x(),
            Expr::add(Expr::load("input", Expr::gid_x()), Expr::u32(7)),
        )],
    );
    let input = VyreBackend::allocate_resident(&backend, 16)
        .expect("Fix: CUDA duplicate-readback input allocation failed.");
    let output = VyreBackend::allocate_resident(&backend, 16)
        .expect("Fix: CUDA duplicate-readback output allocation failed.");
    VyreBackend::upload_resident(&backend, &input, &u32_bytes(&[1, 2, 3, 4]))
        .expect("Fix: CUDA duplicate-readback input upload failed.");

    let resources = [input.clone(), output.clone()];
    let steps = [vyre_driver::backend::ResidentDispatchStep {
        program: &add_seven,
        resources: &resources,
        grid_override: None,
    }];
    let read_ranges = (0..16)
        .map(|_| vyre_driver::backend::ResidentReadRange {
            resource: &output,
            byte_offset: 4,
            byte_len: 8,
        })
        .collect::<Vec<_>>();
    let mut outputs = (0..16).map(|_| Vec::with_capacity(64)).collect::<Vec<_>>();
    let output_ptrs = outputs.iter().map(Vec::as_ptr).collect::<Vec<_>>();

    backend.reset_telemetry();
    {
        let mut output_refs = outputs.iter_mut().collect::<Vec<_>>();
        VyreBackend::dispatch_resident_sequence_read_ranges_into(
            &backend,
            &steps,
            &read_ranges,
            &mut output_refs,
        )
        .expect("Fix: CUDA backend resident sequence-read API must coalesce duplicate readbacks without losing output slots.");
    }

    for (index, output) in outputs.iter().enumerate() {
        assert_eq!(bytes_u32(output), vec![9, 10]);
        assert_eq!(
            output.as_ptr(),
            output_ptrs[index],
            "Fix: duplicate compact readback must preserve caller-owned byte capacity for output slot {index}."
        );
    }
    let telemetry = backend.telemetry_snapshot();
    if !cuda_resident_borrowed_fallback_active() {
        assert_eq!(
            telemetry.readback_bytes, 8,
            "Fix: native CUDA sequence readback must issue one compact D2H copy for duplicate ranges."
        );
        assert_eq!(
            telemetry.device_readback_operations, 1,
            "Fix: native CUDA sequence readback must count one D2H operation for duplicate ranges."
        );
        assert_eq!(
            telemetry.resident_borrowed_fallback_dispatches, 0,
            "Fix: native CUDA resident sequence readback must not touch the borrowed fallback path."
        );
    }

    VyreBackend::free_resident(&backend, input)
        .expect("Fix: CUDA duplicate-readback input free failed.");
    VyreBackend::free_resident(&backend, output)
        .expect("Fix: CUDA duplicate-readback output free failed.");
}

#[test]

fn backend_sequence_read_ranges_fuses_overlapping_and_adjacent_d2h_intervals() {
    let backend = CudaBackendRegistration::new(
        CudaBackend::acquire().expect("Fix: CUDA backend acquire failed on a GPU-required host."),
    );
    let add_seven = Program::wrapped(
        vec![
            BufferDecl::read("input", 0, DataType::U32).with_count(4),
            BufferDecl::output("out", 1, DataType::U32).with_count(4),
        ],
        [1, 1, 1],
        vec![Node::store(
            "out",
            Expr::gid_x(),
            Expr::add(Expr::load("input", Expr::gid_x()), Expr::u32(7)),
        )],
    );
    let input = VyreBackend::allocate_resident(&backend, 16)
        .expect("Fix: CUDA fused-readback input allocation failed.");
    let output = VyreBackend::allocate_resident(&backend, 16)
        .expect("Fix: CUDA fused-readback output allocation failed.");
    VyreBackend::upload_resident(&backend, &input, &u32_bytes(&[1, 2, 3, 4]))
        .expect("Fix: CUDA fused-readback input upload failed.");

    let resources = [input.clone(), output.clone()];
    let steps = [vyre_driver::backend::ResidentDispatchStep {
        program: &add_seven,
        resources: &resources,
        grid_override: None,
    }];
    let read_ranges = [
        vyre_driver::backend::ResidentReadRange {
            resource: &output,
            byte_offset: 0,
            byte_len: 8,
        },
        vyre_driver::backend::ResidentReadRange {
            resource: &output,
            byte_offset: 4,
            byte_len: 8,
        },
        vyre_driver::backend::ResidentReadRange {
            resource: &output,
            byte_offset: 12,
            byte_len: 4,
        },
    ];
    let mut first = Vec::with_capacity(64);
    let mut second = Vec::with_capacity(64);
    let mut third = Vec::with_capacity(64);

    backend.reset_telemetry();
    VyreBackend::dispatch_resident_sequence_read_ranges_into(
        &backend,
        &steps,
        &read_ranges,
        &mut [&mut first, &mut second, &mut third],
    )
    .expect("Fix: CUDA backend resident sequence-read API must fuse overlapping and adjacent readbacks without changing caller output ordering.");

    assert_eq!(bytes_u32(&first), vec![8, 9]);
    assert_eq!(bytes_u32(&second), vec![9, 10]);
    assert_eq!(bytes_u32(&third), vec![11]);
    let telemetry = backend.telemetry_snapshot();
    if !cuda_resident_borrowed_fallback_active() {
        assert_eq!(
            telemetry.readback_bytes, 16,
            "Fix: native CUDA sequence readback must fuse overlapping/adjacent ranges into one 16-byte D2H interval."
        );
        assert_eq!(
            telemetry.device_readback_operations, 1,
            "Fix: native CUDA sequence readback must issue one D2H operation for a fused readback interval."
        );
        assert_eq!(
            telemetry.resident_borrowed_fallback_dispatches, 0,
            "Fix: native CUDA resident sequence readback must not touch the borrowed fallback path."
        );
    }

    VyreBackend::free_resident(&backend, input)
        .expect("Fix: CUDA fused-readback input free failed.");
    VyreBackend::free_resident(&backend, output)
        .expect("Fix: CUDA fused-readback output free failed.");
}

#[test]
fn backend_repeated_sequence_read_ranges_runs_without_expanded_host_window() {
    let backend = CudaBackendRegistration::new(
        CudaBackend::acquire().expect("Fix: CUDA backend acquire failed on a GPU-required host."),
    );
    let add_seven = Program::wrapped(
        vec![
            BufferDecl::read("input", 0, DataType::U32).with_count(4),
            BufferDecl::output("tmp", 1, DataType::U32).with_count(4),
        ],
        [1, 1, 1],
        vec![Node::store(
            "tmp",
            Expr::gid_x(),
            Expr::add(Expr::load("input", Expr::gid_x()), Expr::u32(7)),
        )],
    );
    let double = Program::wrapped(
        vec![
            BufferDecl::read("tmp", 0, DataType::U32).with_count(4),
            BufferDecl::output("out", 1, DataType::U32).with_count(4),
        ],
        [1, 1, 1],
        vec![Node::store(
            "out",
            Expr::gid_x(),
            Expr::mul(Expr::load("tmp", Expr::gid_x()), Expr::u32(2)),
        )],
    );
    let input = VyreBackend::allocate_resident(&backend, 16)
        .expect("Fix: CUDA repeated sequence resident input allocation failed.");
    let tmp = VyreBackend::allocate_resident(&backend, 16)
        .expect("Fix: CUDA repeated sequence resident tmp allocation failed.");
    let output = VyreBackend::allocate_resident(&backend, 16)
        .expect("Fix: CUDA repeated sequence resident output allocation failed.");
    VyreBackend::upload_resident(&backend, &input, &u32_bytes(&[1, 2, 3, 4]))
        .expect("Fix: CUDA repeated sequence resident input upload failed.");

    let prefix_resources = [input.clone(), tmp.clone()];
    let repeated_resources = [tmp.clone(), output.clone()];
    let prefix_steps = [vyre_driver::backend::ResidentDispatchStep {
        program: &add_seven,
        resources: &prefix_resources,
        grid_override: None,
    }];
    let repeated_steps = [vyre_driver::backend::ResidentDispatchStep {
        program: &double,
        resources: &repeated_resources,
        grid_override: None,
    }];
    let read_ranges = [vyre_driver::backend::ResidentReadRange {
        resource: &output,
        byte_offset: 0,
        byte_len: 16,
    }];
    let mut readback = Vec::with_capacity(64);
    let readback_ptr = readback.as_ptr();

    backend.reset_telemetry();
    VyreBackend::dispatch_resident_repeated_sequence_read_ranges_into(
        &backend,
        &prefix_steps,
        &repeated_steps,
        4,
        &read_ranges,
        &mut [&mut readback],
    )
    .expect("Fix: CUDA backend repeated resident sequence-read API must execute without materializing an expanded caller sequence.");

    assert_eq!(bytes_u32(&readback), vec![16, 18, 20, 22]);
    assert_eq!(
        readback.as_ptr(),
        readback_ptr,
        "Fix: CUDA repeated resident sequence-read API must preserve caller-owned output capacity."
    );
    let telemetry = backend.telemetry_snapshot();
    assert_eq!(
        telemetry.kernel_launches, 5,
        "Fix: CUDA repeated resident sequence-read API must launch prefix plus every repeated step."
    );
    assert!(telemetry.sync_points > 0, "Fix: CUDA repeated resident sequence-read API must fence once for the whole repeated window plus readback.");
    assert_eq!(
        telemetry.readback_bytes,
        expected_readback_bytes(16, 176),
        "Fix: CUDA repeated resident sequence-read API must compact readback to the requested byte range."
    );
    assert!(
        telemetry.param_upload_bytes <= 128,
        "Fix: CUDA repeated resident sequence-read API must hoist repeated launch parameter blocks instead of uploading parameters once per repeated step; observed {} bytes.",
        telemetry.param_upload_bytes
    );

    VyreBackend::free_resident(&backend, input)
        .expect("Fix: CUDA repeated sequence resident input free failed.");
    VyreBackend::free_resident(&backend, tmp)
        .expect("Fix: CUDA repeated sequence resident tmp free failed.");
    VyreBackend::free_resident(&backend, output)
        .expect("Fix: CUDA repeated sequence resident output free failed.");
}

#[test]
fn zero_repeat_resident_sequence_does_not_prepare_dead_repeated_steps() {
    let backend = CudaBackendRegistration::new(
        CudaBackend::acquire().expect("Fix: CUDA backend acquire failed on a GPU-required host."),
    );
    let add_seven = Program::wrapped(
        vec![
            BufferDecl::read("input", 0, DataType::U32).with_count(4),
            BufferDecl::output("tmp", 1, DataType::U32).with_count(4),
        ],
        [1, 1, 1],
        vec![Node::store(
            "tmp",
            Expr::gid_x(),
            Expr::add(Expr::load("input", Expr::gid_x()), Expr::u32(7)),
        )],
    );
    let dead_repeated = Program::wrapped(
        vec![
            BufferDecl::read("dead_in", 0, DataType::U32).with_count(4),
            BufferDecl::output("dead_out", 1, DataType::U32).with_count(4),
        ],
        [1, 1, 1],
        vec![Node::store(
            "dead_out",
            Expr::gid_x(),
            Expr::load("dead_in", Expr::gid_x()),
        )],
    );
    let input = VyreBackend::allocate_resident(&backend, 16)
        .expect("Fix: CUDA zero-repeat resident input allocation failed.");
    let tmp = VyreBackend::allocate_resident(&backend, 16)
        .expect("Fix: CUDA zero-repeat resident tmp allocation failed.");
    VyreBackend::upload_resident(&backend, &input, &u32_bytes(&[1, 2, 3, 4]))
        .expect("Fix: CUDA zero-repeat resident input upload failed.");

    let prefix_resources = [input.clone(), tmp.clone()];
    let invalid_repeated_resources = [
        vyre_driver::backend::Resource::default(),
        vyre_driver::backend::Resource::default(),
    ];
    let prefix_steps = [vyre_driver::backend::ResidentDispatchStep {
        program: &add_seven,
        resources: &prefix_resources,
        grid_override: None,
    }];
    let repeated_steps = [vyre_driver::backend::ResidentDispatchStep {
        program: &dead_repeated,
        resources: &invalid_repeated_resources,
        grid_override: None,
    }];
    let read_ranges = [vyre_driver::backend::ResidentReadRange {
        resource: &tmp,
        byte_offset: 0,
        byte_len: 16,
    }];
    let mut readback = Vec::new();

    backend.reset_telemetry();
    VyreBackend::dispatch_resident_repeated_sequence_read_ranges_into(
        &backend,
        &prefix_steps,
        &repeated_steps,
        0,
        &read_ranges,
        &mut [&mut readback],
    )
    .expect("Fix: CUDA zero-repeat resident sequence must not resolve or prepare repeated steps that cannot launch.");

    assert_eq!(bytes_u32(&readback), vec![8, 9, 10, 11]);
    let telemetry = backend.telemetry_snapshot();
    assert_eq!(
        telemetry.kernel_launches, 1,
        "Fix: CUDA zero-repeat resident sequence must launch only the prefix step."
    );
    assert!(
        telemetry.sync_points > 0,
        "Fix: CUDA zero-repeat resident sequence should still use one compact readback fence."
    );

    VyreBackend::free_resident(&backend, input)
        .expect("Fix: CUDA zero-repeat resident input free failed.");
    VyreBackend::free_resident(&backend, tmp)
        .expect("Fix: CUDA zero-repeat resident tmp free failed.");
}

#[test]
fn golden_fixed_graph_replay_keeps_host_overhead_sublinear() {
    let backend = CudaBackendRegistration::new(
        CudaBackend::acquire().expect("Fix: CUDA backend acquire failed on a GPU-required host."),
    );
    let add_seven = Program::wrapped(
        vec![
            BufferDecl::read("input", 0, DataType::U32).with_count(4),
            BufferDecl::output("tmp", 1, DataType::U32).with_count(4),
        ],
        [1, 1, 1],
        vec![Node::store(
            "tmp",
            Expr::gid_x(),
            Expr::add(Expr::load("input", Expr::gid_x()), Expr::u32(7)),
        )],
    );
    let double = Program::wrapped(
        vec![
            BufferDecl::read("tmp", 0, DataType::U32).with_count(4),
            BufferDecl::output("out", 1, DataType::U32).with_count(4),
        ],
        [1, 1, 1],
        vec![Node::store(
            "out",
            Expr::gid_x(),
            Expr::mul(Expr::load("tmp", Expr::gid_x()), Expr::u32(2)),
        )],
    );
    let input = VyreBackend::allocate_resident(&backend, 16)
        .expect("Fix: CUDA golden replay resident input allocation failed.");
    let tmp = VyreBackend::allocate_resident(&backend, 16)
        .expect("Fix: CUDA golden replay resident tmp allocation failed.");
    let output = VyreBackend::allocate_resident(&backend, 16)
        .expect("Fix: CUDA golden replay resident output allocation failed.");
    VyreBackend::upload_resident(&backend, &input, &u32_bytes(&[1, 2, 3, 4]))
        .expect("Fix: CUDA golden replay resident input upload failed.");

    let prefix_resources = [input.clone(), tmp.clone()];
    let repeated_resources = [tmp.clone(), output.clone()];
    let prefix_steps = [vyre_driver::backend::ResidentDispatchStep {
        program: &add_seven,
        resources: &prefix_resources,
        grid_override: None,
    }];
    let repeated_steps = [vyre_driver::backend::ResidentDispatchStep {
        program: &double,
        resources: &repeated_resources,
        grid_override: None,
    }];
    let read_ranges = [vyre_driver::backend::ResidentReadRange {
        resource: &output,
        byte_offset: 0,
        byte_len: 16,
    }];
    let mut readback = Vec::with_capacity(64);
    let readback_ptr = readback.as_ptr();
    let mut baseline_param_upload_bytes = None;

    for repeat_count in [1_u32, 8, 64] {
        backend.reset_telemetry();
        VyreBackend::dispatch_resident_repeated_sequence_read_ranges_into(
            &backend,
            &prefix_steps,
            &repeated_steps,
            repeat_count,
            &read_ranges,
            &mut [&mut readback],
        )
        .expect("Fix: CUDA golden fixed-graph replay must execute without expanding host orchestration.");

        assert_eq!(bytes_u32(&readback), vec![16, 18, 20, 22]);
        assert_eq!(
            readback.as_ptr(),
            readback_ptr,
            "Fix: CUDA golden fixed-graph replay must preserve caller-owned readback capacity across repeat counts."
        );
        let telemetry = backend.telemetry_snapshot();
        assert_eq!(
            telemetry.kernel_launches,
            u64::from(repeat_count) + 1,
            "Fix: CUDA golden replay should launch only prefix plus required repeated device work."
        );
        assert!(
            telemetry.sync_points > 0,
            "Fix: CUDA golden replay must keep host fences constant as repeat count grows."
        );
        assert!(
            telemetry.readback_bytes <= u64::from(repeat_count + 1) * 64,
            "Fix: CUDA golden replay fallback must keep readback bytes bounded by launched work; observed {} bytes.",
            telemetry.readback_bytes
        );
        let _baseline = baseline_param_upload_bytes.get_or_insert(telemetry.param_upload_bytes);
        assert!(
            telemetry.param_upload_bytes <= u64::from(repeat_count + 1) * 128,
            "Fix: CUDA golden replay fallback must keep parameter uploads bounded by launched work; observed {} bytes.",
            telemetry.param_upload_bytes
        );
    }

    VyreBackend::free_resident(&backend, input)
        .expect("Fix: CUDA golden replay resident input free failed.");
    VyreBackend::free_resident(&backend, tmp)
        .expect("Fix: CUDA golden replay resident tmp free failed.");
    VyreBackend::free_resident(&backend, output)
        .expect("Fix: CUDA golden replay resident output free failed.");
}

#[test]
fn repeated_resident_sequence_hoists_launch_resolution_out_of_repeat_loop() {
    let source = include_str!("../src/backend/resident_dispatch/sequence_fused.rs");
    let function_start = source
        .find("pub(crate) fn fill_upload_resident_many_repeated_sequence_read_ranges_borrowed_into")
        .expect("Fix: repeated resident sequence implementation must exist.");
    let function_body = &source[function_start..];
    let repeat_loop_start = function_body
        .find("for _ in 0..repeat_count")
        .expect("Fix: repeated resident sequence path must keep an explicit repeat loop.");
    let readback_start = function_body
        .find("let fused_readbacks = fuse_resident_readback_copies(&requested_readbacks)?")
        .expect("Fix: repeated resident sequence path must retain compact fused readback staging.");
    let _repeat_loop_body = &function_body[repeat_loop_start..readback_start];

    assert!(
        function_body.contains("struct ResolvedStep"),
        "Fix: repeated resident CUDA sequence must cache resolved launch records for unique steps before replay."
    );
    assert!(
        (function_body.contains("VYRE_CUDA_RESIDENT_BORROWED_FALLBACK")
            || function_body.contains("CUDA_RESIDENT_BORROWED_FALLBACK_ENV"))
            && (function_body.contains("VYRE_CUDA_ALLOW_BORROWED_FALLBACK")
                || function_body.contains("CUDA_ALLOW_BORROWED_FALLBACK_ENV"))
            && !function_body.contains("VYRE_CUDA_NATIVE_RESIDENT_SEQUENCE"),
        "Fix: repeated resident CUDA sequence must be native by default and keep borrowed fallback behind an explicit release escape hatch."
    );
}

#[test]
fn release_path_resident_dispatch_keeps_borrowed_fallback_counter_at_zero() {
    let backend =
        CudaBackend::acquire().expect("Fix: CUDA backend acquire failed on a GPU-required host.");
    let program = Program::wrapped(
        vec![
            BufferDecl::read("input", 0, DataType::U32).with_count(4),
            BufferDecl::output("out", 1, DataType::U32).with_count(4),
        ],
        [1, 1, 1],
        vec![Node::store(
            "out",
            Expr::gid_x(),
            Expr::mul(Expr::load("input", Expr::gid_x()), Expr::u32(2)),
        )],
    );
    let input = backend
        .allocate_resident(16)
        .expect("Fix: CUDA resident input allocation failed.");
    let output = backend
        .allocate_resident(16)
        .expect("Fix: CUDA resident output allocation failed.");
    backend
        .upload_resident(input, &u32_bytes(&[1, 2, 3, 4]))
        .expect("Fix: CUDA resident input upload failed.");

    backend.reset_telemetry();
    backend
        .dispatch_resident(&program, &[input, output], &DispatchConfig::default())
        .expect("Fix: CUDA native resident dispatch must succeed on the release path.");

    let telemetry = backend.telemetry_snapshot();
    assert_eq!(
        telemetry.resident_borrowed_fallback_dispatches, 0,
        "Fix: release-path CUDA resident dispatch must not use the host-buffer borrowed fallback unless both VYRE_CUDA_RESIDENT_BORROWED_FALLBACK and VYRE_CUDA_ALLOW_BORROWED_FALLBACK=1 are set."
    );

    backend
        .free_resident(input)
        .expect("Fix: CUDA resident input free failed.");
    backend
        .free_resident(output)
        .expect("Fix: CUDA resident output free failed.");
}

#[test]
fn optimizer_combined_upload_sequence_read_fences_once() {
    let backend =
        CudaBackend::acquire().expect("Fix: CUDA backend acquire failed on a GPU-required host.");
    let dispatcher = CudaOptimizerDispatcher::new(&backend);
    let program = Program::wrapped(
        vec![
            BufferDecl::read("input", 0, DataType::U32).with_count(4),
            BufferDecl::output("out", 1, DataType::U32).with_count(4),
        ],
        [1, 1, 1],
        vec![Node::store(
            "out",
            Expr::gid_x(),
            Expr::add(Expr::load("input", Expr::gid_x()), Expr::u32(7)),
        )],
    );
    let input = dispatcher
        .alloc_resident(16)
        .expect("Fix: optimizer combined path input allocation failed.");
    let output = dispatcher
        .alloc_resident(16)
        .expect("Fix: optimizer combined path output allocation failed.");
    let input_bytes = u32_bytes(&[1, 2, 3, 4]);
    let handle_ids = [input, output];
    let steps = [ResidentDispatchStep {
        program: &program,
        handle_ids: &handle_ids,
        grid_override: None,
    }];

    backend.reset_telemetry();
    let mut outputs = vec![Vec::with_capacity(64)];
    let outer_ptr = outputs.as_ptr();
    let first_slot_ptr = outputs[0].as_ptr();
    dispatcher
        .upload_resident_many_sequence_read_many_into(
            &[(input, input_bytes.as_slice())],
            &steps,
            &[output],
            &mut outputs,
        )
        .expect("Fix: CUDA optimizer combined upload/sequence/read path must succeed.");

    assert_eq!(bytes_u32(&outputs[0]), vec![8, 9, 10, 11]);
    assert_eq!(
        outputs.as_ptr(),
        outer_ptr,
        "Fix: combined resident into path must preserve caller-owned outer output slots."
    );
    assert_eq!(
        outputs[0].as_ptr(),
        first_slot_ptr,
        "Fix: combined resident into path must preserve caller-owned byte capacity."
    );
    let telemetry = backend.telemetry_snapshot();
    assert_eq!(
        telemetry.kernel_launches, 1,
        "Fix: combined resident path must record the queued kernel launch."
    );
    assert!(
        telemetry.sync_points > 0,
        "Fix: combined resident path must fence exactly once for upload + kernel + readback."
    );
    assert!(
        telemetry.host_to_device_bytes >= input_bytes.len() as u64,
        "Fix: combined resident path must include H2D upload telemetry."
    );
    assert_eq!(
        telemetry.readback_bytes,
        expected_readback_bytes(16, 48),
        "Fix: combined resident path must count the final resident readback bytes."
    );

    dispatcher
        .free_resident(input)
        .expect("Fix: combined path input free failed.");
    dispatcher
        .free_resident(output)
        .expect("Fix: combined path output free failed.");
}

#[test]

fn optimizer_combined_duplicate_sequence_uploads_fuse_before_kernel_launch() {
    let backend =
        CudaBackend::acquire().expect("Fix: CUDA backend acquire failed on a GPU-required host.");
    let dispatcher = CudaOptimizerDispatcher::new(&backend);
    let program = Program::wrapped(
        vec![
            BufferDecl::read("input", 0, DataType::U32).with_count(4),
            BufferDecl::output("out", 1, DataType::U32).with_count(4),
        ],
        [1, 1, 1],
        vec![Node::store(
            "out",
            Expr::gid_x(),
            Expr::add(Expr::load("input", Expr::gid_x()), Expr::u32(7)),
        )],
    );
    let input = dispatcher
        .alloc_resident(16)
        .expect("Fix: optimizer duplicate-upload input allocation failed.");
    let output = dispatcher
        .alloc_resident(16)
        .expect("Fix: optimizer duplicate-upload output allocation failed.");
    let first_input = u32_bytes(&[1, 2, 3, 4]);
    let second_input = u32_bytes(&[10, 11, 12, 13]);
    let handle_ids = [input, output];
    let steps = [ResidentDispatchStep {
        program: &program,
        handle_ids: &handle_ids,
        grid_override: None,
    }];

    backend.reset_telemetry();
    let mut outputs = vec![Vec::with_capacity(64)];
    dispatcher
        .upload_resident_many_sequence_read_many_into(
            &[
                (input, first_input.as_slice()),
                (input, second_input.as_slice()),
            ],
            &steps,
            &[output],
            &mut outputs,
        )
        .expect("Fix: CUDA optimizer duplicate upload sequence path must succeed.");

    assert_eq!(
        bytes_u32(&outputs[0]),
        vec![17, 18, 19, 20],
        "Fix: duplicate sequence uploads to the same handle must preserve later-write semantics before kernel launch."
    );
    let telemetry = backend.telemetry_snapshot();
    assert!(
        telemetry.host_upload_operations <= 2,
        "Fix: duplicate full resident sequence uploads must fuse before H2D; observed {} host upload operation(s).",
        telemetry.host_upload_operations
    );
    assert!(
        telemetry.host_to_device_bytes <= (first_input.len() + second_input.len()) as u64,
        "Fix: duplicate full resident sequence uploads must not copy both full payloads; observed {} H2D byte(s).",
        telemetry.host_to_device_bytes
    );

    dispatcher
        .free_resident(input)
        .expect("Fix: duplicate-upload path input free failed.");
    dispatcher
        .free_resident(output)
        .expect("Fix: duplicate-upload path output free failed.");
}

#[test]
fn optimizer_combined_duplicate_fills_keep_last_value_before_readback() {
    let backend =
        CudaBackend::acquire().expect("Fix: CUDA backend acquire failed on a GPU-required host.");
    let dispatcher = CudaOptimizerDispatcher::new(&backend);
    let handle = dispatcher
        .alloc_resident(16)
        .expect("Fix: optimizer duplicate-fill allocation failed.");

    backend.reset_telemetry();
    let mut outputs = vec![Vec::with_capacity(64)];
    dispatcher
        .fill_upload_resident_many_sequence_read_many_into(
            &[(handle, 16, 0x11), (handle, 16, 0xA5)],
            &[],
            &[],
            &[handle],
            &mut outputs,
        )
        .expect("Fix: CUDA optimizer duplicate fill sequence path must succeed.");

    assert_eq!(
        outputs,
        vec![vec![0xA5; 16]],
        "Fix: duplicate sequence fills to the same handle must preserve last-fill semantics."
    );
    assert_eq!(
        backend.telemetry_snapshot().host_to_device_bytes,
        0,
        "Fix: duplicate resident fills must remain device-side memset work, not H2D uploads."
    );

    dispatcher
        .free_resident(handle)
        .expect("Fix: duplicate-fill path handle free failed.");
}

#[test]
fn optimizer_combined_upload_sequence_read_ranges_compacts_d2h_bytes() {
    let backend =
        CudaBackend::acquire().expect("Fix: CUDA backend acquire failed on a GPU-required host.");
    let dispatcher = CudaOptimizerDispatcher::new(&backend);
    let program = Program::wrapped(
        vec![
            BufferDecl::read("input", 0, DataType::U32).with_count(4),
            BufferDecl::output("out", 1, DataType::U32).with_count(4),
        ],
        [1, 1, 1],
        vec![Node::store(
            "out",
            Expr::gid_x(),
            Expr::add(Expr::load("input", Expr::gid_x()), Expr::u32(7)),
        )],
    );

    let input = dispatcher
        .alloc_resident(16)
        .expect("Fix: optimizer compact-read input allocation failed.");
    let output = dispatcher
        .alloc_resident(16)
        .expect("Fix: optimizer compact-read output allocation failed.");
    let input_bytes = u32_bytes(&[1, 2, 3, 4]);
    let handle_ids = [input, output];
    let steps = [ResidentDispatchStep {
        program: &program,
        handle_ids: &handle_ids,
        grid_override: None,
    }];
    let read_ranges = [ResidentReadRange {
        handle_id: output,
        byte_offset: 4,
        byte_len: 8,
    }];

    backend.reset_telemetry();
    let mut outputs = vec![Vec::with_capacity(64)];
    let output_ptr = outputs[0].as_ptr();
    dispatcher
        .upload_resident_many_sequence_read_ranges_into(
            &[(input, input_bytes.as_slice())],
            &steps,
            &read_ranges,
            &mut outputs,
        )
        .expect("Fix: CUDA optimizer compact readback path must succeed.");

    assert_eq!(bytes_u32(&outputs[0]), vec![9, 10]);
    assert_eq!(
        outputs[0].as_ptr(),
        output_ptr,
        "Fix: compact resident readback must preserve caller-owned byte capacity."
    );
    let telemetry = backend.telemetry_snapshot();
    assert!(
        telemetry.sync_points > 0,
        "Fix: compact resident readback must keep the one-fence combined path."
    );
    assert_eq!(
        telemetry.readback_bytes,
        expected_readback_bytes(8, 40),
        "Fix: compact resident readback must transfer only requested bytes, not the full 16-byte output buffer."
    );

    dispatcher
        .free_resident(input)
        .expect("Fix: compact path input free failed.");
    dispatcher
        .free_resident(output)
        .expect("Fix: compact path output free failed.");
}

#[test]
fn cuda_backend_registration_avoids_collect_staging_at_resident_boundaries() {
    let source = include_str!("../src/lib.rs");

    assert!(
        source.contains("fn resolve_uploads")
            && source.contains("fn resolve_offset_uploads")
            && source.contains("fn resolve_download_ranges")
            && source.contains("fn resolve_read_ranges"),
        "Fix: CUDA VyreBackend resident API conversion must be centralized in single-pass helpers."
    );
    assert!(
        !source.contains("collect::<SmallVec")
            && !source.contains("resources.push((*resource).clone())")
            && !source.contains("resources.push(range.resource.clone())")
            && !source.contains("resident_handles_from_resources(std::slice::from_ref(resource))")
            && !source.contains("resident_handles_from_resources(std::slice::from_ref(&resource))"),
        "Fix: CUDA resident upload/readback boundaries must not use iterator collect or Resource-clone staging on the release path."
    );
    assert!(
        source.contains("resident_handle_from_resource(resource)?"),
        "Fix: CUDA resident upload/readback boundaries must resolve borrowed Resource handles directly instead of cloning through temporary Resource vectors."
    );
    assert!(
        !source.contains("let mut resources: Vec<Resource> = Vec::with_capacity(resource_capacity);"),
        "Fix: CUDA dispatch_with_device_buffers must dispatch directly on CUDA resident handles instead of building an intermediate Resource Vec."
    );
}

#[test]
fn cuda_resident_readback_preparation_accounts_bytes_without_rescanning_copies() {
    let source = include_str!("../src/backend/resident_io.rs");
    let fusion_source = include_str!("../../vyre-driver/src/resident_transfer_fusion.rs");
    let cuda_fusion_source = include_str!("../src/backend/resident_readback_fusion.rs");

    assert!(
        source.contains("let mut expected_copy_count = 0usize;")
            && source.contains("let mut total_copy_slots = 0usize;")
            && source.contains("download_resident_fused_copies_many_into")
            && source.contains("download_resident_fused_copy_batches_many_into")
            && fusion_source.contains("let mut non_empty_copy_count = 0usize;")
            && fusion_source.contains("let mut bytes = 0u64;"),
        "Fix: CUDA resident readback preparation must accumulate hot-path accounting through the shared fusion helper."
    );
    assert!(
        cuda_fusion_source.contains("type ResidentReadbackCopy = ResidentTransferInterval")
            && cuda_fusion_source
                .contains("type FusedResidentReadbacks = FusedResidentTransfers")
            && cuda_fusion_source.contains("fuse_resident_transfer_intervals(requested)")
            && !cuda_fusion_source.contains("let mut non_empty_copy_count = 0usize;")
            && !cuda_fusion_source.contains("sort_by_key_if_needed"),
        "Fix: CUDA resident readback fusion must remain a thin adapter over vyre-driver interval fusion."
    );
    assert!(
        !source.contains("copies.iter().filter(|copy| copy.byte_len != 0).count()")
            && !source.contains("copies\n            .iter()\n            .fold(0_u64")
            && !source.contains("copy_batches.iter().map(SmallVec::len).sum()")
            && !source.contains("copy_batches.iter().fold(0_u64"),
        "Fix: CUDA resident readback must not rescan prepared copy batches for counts or byte totals."
    );
    assert!(
        source.contains("add_resident_transfer_bytes")
            && source.contains("add_resident_copy_count")
            && source.contains("add_resident_copy_slots")
            && !source.contains(concat!(".", "saturating_add"))
            && !source.contains(concat!("total_memory", "\n            .saturating_mul")),
        "Fix: CUDA resident IO accounting and budget math must be exact/checked, not saturating."
    );
}

#[test]
fn cuda_resident_sequence_upload_accounting_is_single_pass() {
    let source = include_str!("../src/backend/resident_dispatch.rs");
    let fusion_source = include_str!("../../vyre-driver/src/resident_transfer_fusion.rs");
    let upload_fusion_source = include_str!("../src/backend/resident_upload_fusion.rs");

    assert!(
        source.contains("push_resident_upload_copy(")
            && source.contains("fuse_resident_upload_copies(upload_copies)")
            && upload_fusion_source.contains("let mut uploaded_bytes = 0u64;")
            && upload_fusion_source.contains("add_resident_upload_bytes(&mut uploaded_bytes"),
        "Fix: CUDA resident sequence upload accounting must be accumulated exactly by the shared upload fusion helper."
    );
    assert!(
        source.contains("let fused_readbacks = fuse_resident_readback_copies(&requested_readbacks)?")
            && source.contains("fused_readbacks.non_empty_copy_count")
            && source.contains(".record_device_to_host_readback(fused_readbacks.bytes)")
            && source.contains(".record_device_readback_operations(crate::numeric::usize_to_u64(")
            && fusion_source.contains("let mut non_empty_copy_count = 0usize;")
            && fusion_source.contains("add_copy_count(non_empty_copy_count")
            && fusion_source.contains("add_bytes(bytes"),
        "Fix: CUDA resident sequence readback accounting must be accumulated exactly by the shared readback fusion helper."
    );
    assert!(
        !source.contains("let uploaded_bytes = upload_copies\n                .iter()\n                .fold(0_u64")
            && !source.contains("let uploaded_bytes = uploads\n                .iter()\n                .fold(0_u64")
            && !source.contains(".filter(|copy| copy.byte_len != 0)\n                    .count()")
            && !source.contains(concat!(".", "saturating_add")),
        "Fix: CUDA resident sequence upload/readback accounting must not rescan uploads or use saturating arithmetic after execution."
    );
}

#[test]
fn cuda_resident_handle_count_uses_binding_plan_cardinality() {
    let source = include_str!("../src/backend/resident_dispatch.rs");

    assert!(
        source.contains("fn resident_required_handles")
            && source.contains(".checked_sub(prepared.bindings.shared_indices.len())"),
        "Fix: CUDA resident dispatch must derive required handle count from BindingPlan cardinalities with checked arithmetic."
    );
    let dispatch_source = include_str!("../src/backend/dispatch.rs");
    assert!(
        dispatch_source.contains(".checked_sub(static_bindings.shared_indices.len())"),
        "Fix: CUDA resident prepare must derive required handle count from BindingPlan cardinalities with checked arithmetic."
    );
    assert!(
        !source.contains(".filter(|binding| binding.role != BindingRole::Shared)\n            .count()"),
        "Fix: CUDA resident dispatch must not scan bindings just to count non-shared handles before scanning them again for launch pointers."
    );
    assert!(
        !dispatch_source.contains(".filter(|binding| binding.role != BindingRole::Shared)\n            .count()"),
        "Fix: CUDA resident prepare must not scan bindings just to count non-shared handles before scanning them again for input lengths."
    );
}

#[test]
fn cuda_resident_dispatch_does_not_allocate_for_empty_launch_params() {
    let source = include_str!("../src/backend/resident_dispatch.rs");

    assert!(
        source.matches("None if param_bytes == 0 => 0").count() >= 2,
        "Fix: CUDA resident single and batched dispatch paths must use a null parameter pointer for empty launch params instead of allocating a rounded 1-byte device buffer."
    );
    assert!(
        source.contains("usize::from(static_params_ptr.is_none() && param_bytes != 0)"),
        "Fix: CUDA resident dispatch must not reserve pinned-host transfer slots when there are no parameter bytes to upload."
    );
}

#[test]
fn cuda_host_dispatch_does_not_allocate_for_empty_launch_params() {
    let source = include_str!("../src/backend/host_dispatch.rs");

    assert!(
        source.contains("if param_bytes == 0 {\n            0\n        } else {"),
        "Fix: CUDA host dispatch must use a null parameter pointer for empty launch params instead of allocating a rounded 1-byte device buffer."
    );
    assert!(
        source.contains(".checked_add(usize::from(!prepared.launch.param_words.is_empty()))"),
        "Fix: CUDA host dispatch must not reserve pinned-host transfer slots when there are no parameter words to upload."
    );
}

#[test]
fn cuda_resident_sequence_preparation_borrows_step_config() {
    let source = include_str!("../src/backend/resident_dispatch.rs");

    assert!(
        source.contains("config: &'a DispatchConfig"),
        "Fix: CUDA resident sequence prepared steps must borrow DispatchConfig instead of cloning per unique sequence step."
    );
    assert!(
        source.contains("config: &step.config"),
        "Fix: CUDA resident sequence preparation must store borrowed step configs."
    );
    assert!(
        !source.contains("config: step.config.clone()"),
        "Fix: CUDA resident sequence preparation must not clone DispatchConfig in the hot path."
    );
}

#[test]
fn cuda_dispatch_wrappers_build_borrowed_inputs_without_iterator_collect() {
    let registration_source = include_str!("../src/lib.rs");
    let host_dispatch_source = include_str!("../src/backend/host_dispatch.rs");
    let compiled_dispatch_source = include_str!("../src/pipeline/compiled_dispatch.rs");
    let plan_source = include_str!("../src/backend/plan.rs");

    assert!(
        !registration_source.contains("inputs.iter().map(Vec::as_slice).collect()")
            && !host_dispatch_source.contains("inputs.iter().map(Vec::as_slice).collect()")
            && !compiled_dispatch_source.contains("inputs.iter().map(Vec::as_slice).collect()")
            && !registration_source.contains(concat!(".", "saturating_add")),
        "Fix: CUDA dispatch wrappers must build borrowed input slices with preallocated loops and checked resource capacity, not iterator collect staging or saturating arithmetic."
    );
    assert!(
        !compiled_dispatch_source.contains(".map(|handle| Resource::Resident(handle.id))")
            && !plan_source.contains(".map(|(_, binding_index)| binding_index)"),
        "Fix: CUDA output resource/index conversion must use preallocated loops instead of collect chains."
    );
    assert!(
        host_dispatch_source.contains("let mut upload_bytes = 0_u64;")
            && host_dispatch_source.contains("let mut upload_operations = 0_u64;")
            && host_dispatch_source.contains("add_transfer_bytes(&mut upload_bytes, input.len(), \"host upload\")?")
            && host_dispatch_source
                .contains("add_transfer_operation(&mut upload_operations, \"host upload\")?"),
        "Fix: CUDA host dispatch upload accounting must be accumulated exactly while staging uploads."
    );
    assert!(
        !host_dispatch_source.contains("host_uploads\n            .iter()\n            .fold(0_u64")
            && !host_dispatch_source.contains("host_uploads\n            .iter()\n            .filter(|upload| upload.byte_len != 0)\n            .count()"),
        "Fix: CUDA host dispatch must not rescan staged uploads for telemetry before launch."
    );
    assert!(
        host_dispatch_source.contains(".checked_add(usize_to_u64(")
            && host_dispatch_source.contains("\"host dispatch output readback device offset\"")
            && !host_dispatch_source.contains(".ptr(binding.buffer_index)\n                    .saturating_add(readback.device_offset as u64)")
            && !host_dispatch_source.contains(concat!(".", "saturating_add")),
        "Fix: CUDA host dispatch readback pointer arithmetic and capacity accounting must fail loudly on overflow instead of saturating to a wrong address or capacity."
    );
}

