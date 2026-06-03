//! WGPU backend resident-buffer API contracts.

use vyre_driver::{Resource, VyreBackend};
use vyre_driver_wgpu::WgpuBackend;

fn backend_impl_source() -> String {
    std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/backend_impl.rs"))
        .expect("Fix: resident-buffer contract must read WGPU backend implementation source")
}

fn resident_upload_source() -> String {
    std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/resident_upload.rs"
    ))
    .expect("Fix: resident-buffer contract must read WGPU resident upload implementation source")
}

fn resident_download_source() -> String {
    std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/resident_download.rs"
    ))
    .expect("Fix: resident-buffer contract must read WGPU resident download implementation source")
}

fn resident_resource_source() -> String {
    std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/resident_resource.rs"
    ))
    .expect("Fix: resident-buffer contract must read WGPU resident resource implementation source")
}

fn buffer_handle_source() -> String {
    std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/buffer/handle.rs"))
        .expect("Fix: resident-buffer contract must read WGPU buffer handle implementation source")
}

fn record_and_readback_source() -> String {
    std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/engine/record_and_readback/readback.rs"
    ))
    .expect("Fix: resident-buffer contract must read WGPU record-and-readback collector source")
}

fn readback_ring_source() -> String {
    std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/runtime/readback_ring.rs"
    ))
    .expect("Fix: resident-buffer contract must read WGPU readback ring source")
}

fn backend() -> WgpuBackend {
    WgpuBackend::new().expect(
        "Fix: live WGPU backend required for resident-buffer contracts; missing GPU is a configuration bug.",
    )
}

#[test]
fn wgpu_resident_lifecycle_is_module_owned() {
    let source = resident_resource_source();
    let backend_source = backend_impl_source();
    assert!(
        source.contains("pub(crate) fn allocate_resident(")
            && source.contains("pub(crate) fn free_resident("),
        "resident resource module must own allocation and free helpers"
    );
    assert!(
        source.contains("GpuBufferHandle::alloc")
            && source.contains("backend.resident_handles.insert")
            && source.contains("backend.resident_handles.remove"),
        "resident resource lifecycle must allocate, register, and remove resident handles in one module"
    );
    let allocate_forwarder = backend_source
        .split("fn allocate_resident(")
        .nth(1)
        .and_then(|tail| tail.split("fn upload_resident(").next())
        .expect("Fix: WGPU backend must expose allocate_resident before upload_resident");
    let free_forwarder = backend_source
        .split("fn free_resident(")
        .nth(1)
        .and_then(|tail| tail.split("fn dispatch_resident_timed(").next())
        .expect("Fix: WGPU backend must expose free_resident before dispatch_resident_timed");
    assert!(
        allocate_forwarder.contains("crate::resident_resource::allocate_resident")
            && free_forwarder.contains("crate::resident_resource::free_resident"),
        "backend trait implementation must delegate resident lifecycle to the resident resource module"
    );
    assert!(
        !allocate_forwarder.contains("GpuBufferHandle::alloc")
            && !free_forwarder.contains("resident_handles.remove"),
        "backend_impl.rs must not re-embed resident lifecycle internals"
    );
}

#[test]
fn wgpu_resident_batch_upload_uses_fallible_descriptor_reservation() {
    let source = resident_upload_source();
    let single_body = source
        .split("fn upload_resident(")
        .nth(1)
        .and_then(|tail| tail.split("fn upload_resident_many(").next())
        .expect(
            "Fix: WGPU resident upload module must expose upload_resident before upload_resident_many",
        );
    let batch_body = source
        .split("fn upload_resident_many(")
        .nth(1)
        .and_then(|tail| tail.split("fn upload_resident_at(").next())
        .expect("Fix: WGPU resident upload module must expose upload_resident_many before upload_resident_at");
    assert!(
        single_body.contains("upload_resident_many(backend, &[(resource, bytes)])")
            && !single_body.contains("backend.resident_handles.get")
            && !single_body.contains("crate::buffer::write_padded"),
        "single resident upload must delegate to the batch path instead of duplicating validation and staging internals"
    );
    assert!(
        batch_body.contains("try_reserve_smallvec_to_capacity(&mut resolved, uploads.len())"),
        "resident batch upload must reserve validated descriptor storage fallibly"
    );
    assert!(
        !batch_body.contains("with_capacity(uploads.len())"),
        "resident batch upload must not use infallible descriptor allocation in the hot path"
    );
}

#[test]
fn wgpu_resident_download_constructors_use_fallible_output_reservation() {
    let source = resident_download_source();
    let full_body = source
        .split("fn download_resident(")
        .nth(1)
        .and_then(|tail| tail.split("fn download_resident_into(").next())
        .expect(
            "Fix: WGPU resident download module must expose download_resident before download_resident_into",
        );
    let range_body = source
        .split("fn download_resident_range(")
        .nth(1)
        .and_then(|tail| tail.split("fn download_resident_range_into(").next())
        .expect(
            "Fix: WGPU resident download module must expose download_resident_range before download_resident_range_into",
        );
    assert!(
        full_body.contains("try_reserve_vec_to_capacity(&mut bytes, allocation_len)"),
        "full resident download must reserve output storage fallibly"
    );
    assert!(
        range_body.contains("try_reserve_vec_to_capacity(&mut bytes, byte_len)"),
        "ranged resident download must reserve output storage fallibly"
    );
    assert!(
        !full_body.contains("Vec::with_capacity(allocation_len)")
            && !range_body.contains("Vec::with_capacity(byte_len)"),
        "resident download constructors must not use infallible output allocation"
    );
}

#[test]
fn wgpu_buffer_handle_readback_reserves_before_clearing_caller_output() {
    let source = buffer_handle_source();
    let readback = source
        .split("pub(crate) fn readback_range_until(")
        .nth(1)
        .and_then(|tail| tail.split("/// Stable process-local handle id").next())
        .expect("Fix: WGPU buffer handle must expose readback_range_until before handle identity helpers.");
    let reserve_pos = readback
        .find("out.try_reserve_exact(additional)")
        .expect("Fix: WGPU buffer handle readback must reserve caller output storage fallibly.");
    let clear_pos = readback
        .find("out.clear();\n            out.extend_from_slice(visible);")
        .expect("Fix: WGPU buffer handle readback must clear and rewrite caller output after successful reservation.");

    assert!(
        reserve_pos < clear_pos,
        "Fix: shared WGPU handle readback must reserve before clearing caller output so full, ranged, resident, and pipeline readbacks stay transactional on allocation failure."
    );
}

#[test]
fn wgpu_recorded_readback_reserves_before_clearing_caller_output() {
    let source = record_and_readback_source();
    let collector = source
        .split("pub(crate) fn collect_after_submission_wait_timed(")
        .nth(1)
        .expect("Fix: WGPU record-and-readback collector must expose timed collection.");
    let reserve_pos = collector
        .find("try_reserve_vec_to_capacity(out, read_len)")
        .expect(
            "Fix: WGPU recorded readback collector must reserve caller output storage fallibly.",
        );
    let clear_pos = collector
        .find("out.clear();\n                        out.extend_from_slice(bytes);")
        .expect("Fix: WGPU recorded readback collector must clear and rewrite caller output after successful reservation.");

    assert!(
        reserve_pos < clear_pos,
        "Fix: direct WGPU recorded readback must reserve before clearing caller output so allocation failure cannot clobber existing bytes."
    );
}

#[test]
fn wgpu_readback_ring_collect_reserves_before_clearing_caller_output() {
    let source = readback_ring_source();
    let collector = source
        .split("fn copy_ready_slot_into(")
        .nth(1)
        .and_then(|tail| tail.split("#[inline]").next())
        .expect("Fix: WGPU readback ring must expose ready-slot collection before slot traversal helpers.");
    let reserve_pos = collector
        .find("out.try_reserve_exact(additional)")
        .expect("Fix: WGPU readback ring collection must reserve caller output storage fallibly.");
    let clear_pos = collector
        .find("out.clear();\n                out.extend_from_slice(bytes);")
        .expect("Fix: WGPU readback ring collection must clear and rewrite caller output after successful reservation.");

    assert!(
        reserve_pos < clear_pos,
        "Fix: WGPU readback ring collection must reserve before clearing caller output so ring-backed dispatches stay transactional on allocation failure."
    );
}

#[test]
fn wgpu_resident_batch_download_uses_shared_interval_fusion() {
    let source = resident_download_source();
    let batch_body = source
        .split("fn download_resident_ranges_into(")
        .nth(1)
        .and_then(|tail| tail.split("fn copy_fused_resident_view_into(").next())
        .expect("Fix: WGPU resident download module must expose batch download before fused output materialization.");
    assert!(
        source.contains("vyre_driver::resident_transfer_fusion")
            && batch_body.contains("fuse_resident_transfer_intervals(&copies)?")
            && batch_body.contains("reserve_fused_resident_view_outputs(&fused.copies, &fused.views, outputs)?")
            && batch_body.contains("handles.sort_unstable_by_key")
            && batch_body.contains("handles.dedup_by_key")
            && batch_body.contains("for copy in fused.copies.iter().copied()")
            && batch_body.contains("handles\n            .binary_search_by_key")
            && batch_body.contains("for (view, output) in fused.views.iter().copied().zip(outputs.iter_mut())")
            && !batch_body.contains("for ((handle, byte_offset, byte_len), output)"),
        "Fix: WGPU resident ranged batch download must share CUDA's backend-neutral interval fusion instead of issuing one readback per requested range."
    );
}

#[test]
fn wgpu_resident_fused_batch_download_preflights_outputs_before_readback() {
    let source = resident_download_source();
    let batch_body = source
        .split("fn download_resident_ranges_into(")
        .nth(1)
        .and_then(|tail| tail.split("fn reserve_fused_resident_view_outputs(").next())
        .expect("Fix: WGPU resident download module must expose batch download before fused output preflight.");
    let preflight_pos = batch_body
        .find("reserve_fused_resident_view_outputs(&fused.copies, &fused.views, outputs)?")
        .expect("Fix: WGPU fused resident batch download must preflight caller output slots.");
    let device_queue_pos = batch_body
        .find("let device_queue = backend.current_device_queue();")
        .expect("Fix: WGPU fused resident batch download must stage device readbacks.");
    let materialize_pos = batch_body
        .find("copy_fused_resident_view_into(&fused_outputs, view, output)?")
        .expect("Fix: WGPU fused resident batch download must materialize every fused view.");

    assert!(
        preflight_pos < device_queue_pos && preflight_pos < materialize_pos,
        "Fix: WGPU fused resident batch download must validate fused views and reserve every caller output before any GPU readback or output mutation."
    );

    let preflight = source
        .split("fn reserve_fused_resident_view_outputs(")
        .nth(1)
        .and_then(|tail| tail.split("fn validate_resident_readback_range(").next())
        .expect("Fix: WGPU resident download module must expose fused output preflight before range validation.");
    assert!(
        preflight.contains("views.len() != outputs.len()")
            && preflight.contains("copies.get(view.copy_slot)")
            && preflight.contains("view.byte_offset.checked_add(view.byte_len)")
            && preflight.contains("view_end > copy.byte_len")
            && preflight.contains("try_reserve_vec_to_capacity(*output, view.byte_len)"),
        "Fix: WGPU fused resident output preflight must reject cardinality/view drift and reserve all caller output bytes before materialization."
    );
}

#[test]
fn wgpu_resident_single_ranged_download_validates_bounds_before_readback() {
    let source = resident_download_source();
    let single_body = source
        .split("fn download_resident_range_into(")
        .nth(1)
        .and_then(|tail| tail.split("/// Download several validated resident byte ranges").next())
        .expect("Fix: WGPU resident download module must expose single ranged download before batch ranged download.");
    let validator = source
        .split("fn validate_resident_readback_range(")
        .nth(1)
        .and_then(|tail| tail.split("fn copy_fused_resident_view_into(").next())
        .expect("Fix: WGPU resident download module must expose a shared resident readback range validator.");

    assert!(
        single_body.contains("validate_resident_readback_range(")
            && validator.contains("byte_offset.checked_add(byte_len)")
            && validator.contains("end > allocation_len")
            && validator.contains("requested byte range [{byte_offset}..{end})"),
        "Fix: single WGPU resident ranged download must share the batch path's checked offset/length validation before readback."
    );
}

#[test]
fn wgpu_resident_fused_batch_materialization_reserves_before_clearing_output() {
    let source = resident_download_source();
    let copier = source
        .split("fn copy_fused_resident_view_into(")
        .nth(1)
        .expect("Fix: WGPU resident download module must expose fused output materialization.");
    let reserve_pos = copier
        .find("try_reserve_exact(bytes.len() - output.capacity())")
        .expect("Fix: WGPU fused resident output materialization must reserve caller output storage fallibly.");
    let clear_pos = copier
        .find("output.clear();\n    output.extend_from_slice(bytes);")
        .expect("Fix: WGPU fused resident output materialization must clear and rewrite caller output after successful reservation.");

    assert!(
        reserve_pos < clear_pos,
        "Fix: WGPU fused resident output materialization must reserve before clearing caller-owned output so allocation failure cannot clobber existing bytes."
    );
}

#[test]
fn wgpu_backend_allocates_uploads_batches_and_frees_resident_buffers() {
    let backend = backend();
    let first = backend
        .allocate_resident(16)
        .expect("WGPU backend must allocate resident buffers");
    let second = backend
        .allocate_resident(16)
        .expect("WGPU backend must allocate a second resident buffer");

    backend
        .upload_resident_many(&[(&first, &[1, 2, 3, 4]), (&second, &[5, 6, 7, 8])])
        .expect(
            "WGPU backend must batch resident uploads without falling back to unsupported defaults",
        );

    let mut first_readback = Vec::with_capacity(64);
    backend
        .download_resident_range_into(&first, 1, 3, &mut first_readback)
        .expect("WGPU backend must ranged-download resident buffers into caller-owned scratch");
    assert_eq!(first_readback, vec![2, 3, 4]);
    assert!(
        first_readback.capacity() >= 64,
        "resident ranged download must preserve caller scratch capacity"
    );

    let second_readback = backend
        .download_resident(&second)
        .expect("WGPU backend must download complete resident buffers");
    assert_eq!(
        &second_readback[..8],
        &[5, 6, 7, 8, 0, 0, 0, 0],
        "full resident readback must return uploaded prefix and padded zero fill"
    );

    backend
        .free_resident(first)
        .expect("WGPU backend must free first resident buffer");
    backend
        .free_resident(second)
        .expect("WGPU backend must free second resident buffer");
}

#[test]
fn wgpu_backend_ranged_upload_updates_only_requested_resident_bytes() {
    let backend = backend();
    let resource = backend
        .allocate_resident(16)
        .expect("WGPU backend must allocate resident buffers");
    backend
        .upload_resident(&resource, &[0x10; 16])
        .expect("initial full resident upload must succeed");

    backend
        .upload_resident_at(&resource, 4, &[1, 2, 3, 4, 5, 6, 7, 8])
        .expect("WGPU backend must support aligned ranged resident uploads");

    let bytes = backend
        .download_resident(&resource)
        .expect("resident buffer must download after ranged upload");
    assert_eq!(
        &bytes[..16],
        &[0x10, 0x10, 0x10, 0x10, 1, 2, 3, 4, 5, 6, 7, 8, 0x10, 0x10, 0x10, 0x10],
        "ranged resident upload must mutate only the requested byte range"
    );

    backend
        .free_resident(resource)
        .expect("ranged-upload resident buffer must free cleanly");
}

#[test]
fn wgpu_backend_invalid_single_range_download_preserves_caller_output() {
    let backend = backend();
    let resource = backend
        .allocate_resident(4)
        .expect("WGPU backend must allocate resident buffer");
    backend
        .upload_resident(&resource, &[1, 2, 3, 4])
        .expect("initial resident upload must succeed");

    let mut output = Vec::with_capacity(32);
    output.extend_from_slice(&[9, 9, 9]);
    let capacity = output.capacity();
    let error = backend
        .download_resident_range_into(&resource, 3, 2, &mut output)
        .expect_err("invalid single resident range download must reject before readback");

    assert!(
        error.to_string().contains("byte range [3..5)"),
        "invalid single range error must describe the requested byte range, got: {error}"
    );
    assert_eq!(
        output,
        vec![9, 9, 9],
        "invalid single range download must not clobber caller-owned output"
    );
    assert_eq!(output.capacity(), capacity);

    backend
        .free_resident(resource)
        .expect("resident buffer must free cleanly after rejected range download");
}

#[test]
fn wgpu_backend_ranged_batch_upload_updates_multiple_resources() {
    let backend = backend();
    let first = backend
        .allocate_resident(16)
        .expect("WGPU backend must allocate first resident buffer");
    let second = backend
        .allocate_resident(16)
        .expect("WGPU backend must allocate second resident buffer");
    backend
        .upload_resident_many(&[(&first, &[0x10; 16]), (&second, &[0x20; 16])])
        .expect("initial resident uploads must succeed");

    backend
        .upload_resident_at_many(&[(&first, 4, &[1, 2, 3, 4]), (&second, 8, &[5, 6, 7, 8])])
        .expect("WGPU backend must support successful ranged batch resident uploads");

    let first_bytes = backend
        .download_resident(&first)
        .expect("first resident buffer must download after ranged batch upload");
    let second_bytes = backend
        .download_resident(&second)
        .expect("second resident buffer must download after ranged batch upload");
    assert_eq!(
        &first_bytes[..16],
        &[0x10, 0x10, 0x10, 0x10, 1, 2, 3, 4, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10],
        "ranged batch upload must update only the first resource range"
    );
    assert_eq!(
        &second_bytes[..16],
        &[0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 5, 6, 7, 8, 0x20, 0x20, 0x20, 0x20],
        "ranged batch upload must update only the second resource range"
    );

    backend
        .free_resident(first)
        .expect("first resident buffer must free cleanly");
    backend
        .free_resident(second)
        .expect("second resident buffer must free cleanly");
}

#[test]
fn wgpu_backend_ranged_batch_download_reads_multiple_resources() {
    let backend = backend();
    let first = backend
        .allocate_resident(16)
        .expect("WGPU backend must allocate first resident buffer");
    let second = backend
        .allocate_resident(16)
        .expect("WGPU backend must allocate second resident buffer");
    backend
        .upload_resident_many(&[
            (&first, &[0, 1, 2, 3, 4, 5, 6, 7]),
            (&second, &[8, 9, 10, 11, 12, 13, 14, 15]),
        ])
        .expect("initial resident uploads must succeed");

    let mut first_out = Vec::with_capacity(64);
    let mut second_out = Vec::with_capacity(64);
    backend
        .download_resident_ranges_into(
            &[(&first, 2, 4), (&second, 4, 4)],
            &mut [&mut first_out, &mut second_out],
        )
        .expect("WGPU backend must support ranged batch resident downloads");
    assert_eq!(first_out, vec![2, 3, 4, 5]);
    assert_eq!(second_out, vec![12, 13, 14, 15]);
    assert!(
        first_out.capacity() >= 64 && second_out.capacity() >= 64,
        "resident ranged batch download must preserve caller scratch capacity"
    );

    backend
        .free_resident(first)
        .expect("first resident buffer must free cleanly");
    backend
        .free_resident(second)
        .expect("second resident buffer must free cleanly");
}

#[test]
fn wgpu_backend_ranged_batch_download_fuses_overlapping_same_handle_ranges() {
    let backend = backend();
    let resident = backend
        .allocate_resident(16)
        .expect("WGPU backend must allocate resident buffer for fused range readback");
    backend
        .upload_resident(&resident, &[0, 1, 2, 3, 4, 5, 6, 7])
        .expect("initial resident upload must succeed");

    let mut first_out = Vec::with_capacity(64);
    let mut second_out = Vec::with_capacity(64);
    let mut empty_out = vec![0xaa];
    backend
        .download_resident_ranges_into(
            &[(&resident, 0, 4), (&resident, 2, 4), (&resident, 6, 0)],
            &mut [&mut first_out, &mut second_out, &mut empty_out],
        )
        .expect("WGPU backend must fuse overlapping resident range readbacks without changing caller outputs");

    assert_eq!(first_out, vec![0, 1, 2, 3]);
    assert_eq!(second_out, vec![2, 3, 4, 5]);
    assert!(
        empty_out.is_empty(),
        "zero-byte fused resident views must clear the caller output slot"
    );
    assert!(
        first_out.capacity() >= 64 && second_out.capacity() >= 64,
        "fused resident ranged batch download must preserve caller scratch capacity"
    );

    backend
        .free_resident(resident)
        .expect("fused resident readback buffer must free cleanly");
}

#[test]
fn wgpu_backend_rejects_stale_and_borrowed_resident_handles() {
    let backend = backend();
    let resident = backend
        .allocate_resident(4)
        .expect("WGPU backend must allocate resident buffers");
    let stale = resident.clone();
    backend
        .free_resident(resident)
        .expect("first resident free must succeed");
    let err = backend
        .upload_resident(&stale, &[1, 2, 3, 4])
        .expect_err("stale resident upload must fail loudly");
    assert!(
        err.to_string().contains("stale handle"),
        "stale upload error must explain stale resident handles, got: {err}"
    );

    let borrowed = Resource::Borrowed(vec![0; 4]);
    let err = backend
        .free_resident(borrowed)
        .expect_err("borrowed resource free must fail loudly");
    assert!(
        err.to_string().contains("borrowed resource"),
        "borrowed free error must explain resource kind, got: {err}"
    );

    let borrowed = Resource::Borrowed(vec![0; 4]);
    let err = backend
        .upload_resident_at(&borrowed, 0, &[1, 2, 3, 4])
        .expect_err("borrowed ranged upload must fail loudly");
    assert!(
        err.to_string().contains("borrowed resource"),
        "borrowed ranged upload error must explain resource kind, got: {err}"
    );

    let err = backend
        .upload_resident_at(&stale, 0, &[1, 2, 3, 4])
        .expect_err("stale ranged upload must fail loudly");
    assert!(
        err.to_string().contains("stale handle"),
        "stale ranged upload error must explain stale resident handles, got: {err}"
    );
}

#[test]
fn wgpu_backend_batch_upload_validates_before_any_write() {
    let backend = backend();
    let first = backend
        .allocate_resident(4)
        .expect("WGPU backend must allocate first resident buffer");
    let second = backend
        .allocate_resident(4)
        .expect("WGPU backend must allocate second resident buffer");
    backend
        .upload_resident_many(&[(&first, &[9]), (&second, &[8])])
        .expect("initial resident uploads must succeed");

    let oversized = [0u8; 8];
    let err = backend
        .upload_resident_many(&[(&first, &[1, 2, 3, 4]), (&second, &oversized)])
        .expect_err("invalid second upload must reject the entire batch");
    assert!(
        err.to_string().contains("batch upload"),
        "batch upload error must name the failing operation, got: {err}"
    );

    let mut first_readback = Vec::new();
    backend
        .download_resident_range_into(&first, 0, 4, &mut first_readback)
        .expect("first resident readback must succeed after rejected batch");
    assert_eq!(
        first_readback,
        vec![9, 0, 0, 0],
        "batch upload must not partially update earlier resources when a later upload is invalid"
    );

    backend
        .free_resident(first)
        .expect("first resident buffer must free cleanly");
    backend
        .free_resident(second)
        .expect("second resident buffer must free cleanly");
}

#[test]
fn wgpu_backend_ranged_batch_upload_validates_before_any_write() {
    let backend = backend();
    let first = backend
        .allocate_resident(16)
        .expect("WGPU backend must allocate first resident buffer");
    let second = backend
        .allocate_resident(16)
        .expect("WGPU backend must allocate second resident buffer");
    backend
        .upload_resident_many(&[(&first, &[9; 16]), (&second, &[8; 16])])
        .expect("initial resident uploads must succeed");

    let err = backend
        .upload_resident_at_many(&[
            (&first, 4, &[1, 2, 3, 4]),
            (&second, 12, &[5, 6, 7, 8, 9, 10, 11, 12]),
        ])
        .expect_err("invalid second ranged upload must reject the entire batch");
    assert!(
        err.to_string().contains("ranged batch upload"),
        "ranged batch upload error must name the failing operation, got: {err}"
    );

    let mut first_readback = Vec::new();
    backend
        .download_resident_range_into(&first, 0, 16, &mut first_readback)
        .expect("first resident readback must succeed after rejected ranged batch");
    assert_eq!(
        first_readback,
        vec![9; 16],
        "ranged batch upload must not partially update earlier resources when a later range is invalid"
    );

    backend
        .free_resident(first)
        .expect("first resident buffer must free cleanly");
    backend
        .free_resident(second)
        .expect("second resident buffer must free cleanly");
}

#[test]
fn wgpu_backend_ranged_batch_alignment_error_writes_nothing() {
    let backend = backend();
    let first = backend
        .allocate_resident(16)
        .expect("WGPU backend must allocate first resident buffer");
    let second = backend
        .allocate_resident(16)
        .expect("WGPU backend must allocate second resident buffer");
    backend
        .upload_resident_many(&[(&first, &[3; 16]), (&second, &[4; 16])])
        .expect("initial resident uploads must succeed");

    let err = backend
        .upload_resident_at_many(&[(&first, 4, &[9, 9, 9, 9]), (&second, 2, &[1, 2, 3, 4])])
        .expect_err("unaligned ranged upload must reject the entire batch");
    assert!(
        err.to_string().contains("aligned"),
        "alignment failure must explain the WGPU copy alignment contract, got: {err}"
    );

    let first_bytes = backend
        .download_resident(&first)
        .expect("first resident buffer must download after rejected alignment batch");
    let second_bytes = backend
        .download_resident(&second)
        .expect("second resident buffer must download after rejected alignment batch");
    assert_eq!(
        &first_bytes[..16],
        &[3; 16],
        "alignment rejection must not partially update the already-valid first range"
    );
    assert_eq!(
        &second_bytes[..16],
        &[4; 16],
        "alignment rejection must not update the invalid second range"
    );

    backend
        .free_resident(first)
        .expect("first resident buffer must free cleanly");
    backend
        .free_resident(second)
        .expect("second resident buffer must free cleanly");
}

#[test]

fn wgpu_backend_ranged_batch_download_validates_before_any_readback() {
    let backend = backend();
    let first = backend
        .allocate_resident(16)
        .expect("WGPU backend must allocate first resident buffer");
    let second = backend
        .allocate_resident(16)
        .expect("WGPU backend must allocate second resident buffer");
    backend
        .upload_resident_many(&[(&first, &[1; 16]), (&second, &[2; 16])])
        .expect("initial resident uploads must succeed");

    let mut first_out = vec![0xaa];
    let mut second_out = vec![0xbb];
    let err = backend
        .download_resident_ranges_into(
            &[(&first, 0, 4), (&second, 12, 8)],
            &mut [&mut first_out, &mut second_out],
        )
        .expect_err("invalid second ranged download must reject the entire batch");
    assert!(
        err.to_string().contains("ranged batch download"),
        "ranged batch download error must name the failing operation, got: {err}"
    );
    assert_eq!(
        first_out,
        vec![0xaa],
        "ranged batch download must not mutate an earlier output before a later range fails validation"
    );
    assert_eq!(
        second_out,
        vec![0xbb],
        "ranged batch download must not mutate the invalid output"
    );

    backend
        .free_resident(first)
        .expect("first resident buffer must free cleanly");
    backend
        .free_resident(second)
        .expect("second resident buffer must free cleanly");
}
