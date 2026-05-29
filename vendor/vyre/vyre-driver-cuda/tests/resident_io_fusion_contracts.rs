//! Contracts for CUDA resident readback fusion plumbing.

#[test]
fn compiled_resident_single_readbacks_use_fused_copy_path() {
    let source = include_str!("../src/backend/resident_io.rs");
    let method = source
        .split("pub(crate) fn download_resident_readbacks_many_into")
        .nth(1)
        .and_then(|tail| tail.split("fn download_resident_copies_many_into").next())
        .expect("Fix: resident_io.rs must expose download_resident_readbacks_many_into before the copy helpers.");

    assert!(
        method.contains("self.download_resident_fused_copies_many_into(&copies, outputs)")
            && !method.contains("self.download_resident_copies_many_into("),
        "Fix: compiled resident readbacks must use fused D2H copies instead of one transfer per requested output range."
    );
}

#[test]
fn compiled_resident_batch_readbacks_use_fused_copy_path() {
    let source = include_str!("../src/backend/resident_io.rs");
    let method = source
        .split("pub(crate) fn download_resident_readback_batches_many_into")
        .nth(1)
        .and_then(|tail| tail.split("pub fn free_resident").next())
        .expect("Fix: resident_io.rs must expose download_resident_readback_batches_many_into before free_resident.");

    assert!(
        method.contains("self.download_resident_fused_copy_batches_many_into(")
            && !method.contains("host_transfers.collect_output_into(transfer_index, output)"),
        "Fix: resident batch readbacks must flatten and fuse D2H copies before slicing outputs back into batch slots."
    );
}

#[test]
fn resident_readback_fusion_is_scoped_by_handle_identity() {
    let cuda_source = include_str!("../src/backend/resident_readback_fusion.rs");
    let driver_source = include_str!("../../vyre-driver/src/resident_transfer_fusion.rs");
    let helper = cuda_source
        .split("fn fuse_resident_readback_copies")
        .nth(1)
        .expect("Fix: resident_readback_fusion.rs must expose fuse_resident_readback_copies.");

    assert!(
        helper.contains("fuse_resident_transfer_intervals(requested)")
            && cuda_source.contains("type ResidentReadbackCopy = ResidentTransferInterval")
            && driver_source.contains("iter_is_monotonic_by_key(")
            && driver_source.contains(
                "sort_by_key_if_needed(&mut ordered, |(_, copy)| (copy.handle_id, copy.src))"
            )
            && driver_source.contains("last.handle_id == copy.handle_id && copy.src <= last_end"),
        "Fix: resident readback fusion must delegate to the backend-neutral interval helper and merge only overlapping/adjacent ranges from the same resident handle."
    );
}

#[test]
fn resident_sequence_readbacks_share_the_common_fusion_helper() {
    let source = include_str!("../src/backend/resident_dispatch.rs");
    let method = source
        .split("pub(crate) fn fill_upload_resident_many_repeated_sequence_read_ranges_borrowed_into")
        .nth(1)
        .and_then(|tail| tail.split("pub fn dispatch_resident_timed").next())
        .expect("Fix: resident_dispatch.rs must expose fill_upload_resident_many_repeated_sequence_read_ranges_borrowed_into before dispatch_resident_timed.");

    assert!(
        method.contains("fuse_resident_readback_copies(&requested_readbacks)")
            && !method.contains("readback_order.sort_unstable_by_key")
            && !method.contains("struct ReadbackOutputView"),
        "Fix: resident sequence readbacks must reuse the shared fusion helper instead of carrying a nested duplicate interval-merger."
    );
}
