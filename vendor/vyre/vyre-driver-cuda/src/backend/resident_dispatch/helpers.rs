use std::ffi::c_void;
use std::sync::Arc;

use rustc_hash::{FxHashMap, FxHashSet};
use smallvec::SmallVec;
use vyre_driver::{BackendError, DispatchConfig};
use vyre_foundation::ir::Program;

use crate::backend::allocations::HostTransferAllocations;
use crate::backend::plan::CudaDispatchPlan;
use crate::backend::resident::{CudaResidentBuffer, ResidentViewCache};
use crate::backend::resident_upload_fusion::{
    fuse_resident_upload_copies, push_resident_upload_copy, ResidentUploadCopy,
};
use crate::backend::staging_reserve::{
    reserve_hash_set, reserve_smallvec, reserve_vec, resize_vec_slots,
};

pub(crate) fn resident_required_handles(prepared: &CudaDispatchPlan) -> Result<usize, BackendError> {
    prepared
        .bindings
        .bindings
        .len()
        .checked_sub(prepared.bindings.shared_indices.len())
        .ok_or_else(|| BackendError::InvalidProgram {
            fix: format!(
                "Fix: CUDA resident binding plan has {} binding(s) but {} shared binding index(es). Rebuild the dispatch plan before launching.",
                prepared.bindings.bindings.len(),
                prepared.bindings.shared_indices.len()
            ),
        })
}

pub(crate) fn stage_resident_fill_payload(
    payload: &mut Vec<u8>,
    value: u8,
    byte_len: usize,
) -> Result<&[u8], BackendError> {
    reserve_vec(payload, byte_len, "resident fallback fill byte")?;
    payload.clear();
    payload.resize(byte_len, value);
    Ok(payload.as_slice())
}

pub(crate) fn enqueue_resident_h2d_copy(
    dst_ptr: u64,
    host_ptr: *const c_void,
    byte_len: usize,
    stream_raw: cudarc::driver::sys::CUstream,
) -> Result<(), BackendError> {
    // SAFETY: The caller owns the stream ordering and guarantees that the
    // pinned host allocation and resident destination remain live until the
    // stream reaches this copy. The shared copy helper validates null pointers
    // for non-empty copies and treats zero-byte copies as no-ops.
    unsafe { crate::backend::copy::h2d_async_checked(dst_ptr, host_ptr, byte_len, stream_raw) }
}

pub(crate) fn enqueue_optional_resident_h2d_copy(
    upload: Option<(u64, *const c_void, usize)>,
    stream_raw: cudarc::driver::sys::CUstream,
) -> Result<(), BackendError> {
    if let Some((dst_ptr, host_ptr, byte_len)) = upload {
        enqueue_resident_h2d_copy(dst_ptr, host_ptr, byte_len, stream_raw)?;
    }
    Ok(())
}

pub(crate) fn enqueue_resident_upload_copies_on_stream(
    copies: &[ResidentUploadCopy<'_>],
    host_transfers: &mut HostTransferAllocations,
    stream_raw: cudarc::driver::sys::CUstream,
) -> Result<(), BackendError> {
    for copy in copies {
        let bytes = copy.bytes.as_slice();
        let host_ptr = host_transfers.push_upload(bytes)?;
        enqueue_resident_h2d_copy(copy.dst_ptr, host_ptr, bytes.len(), stream_raw)?;
    }
    Ok(())
}

pub(crate) fn borrow_resident_sequence_output_slots(
    outputs: &mut Vec<Vec<u8>>,
    slot_count: usize,
) -> Result<SmallVec<[&mut Vec<u8>; 8]>, BackendError> {
    resize_vec_slots(outputs, slot_count, "resident sequence output slots")?;
    let mut borrowed_outputs = SmallVec::<[&mut Vec<u8>; 8]>::new();
    reserve_smallvec(
        &mut borrowed_outputs,
        outputs.len(),
        "resident sequence borrowed output slots",
    )?;
    borrowed_outputs.extend(outputs.iter_mut());
    Ok(borrowed_outputs)
}

pub(crate) fn prepare_resident_sequence_fills(
    fills: &[(CudaResidentBuffer, u8)],
    uploads: &[(CudaResidentBuffer, &[u8])],
) -> Result<SmallVec<[(CudaResidentBuffer, u8); 8]>, BackendError> {
    let mut uploaded_handles = FxHashSet::<CudaResidentBuffer>::default();
    if !uploads.is_empty() {
        reserve_hash_set(
            &mut uploaded_handles,
            uploads.len(),
            "resident sequence upload handle set",
        )?;
        uploaded_handles.extend(uploads.iter().map(|&(handle, _)| handle));
    }

    let mut effective = SmallVec::<[(CudaResidentBuffer, u8); 8]>::new();
    reserve_smallvec(
        &mut effective,
        fills.len(),
        "resident sequence effective fills",
    )?;

    let mut effective_indices = FxHashMap::<CudaResidentBuffer, usize>::default();
    effective_indices
        .try_reserve(fills.len())
        .map_err(|error| BackendError::InvalidProgram {
            fix: format!(
                "Fix: CUDA resident sequence fill index could not reserve {} handle slot(s): {error}.",
                fills.len()
            ),
        })?;

    for &(handle, value) in fills {
        if !uploaded_handles.is_empty() && uploaded_handles.contains(&handle) {
            continue;
        }
        if let Some(&index) = effective_indices.get(&handle) {
            effective[index].1 = value;
            continue;
        }
        effective_indices.insert(handle, effective.len());
        effective.push((handle, value));
    }

    Ok(effective)
}

pub(crate) struct PreparedStep<'a> {
    pub(crate) program: &'a Program,
    pub(crate) handles: SmallVec<[CudaResidentBuffer; 8]>,
    pub(crate) config: &'a DispatchConfig,
    pub(crate) ptx_src: Arc<str>,
    pub(crate) module_key: crate::backend::module_cache::ModuleCacheKey,
    pub(crate) prepared: CudaDispatchPlan,
}
