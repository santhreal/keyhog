//! Resident download helpers for WGPU backend resources.

use crate::numeric::usize_to_u64;
use crate::WgpuBackend;

/// Download a complete backend-resident WGPU buffer into a new host buffer.
pub(crate) fn download_resident(
    backend: &WgpuBackend,
    resource: &vyre_driver::Resource,
) -> Result<Vec<u8>, vyre_driver::BackendError> {
    let vyre_driver::Resource::Resident(id) = resource else {
        return Err(vyre_driver::BackendError::new(
            "WGPU resident download received a borrowed resource. Fix: allocate a resident buffer before calling download_resident_into.",
        ));
    };
    let handle = backend.resident_handles.get(id).ok_or_else(|| {
        vyre_driver::BackendError::new(format!(
            "WGPU resident download received stale handle {id}. Fix: keep the resource allocated until all resident readbacks finish."
        ))
    })?;
    let allocation_len = usize::try_from(handle.allocation_len()).map_err(|source| {
        vyre_driver::BackendError::new(format!(
            "WGPU resident download allocation length cannot fit usize: {source}. Fix: split the resident readback before downloading."
        ))
    })?;
    let mut bytes = Vec::new();
    vyre_driver::allocation::try_reserve_vec_to_capacity(&mut bytes, allocation_len).map_err(|source| {
        vyre_driver::BackendError::new(format!(
            "WGPU resident download could not reserve {allocation_len} output byte(s): {source}. Fix: split the resident readback before downloading."
        ))
    })?;
    let device_queue = backend.current_device_queue();
    handle.readback_until(&device_queue.0, None, &device_queue.1, &mut bytes, None)?;
    Ok(bytes)
}

/// Download a complete backend-resident WGPU buffer into caller-owned storage.
pub(crate) fn download_resident_into(
    backend: &WgpuBackend,
    resource: &vyre_driver::Resource,
    out: &mut Vec<u8>,
) -> Result<(), vyre_driver::BackendError> {
    let vyre_driver::Resource::Resident(id) = resource else {
        return Err(vyre_driver::BackendError::new(
            "WGPU resident download received a borrowed resource. Fix: allocate a resident buffer before calling download_resident_into.",
        ));
    };
    let handle = backend.resident_handles.get(id).ok_or_else(|| {
        vyre_driver::BackendError::new(format!(
            "WGPU resident download received stale handle {id}. Fix: keep the resource allocated until all resident readbacks finish."
        ))
    })?;
    let device_queue = backend.current_device_queue();
    handle.readback_until(&device_queue.0, None, &device_queue.1, out, None)
}

/// Download one byte range from a backend-resident WGPU buffer into a new host buffer.
pub(crate) fn download_resident_range(
    backend: &WgpuBackend,
    resource: &vyre_driver::Resource,
    byte_offset: usize,
    byte_len: usize,
) -> Result<Vec<u8>, vyre_driver::BackendError> {
    let mut bytes = Vec::new();
    vyre_driver::allocation::try_reserve_vec_to_capacity(&mut bytes, byte_len).map_err(|source| {
        vyre_driver::BackendError::new(format!(
            "WGPU resident ranged download could not reserve {byte_len} output byte(s): {source}. Fix: split the resident readback range before downloading."
        ))
    })?;
    download_resident_range_into(backend, resource, byte_offset, byte_len, &mut bytes)?;
    Ok(bytes)
}

/// Download one byte range from a backend-resident WGPU buffer into caller-owned storage.
pub(crate) fn download_resident_range_into(
    backend: &WgpuBackend,
    resource: &vyre_driver::Resource,
    byte_offset: usize,
    byte_len: usize,
    out: &mut Vec<u8>,
) -> Result<(), vyre_driver::BackendError> {
    let vyre_driver::Resource::Resident(id) = resource else {
        return Err(vyre_driver::BackendError::new(
            "WGPU resident ranged download received a borrowed resource. Fix: allocate a resident buffer before calling download_resident_range_into.",
        ));
    };
    let handle = backend.resident_handles.get(id).ok_or_else(|| {
        vyre_driver::BackendError::new(format!(
            "WGPU resident ranged download received stale handle {id}. Fix: keep the resource allocated until all resident readbacks finish."
        ))
    })?;
    let byte_offset = usize_to_u64(byte_offset, "resident ranged download offset")?;
    let byte_len = usize_to_u64(byte_len, "resident ranged download length")?;
    let device_queue = backend.current_device_queue();
    handle.readback_range_until(
        &device_queue.0,
        None,
        &device_queue.1,
        byte_offset,
        byte_len,
        out,
        None,
    )
}

/// Download several validated resident byte ranges into caller-owned buffers.
pub(crate) fn download_resident_ranges_into(
    backend: &WgpuBackend,
    ranges: &[(&vyre_driver::Resource, usize, usize)],
    outputs: &mut [&mut Vec<u8>],
) -> Result<(), vyre_driver::BackendError> {
    if ranges.len() != outputs.len() {
        return Err(vyre_driver::BackendError::new(format!(
            "WGPU resident ranged batch download expected matching range/output counts but got {} range(s) and {} output(s). Fix: pass one caller-owned output Vec per readback range.",
            ranges.len(),
            outputs.len()
        )));
    }
    let mut resolved = smallvec::SmallVec::<[_; 8]>::new();
    vyre_foundation::allocation::try_reserve_smallvec_to_capacity(&mut resolved, ranges.len()).map_err(|source| {
        vyre_driver::BackendError::new(format!(
            "WGPU resident ranged batch download could not reserve {} validated readback descriptor(s): {source}. Fix: split the resident readback batch before staging.",
            ranges.len()
        ))
    })?;
    for &(resource, byte_offset, byte_len) in ranges {
        let vyre_driver::Resource::Resident(id) = resource else {
            return Err(vyre_driver::BackendError::new(
                "WGPU resident ranged batch download received a borrowed resource. Fix: allocate every resident buffer before calling download_resident_ranges_into.",
            ));
        };
        let handle = backend.resident_handles.get(id).ok_or_else(|| {
            vyre_driver::BackendError::new(format!(
                "WGPU resident ranged batch download received stale handle {id}. Fix: keep every resource allocated until all resident readbacks finish."
            ))
        })?;
        let byte_offset = usize_to_u64(byte_offset, "resident ranged batch download offset")?;
        let byte_len = usize_to_u64(byte_len, "resident ranged batch download length")?;
        let end = byte_offset.checked_add(byte_len).ok_or_else(|| {
            vyre_driver::BackendError::new(format!(
                "WGPU resident ranged batch download overflows u64 at offset {byte_offset} len {byte_len} for handle {id}. Fix: split the readback before calling download_resident_ranges_into."
            ))
        })?;
        if end > handle.allocation_len() {
            return Err(vyre_driver::BackendError::new(format!(
                "WGPU resident ranged batch download requested byte range [{byte_offset}..{end}) from allocation {} on handle {id}. Fix: clamp the readback to the resident buffer size or split the resource.",
                handle.allocation_len()
            )));
        }
        resolved.push((handle.clone(), byte_offset, byte_len));
    }
    let device_queue = backend.current_device_queue();
    for ((handle, byte_offset, byte_len), output) in resolved.into_iter().zip(outputs.iter_mut()) {
        handle.readback_range_until(
            &device_queue.0,
            None,
            &device_queue.1,
            byte_offset,
            byte_len,
            output,
            None,
        )?;
    }
    Ok(())
}
