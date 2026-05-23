//! Host and device copies for CUDA-resident buffers.

use vyre_driver::{BackendError, OutputBuffers};

use super::allocations::{cuda_check, HostTransferAllocations};
use super::dispatch::CudaBackend;
use super::output_range::CudaOutputReadback;
use super::resident::CudaResidentBuffer;
use super::staging_reserve::{clear_vec_slots, reserve_smallvec, reserved_vec, resize_vec_slots};
use crate::numeric::usize_to_u64;
use smallvec::SmallVec;

const CUDA_RESIDENT_BUDGET_NUMERATOR: u64 = 9;
const CUDA_RESIDENT_BUDGET_DENOMINATOR: u64 = 10;

#[derive(Clone, Copy)]
struct ResidentReadbackCopy {
    src: u64,
    byte_len: usize,
}

impl CudaBackend {
    fn with_resident_stream<T>(
        &self,
        operation: impl FnOnce(&crate::stream::CudaStream) -> Result<T, BackendError>,
    ) -> Result<T, BackendError> {
        let stream = self.launch_resources.acquire_stream()?;
        let result = operation(&stream);
        self.launch_resources.release_stream(stream);
        result
    }
}

fn add_resident_transfer_bytes(
    total: &mut u64,
    bytes: usize,
    label: &str,
) -> Result<(), BackendError> {
    let bytes = u64::try_from(bytes).map_err(|_| BackendError::InvalidProgram {
        fix: format!(
            "Fix: CUDA resident {label} byte count exceeds u64; split the transfer into bounded chunks."
        ),
    })?;
    *total = total
        .checked_add(bytes)
        .ok_or_else(|| BackendError::InvalidProgram {
            fix: format!(
                "Fix: CUDA resident {label} byte accounting overflowed u64; split the transfer into bounded chunks."
            ),
        })?;
    Ok(())
}

fn add_resident_copy_count(total: &mut usize, label: &str) -> Result<(), BackendError> {
    *total = total
        .checked_add(1)
        .ok_or_else(|| BackendError::InvalidProgram {
            fix: format!(
                "Fix: CUDA resident {label} copy counting overflowed usize; split the transfer into bounded chunks."
            ),
        })?;
    Ok(())
}

fn add_resident_copy_slots(
    total: &mut usize,
    slots: usize,
    label: &str,
) -> Result<(), BackendError> {
    *total = total
        .checked_add(slots)
        .ok_or_else(|| BackendError::InvalidProgram {
            fix: format!(
                "Fix: CUDA resident {label} copy-slot accounting overflowed usize; split the transfer into bounded chunks."
            ),
        })?;
    Ok(())
}

fn clear_resident_copy_outputs(
    copies: &[ResidentReadbackCopy],
    outputs: &mut OutputBuffers,
) -> Result<(), BackendError> {
    resize_vec_slots(outputs, copies.len(), "readback output")?;
    clear_vec_slots(outputs);
    Ok(())
}

impl CudaBackend {
    /// Allocate a CUDA-resident buffer owned by this backend.
    pub fn allocate_resident(&self, byte_len: usize) -> Result<CudaResidentBuffer, BackendError> {
        if byte_len == 0 {
            return Err(BackendError::InvalidProgram {
                fix: "Fix: CUDA resident buffers must have a non-zero byte length.".to_string(),
            });
        }
        self.warmup()?;
        let handle = self
            .resident_store
            .allocate(byte_len, self.cuda_resident_budget_bytes())?;
        self.telemetry
            .record_resident_allocation_bytes(usize_to_u64(
                byte_len,
                "resident allocation byte count",
            )?);
        Ok(handle)
    }

    /// Upload bytes into an existing CUDA-resident buffer.
    pub fn upload_resident(
        &self,
        handle: CudaResidentBuffer,
        bytes: &[u8],
    ) -> Result<(), BackendError> {
        self.upload_resident_many(&[(handle, bytes)])
    }

    /// Upload several full CUDA-resident buffers with one stream synchronization.
    pub fn upload_resident_many(
        &self,
        uploads: &[(CudaResidentBuffer, &[u8])],
    ) -> Result<(), BackendError> {
        if uploads.is_empty() {
            return Ok(());
        }
        let mut copies = SmallVec::<[(u64, &[u8]); 8]>::new();
        reserve_smallvec(&mut copies, uploads.len(), "upload copy")?;
        let mut uploaded_bytes = 0_u64;
        for &(handle, bytes) in uploads {
            let buffer = self.resident_store.view(handle)?;
            if bytes.len() != buffer.byte_len {
                return Err(BackendError::InvalidProgram {
                    fix: format!(
                        "Fix: CUDA resident upload for handle {} expected {} bytes but received {}.",
                        handle.id,
                        buffer.byte_len,
                        bytes.len()
                    ),
                });
            }
            if !bytes.is_empty() {
                copies.push((buffer.ptr, bytes));
                add_resident_transfer_bytes(&mut uploaded_bytes, bytes.len(), "upload")?;
            }
        }
        if copies.is_empty() {
            return Ok(());
        }
        self.warmup()?;
        let mut host_transfers = HostTransferAllocations::with_capacity(
            std::sync::Arc::clone(&self.host_pool),
            copies.len(),
            0,
        )?;
        self.with_resident_stream(|stream| {
            for &(dst_ptr, bytes) in &copies {
                let host_ptr = host_transfers.push_upload(bytes)?;
                // SAFETY: FFI to libcuda.so. Pointer args were validated by the
                // matching alloc / store API; lifetimes are documented in the
                // surrounding function. cuda_check (or matching CUresult guard)
                // propagates non-success codes as BackendError.
                unsafe {
                    cuda_check(
                        cudarc::driver::sys::cuMemcpyHtoDAsync_v2(
                            dst_ptr,
                            host_ptr,
                            bytes.len(),
                            stream.raw(),
                        ),
                        "cuMemcpyHtoDAsync_v2",
                    )?;
                }
            }
            stream.synchronize()
        })?;
        self.telemetry.record_sync_point();
        self.telemetry.record_host_to_device_bytes(uploaded_bytes);
        self.telemetry.record_host_upload_operations(usize_to_u64(
            copies.len(),
            "resident upload operation count",
        )?);
        drop(host_transfers);
        Ok(())
    }

    /// Download bytes from an existing CUDA-resident buffer.
    pub fn download_resident(&self, handle: CudaResidentBuffer) -> Result<Vec<u8>, BackendError> {
        let byte_len = self.resident_store.view(handle)?.byte_len;
        let mut bytes = reserved_vec(byte_len, "resident download output bytes")?;
        self.download_resident_into(handle, &mut bytes)?;
        Ok(bytes)
    }

    /// Download several full CUDA-resident buffers with one stream fence.
    pub fn download_resident_many(
        &self,
        handles: &[CudaResidentBuffer],
    ) -> Result<Vec<Vec<u8>>, BackendError> {
        let mut outputs = reserved_vec(handles.len(), "resident output")?;
        self.download_resident_many_into(handles, &mut outputs)?;
        Ok(outputs)
    }

    /// Download several full CUDA-resident buffers into caller-owned output
    /// slots with one stream fence.
    pub fn download_resident_many_into(
        &self,
        handles: &[CudaResidentBuffer],
        outputs: &mut OutputBuffers,
    ) -> Result<(), BackendError> {
        let mut copies = SmallVec::<[ResidentReadbackCopy; 8]>::new();
        reserve_smallvec(&mut copies, handles.len(), "full readback copy")?;
        let mut expected_copy_count = 0usize;
        let mut readback_bytes = 0_u64;
        for &handle in handles {
            let buffer = self.resident_store.view(handle)?;
            copies.push(ResidentReadbackCopy {
                src: if buffer.byte_len == 0 { 0 } else { buffer.ptr },
                byte_len: buffer.byte_len,
            });
            if buffer.byte_len != 0 {
                add_resident_copy_count(&mut expected_copy_count, "full readback")?;
                add_resident_transfer_bytes(&mut readback_bytes, buffer.byte_len, "full readback")?;
            }
        }
        self.download_resident_copies_many_into(
            &copies,
            expected_copy_count,
            readback_bytes,
            outputs,
        )
    }

    /// Download bytes from an existing CUDA-resident buffer into caller-owned
    /// storage.
    pub fn download_resident_into(
        &self,
        handle: CudaResidentBuffer,
        bytes: &mut Vec<u8>,
    ) -> Result<(), BackendError> {
        let byte_len = self.resident_store.view(handle)?.byte_len;
        self.download_resident_range_into(handle, 0, byte_len, bytes)
    }

    /// Download a byte range from an existing CUDA-resident buffer.
    pub fn download_resident_range(
        &self,
        handle: CudaResidentBuffer,
        byte_offset: usize,
        byte_len: usize,
    ) -> Result<Vec<u8>, BackendError> {
        let mut bytes = reserved_vec(byte_len, "resident ranged download output bytes")?;
        self.download_resident_range_into(handle, byte_offset, byte_len, &mut bytes)?;
        Ok(bytes)
    }

    /// Download a byte range from an existing CUDA-resident buffer into
    /// caller-owned storage.
    pub fn download_resident_range_into(
        &self,
        handle: CudaResidentBuffer,
        byte_offset: usize,
        byte_len: usize,
        bytes: &mut Vec<u8>,
    ) -> Result<(), BackendError> {
        self.with_resident(handle, |buffer| {
            let end = byte_offset.checked_add(byte_len).ok_or_else(|| {
                BackendError::InvalidProgram {
                    fix: format!(
                        "Fix: CUDA resident ranged download overflows usize at offset {byte_offset} len {byte_len}."
                    ),
                }
            })?;
            if end > buffer.byte_len {
                return Err(BackendError::InvalidProgram {
                    fix: format!(
                        "Fix: CUDA resident ranged download requested bytes [{byte_offset}..{end}) but buffer has {} bytes.",
                        buffer.byte_len
                    ),
                });
            }
            if byte_len == 0 {
                bytes.clear();
                return Ok(());
            }
            let src = buffer
                .ptr
                .checked_add(usize_to_u64(
                    byte_offset,
                    "resident ranged download byte offset",
                )?)
                .ok_or_else(|| BackendError::InvalidProgram {
                    fix: format!(
                        "Fix: CUDA resident ranged download pointer arithmetic overflowed at offset {byte_offset}."
                    ),
                })?;
            self.warmup()?;
            let mut host_transfers = HostTransferAllocations::with_capacity(
                std::sync::Arc::clone(&self.host_pool),
                1,
                1,
            )?;
            self.with_resident_stream(|stream| {
                let dst = host_transfers.push_output(byte_len)?;
                // SAFETY: FFI to libcuda.so. Pointer args are bounds-checked
                // against the resident allocation above. The stream
                // synchronization below proves CUDA completed the copy before the
                // pinned host bytes are materialized into caller-owned storage.
                unsafe {
                    cuda_check(
                        cudarc::driver::sys::cuMemcpyDtoHAsync_v2(
                            dst,
                            src,
                            byte_len,
                            stream.raw(),
                        ),
                        "cuMemcpyDtoHAsync_v2",
                    )?;
                }
                stream.synchronize()
            })?;
            self.telemetry.record_device_to_host_readback(usize_to_u64(
                byte_len,
                "resident ranged download byte count",
            )?);
            self.telemetry
                .record_device_readback_operations(if byte_len == 0 { 0 } else { 1 });
            self.telemetry.record_sync_point();
            host_transfers.collect_output_into(0, bytes)?;
            Ok(())
        })
    }

    /// Download selected byte ranges from resident buffers into caller-owned
    /// output slots with one stream fence.
    pub fn download_resident_ranges_into(
        &self,
        ranges: &[(CudaResidentBuffer, usize, usize)],
        outputs: &mut [&mut Vec<u8>],
    ) -> Result<(), BackendError> {
        if ranges.len() != outputs.len() {
            return Err(BackendError::InvalidProgram {
                fix: format!(
                    "Fix: CUDA resident ranged batch download expected matching range/output counts but got {} range(s) and {} output(s).",
                    ranges.len(),
                    outputs.len()
                ),
            });
        }
        let mut copies = SmallVec::<[ResidentReadbackCopy; 8]>::new();
        reserve_smallvec(&mut copies, ranges.len(), "ranged readback copy")?;
        let mut expected_copy_count = 0usize;
        let mut readback_bytes = 0_u64;
        for &(handle, byte_offset, byte_len) in ranges {
            let buffer = self.resident_store.view(handle)?;
            let end = byte_offset.checked_add(byte_len).ok_or_else(|| {
                BackendError::InvalidProgram {
                    fix: format!(
                        "Fix: CUDA resident ranged batch download for handle {} overflows usize at offset {byte_offset} len {byte_len}.",
                        handle.id
                    ),
                }
            })?;
            if end > buffer.byte_len {
                return Err(BackendError::InvalidProgram {
                    fix: format!(
                        "Fix: CUDA resident ranged batch download for handle {} requested bytes [{byte_offset}..{end}) but buffer has {} bytes.",
                        handle.id, buffer.byte_len
                    ),
                });
            }
            let src = if byte_len == 0 {
                0
            } else {
                buffer
                    .ptr
                    .checked_add(usize_to_u64(
                        byte_offset,
                        "resident ranged batch download byte offset",
                    )?)
                    .ok_or_else(|| BackendError::InvalidProgram {
                        fix: format!(
                            "Fix: CUDA resident ranged batch download pointer arithmetic overflowed for handle {} at offset {byte_offset}.",
                            handle.id
                        ),
                    })?
            };
            copies.push(ResidentReadbackCopy { src, byte_len });
            if byte_len != 0 {
                add_resident_copy_count(&mut expected_copy_count, "ranged readback")?;
                add_resident_transfer_bytes(&mut readback_bytes, byte_len, "ranged readback")?;
            }
        }
        if expected_copy_count == 0 {
            for output in outputs.iter_mut() {
                output.clear();
            }
            return Ok(());
        }
        self.warmup()?;
        let mut host_transfers = HostTransferAllocations::with_capacity(
            std::sync::Arc::clone(&self.host_pool),
            expected_copy_count,
            copies.len(),
        )?;
        let copy_count = self.with_resident_stream(|stream| {
            let mut copy_count = 0usize;
            for copy in &copies {
                let dst = host_transfers.push_output(copy.byte_len)?;
                if copy.byte_len != 0 {
                    // SAFETY: FFI to libcuda.so. Source pointer/range was
                    // validated above against the resident allocation; the target
                    // is a pinned host-transfer slot owned until synchronization.
                    unsafe {
                        cuda_check(
                            cudarc::driver::sys::cuMemcpyDtoHAsync_v2(
                                dst,
                                copy.src,
                                copy.byte_len,
                                stream.raw(),
                            ),
                            "cuMemcpyDtoHAsync_v2",
                        )?;
                    }
                    copy_count += 1;
                }
            }
            if copy_count != 0 {
                stream.synchronize()?;
                self.telemetry.record_sync_point();
            }
            Ok::<usize, BackendError>(copy_count)
        })?;
        for (output_index, output) in outputs.iter_mut().enumerate() {
            host_transfers.collect_output_into(output_index, *output)?;
        }
        self.telemetry
            .record_device_to_host_readback(readback_bytes);
        self.telemetry
            .record_device_readback_operations(usize_to_u64(
                copy_count,
                "resident readback operation count",
            )?);
        Ok(())
    }

    /// Download selected byte ranges from several CUDA-resident buffers with one stream fence.
    pub(crate) fn download_resident_readbacks_many(
        &self,
        handles: &[CudaResidentBuffer],
        readbacks: &[CudaOutputReadback],
    ) -> Result<Vec<Vec<u8>>, BackendError> {
        let mut outputs = reserved_vec(handles.len(), "resident readback output")?;
        self.download_resident_readbacks_many_into(handles, readbacks, &mut outputs)?;
        Ok(outputs)
    }

    /// Download selected byte ranges from several CUDA-resident buffers into
    /// caller-owned output slots with one stream fence.
    pub(crate) fn download_resident_readbacks_many_into(
        &self,
        handles: &[CudaResidentBuffer],
        readbacks: &[CudaOutputReadback],
        outputs: &mut OutputBuffers,
    ) -> Result<(), BackendError> {
        if handles.len() != readbacks.len() {
            return Err(BackendError::InvalidProgram {
                fix: format!(
                    "Fix: CUDA resident readback expected matching handle/range counts but got {} handle(s) and {} range(s).",
                    handles.len(),
                    readbacks.len()
                ),
            });
        }
        let mut copies = SmallVec::<[ResidentReadbackCopy; 8]>::new();
        reserve_smallvec(&mut copies, handles.len(), "readback copy")?;
        let mut expected_copy_count = 0usize;
        let mut readback_bytes = 0_u64;
        for (&handle, readback) in handles.iter().zip(readbacks.iter()) {
            let buffer = self.resident_store.view(handle)?;
            let end = readback
                .device_offset
                .checked_add(readback.byte_len)
                .ok_or_else(|| BackendError::InvalidProgram {
                    fix: format!(
                        "Fix: CUDA resident readback for handle {} overflows usize at offset {} len {}.",
                        handle.id, readback.device_offset, readback.byte_len
                    ),
                })?;
            if end > buffer.byte_len {
                return Err(BackendError::InvalidProgram {
                    fix: format!(
                        "Fix: CUDA resident readback for handle {} requested bytes [{}..{}) but buffer has {} bytes.",
                        handle.id, readback.device_offset, end, buffer.byte_len
                    ),
                });
            }
            let src = if readback.byte_len == 0 {
                0
            } else {
                buffer
                    .ptr
                    .checked_add(usize_to_u64(
                        readback.device_offset,
                        "resident readback device offset",
                    )?)
                    .ok_or_else(|| BackendError::InvalidProgram {
                        fix: format!(
                            "Fix: CUDA resident readback pointer arithmetic overflowed for handle {} at offset {}.",
                            handle.id, readback.device_offset
                        ),
                    })?
            };
            copies.push(ResidentReadbackCopy {
                src,
                byte_len: readback.byte_len,
            });
            if readback.byte_len != 0 {
                add_resident_copy_count(&mut expected_copy_count, "readback")?;
                add_resident_transfer_bytes(&mut readback_bytes, readback.byte_len, "readback")?;
            }
        }
        if expected_copy_count == 0 {
            return clear_resident_copy_outputs(&copies, outputs);
        }
        self.download_resident_copies_many_into(
            &copies,
            expected_copy_count,
            readback_bytes,
            outputs,
        )
    }

    fn download_resident_copies_many_into(
        &self,
        copies: &[ResidentReadbackCopy],
        expected_copy_count: usize,
        readback_bytes: u64,
        outputs: &mut OutputBuffers,
    ) -> Result<(), BackendError> {
        if expected_copy_count == 0 {
            return clear_resident_copy_outputs(copies, outputs);
        }
        self.warmup()?;
        let mut host_transfers = HostTransferAllocations::with_capacity(
            std::sync::Arc::clone(&self.host_pool),
            expected_copy_count,
            copies.len(),
        )?;
        let copy_count = self.with_resident_stream(|stream| {
            let mut copy_count = 0usize;
            for copy in copies {
                let dst = host_transfers.push_output(copy.byte_len)?;
                if copy.byte_len != 0 {
                    // SAFETY: FFI to libcuda.so. Pointer args were validated by
                    // the matching alloc / store API; lifetimes are documented in
                    // the surrounding function. cuda_check (or matching CUresult
                    // guard) propagates non-success codes as BackendError.
                    unsafe {
                        cuda_check(
                            cudarc::driver::sys::cuMemcpyDtoHAsync_v2(
                                dst,
                                copy.src,
                                copy.byte_len,
                                stream.raw(),
                            ),
                            "cuMemcpyDtoHAsync_v2",
                        )?;
                    }
                    copy_count += 1;
                }
            }
            if copy_count != 0 {
                stream.synchronize()?;
                self.telemetry.record_sync_point();
            }
            Ok::<usize, BackendError>(copy_count)
        })?;
        host_transfers.collect_outputs_into(outputs)?;
        self.telemetry
            .record_device_to_host_readback(readback_bytes);
        self.telemetry
            .record_device_readback_operations(usize_to_u64(
                copy_count,
                "resident readback operation count",
            )?);
        Ok(())
    }

    /// Download selected byte ranges from several resident-output batches into
    /// caller-owned output storage with one stream fence.
    pub(crate) fn download_resident_readback_batches_many_into(
        &self,
        handle_batches: &[SmallVec<[CudaResidentBuffer; 8]>],
        readback_batches: &[SmallVec<[CudaOutputReadback; 8]>],
        outputs: &mut Vec<OutputBuffers>,
    ) -> Result<(), BackendError> {
        if handle_batches.len() != readback_batches.len() {
            return Err(BackendError::InvalidProgram {
                fix: format!(
                    "Fix: CUDA resident batch readback expected matching batch counts but got {} handle batch(es) and {} range batch(es).",
                    handle_batches.len(),
                    readback_batches.len()
                ),
            });
        }
        let mut copy_batches = SmallVec::<[SmallVec<[ResidentReadbackCopy; 8]>; 8]>::new();
        reserve_smallvec(&mut copy_batches, handle_batches.len(), "readback batch")?;
        let mut expected_copy_count = 0usize;
        let mut total_copy_slots = 0usize;
        let mut readback_bytes = 0_u64;
        for (batch_index, (handles, readbacks)) in handle_batches
            .iter()
            .zip(readback_batches.iter())
            .enumerate()
        {
            if handles.len() != readbacks.len() {
                return Err(BackendError::InvalidProgram {
                    fix: format!(
                        "Fix: CUDA resident batch readback item {batch_index} expected matching handle/range counts but got {} handle(s) and {} range(s).",
                        handles.len(),
                        readbacks.len()
                    ),
                });
            }
            let mut copies = SmallVec::<[ResidentReadbackCopy; 8]>::new();
            reserve_smallvec(&mut copies, handles.len(), "batched readback copy")?;
            add_resident_copy_slots(&mut total_copy_slots, handles.len(), "batch readback")?;
            for (&handle, readback) in handles.iter().zip(readbacks.iter()) {
                let buffer = self.resident_store.view(handle)?;
                let end = readback
                    .device_offset
                    .checked_add(readback.byte_len)
                    .ok_or_else(|| BackendError::InvalidProgram {
                        fix: format!(
                            "Fix: CUDA resident batch readback for handle {} overflows usize at offset {} len {}.",
                            handle.id, readback.device_offset, readback.byte_len
                        ),
                    })?;
                if end > buffer.byte_len {
                    return Err(BackendError::InvalidProgram {
                        fix: format!(
                            "Fix: CUDA resident batch readback for handle {} requested bytes [{}..{}) but buffer has {} bytes.",
                            handle.id, readback.device_offset, end, buffer.byte_len
                        ),
                    });
                }
                let src = if readback.byte_len == 0 {
                    0
                } else {
                    buffer
                        .ptr
                        .checked_add(usize_to_u64(
                            readback.device_offset,
                            "resident batch readback device offset",
                        )?)
                        .ok_or_else(|| BackendError::InvalidProgram {
                            fix: format!(
                                "Fix: CUDA resident batch readback pointer arithmetic overflowed for handle {} at offset {}.",
                                handle.id, readback.device_offset
                            ),
                        })?
                };
                copies.push(ResidentReadbackCopy {
                    src,
                    byte_len: readback.byte_len,
                });
                if readback.byte_len != 0 {
                    add_resident_copy_count(&mut expected_copy_count, "batch readback")?;
                    add_resident_transfer_bytes(
                        &mut readback_bytes,
                        readback.byte_len,
                        "batch readback",
                    )?;
                }
            }
            copy_batches.push(copies);
        }
        if expected_copy_count == 0 {
            resize_vec_slots(outputs, copy_batches.len(), "batched readback output")?;
            for (copies, batch_outputs) in copy_batches.iter().zip(outputs.iter_mut()) {
                resize_vec_slots(batch_outputs, copies.len(), "batched readback item")?;
                clear_vec_slots(batch_outputs);
            }
            return Ok(());
        }
        self.warmup()?;
        let mut host_transfers = HostTransferAllocations::with_capacity(
            std::sync::Arc::clone(&self.host_pool),
            expected_copy_count,
            total_copy_slots,
        )?;
        let copy_count = self.with_resident_stream(|stream| {
            let mut copy_count = 0usize;
            for copies in &copy_batches {
                for copy in copies {
                    let dst = host_transfers.push_output(copy.byte_len)?;
                    if copy.byte_len != 0 {
                        // SAFETY: FFI to libcuda.so. Pointer args were validated
                        // by the matching alloc / store API; lifetimes are
                        // documented in the surrounding function. cuda_check (or
                        // matching CUresult guard) propagates non-success codes as
                        // BackendError.
                        unsafe {
                            cuda_check(
                                cudarc::driver::sys::cuMemcpyDtoHAsync_v2(
                                    dst,
                                    copy.src,
                                    copy.byte_len,
                                    stream.raw(),
                                ),
                                "cuMemcpyDtoHAsync_v2",
                            )?;
                        }
                        copy_count += 1;
                    }
                }
            }
            if copy_count != 0 {
                stream.synchronize()?;
                self.telemetry.record_sync_point();
            }
            Ok::<usize, BackendError>(copy_count)
        })?;
        resize_vec_slots(outputs, copy_batches.len(), "batched readback output")?;
        let mut transfer_index = 0usize;
        for (copies, batch_outputs) in copy_batches.iter().zip(outputs.iter_mut()) {
            resize_vec_slots(batch_outputs, copies.len(), "batched readback item")?;
            for output in batch_outputs {
                host_transfers.collect_output_into(transfer_index, output)?;
                transfer_index += 1;
            }
        }
        self.telemetry
            .record_device_to_host_readback(readback_bytes);
        self.telemetry
            .record_device_readback_operations(usize_to_u64(
                copy_count,
                "resident batched readback operation count",
            )?);
        Ok(())
    }

    /// Free a CUDA-resident buffer handle.
    pub fn free_resident(&self, handle: CudaResidentBuffer) -> Result<(), BackendError> {
        self.resident_store.free(handle)
    }

    /// Upload a partial byte slice into a CUDA-resident buffer at a byte offset.
    pub fn upload_resident_at(
        &self,
        handle: CudaResidentBuffer,
        dst_offset_bytes: usize,
        bytes: &[u8],
    ) -> Result<(), BackendError> {
        self.upload_resident_at_many(&[(handle, dst_offset_bytes, bytes)])
    }

    /// Upload several partial byte slices into CUDA-resident buffers with one stream fence.
    pub fn upload_resident_at_many(
        &self,
        uploads: &[(CudaResidentBuffer, usize, &[u8])],
    ) -> Result<(), BackendError> {
        if uploads.is_empty() {
            return Ok(());
        }
        let mut copies = SmallVec::<[(u64, &[u8]); 8]>::new();
        reserve_smallvec(&mut copies, uploads.len(), "offset upload copy")?;
        let mut uploaded_bytes = 0_u64;
        for &(handle, dst_offset_bytes, bytes) in uploads {
            let buffer = self.resident_store.view(handle)?;
            let dst_ptr = checked_resident_dst(
                handle,
                buffer.ptr,
                buffer.byte_len,
                dst_offset_bytes,
                bytes.len(),
            )?;
            if !bytes.is_empty() {
                copies.push((dst_ptr, bytes));
                add_resident_transfer_bytes(&mut uploaded_bytes, bytes.len(), "offset upload")?;
            }
        }
        if copies.is_empty() {
            return Ok(());
        }
        self.warmup()?;
        let mut host_transfers = HostTransferAllocations::with_capacity(
            std::sync::Arc::clone(&self.host_pool),
            copies.len(),
            0,
        )?;
        self.with_resident_stream(|stream| {
            for &(dst_ptr, bytes) in &copies {
                let host_ptr = host_transfers.push_upload(bytes)?;
                // SAFETY: FFI to libcuda.so. Pointer args were validated by the
                // matching alloc / store API; lifetimes are documented in the
                // surrounding function. cuda_check (or matching CUresult guard)
                // propagates non-success codes as BackendError.
                unsafe {
                    cuda_check(
                        cudarc::driver::sys::cuMemcpyHtoDAsync_v2(
                            dst_ptr,
                            host_ptr,
                            bytes.len(),
                            stream.raw(),
                        ),
                        "cuMemcpyHtoDAsync_v2",
                    )?;
                }
            }
            stream.synchronize()
        })?;
        self.telemetry.record_sync_point();
        self.telemetry.record_host_to_device_bytes(uploaded_bytes);
        self.telemetry.record_host_upload_operations(usize_to_u64(
            copies.len(),
            "resident upload operation count",
        )?);
        drop(host_transfers);
        Ok(())
    }

    /// Return the raw CUDA device pointer for a resident buffer.
    pub fn resident_device_ptr(&self, handle: CudaResidentBuffer) -> Result<u64, BackendError> {
        self.with_resident(handle, |buffer| Ok(buffer.ptr))
    }

    /// Bytes currently held by CUDA resident buffers.
    #[must_use]
    pub fn resident_allocated_bytes(&self) -> u64 {
        self.resident_store.allocated_bytes()
    }

    fn cuda_resident_budget_bytes(&self) -> u64 {
        let budget = (u128::from(self.caps.total_memory)
            * u128::from(CUDA_RESIDENT_BUDGET_NUMERATOR))
            / u128::from(CUDA_RESIDENT_BUDGET_DENOMINATOR);
        budget as u64
    }

    /// Pin a pre-allocated host buffer as page-locked for fast async H2D.
    ///
    /// # Safety
    ///
    /// The caller asserts `ptr..ptr+byte_len` is a uniquely owned, mapped
    /// host region that lives at least until [`Self::unpin_host_buffer`] is called.
    pub unsafe fn pin_host_buffer(&self, ptr: u64, byte_len: usize) -> Result<(), BackendError> {
        if byte_len == 0 {
            return Err(BackendError::InvalidProgram {
                fix: "Fix: pin_host_buffer requires a non-zero byte length.".to_string(),
            });
        }
        self.warmup()?;
        // SAFETY: FFI to libcuda.so. Pointer args were validated by the
        // matching alloc / store API; lifetimes are documented in the
        // surrounding function. cuda_check (or matching CUresult guard)
        // propagates non-success codes as BackendError.
        unsafe {
            cuda_check(
                cudarc::driver::sys::cuMemHostRegister_v2(
                    ptr as *mut std::ffi::c_void,
                    byte_len,
                    cudarc::driver::sys::CU_MEMHOSTREGISTER_PORTABLE as ::std::os::raw::c_uint,
                ),
                "cuMemHostRegister_v2",
            )
        }
    }

    /// Unregister a previously [`Self::pin_host_buffer`]d host region.
    ///
    /// # Safety
    ///
    /// The caller asserts there are no in-flight async copies sourcing from
    /// this region.
    pub unsafe fn unpin_host_buffer(&self, ptr: u64) -> Result<(), BackendError> {
        self.warmup()?;
        // SAFETY: FFI to libcuda.so. Pointer args were validated by the
        // matching alloc / store API; lifetimes are documented in the
        // surrounding function. cuda_check (or matching CUresult guard)
        // propagates non-success codes as BackendError.
        unsafe {
            cuda_check(
                cudarc::driver::sys::cuMemHostUnregister(ptr as *mut std::ffi::c_void),
                "cuMemHostUnregister",
            )
        }
    }

    /// Async H2D copy from a pinned host pointer into a CUDA-resident buffer.
    ///
    /// # Safety
    ///
    /// The caller asserts `src_ptr..src_ptr+byte_count` is page-locked and
    /// remains uniquely borrowed until [`Self::synchronize_uploads`] returns.
    pub unsafe fn upload_resident_async_at(
        &self,
        handle: CudaResidentBuffer,
        dst_offset_bytes: usize,
        src_ptr: u64,
        byte_count: usize,
    ) -> Result<(), BackendError> {
        if byte_count == 0 {
            return Ok(());
        }
        self.with_resident(handle, |buffer| {
            let end = dst_offset_bytes
                .checked_add(byte_count)
                .ok_or_else(|| BackendError::InvalidProgram {
                    fix: format!(
                        "Fix: async upload at offset {dst_offset_bytes} for handle {} would overflow usize.",
                        handle.id
                    ),
                })?;
            if end > buffer.byte_len {
                return Err(BackendError::InvalidProgram {
                    fix: format!(
                        "Fix: async upload for handle {} writes [{dst_offset_bytes}..{end}) but buffer is only {} bytes.",
                        handle.id, buffer.byte_len
                    ),
                });
            }
            let dst_ptr = checked_resident_dst(handle, buffer.ptr, buffer.byte_len, dst_offset_bytes, byte_count)?;
            let mut pending_stream = self.async_upload_stream.lock().map_err(|_| {
                BackendError::new("CUDA async upload stream lock was poisoned. Fix: recreate the backend before queueing more resident uploads.")
            })?;
            let created_stream = pending_stream.is_none();
            if created_stream {
                *pending_stream = Some(self.launch_resources.acquire_stream()?);
            }
            let stream = pending_stream.as_ref().ok_or_else(|| {
                BackendError::new("CUDA async upload stream allocation failed. Fix: recreate the backend or lower concurrent upload pressure.")
            })?;
            // SAFETY: FFI to libcuda.so. Pointer args were validated by the
            // matching alloc / store API; lifetimes are documented in the
            // surrounding function. cuda_check (or matching CUresult guard)
            // propagates non-success codes as BackendError.
            unsafe {
                let copy_result = cuda_check(
                    cudarc::driver::sys::cuMemcpyHtoDAsync_v2(
                        dst_ptr,
                        src_ptr as *const std::ffi::c_void,
                        byte_count,
                        stream.raw(),
                    ),
                    "cuMemcpyHtoDAsync_v2",
                );
                if let Err(error) = copy_result {
                    if created_stream {
                        if let Some(stream) = pending_stream.take() {
                            self.launch_resources.release_stream(stream);
                        }
                    }
                    return Err(error);
                }
            }
            self.telemetry
                .record_host_to_device_bytes(usize_to_u64(
                    byte_count,
                    "resident byte upload count",
                )?);
            self.telemetry.record_host_upload_operations(1);
            Ok(())
        })
    }

    /// Block until every queued async H2D copy on this backend's upload stream completes.
    pub fn synchronize_uploads(&self) -> Result<(), BackendError> {
        self.warmup()?;
        let stream = self
            .async_upload_stream
            .lock()
            .map_err(|_| {
                BackendError::new("CUDA async upload stream lock was poisoned. Fix: recreate the backend before synchronizing resident uploads.")
            })?
            .take();
        let Some(stream) = stream else {
            return Ok(());
        };
        let result = stream.synchronize();
        self.launch_resources.release_stream(stream);
        result?;
        self.telemetry.record_sync_point();
        Ok(())
    }
}

#[cfg(test)]
mod async_upload_tests {
    #[test]
    fn async_uploads_use_backend_stream_not_null_stream() {
        let source = include_str!("resident_io.rs");
        assert!(
            source.contains("async_upload_stream")
                && source.contains("stream.raw()")
                && source.contains("release_stream(stream)"),
            "Fix: CUDA async resident uploads must retain a backend-owned stream until synchronize_uploads releases it."
        );
        assert!(
            !source.contains(concat!("cuStreamSynchronize", "(std::ptr::null_mut())"))
                && !source.contains(concat!(
                    "cuMemcpyHtoDAsync_v2(\n                        dst_ptr,\n                        src_ptr as *const std::ffi::c_void,\n                        byte_count,\n                        ",
                    "std::ptr::null_mut(),"
                )),
            "Fix: CUDA async resident uploads must not enqueue or synchronize on the null stream; that creates a global device fence."
        );
    }
}

fn checked_resident_dst(
    handle: CudaResidentBuffer,
    base_ptr: u64,
    buffer_len: usize,
    dst_offset_bytes: usize,
    byte_count: usize,
) -> Result<u64, BackendError> {
    let end = dst_offset_bytes
        .checked_add(byte_count)
        .ok_or_else(|| BackendError::InvalidProgram {
            fix: format!(
                "Fix: CUDA resident upload at offset {dst_offset_bytes} for handle {} would overflow usize.",
                handle.id
            ),
        })?;
    if end > buffer_len {
        return Err(BackendError::InvalidProgram {
            fix: format!(
                "Fix: CUDA resident upload for handle {} writes [{dst_offset_bytes}..{end}) but buffer is only {buffer_len} bytes; resize the resident slot or trim the source slice.",
                handle.id
            ),
        });
    }
    let dst_offset = u64::try_from(dst_offset_bytes).map_err(|_| BackendError::InvalidProgram {
        fix: format!(
            "Fix: CUDA resident upload offset {dst_offset_bytes} does not fit CUdeviceptr arithmetic for handle {}.",
            handle.id
        ),
    })?;
    base_ptr
        .checked_add(dst_offset)
        .ok_or_else(|| BackendError::InvalidProgram {
            fix: format!(
                "Fix: CUDA resident upload pointer arithmetic overflowed for handle {} at offset {dst_offset_bytes}.",
                handle.id
            ),
        })
}
