//! Host and device copies for CUDA-resident buffers.

use vyre_driver::BackendError;

use super::allocations::{cuda_check, HostTransferAllocations};
use super::dispatch::CudaBackend;
use super::output_range::CudaOutputReadback;
use super::resident::CudaResidentBuffer;
use smallvec::SmallVec;

#[derive(Clone, Copy)]
struct ResidentReadbackCopy {
    src: u64,
    byte_len: usize,
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
        self.resident_store.allocate(byte_len)
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
        let mut copies = SmallVec::<[(u64, &[u8]); 8]>::with_capacity(uploads.len());
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
            }
        }
        if copies.is_empty() {
            return Ok(());
        }
        self.warmup()?;
        let stream = self.launch_resources.acquire_stream()?;
        let mut host_transfers =
            HostTransferAllocations::new(std::sync::Arc::clone(&self.host_pool));
        for &(dst_ptr, bytes) in &copies {
            let host_ptr = host_transfers.push_upload(bytes)?;
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
        stream.synchronize()?;
        self.launch_resources.release_stream(stream);
        drop(host_transfers);
        Ok(())
    }

    /// Download bytes from an existing CUDA-resident buffer.
    pub fn download_resident(&self, handle: CudaResidentBuffer) -> Result<Vec<u8>, BackendError> {
        self.with_resident(handle, |buffer| {
            let mut bytes = vec![0u8; buffer.byte_len];
            unsafe {
                cuda_check(
                    cudarc::driver::sys::cuMemcpyDtoH_v2(
                        bytes.as_mut_ptr().cast(),
                        buffer.ptr,
                        bytes.len(),
                    ),
                    "cuMemcpyDtoH_v2",
                )?;
            }
            Ok(bytes)
        })
    }

    /// Download selected byte ranges from several CUDA-resident buffers with one stream fence.
    pub(crate) fn download_resident_readbacks_many(
        &self,
        handles: &[CudaResidentBuffer],
        readbacks: &[CudaOutputReadback],
    ) -> Result<Vec<Vec<u8>>, BackendError> {
        if handles.len() != readbacks.len() {
            return Err(BackendError::InvalidProgram {
                fix: format!(
                    "Fix: CUDA resident readback expected matching handle/range counts but got {} handle(s) and {} range(s).",
                    handles.len(),
                    readbacks.len()
                ),
            });
        }
        let mut copies = SmallVec::<[ResidentReadbackCopy; 8]>::with_capacity(handles.len());
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
                    .checked_add(readback.device_offset as u64)
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
        }
        self.warmup()?;
        let stream = self.launch_resources.acquire_stream()?;
        let mut outputs = Vec::with_capacity(copies.len());
        let mut output_lengths = SmallVec::<[usize; 8]>::with_capacity(copies.len());
        let mut copy_count = 0usize;
        for copy in &copies {
            let mut bytes = Vec::<u8>::with_capacity(copy.byte_len);
            if copy.byte_len != 0 {
                unsafe {
                    cuda_check(
                        cudarc::driver::sys::cuMemcpyDtoHAsync_v2(
                            bytes.as_mut_ptr().cast(),
                            copy.src,
                            copy.byte_len,
                            stream.raw(),
                        ),
                        "cuMemcpyDtoHAsync_v2",
                    )?;
                }
                copy_count += 1;
            }
            output_lengths.push(copy.byte_len);
            outputs.push(bytes);
        }
        if copy_count != 0 {
            stream.synchronize()?;
        }
        for (output, byte_len) in outputs.iter_mut().zip(output_lengths) {
            if byte_len != 0 {
                // SAFETY: the vector was allocated with at least `byte_len`
                // capacity and the preceding stream synchronization proves
                // CUDA wrote exactly that many bytes into `as_mut_ptr()`.
                unsafe {
                    output.set_len(byte_len);
                }
            }
        }
        self.launch_resources.release_stream(stream);
        Ok(outputs)
    }

    /// Download selected byte ranges from several resident-output batches with one stream fence.
    pub(crate) fn download_resident_readback_batches_many(
        &self,
        handle_batches: &[SmallVec<[CudaResidentBuffer; 8]>],
        readback_batches: &[SmallVec<[CudaOutputReadback; 8]>],
    ) -> Result<Vec<Vec<Vec<u8>>>, BackendError> {
        if handle_batches.len() != readback_batches.len() {
            return Err(BackendError::InvalidProgram {
                fix: format!(
                    "Fix: CUDA resident batch readback expected matching batch counts but got {} handle batch(es) and {} range batch(es).",
                    handle_batches.len(),
                    readback_batches.len()
                ),
            });
        }
        let mut copy_batches =
            SmallVec::<[SmallVec<[ResidentReadbackCopy; 8]>; 8]>::with_capacity(
                handle_batches.len(),
            );
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
            let mut copies = SmallVec::<[ResidentReadbackCopy; 8]>::with_capacity(handles.len());
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
                        .checked_add(readback.device_offset as u64)
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
            }
            copy_batches.push(copies);
        }
        self.warmup()?;
        let stream = self.launch_resources.acquire_stream()?;
        let mut batches = Vec::with_capacity(copy_batches.len());
        let mut output_lengths =
            SmallVec::<[SmallVec<[usize; 8]>; 8]>::with_capacity(copy_batches.len());
        let mut copy_count = 0usize;
        for copies in &copy_batches {
            let mut outputs = Vec::with_capacity(copies.len());
            let mut item_lengths = SmallVec::<[usize; 8]>::with_capacity(copies.len());
            for copy in copies {
                let mut bytes = Vec::<u8>::with_capacity(copy.byte_len);
                if copy.byte_len != 0 {
                    unsafe {
                        cuda_check(
                            cudarc::driver::sys::cuMemcpyDtoHAsync_v2(
                                bytes.as_mut_ptr().cast(),
                                copy.src,
                                copy.byte_len,
                                stream.raw(),
                            ),
                            "cuMemcpyDtoHAsync_v2",
                        )?;
                    }
                    copy_count += 1;
                }
                item_lengths.push(copy.byte_len);
                outputs.push(bytes);
            }
            output_lengths.push(item_lengths);
            batches.push(outputs);
        }
        if copy_count != 0 {
            stream.synchronize()?;
        }
        for (outputs, lengths) in batches.iter_mut().zip(output_lengths) {
            for (output, byte_len) in outputs.iter_mut().zip(lengths) {
                if byte_len != 0 {
                    // SAFETY: the vector was allocated with at least
                    // `byte_len` capacity and the preceding stream
                    // synchronization proves CUDA wrote exactly that many
                    // bytes into `as_mut_ptr()`.
                    unsafe {
                        output.set_len(byte_len);
                    }
                }
            }
        }
        self.launch_resources.release_stream(stream);
        Ok(batches)
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
        let mut copies = SmallVec::<[(u64, &[u8]); 8]>::with_capacity(uploads.len());
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
            }
        }
        if copies.is_empty() {
            return Ok(());
        }
        self.warmup()?;
        let stream = self.launch_resources.acquire_stream()?;
        let mut host_transfers =
            HostTransferAllocations::new(std::sync::Arc::clone(&self.host_pool));
        for &(dst_ptr, bytes) in &copies {
            let host_ptr = host_transfers.push_upload(bytes)?;
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
        stream.synchronize()?;
        self.launch_resources.release_stream(stream);
        drop(host_transfers);
        Ok(())
    }

    /// Return the raw CUDA device pointer for a resident buffer.
    pub fn resident_device_ptr(&self, handle: CudaResidentBuffer) -> Result<u64, BackendError> {
        self.with_resident(handle, |buffer| Ok(buffer.ptr))
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
            unsafe {
                cuda_check(
                    cudarc::driver::sys::cuMemcpyHtoDAsync_v2(
                        dst_ptr,
                        src_ptr as *const std::ffi::c_void,
                        byte_count,
                        std::ptr::null_mut(),
                    ),
                    "cuMemcpyHtoDAsync_v2",
                )
            }
        })
    }

    /// Block until every queued async H2D copy on the default stream completes.
    pub fn synchronize_uploads(&self) -> Result<(), BackendError> {
        self.warmup()?;
        unsafe {
            cuda_check(
                cudarc::driver::sys::cuStreamSynchronize(std::ptr::null_mut()),
                "cuStreamSynchronize",
            )
        }
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
