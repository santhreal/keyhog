use std::ffi::c_void;
use std::hash::BuildHasherDefault;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use crossbeam_queue::SegQueue;
use cudarc::driver::sys::{CUresult, CU_MEMHOSTALLOC_PORTABLE};
use dashmap::DashMap;
use rustc_hash::FxHasher;
use smallvec::SmallVec;
use vyre_driver::BackendError;

pub(crate) fn cuda_check(result: CUresult, operation: &str) -> Result<(), BackendError> {
    if result == CUresult::CUDA_SUCCESS {
        return Ok(());
    }
    Err(BackendError::DispatchFailed {
        code: Some(result as i32),
        message: format!("{operation} failed with {result:?}"),
    })
}

#[derive(Debug)]
pub(crate) struct DispatchAllocations {
    pool: Arc<DeviceAllocationPool>,
    ptrs: SmallVec<[DeviceAllocation; 8]>,
    params: DeviceAllocation,
}

impl DispatchAllocations {
    pub(crate) fn new(buffer_count: usize, pool: Arc<DeviceAllocationPool>) -> Self {
        let mut ptrs = SmallVec::with_capacity(buffer_count);
        ptrs.resize(buffer_count, DeviceAllocation::default());
        Self {
            pool,
            ptrs,
            params: DeviceAllocation::default(),
        }
    }

    pub(crate) fn set_ptr(&mut self, index: usize, allocation: DeviceAllocation) {
        self.ptrs[index] = allocation;
    }

    pub(crate) fn ptr(&self, index: usize) -> u64 {
        self.ptrs[index].ptr
    }

    pub(crate) fn set_params(&mut self, allocation: DeviceAllocation) {
        self.params = allocation;
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct PinnedHostAllocation {
    ptr: *mut u8,
    pub(crate) byte_len: usize,
}

unsafe impl Send for PinnedHostAllocation {}
unsafe impl Sync for PinnedHostAllocation {}

impl Default for PinnedHostAllocation {
    fn default() -> Self {
        Self {
            ptr: std::ptr::null_mut(),
            byte_len: 0,
        }
    }
}

impl PinnedHostAllocation {
    pub(crate) fn as_ptr(&self) -> *const c_void {
        self.ptr.cast()
    }

    pub(crate) fn as_mut_ptr(&mut self) -> *mut c_void {
        self.ptr.cast()
    }

    pub(crate) fn copy_from_slice(&mut self, bytes: &[u8]) {
        debug_assert!(bytes.len() <= self.byte_len);
        if bytes.is_empty() {
            return;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), self.ptr, bytes.len());
        }
    }

    pub(crate) fn copy_u32_le_words(&mut self, words: &[u32]) {
        let byte_len = std::mem::size_of_val(words);
        debug_assert!(byte_len <= self.byte_len);
        if byte_len == 0 {
            return;
        }
        #[cfg(target_endian = "little")]
        unsafe {
            std::ptr::copy_nonoverlapping(words.as_ptr().cast::<u8>(), self.ptr, byte_len);
        }
        #[cfg(not(target_endian = "little"))]
        {
            let dst = unsafe { std::slice::from_raw_parts_mut(self.ptr, byte_len) };
            for (chunk, word) in dst.chunks_exact_mut(4).zip(words) {
                chunk.copy_from_slice(&word.to_le_bytes());
            }
        }
    }

    pub(crate) fn copy_prefix_into(&self, byte_len: usize, dst: &mut Vec<u8>) {
        debug_assert!(byte_len <= self.byte_len);
        copy_raw_bytes_into_vec(self.ptr, byte_len, dst);
    }
}

fn copy_raw_bytes_into_vec(src: *const u8, byte_len: usize, dst: &mut Vec<u8>) {
    dst.clear();
    if byte_len == 0 {
        return;
    }
    if dst.capacity() < byte_len {
        dst.reserve_exact(byte_len);
    }
    unsafe {
        std::ptr::copy_nonoverlapping(src, dst.as_mut_ptr(), byte_len);
        dst.set_len(byte_len);
    }
}

#[derive(Debug)]
pub(crate) struct PinnedHostAllocationPool {
    free: DashMap<usize, SegQueue<usize>, BuildHasherDefault<FxHasher>>,
    cached_bytes: AtomicUsize,
    max_cached_bytes: usize,
}

impl PinnedHostAllocationPool {
    pub(crate) fn new(max_cached_bytes: usize) -> Self {
        Self {
            free: DashMap::with_hasher(BuildHasherDefault::<FxHasher>::default()),
            cached_bytes: AtomicUsize::new(0),
            max_cached_bytes,
        }
    }

    pub(crate) fn acquire(&self, byte_len: usize) -> Result<PinnedHostAllocation, BackendError> {
        let bucket = allocation_bucket(byte_len, "CUDA pinned host allocation")?;
        if let Some(ptr) = self.take_cached(bucket)? {
            return Ok(PinnedHostAllocation {
                ptr: ptr as *mut u8,
                byte_len: bucket,
            });
        }
        let mut ptr = std::ptr::null_mut::<c_void>();
        unsafe {
            cuda_check(
                cudarc::driver::sys::cuMemHostAlloc(&mut ptr, bucket, CU_MEMHOSTALLOC_PORTABLE),
                "cuMemHostAlloc",
            )?;
        }
        Ok(PinnedHostAllocation {
            ptr: ptr.cast(),
            byte_len: bucket,
        })
    }

    pub(crate) fn clear(&self) -> Result<(), BackendError> {
        for entry in &self.free {
            while let Some(ptr) = entry.value().pop() {
                free_pinned_host_ptr(ptr as *mut c_void);
            }
        }
        self.free.clear();
        self.cached_bytes.store(0, Ordering::Release);
        Ok(())
    }

    fn take_cached(&self, bucket: usize) -> Result<Option<usize>, BackendError> {
        Ok(self.free.get(&bucket).and_then(|queue| {
            let ptr = queue.pop()?;
            self.cached_bytes.fetch_sub(bucket, Ordering::AcqRel);
            Some(ptr)
        }))
    }

    pub(crate) fn release(&self, allocation: PinnedHostAllocation) {
        if allocation.ptr.is_null() || allocation.byte_len == 0 {
            return;
        }
        if !reserve_cached_bytes(
            &self.cached_bytes,
            self.max_cached_bytes,
            allocation.byte_len,
        ) {
            free_pinned_host_ptr(allocation.ptr.cast());
            return;
        }

        self.free
            .entry(allocation.byte_len)
            .or_default()
            .push(allocation.ptr as usize);
    }
}

impl Drop for PinnedHostAllocationPool {
    fn drop(&mut self) {
        for entry in &self.free {
            while let Some(ptr) = entry.value().pop() {
                free_pinned_host_ptr(ptr as *mut c_void);
            }
        }
        self.cached_bytes.store(0, Ordering::Release);
    }
}

#[derive(Debug)]
pub(crate) struct HostTransferAllocations {
    pool: Arc<PinnedHostAllocationPool>,
    allocations: SmallVec<[PinnedHostAllocation; 8]>,
    outputs: SmallVec<[(usize, usize); 8]>,
}

impl HostTransferAllocations {
    pub(crate) fn new(pool: Arc<PinnedHostAllocationPool>) -> Self {
        Self::with_capacity(pool, 0, 0)
    }

    pub(crate) fn with_capacity(
        pool: Arc<PinnedHostAllocationPool>,
        transfer_capacity: usize,
        output_capacity: usize,
    ) -> Self {
        Self {
            pool,
            allocations: SmallVec::with_capacity(transfer_capacity),
            outputs: SmallVec::with_capacity(output_capacity),
        }
    }

    pub(crate) fn push_upload(&mut self, bytes: &[u8]) -> Result<*const c_void, BackendError> {
        let mut allocation = self.pool.acquire(bytes.len())?;
        allocation.copy_from_slice(bytes);
        let ptr = allocation.as_ptr();
        self.allocations.push(allocation);
        Ok(ptr)
    }

    pub(crate) fn push_u32_words(&mut self, words: &[u32]) -> Result<*const c_void, BackendError> {
        let byte_len = std::mem::size_of_val(words);
        let mut allocation = self.pool.acquire(byte_len)?;
        allocation.copy_u32_le_words(words);
        let ptr = allocation.as_ptr();
        self.allocations.push(allocation);
        Ok(ptr)
    }

    pub(crate) fn push_output(&mut self, byte_len: usize) -> Result<*mut c_void, BackendError> {
        let mut allocation = self.pool.acquire(byte_len)?;
        let ptr = allocation.as_mut_ptr();
        let index = self.allocations.len();
        self.allocations.push(allocation);
        self.outputs.push((index, byte_len));
        Ok(ptr)
    }

    pub(crate) fn collect_outputs_into(&self, outputs: &mut Vec<Vec<u8>>) {
        if outputs.len() < self.outputs.len() {
            outputs.resize_with(self.outputs.len(), Vec::new);
        } else {
            outputs.truncate(self.outputs.len());
        }
        for (output_index, &(allocation_index, byte_len)) in self.outputs.iter().enumerate() {
            self.allocations[allocation_index]
                .copy_prefix_into(byte_len, &mut outputs[output_index]);
        }
    }
}

impl Drop for HostTransferAllocations {
    fn drop(&mut self) {
        for allocation in self.allocations.drain(..) {
            self.pool.release(allocation);
        }
    }
}

impl Drop for DispatchAllocations {
    fn drop(&mut self) {
        for allocation in self.ptrs.drain(..) {
            self.pool.release(allocation);
        }
        self.pool.release(std::mem::take(&mut self.params));
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct DeviceAllocation {
    pub(crate) ptr: u64,
    pub(crate) byte_len: usize,
}

#[derive(Debug)]
pub(crate) struct DeviceAllocationPool {
    free: DashMap<usize, SegQueue<u64>, BuildHasherDefault<FxHasher>>,
    cached_bytes: AtomicUsize,
    max_cached_bytes: usize,
}

impl DeviceAllocationPool {
    pub(crate) fn new(max_cached_bytes: usize) -> Self {
        Self {
            free: DashMap::with_hasher(BuildHasherDefault::<FxHasher>::default()),
            cached_bytes: AtomicUsize::new(0),
            max_cached_bytes,
        }
    }

    pub(crate) fn acquire(&self, byte_len: usize) -> Result<DeviceAllocation, BackendError> {
        let bucket = allocation_bucket(byte_len, "CUDA device allocation")?;
        if let Some(ptr) = self.take_cached(bucket)? {
            return Ok(DeviceAllocation {
                ptr,
                byte_len: bucket,
            });
        }
        let mut ptr = 0u64;
        unsafe {
            cuda_check(
                cudarc::driver::sys::cuMemAlloc_v2(&mut ptr, bucket),
                "cuMemAlloc_v2",
            )?;
        }
        Ok(DeviceAllocation {
            ptr,
            byte_len: bucket,
        })
    }

    pub(crate) fn cached_bytes(&self) -> Result<usize, BackendError> {
        Ok(self.cached_bytes.load(Ordering::Acquire))
    }

    pub(crate) fn clear(&self) -> Result<(), BackendError> {
        for entry in &self.free {
            while let Some(ptr) = entry.value().pop() {
                free_cuda_ptr(ptr);
            }
        }
        self.free.clear();
        self.cached_bytes.store(0, Ordering::Release);
        Ok(())
    }

    fn take_cached(&self, bucket: usize) -> Result<Option<u64>, BackendError> {
        Ok(self.free.get(&bucket).and_then(|queue| {
            let ptr = queue.pop()?;
            self.cached_bytes.fetch_sub(bucket, Ordering::AcqRel);
            Some(ptr)
        }))
    }

    pub(crate) fn release(&self, allocation: DeviceAllocation) {
        if allocation.ptr == 0 || allocation.byte_len == 0 {
            return;
        }
        if !reserve_cached_bytes(
            &self.cached_bytes,
            self.max_cached_bytes,
            allocation.byte_len,
        ) {
            free_cuda_ptr(allocation.ptr);
            return;
        }

        self.free
            .entry(allocation.byte_len)
            .or_default()
            .push(allocation.ptr);
    }
}

impl Drop for DeviceAllocationPool {
    fn drop(&mut self) {
        for entry in &self.free {
            while let Some(ptr) = entry.value().pop() {
                free_cuda_ptr(ptr);
            }
        }
        self.cached_bytes.store(0, Ordering::Release);
    }
}

fn allocation_bucket(byte_len: usize, label: &'static str) -> Result<usize, BackendError> {
    byte_len
        .max(1)
        .checked_next_power_of_two()
        .ok_or_else(|| BackendError::DispatchFailed {
            code: None,
            message: format!(
                "{label} request of {byte_len} bytes cannot be rounded to a power-of-two bucket. Fix: cap dispatch buffer sizes before allocation."
            ),
        })
}

fn reserve_cached_bytes(counter: &AtomicUsize, max_cached_bytes: usize, bytes: usize) -> bool {
    let mut observed = counter.load(Ordering::Acquire);
    loop {
        let Some(next) = observed.checked_add(bytes) else {
            return false;
        };
        if next > max_cached_bytes {
            return false;
        }
        match counter.compare_exchange_weak(observed, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return true,
            Err(actual) => observed = actual,
        }
    }
}

pub(crate) fn free_cuda_ptr(ptr: u64) {
    if ptr == 0 {
        return;
    }
    unsafe {
        let result = cudarc::driver::sys::cuMemFree_v2(ptr);
        if result != CUresult::CUDA_SUCCESS {
            eprintln!(
                "Fix: cuMemFree_v2 failed while releasing CUDA allocation with {result:?}; ensure all launches using the allocation have completed."
            );
        }
    }
}

fn free_pinned_host_ptr(ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        let result = cudarc::driver::sys::cuMemFreeHost(ptr);
        if result != CUresult::CUDA_SUCCESS {
            eprintln!(
                "Fix: cuMemFreeHost failed while releasing pinned host allocation with {result:?}; ensure all DMA using the allocation has completed."
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::copy_raw_bytes_into_vec;

    #[test]
    fn copy_raw_bytes_into_vec_reuses_capacity_without_zero_fill_resize() {
        let src = [1u8, 2, 3, 4, 5, 6];
        let mut dst = Vec::with_capacity(16);
        dst.extend_from_slice(&[9, 9, 9, 9]);
        let capacity = dst.capacity();

        copy_raw_bytes_into_vec(src.as_ptr(), 4, &mut dst);

        assert_eq!(dst, vec![1, 2, 3, 4]);
        assert_eq!(dst.capacity(), capacity);

        copy_raw_bytes_into_vec(src[2..].as_ptr(), 0, &mut dst);
        assert!(dst.is_empty());
        assert_eq!(dst.capacity(), capacity);
    }
}
