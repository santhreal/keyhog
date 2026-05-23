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

use super::staging_reserve::{reserve_vec, resize_vec_slots};

pub(crate) fn cuda_check(result: CUresult, operation: &str) -> Result<(), BackendError> {
    if result == CUresult::CUDA_SUCCESS {
        return Ok(());
    }
    Err(BackendError::DispatchFailed {
        code: Some(cuda_result_code(result)),
        message: format!("{operation} failed with {result:?}"),
    })
}

pub(crate) fn cuda_result_code(result: CUresult) -> i32 {
    result as i32
}

#[derive(Debug)]
pub(crate) struct DispatchAllocations {
    pool: Arc<DeviceAllocationPool>,
    ptrs: SmallVec<[DeviceAllocation; 8]>,
    params: DeviceAllocation,
}

impl DispatchAllocations {
    pub(crate) fn new(
        buffer_count: usize,
        pool: Arc<DeviceAllocationPool>,
    ) -> Result<Self, BackendError> {
        let mut ptrs = SmallVec::new();
        ptrs.try_reserve_exact(buffer_count).map_err(|error| {
            BackendError::InvalidProgram {
                fix: format!(
                    "Fix: CUDA dispatch allocation table could not reserve {buffer_count} buffer pointer slots: {error}. Shard the dispatch before launch."
                ),
            }
        })?;
        ptrs.extend((0..buffer_count).map(|_| DeviceAllocation::default()));
        Ok(Self {
            pool,
            ptrs,
            params: DeviceAllocation::default(),
        })
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

// SAFETY: PinnedHostAllocation owns a CUDA-pinned host pointer that
// is valid across threads. The pinned-host page is allocated by
// cuMemHostAlloc with CU_MEMHOSTALLOC_PORTABLE so it is addressable
// from every CUDA context on this process; the Rust-level
// PinnedHostAllocationPool synchronises bucket-cache access with
// DashMap + SegQueue so concurrent take/release is safe. Send + Sync
// are sound because no thread can produce a torn read of the raw
// pointer (it is just an address) or the byte_len.
unsafe impl Send for PinnedHostAllocation {}
// SAFETY: see the Send impl above — same reasoning applies for
// shared (&) access; PinnedHostAllocation is Copy and never holds
// thread-local state.
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

    pub(crate) fn copy_from_slice(&mut self, bytes: &[u8]) -> Result<(), BackendError> {
        if bytes.len() > self.byte_len {
            return Err(BackendError::InvalidProgram {
                fix: format!(
                    "Fix: CUDA pinned-host upload attempted to copy {} byte(s) into a {} byte allocation. Recompute transfer sizing before enqueueing DMA.",
                    bytes.len(),
                    self.byte_len
                ),
            });
        }
        if bytes.is_empty() {
            return Ok(());
        }
        // SAFETY: bytes.as_ptr() is a valid &[u8] source for bytes.len()
        // bytes; self.ptr is a CUDA-pinned host allocation of self.byte_len
        // bytes (checked above proves bytes.len() ≤ self.byte_len);
        // pinned-host memory and stack/heap memory cannot overlap so
        // copy_nonoverlapping's non-aliasing precondition holds.
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), self.ptr, bytes.len());
        }
        Ok(())
    }

    pub(crate) fn copy_u32_le_words(&mut self, words: &[u32]) -> Result<(), BackendError> {
        let byte_len = std::mem::size_of_val(words);
        if byte_len > self.byte_len {
            return Err(BackendError::InvalidProgram {
                fix: format!(
                    "Fix: CUDA pinned-host u32 upload attempted to copy {byte_len} byte(s) into a {} byte allocation. Recompute parameter staging size before launch.",
                    self.byte_len
                ),
            });
        }
        if byte_len == 0 {
            return Ok(());
        }
        #[cfg(target_endian = "little")]
        // SAFETY: same as copy_from_slice — words.as_ptr() is a valid
        // &[u32] source for byte_len bytes (size_of_val); self.ptr owns
        // self.byte_len ≥ byte_len bytes of pinned-host memory by the
        // checked guard above; cast to
        // u8 is safe because u32 → u8 narrowing of a pointer reads the
        // same address space.
        unsafe {
            std::ptr::copy_nonoverlapping(words.as_ptr().cast::<u8>(), self.ptr, byte_len);
        }
        #[cfg(not(target_endian = "little"))]
        {
            // SAFETY: self.ptr is a valid pinned-host allocation of
            // self.byte_len ≥ byte_len bytes (debug_assert above) and is
            // not aliased while we hold &mut self.
            let dst = unsafe { std::slice::from_raw_parts_mut(self.ptr, byte_len) };
            for (chunk, word) in dst.chunks_exact_mut(4).zip(words) {
                chunk.copy_from_slice(&word.to_le_bytes());
            }
        }
        Ok(())
    }

    pub(crate) fn copy_prefix_into(
        &self,
        byte_len: usize,
        dst: &mut Vec<u8>,
    ) -> Result<(), BackendError> {
        if byte_len > self.byte_len {
            return Err(BackendError::InvalidProgram {
                fix: format!(
                    "Fix: CUDA pinned-host readback attempted to copy {byte_len} byte(s) from a {} byte allocation. Recompute output transfer sizing before collecting results.",
                    self.byte_len
                ),
            });
        }
        copy_raw_bytes_into_vec(self.ptr, byte_len, dst)
    }
}

fn copy_raw_bytes_into_vec(
    src: *const u8,
    byte_len: usize,
    dst: &mut Vec<u8>,
) -> Result<(), BackendError> {
    dst.clear();
    if byte_len == 0 {
        return Ok(());
    }
    if dst.capacity() < byte_len {
        reserve_vec(dst, byte_len, "CUDA readback output bytes")?;
    }
    // SAFETY: src is a non-null pointer to byte_len readable bytes
    // (caller's contract — every internal call site passes a CUDA-host
    // allocation pointer). dst.as_mut_ptr() points to dst's owned
    // capacity which is ≥ byte_len after the fallible reservation above.
    // dst is freshly cleared so set_len(byte_len) leaves the new
    // contents initialised by the copy.
    unsafe {
        std::ptr::copy_nonoverlapping(src, dst.as_mut_ptr(), byte_len);
        dst.set_len(byte_len);
    }
    Ok(())
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
        self.free.entry(bucket).or_default();
        let mut ptr = std::ptr::null_mut::<c_void>();
        // SAFETY: FFI to libcuda.so cuMemHostAlloc. &mut ptr is a valid
        // *mut *mut c_void output param; bucket is the byte size; the
        // PORTABLE flag is documented driver API. cuda_check propagates
        // a non-success CUresult as BackendError.
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

    #[cfg(test)]
    pub(crate) fn cached_bytes(&self) -> usize {
        self.cached_bytes.load(Ordering::Acquire)
    }

    fn take_cached(&self, bucket: usize) -> Result<Option<usize>, BackendError> {
        let Some(queue) = self.free.get(&bucket) else {
            return Ok(None);
        };
        let Some(ptr) = queue.pop() else {
            return Ok(None);
        };
        subtract_cached_bytes_or_repair(
            &self.cached_bytes,
            bucket,
            "CUDA pinned-host allocation-pool cached bytes",
        );
        Ok(Some(ptr))
    }

    pub(crate) fn release(&self, allocation: PinnedHostAllocation) {
        if allocation.ptr.is_null() || allocation.byte_len == 0 {
            return;
        }
        let Some(queue) = self.free.get(&allocation.byte_len) else {
            free_pinned_host_ptr(allocation.ptr.cast());
            return;
        };
        if !reserve_cached_bytes(
            &self.cached_bytes,
            self.max_cached_bytes,
            allocation.byte_len,
        ) {
            free_pinned_host_ptr(allocation.ptr.cast());
            return;
        }

        queue.push(allocation.ptr.addr());
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
    outputs: SmallVec<[HostOutputTransfer; 8]>,
}

#[derive(Clone, Copy, Debug)]
struct HostOutputTransfer {
    allocation_index: Option<usize>,
    byte_len: usize,
}

impl HostTransferAllocations {
    pub(crate) fn with_capacity(
        pool: Arc<PinnedHostAllocationPool>,
        transfer_capacity: usize,
        output_capacity: usize,
    ) -> Result<Self, BackendError> {
        let mut allocations = SmallVec::new();
        allocations
            .try_reserve_exact(transfer_capacity)
            .map_err(|error| BackendError::InvalidProgram {
                fix: format!(
                    "Fix: CUDA pinned-host transfer table could not reserve {transfer_capacity} transfer slot(s): {error}. Shard the transfer batch before launch."
                ),
            })?;
        let mut outputs = SmallVec::new();
        outputs
            .try_reserve_exact(output_capacity)
            .map_err(|error| BackendError::InvalidProgram {
                fix: format!(
                    "Fix: CUDA pinned-host output table could not reserve {output_capacity} readback slot(s): {error}. Shard the readback batch before launch."
                ),
            })?;
        Ok(Self {
            pool,
            allocations,
            outputs,
        })
    }

    pub(crate) fn push_upload(&mut self, bytes: &[u8]) -> Result<*const c_void, BackendError> {
        if bytes.is_empty() {
            return Ok(std::ptr::null());
        }
        let mut allocation = self.pool.acquire(bytes.len())?;
        allocation.copy_from_slice(bytes)?;
        let ptr = allocation.as_ptr();
        self.allocations.push(allocation);
        Ok(ptr)
    }

    pub(crate) fn push_u32_words(&mut self, words: &[u32]) -> Result<*const c_void, BackendError> {
        let byte_len = std::mem::size_of_val(words);
        if byte_len == 0 {
            return Ok(std::ptr::null());
        }
        let mut allocation = self.pool.acquire(byte_len)?;
        allocation.copy_u32_le_words(words)?;
        let ptr = allocation.as_ptr();
        self.allocations.push(allocation);
        Ok(ptr)
    }

    pub(crate) fn push_output(&mut self, byte_len: usize) -> Result<*mut c_void, BackendError> {
        if byte_len == 0 {
            self.outputs.push(HostOutputTransfer {
                allocation_index: None,
                byte_len,
            });
            return Ok(std::ptr::null_mut());
        }
        let mut allocation = self.pool.acquire(byte_len)?;
        let ptr = allocation.as_mut_ptr();
        let index = self.allocations.len();
        self.allocations.push(allocation);
        self.outputs.push(HostOutputTransfer {
            allocation_index: Some(index),
            byte_len,
        });
        Ok(ptr)
    }

    pub(crate) fn collect_outputs_into(
        &self,
        outputs: &mut Vec<Vec<u8>>,
    ) -> Result<(), BackendError> {
        reserve_vec(
            outputs,
            self.outputs.len(),
            "CUDA host transfer output vector",
        )?;
        resize_vec_slots(
            outputs,
            self.outputs.len(),
            "CUDA host transfer output vector",
        )?;
        for output_index in 0..self.outputs.len() {
            self.collect_output_into(output_index, &mut outputs[output_index])?;
        }
        Ok(())
    }

    pub(crate) fn collect_borrowed_outputs_into(
        &self,
        outputs: &mut [&mut Vec<u8>],
    ) -> Result<(), BackendError> {
        if outputs.len() != self.outputs.len() {
            return Err(BackendError::InvalidProgram {
                fix: format!(
                    "Fix: CUDA borrowed output collection received {} output slot(s) for {} pending readback(s). Pass one output buffer per declared CUDA output.",
                    outputs.len(),
                    self.outputs.len()
                ),
            });
        }
        for (output_index, output) in outputs.iter_mut().enumerate() {
            self.collect_output_into(output_index, *output)?;
        }
        Ok(())
    }

    pub(crate) fn collect_output_into(
        &self,
        output_index: usize,
        output: &mut Vec<u8>,
    ) -> Result<(), BackendError> {
        let Some(&transfer) = self.outputs.get(output_index) else {
            return Err(BackendError::InvalidProgram {
                fix: format!(
                    "Fix: CUDA output collection requested output index {output_index}, but only {} output transfer(s) exist.",
                    self.outputs.len()
                ),
            });
        };
        if let Some(allocation_index) = transfer.allocation_index {
            let Some(allocation) = self.allocations.get(allocation_index) else {
                return Err(BackendError::InvalidProgram {
                    fix: format!(
                        "Fix: CUDA output transfer {output_index} references allocation index {allocation_index}, but only {} allocation(s) exist.",
                        self.allocations.len()
                    ),
                });
            };
            allocation.copy_prefix_into(transfer.byte_len, output)?;
        } else {
            output.clear();
        }
        Ok(())
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
    allocated_bytes: AtomicUsize,
    max_cached_bytes: usize,
}

impl DeviceAllocationPool {
    pub(crate) fn new(max_cached_bytes: usize) -> Self {
        Self {
            free: DashMap::with_hasher(BuildHasherDefault::<FxHasher>::default()),
            cached_bytes: AtomicUsize::new(0),
            allocated_bytes: AtomicUsize::new(0),
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
        self.free.entry(bucket).or_default();
        let mut ptr = 0u64;
        // SAFETY: FFI to libcuda.so cuMemAlloc_v2. &mut ptr is a valid
        // *mut CUdeviceptr output param; bucket is the byte size to
        // allocate. cuda_check propagates a non-success CUresult as a
        // BackendError so the returned ptr is only consumed on success.
        unsafe {
            cuda_check(
                cudarc::driver::sys::cuMemAlloc_v2(&mut ptr, bucket),
                "cuMemAlloc_v2",
            )?;
        }
        if let Err(error) = add_cached_bytes(
            &self.allocated_bytes,
            bucket,
            "CUDA allocation-pool live device bytes",
        ) {
            free_cuda_ptr(ptr);
            return Err(error);
        }
        Ok(DeviceAllocation {
            ptr,
            byte_len: bucket,
        })
    }

    pub(crate) fn cached_bytes(&self) -> Result<usize, BackendError> {
        Ok(self.cached_bytes.load(Ordering::Acquire))
    }

    pub(crate) fn allocated_bytes(&self) -> Result<usize, BackendError> {
        Ok(self.allocated_bytes.load(Ordering::Acquire))
    }

    pub(crate) fn clear(&self) -> Result<(), BackendError> {
        let mut freed_bytes = 0usize;
        for entry in &self.free {
            while let Some(ptr) = entry.value().pop() {
                free_cuda_ptr(ptr);
                freed_bytes =
                    freed_bytes
                        .checked_add(*entry.key())
                        .ok_or_else(|| BackendError::InvalidProgram {
                            fix: "Fix: CUDA allocation-pool clear byte accounting overflowed usize; allocator state is corrupt."
                                .to_string(),
                        })?;
            }
        }
        self.free.clear();
        self.cached_bytes.store(0, Ordering::Release);
        subtract_cached_bytes_or_repair(
            &self.allocated_bytes,
            freed_bytes,
            "CUDA allocation-pool live device bytes",
        );
        Ok(())
    }

    fn take_cached(&self, bucket: usize) -> Result<Option<u64>, BackendError> {
        let Some(queue) = self.free.get(&bucket) else {
            return Ok(None);
        };
        let Some(ptr) = queue.pop() else {
            return Ok(None);
        };
        subtract_cached_bytes_or_repair(
            &self.cached_bytes,
            bucket,
            "CUDA allocation-pool cached device bytes",
        );
        Ok(Some(ptr))
    }

    pub(crate) fn release(&self, allocation: DeviceAllocation) {
        if allocation.ptr == 0 || allocation.byte_len == 0 {
            return;
        }
        let Some(queue) = self.free.get(&allocation.byte_len) else {
            free_cuda_ptr(allocation.ptr);
            if let Err(error) = subtract_cached_bytes(&self.allocated_bytes, allocation.byte_len) {
                eprintln!("{error}");
            }
            return;
        };
        if !reserve_cached_bytes(
            &self.cached_bytes,
            self.max_cached_bytes,
            allocation.byte_len,
        ) {
            free_cuda_ptr(allocation.ptr);
            if let Err(error) = subtract_cached_bytes(&self.allocated_bytes, allocation.byte_len) {
                eprintln!("{error}");
            }
            return;
        }

        queue.push(allocation.ptr);
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
        self.allocated_bytes.store(0, Ordering::Release);
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

fn add_cached_bytes(
    counter: &AtomicUsize,
    bytes: usize,
    label: &'static str,
) -> Result<(), BackendError> {
    let mut observed = counter.load(Ordering::Acquire);
    loop {
        let next = observed.checked_add(bytes).ok_or_else(|| {
            BackendError::InvalidProgram {
                fix: format!(
                    "Fix: {label} accounting overflowed while adding {bytes} to observed {observed}; shard the allocation workload before enqueueing more CUDA work."
                ),
            }
        })?;
        match counter.compare_exchange_weak(observed, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return Ok(()),
            Err(actual) => observed = actual,
        }
    }
}

fn subtract_cached_bytes(counter: &AtomicUsize, bytes: usize) -> Result<(), BackendError> {
    let mut observed = counter.load(Ordering::Acquire);
    loop {
        let next = observed.checked_sub(bytes).ok_or_else(|| {
            BackendError::InvalidProgram {
                fix: format!(
                    "Fix: CUDA allocation-pool byte accounting underflowed while subtracting {bytes} from observed {observed}; allocator state is corrupt."
                ),
            }
        })?;
        match counter.compare_exchange_weak(observed, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return Ok(()),
            Err(actual) => observed = actual,
        }
    }
}

fn subtract_cached_bytes_or_repair(counter: &AtomicUsize, bytes: usize, label: &'static str) {
    let mut observed = counter.load(Ordering::Acquire);
    loop {
        let Some(next) = observed.checked_sub(bytes) else {
            match counter.compare_exchange_weak(observed, 0, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => {
                    tracing::error!(
                        "{label} underflowed while subtracting {bytes} from observed {observed}; repaired accounting to zero."
                    );
                    return;
                }
                Err(actual) => {
                    observed = actual;
                    continue;
                }
            }
        };
        match counter.compare_exchange_weak(observed, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return,
            Err(actual) => observed = actual,
        }
    }
}

pub(crate) fn free_cuda_ptr(ptr: u64) {
    if ptr == 0 {
        return;
    }
    // SAFETY: FFI to libcuda.so cuMemFree_v2. ptr was returned by a
    // matching cuMemAlloc_v2 call (the pool owns the lifetime); the
    // null guard above ensures we never pass 0. CUDA_SUCCESS check
    // surfaces unexpected failures via stderr without propagating
    // (free runs on Drop / pool clear paths where ?-propagation is
    // not available).
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
    // SAFETY: FFI to libcuda.so cuMemFreeHost. ptr was returned by a
    // matching cuMemHostAlloc call; the null guard above ensures we
    // never pass nullptr. Same Drop-path stderr fallback as
    // free_cuda_ptr above.
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
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    use super::{
        copy_raw_bytes_into_vec, subtract_cached_bytes, HostOutputTransfer,
        HostTransferAllocations, PinnedHostAllocation, PinnedHostAllocationPool,
    };

    #[test]
    fn copy_raw_bytes_into_vec_reuses_capacity_without_zero_fill_resize() {
        let src = [1u8, 2, 3, 4, 5, 6];
        let mut dst = Vec::with_capacity(16);
        dst.extend_from_slice(&[9, 9, 9, 9]);
        let capacity = dst.capacity();

        copy_raw_bytes_into_vec(src.as_ptr(), 4, &mut dst).unwrap();

        assert_eq!(dst, vec![1, 2, 3, 4]);
        assert_eq!(dst.capacity(), capacity);

        copy_raw_bytes_into_vec(src[2..].as_ptr(), 0, &mut dst).unwrap();
        assert!(dst.is_empty());
        assert_eq!(dst.capacity(), capacity);
    }

    #[test]
    fn zero_byte_output_readback_does_not_acquire_pinned_host_memory() {
        let pool = Arc::new(PinnedHostAllocationPool::new(0));
        let mut transfers = HostTransferAllocations::with_capacity(Arc::clone(&pool), 0, 1)
            .expect("host transfer table should reserve");

        let ptr = transfers
            .push_output(0)
            .expect("zero-byte output reservation must not touch CUDA allocation APIs");

        assert!(ptr.is_null());
        assert!(transfers.allocations.is_empty());

        let mut outputs = vec![vec![1, 2, 3]];
        let capacity = outputs[0].capacity();
        transfers.collect_outputs_into(&mut outputs).unwrap();

        assert_eq!(outputs.len(), 1);
        assert!(outputs[0].is_empty());
        assert_eq!(outputs[0].capacity(), capacity);
        assert_eq!(pool.cached_bytes(), 0);
    }

    #[test]
    fn borrowed_zero_byte_output_readback_preserves_caller_capacity() {
        let pool = Arc::new(PinnedHostAllocationPool::new(0));
        let mut transfers = HostTransferAllocations::with_capacity(Arc::clone(&pool), 0, 1)
            .expect("host transfer table should reserve");
        let ptr = transfers
            .push_output(0)
            .expect("zero-byte borrowed output reservation must not touch CUDA allocation APIs");
        let mut output = Vec::with_capacity(32);
        output.extend_from_slice(&[7, 7, 7, 7]);
        let capacity = output.capacity();

        assert!(ptr.is_null());
        transfers
            .collect_borrowed_outputs_into(&mut [&mut output])
            .unwrap();

        assert!(output.is_empty());
        assert_eq!(output.capacity(), capacity);
        assert_eq!(pool.cached_bytes(), 0);
    }

    #[test]
    fn zero_byte_uploads_do_not_acquire_pinned_host_memory() {
        let pool = Arc::new(PinnedHostAllocationPool::new(0));
        let mut transfers = HostTransferAllocations::with_capacity(Arc::clone(&pool), 2, 0)
            .expect("host transfer table should reserve");

        let bytes_ptr = transfers
            .push_upload(&[])
            .expect("empty byte upload must not touch CUDA allocation APIs");
        let words_ptr = transfers
            .push_u32_words(&[])
            .expect("empty parameter upload must not touch CUDA allocation APIs");

        assert!(bytes_ptr.is_null());
        assert!(words_ptr.is_null());
        assert!(transfers.allocations.is_empty());
        assert_eq!(pool.cached_bytes(), 0);
    }

    #[test]
    fn pinned_host_copy_rejects_oversized_upload_in_release_path() {
        let mut allocation = PinnedHostAllocation {
            ptr: std::ptr::NonNull::<u8>::dangling().as_ptr(),
            byte_len: 2,
        };
        let error = allocation
            .copy_from_slice(&[1, 2, 3])
            .expect_err("oversized pinned-host upload must return a typed error");

        assert!(
            error.to_string().contains("attempted to copy 3 byte"),
            "error should describe the oversized host upload: {error}"
        );
    }

    #[test]
    fn pinned_host_readback_rejects_oversized_prefix_in_release_path() {
        let allocation = PinnedHostAllocation {
            ptr: std::ptr::NonNull::<u8>::dangling().as_ptr(),
            byte_len: 2,
        };
        let mut output = Vec::new();
        let error = allocation
            .copy_prefix_into(3, &mut output)
            .expect_err("oversized pinned-host readback must return a typed error");

        assert!(
            error.to_string().contains("attempted to copy 3 byte"),
            "error should describe the oversized host readback: {error}"
        );
    }

    #[test]
    fn borrowed_output_collection_rejects_slot_count_mismatch() {
        let pool = Arc::new(PinnedHostAllocationPool::new(0));
        let mut transfers = HostTransferAllocations::with_capacity(pool, 0, 1)
            .expect("host transfer table should reserve");
        transfers.outputs.push(HostOutputTransfer {
            allocation_index: None,
            byte_len: 0,
        });
        let error = transfers
            .collect_borrowed_outputs_into(&mut [])
            .expect_err("borrowed output collection must reject slot-count mismatch");

        assert!(
            error
                .to_string()
                .contains("one output buffer per declared CUDA output"),
            "error should describe the borrowed output slot mismatch: {error}"
        );
    }

    #[test]
    fn output_collection_rejects_out_of_range_transfer_index() {
        let pool = Arc::new(PinnedHostAllocationPool::new(0));
        let transfers = HostTransferAllocations::with_capacity(pool, 0, 0)
            .expect("host transfer table should reserve");
        let mut output = Vec::new();
        let error = transfers
            .collect_output_into(0, &mut output)
            .expect_err("output collection must reject out-of-range transfer indexes");

        assert!(
            error.to_string().contains("requested output index 0"),
            "error should describe the invalid output transfer index: {error}"
        );
    }

    #[test]
    fn subtract_cached_bytes_fails_loudly_on_accounting_underflow() {
        let counter = AtomicUsize::new(4);
        let error = subtract_cached_bytes(&counter, 8)
            .expect_err("Fix: allocation-pool underflow must return a typed error.");
        assert!(error.to_string().contains("underflowed"));
        assert_eq!(counter.load(Ordering::Acquire), 4);
    }

    #[test]
    fn allocation_pool_accounting_uses_checked_arithmetic_not_saturation() {
        let source = include_str!("allocations.rs");
        assert!(
            !source.contains(concat!(".", "saturating_add"))
                && !source.contains(concat!(".", "saturating_sub")),
            "Fix: CUDA allocation-pool byte accounting must not saturate overflow or underflow."
        );
        let counter = AtomicUsize::new(8);
        subtract_cached_bytes(&counter, 3)
            .expect("Fix: valid allocation-pool subtraction should succeed.");
        assert_eq!(counter.load(Ordering::Acquire), 5);
    }

    #[test]
    fn cuda_device_allocation_is_freed_when_live_accounting_fails_after_alloc() {
        let source = include_str!("allocations.rs");
        let acquire = source
            .split("pub(crate) fn acquire(&self, byte_len: usize) -> Result<DeviceAllocation, BackendError>")
            .nth(1)
            .and_then(|tail| tail.split("pub(crate) fn cached_bytes").next())
            .expect("DeviceAllocationPool::acquire source must be discoverable");
        assert!(
            acquire.contains("if let Err(error) = add_cached_bytes(")
                && acquire.contains("free_cuda_ptr(ptr);")
                && acquire.contains("return Err(error);"),
            "Fix: CUDA device allocation must free cuMemAlloc_v2 output if live-byte accounting fails after allocation."
        );
        assert!(
            source.contains("subtract_cached_bytes_or_repair("),
            "Fix: cached CUDA allocation-pool byte accounting must repair non-critical cache counters instead of rejecting valid pool reuse."
        );
    }

    #[test]
    fn cuda_dispatch_and_host_transfer_tables_reserve_fallibly() {
        let source = include_str!("allocations.rs");
        assert!(
            source.contains("ptrs.try_reserve_exact(buffer_count)")
                && source.contains("allocations")
                && source.contains("try_reserve_exact(transfer_capacity)")
                && source.contains("try_reserve_exact(output_capacity)"),
            "Fix: CUDA dispatch and host-transfer staging tables must reserve fallibly before launch."
        );
        assert!(
            !source.contains(concat!("SmallVec::with_capacity", "(buffer_count)"))
                && !source.contains(concat!("ptrs", ".resize(buffer_count"))
                && !source.contains(concat!(
                    "SmallVec::with_capacity",
                    "(transfer_capacity)"
                ))
                && !source.contains(concat!(
                    "SmallVec::with_capacity",
                    "(output_capacity)"
                )),
            "Fix: CUDA allocation staging must not use infallible SmallVec capacity constructors in production."
        );
    }

    #[test]
    fn pinned_host_transfer_bounds_are_checked_without_debug_assert_contracts() {
        let source = include_str!("allocations.rs");
        let pinned_allocation = source
            .split("impl PinnedHostAllocation {")
            .nth(1)
            .expect("pinned-host allocation impl must be present")
            .split("#[derive(Debug)]\npub(crate) struct PinnedHostAllocationPool")
            .next()
            .expect("pinned-host allocation impl must precede pool type");
        let host_transfers = source
            .split("impl HostTransferAllocations {")
            .nth(1)
            .expect("host transfer impl must be present")
            .split("impl Drop for HostTransferAllocations")
            .next()
            .expect("host transfer impl must precede Drop impl");

        assert!(
            pinned_allocation.contains("pub(crate) fn copy_from_slice(&mut self, bytes: &[u8]) -> Result<(), BackendError>")
                && pinned_allocation.contains("pub(crate) fn copy_u32_le_words(&mut self, words: &[u32]) -> Result<(), BackendError>")
                && host_transfers.contains("pub(crate) fn collect_borrowed_outputs_into(")
                && !host_transfers.contains("debug_assert_eq!(outputs.len(), self.outputs.len())")
                && !pinned_allocation.contains("debug_assert!(byte_len <= self.byte_len)")
                && !pinned_allocation.contains("debug_assert!(bytes.len() <= self.byte_len)"),
            "Fix: CUDA pinned-host transfer bounds must be checked in release builds, not guarded only by debug_assert."
        );
    }
}
