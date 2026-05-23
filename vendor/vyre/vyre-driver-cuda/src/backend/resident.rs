//! CUDA-resident buffer table and in-flight handle accounting.

use std::hash::BuildHasherDefault;
use std::sync::{
    atomic::{AtomicU64, AtomicUsize, Ordering},
    Arc,
};

use cudarc::driver::sys::CUresult;
use dashmap::DashMap;
use rustc_hash::{FxHashMap, FxHasher};
use smallvec::SmallVec;
use vyre_driver::BackendError;

use super::accounting::checked_sub_u64;
use super::allocations::{cuda_check, free_cuda_ptr};
use super::staging_reserve::{reserve_hash_map, reserve_smallvec};

#[derive(Debug)]
pub(crate) struct ResidentBuffer {
    pub(crate) ptr: u64,
    pub(crate) byte_len: usize,
}

// SAFETY: FFI to libcuda.so. Pointer args were validated by the matching alloc
// / store API; lifetimes are documented in the surrounding function.
// cuda_check (or matching CUresult guard) propagates non-success codes as
// BackendError.
unsafe impl Send for ResidentBuffer {}
// SAFETY: FFI to libcuda.so. Pointer args were validated by the matching alloc
// / store API; lifetimes are documented in the surrounding function.
// cuda_check (or matching CUresult guard) propagates non-success codes as
// BackendError.
unsafe impl Sync for ResidentBuffer {}

impl Drop for ResidentBuffer {
    fn drop(&mut self) {
        if self.ptr != 0 {
            // SAFETY: `ptr` came from `cuMemAlloc_v2` and is owned by this handle.
            unsafe {
                let result = cudarc::driver::sys::cuMemFree_v2(self.ptr);
                if result != CUresult::CUDA_SUCCESS {
                    eprintln!(
                        "Fix: cuMemFree_v2 failed while dropping CUDA resident buffer with {result:?}; ensure all resident dispatches have completed."
                    );
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ResidentBufferView {
    pub(crate) ptr: u64,
    pub(crate) byte_len: usize,
}

/// Stable CUDA-resident buffer handle owned by [`crate::backend::CudaBackend`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CudaResidentBuffer {
    /// Opaque backend-local handle id.
    pub id: u64,
    /// Buffer size in bytes.
    pub byte_len: usize,
}

#[derive(Debug)]
pub(crate) struct CudaResidentStore {
    buffers: DashMap<u64, ResidentBuffer, BuildHasherDefault<FxHasher>>,
    inflight: Arc<DashMap<u64, AtomicUsize, BuildHasherDefault<FxHasher>>>,
    next_id: AtomicU64,
    resident_bytes: AtomicU64,
}

impl CudaResidentStore {
    pub(crate) fn new() -> Self {
        Self {
            buffers: DashMap::with_hasher(BuildHasherDefault::<FxHasher>::default()),
            inflight: Arc::new(DashMap::with_hasher(
                BuildHasherDefault::<FxHasher>::default(),
            )),
            next_id: AtomicU64::new(1),
            resident_bytes: AtomicU64::new(0),
        }
    }

    pub(crate) fn clear(&self) -> Result<(), BackendError> {
        let inflight = self.inflight_count()?;
        if inflight != 0 {
            return Err(BackendError::InvalidProgram {
                fix: format!(
                    "Fix: CUDA cleanup found {inflight} resident buffer handle reference(s) still bound to in-flight dispatches; wait for pending work before shutdown."
                ),
            });
        }
        self.buffers.clear();
        self.inflight.clear();
        self.resident_bytes.store(0, Ordering::Release);
        Ok(())
    }

    pub(crate) fn allocate(
        &self,
        byte_len: usize,
        budget_bytes: u64,
    ) -> Result<CudaResidentBuffer, BackendError> {
        if byte_len == 0 {
            return Err(BackendError::InvalidProgram {
                fix: "Fix: CUDA resident buffers must have a non-zero byte length.".to_string(),
            });
        }
        let requested_bytes = u64::try_from(byte_len).map_err(|_| BackendError::InvalidProgram {
            fix: format!(
                "Fix: CUDA resident allocation request of {byte_len} bytes does not fit u64 accounting; shard the resident buffer."
            ),
        })?;
        reserve_resident_budget(&self.resident_bytes, requested_bytes, budget_bytes)?;
        let mut ptr = 0u64;
        // SAFETY: FFI to libcuda.so. Pointer args were validated by the
        // matching alloc / store API; lifetimes are documented in the
        // surrounding function. cuda_check (or matching CUresult guard)
        // propagates non-success codes as BackendError.
        unsafe {
            let allocation_result = cuda_check(
                cudarc::driver::sys::cuMemAlloc_v2(&mut ptr, byte_len),
                "cuMemAlloc_v2",
            );
            if let Err(error) = allocation_result {
                release_resident_budget_or_repair(
                    &self.resident_bytes,
                    requested_bytes,
                    "CUDA resident budget rollback after allocation failure",
                );
                return Err(error);
            }
        }
        let id = match allocate_resident_handle_id(&self.next_id) {
            Ok(id) => id,
            Err(error) => {
                free_cuda_ptr(ptr);
                release_resident_budget_or_repair(
                    &self.resident_bytes,
                    requested_bytes,
                    "CUDA resident budget rollback after handle-id allocation failure",
                );
                return Err(error);
            }
        };
        self.buffers.insert(id, ResidentBuffer { ptr, byte_len });
        Ok(CudaResidentBuffer { id, byte_len })
    }

    pub(crate) fn free(&self, handle: CudaResidentBuffer) -> Result<(), BackendError> {
        let in_use = self.inflight_for(handle.id);
        if in_use != 0 {
            return Err(BackendError::InvalidProgram {
                fix: format!(
                    "Fix: CUDA resident buffer handle {} is bound to {in_use} in-flight dispatch(es); wait for the pending dispatch before freeing it.",
                    handle.id
                ),
            });
        }
        let (_, removed) =
            self.buffers
                .remove(&handle.id)
                .ok_or_else(|| BackendError::InvalidProgram {
                    fix: format!(
                        "Fix: CUDA resident buffer handle {} is not owned by this backend.",
                        handle.id
                    ),
                })?;
        let removed_bytes =
            u64::try_from(removed.byte_len).map_err(|_| BackendError::InvalidProgram {
                fix: format!(
                    "Fix: CUDA resident buffer handle {} has {} bytes, which does not fit u64 accounting on this target; recreate the backend and shard resident buffers.",
                    handle.id, removed.byte_len
                ),
            })?;
        if release_resident_budget(&self.resident_bytes, removed_bytes).is_err() {
            self.rebuild_resident_byte_accounting()?;
        }
        self.inflight.remove(&handle.id);
        Ok(())
    }

    pub(crate) fn allocated_bytes(&self) -> u64 {
        self.resident_bytes.load(Ordering::Acquire)
    }

    pub(crate) fn view(
        &self,
        handle: CudaResidentBuffer,
    ) -> Result<ResidentBufferView, BackendError> {
        let buffer = self
            .buffers
            .get(&handle.id)
            .ok_or_else(|| BackendError::InvalidProgram {
                fix: format!(
                    "Fix: CUDA resident buffer handle {} is not owned by this backend.",
                    handle.id
                ),
            })?;
        if buffer.byte_len != handle.byte_len {
            return Err(BackendError::InvalidProgram {
                fix: format!(
                    "Fix: CUDA resident buffer handle {} byte length drifted from {} to {}.",
                    handle.id, handle.byte_len, buffer.byte_len
                ),
            });
        }
        Ok(ResidentBufferView {
            ptr: buffer.ptr,
            byte_len: buffer.byte_len,
        })
    }

    pub(crate) fn mark_inflight(
        &self,
        handles: &[CudaResidentBuffer],
    ) -> Result<ResidentUseGuard, BackendError> {
        let mut guard = ResidentUseGuard {
            inflight: Arc::clone(&self.inflight),
            ids: SmallVec::new(),
        };
        if handles.is_empty() {
            return Ok(guard);
        }
        reserve_smallvec(
            &mut guard.ids,
            handles.len(),
            "resident in-flight guard ids",
        )?;
        if handles.len() <= 8 {
            let mut seen = SmallVec::<[(u64, usize); 8]>::new();
            'mark_small: for handle in handles {
                for (seen_id, seen_byte_len) in &seen {
                    if *seen_id == handle.id {
                        if *seen_byte_len != handle.byte_len {
                            return Err(BackendError::InvalidProgram {
                                fix: format!(
                                    "Fix: CUDA resident buffer handle {} byte length drifted from {} to {} during in-flight marking.",
                                    handle.id, seen_byte_len, handle.byte_len
                                ),
                            });
                        }
                        continue 'mark_small;
                    }
                }
                seen.push((handle.id, handle.byte_len));
                self.mark_unique_inflight_handle(*handle, &mut guard)?;
            }
            return Ok(guard);
        }

        let mut seen = FxHashMap::default();
        reserve_hash_map(&mut seen, handles.len(), "resident duplicate check")?;
        for handle in handles {
            if let Some(&seen_byte_len) = seen.get(&handle.id) {
                if seen_byte_len != handle.byte_len {
                    return Err(BackendError::InvalidProgram {
                        fix: format!(
                            "Fix: CUDA resident buffer handle {} byte length drifted from {} to {} during in-flight marking.",
                            handle.id, seen_byte_len, handle.byte_len
                        ),
                    });
                }
                continue;
            }
            seen.insert(handle.id, handle.byte_len);
            self.mark_unique_inflight_handle(*handle, &mut guard)?;
        }
        Ok(guard)
    }

    fn mark_unique_inflight_handle(
        &self,
        handle: CudaResidentBuffer,
        guard: &mut ResidentUseGuard,
    ) -> Result<(), BackendError> {
        self.view(handle)?;
        let counter = self
            .inflight
            .entry(handle.id)
            .or_insert_with(|| AtomicUsize::new(0))
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(1)
            });
        counter.map_err(|value| BackendError::InvalidProgram {
            fix: format!(
                "Fix: CUDA resident in-flight reference count overflowed for handle {id} at {value}; wait for pending dispatches before rebinding this resident buffer.",
                id = handle.id
            ),
        })?;
        guard.ids.push(handle.id);
        Ok(())
    }

    pub(crate) fn handles_from_resources(
        &self,
        resources: &[vyre_driver::Resource],
    ) -> Result<SmallVec<[CudaResidentBuffer; 8]>, BackendError> {
        let mut handles = SmallVec::new();
        reserve_smallvec(&mut handles, resources.len(), "resident resource handles")?;
        for resource in resources {
            handles.push(self.handle_from_resource(resource)?);
        }
        Ok(handles)
    }

    pub(crate) fn handle_from_resource(
        &self,
        resource: &vyre_driver::Resource,
    ) -> Result<CudaResidentBuffer, BackendError> {
        match resource {
            vyre_driver::Resource::Resident(id) => {
                let buffer = self
                    .buffers
                    .get(id)
                    .ok_or_else(|| BackendError::InvalidProgram {
                        fix: format!(
                            "Fix: CUDA compiled resident dispatch received unknown resident handle {id}."
                        ),
                    })?;
                Ok(CudaResidentBuffer {
                    id: *id,
                    byte_len: buffer.byte_len,
                })
            }
            vyre_driver::Resource::Borrowed(_) => Err(BackendError::UnsupportedFeature {
                name: "cuda_compiled_persistent_borrowed_resource".to_string(),
                backend: crate::CUDA_BACKEND_ID.to_string(),
            }),
        }
    }

    fn inflight_for(&self, id: u64) -> usize {
        match self.inflight.get(&id) {
            Some(count) => count.load(Ordering::Acquire),
            None => 0,
        }
    }

    fn rebuild_resident_byte_accounting(&self) -> Result<(), BackendError> {
        let mut total = 0u64;
        for entry in self.buffers.iter() {
            let bytes = u64::try_from(entry.byte_len).map_err(|_| BackendError::InvalidProgram {
                fix: format!(
                    "Fix: CUDA resident buffer handle {} has {} bytes, which does not fit u64 while rebuilding resident byte accounting; recreate the backend and shard resident buffers.",
                    entry.key(),
                    entry.byte_len
                ),
            })?;
            total = total.checked_add(bytes).ok_or_else(|| BackendError::InvalidProgram {
                fix: format!(
                    "Fix: CUDA resident byte accounting overflowed while rebuilding from live handle {} with {bytes} bytes; shard the resident set.",
                    entry.key()
                ),
            })?;
        }
        self.resident_bytes.store(total, Ordering::Release);
        Ok(())
    }

    fn inflight_count(&self) -> Result<usize, BackendError> {
        let mut total = 0usize;
        for entry in self.inflight.iter() {
            let count = entry.value().load(Ordering::Acquire);
            total = total.checked_add(count).ok_or_else(|| {
                BackendError::InvalidProgram {
                    fix: format!(
                        "Fix: CUDA resident in-flight reference count overflowed while summing handle {} with {count} reference(s). Wait for pending work and repair resident dispatch lifetime accounting; never continue with saturated in-flight state.",
                        entry.key()
                    ),
                }
            })?;
        }
        Ok(total)
    }
}

fn allocate_resident_handle_id(next_id: &AtomicU64) -> Result<u64, BackendError> {
    let mut observed = next_id.load(Ordering::Acquire);
    loop {
        if observed == u64::MAX {
            return Err(BackendError::InvalidProgram {
                fix: "Fix: CUDA resident buffer handle id space is exhausted before allocation; recreate the backend session instead of wrapping handle ids.".to_string(),
            });
        }
        let next = observed + 1;
        match next_id.compare_exchange_weak(observed, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return Ok(observed),
            Err(actual) => observed = actual,
        }
    }
}

fn reserve_resident_budget(
    resident_bytes: &AtomicU64,
    requested_bytes: u64,
    budget_bytes: u64,
) -> Result<(), BackendError> {
    let mut observed = resident_bytes.load(Ordering::Acquire);
    loop {
        let next = observed.checked_add(requested_bytes).ok_or_else(|| {
            BackendError::InvalidProgram {
                fix: format!(
                    "Fix: CUDA resident allocation accounting overflowed while adding {requested_bytes} bytes to {observed} resident bytes; shard the resident set."
                ),
            }
        })?;
        validate_resident_allocation_budget(next, budget_bytes)?;
        match resident_bytes.compare_exchange_weak(
            observed,
            next,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return Ok(()),
            Err(actual) => observed = actual,
        }
    }
}

fn release_resident_budget(
    resident_bytes: &AtomicU64,
    released_bytes: u64,
) -> Result<(), BackendError> {
    checked_sub_u64(resident_bytes, released_bytes, |observed, released| {
        BackendError::InvalidProgram {
                fix: format!(
                    "Fix: CUDA resident allocation accounting underflowed while releasing {released} bytes from {observed} resident bytes; recreate the backend because resident byte accounting is inconsistent."
                ),
            }
    })
}

fn release_resident_budget_or_repair(
    resident_bytes: &AtomicU64,
    released_bytes: u64,
    label: &'static str,
) {
    if let Err(error) = release_resident_budget(resident_bytes, released_bytes) {
        tracing::error!("{label}: {error}. Resident byte accounting was repaired to zero.");
        resident_bytes.store(0, Ordering::Release);
    }
}

pub(crate) fn validate_resident_allocation_budget(
    required_bytes: u64,
    budget_bytes: u64,
) -> Result<(), BackendError> {
    if required_bytes > budget_bytes {
        return Err(BackendError::InvalidProgram {
            fix: format!(
                "Fix: CUDA resident buffers would require {required_bytes} bytes but the live-device resident budget is {budget_bytes} bytes. Free unused resident handles, shard the resident set, compact outputs, or raise the CUDA resident memory budget deliberately."
            ),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_resident_allocation_budget;
    use vyre_driver::BackendError;

    #[test]
    fn resident_budget_validation_rejects_cumulative_over_budget_allocation() {
        let error = validate_resident_allocation_budget(1025, 1024)
            .expect_err("resident allocation must fail before CUDA allocation");

        match error {
            BackendError::InvalidProgram { fix } => {
                assert!(fix.contains("CUDA resident buffers would require 1025 bytes"));
                assert!(fix.contains("resident budget is 1024 bytes"));
                assert!(fix.contains("Free unused resident handles"));
            }
            other => panic!("expected InvalidProgram, got {other:?}"),
        }
    }

    #[test]
    fn resident_source_forbids_wrapping_handle_ids_and_inflight_counts() {
        let source = include_str!("resident.rs");
        assert!(
            !source.contains(concat!("next_id", ".fetch_add")),
            "Fix: CUDA resident handle ids must use checked compare-exchange allocation, not wrapping atomic fetch_add."
        );
        assert!(
            !source.contains(concat!(".fetch_add", "(1, Ordering::AcqRel)")),
            "Fix: CUDA resident in-flight reference counts must use checked increment, not wrapping atomic fetch_add."
        );
        assert!(
            !source.contains(concat!("total = total", ".saturating_add")),
            "Fix: CUDA resident in-flight totals must report overflow instead of hiding corrupt lifetime accounting behind saturated counts."
        );
        assert!(
            !source.contains(concat!("resident_bytes", "\n                    .fetch_sub"))
                && !source.contains(concat!("resident_bytes", "\n            .fetch_sub")),
            "Fix: CUDA resident byte accounting releases must use checked arithmetic, not wrapping atomic fetch_sub."
        );
        let allocate = source
            .split("pub(crate) fn allocate(")
            .nth(1)
            .and_then(|tail| tail.split("pub(crate) fn free(&self").next())
            .expect("resident allocate source must be discoverable");
        assert!(
            allocate.contains("free_cuda_ptr(ptr);")
                && allocate.contains("release_resident_budget_or_repair(")
                && allocate.contains("return Err(error);"),
            "Fix: CUDA resident allocation must free cuMemAlloc_v2 output and roll back budget if handle-id allocation fails after device allocation."
        );
        assert!(
            source.contains("fn rebuild_resident_byte_accounting(&self) -> Result<(), BackendError>"),
            "Fix: CUDA resident free must repair resident byte accounting from live handles when release accounting drifts."
        );
        assert!(
            source.contains("use super::staging_reserve::{reserve_hash_map, reserve_smallvec};"),
            "Fix: CUDA resident store must use the shared fallible staging reservation contract before mutating resident handle state."
        );
        assert!(
            source.contains("reserve_hash_map(&mut seen, handles.len(), \"resident duplicate check\")?"),
            "Fix: large resident handle duplicate detection must reserve fallibly before marking handles in-flight."
        );
        assert!(
            source.contains("reserve_smallvec(&mut guard.ids, handles.len(), \"resident in-flight guard ids\")?"),
            "Fix: resident in-flight guard ids must reserve fallibly before reference counts are incremented."
        );
        assert!(
            source.contains("fn mark_unique_inflight_handle(")
                && source.contains("self.mark_unique_inflight_handle(*handle, &mut guard)?;"),
            "Fix: resident in-flight marking must use one transactional validate/increment/stage helper across duplicate-detection strategies."
        );
        assert!(
            source.contains(".remove_if(id, |_, count| count.load(Ordering::Acquire) == 0)"),
            "Fix: resident in-flight guard drop must prune zero-count entries without removing concurrently reused handles."
        );
        assert!(
            !source.contains(concat!("FxHashMap::with_capacity", "_and_hasher")),
            "Fix: CUDA resident duplicate detection must not allocate hash storage infallibly."
        );
        assert!(
            !source.contains(concat!("SmallVec::<[u64; 8]>", "::with_capacity")),
            "Fix: CUDA resident in-flight guard ids must not rely on infallible SmallVec growth."
        );
        assert!(
            !source.contains(concat!("SmallVec::with_capacity", "(resources.len())")),
            "Fix: CUDA resident resource handle staging must not allocate infallibly."
        );
    }
}

/// Reference-count guard for resident buffers currently bound to async work.
#[derive(Debug)]
pub(crate) struct ResidentUseGuard {
    inflight: Arc<DashMap<u64, AtomicUsize, BuildHasherDefault<FxHasher>>>,
    ids: SmallVec<[u64; 8]>,
}

impl Drop for ResidentUseGuard {
    fn drop(&mut self) {
        for id in &self.ids {
            let should_remove = if let Some(count) = self.inflight.get(id) {
                match count.fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                    value.checked_sub(1)
                }) {
                    Ok(_) => count.load(Ordering::Acquire) == 0,
                    Err(value) => {
                        eprintln!(
                            "Fix: CUDA resident in-flight reference count underflowed for handle {id} at {value}; resident dispatch lifetime accounting is corrupt."
                        );
                        false
                    }
                }
            } else {
                false
            };
            if should_remove {
                self.inflight
                    .remove_if(id, |_, count| count.load(Ordering::Acquire) == 0);
            }
        }
    }
}
