//! CUDA-resident buffer table and in-flight handle accounting.

use std::hash::BuildHasherDefault;
use std::sync::{
    atomic::{AtomicU64, AtomicUsize, Ordering},
    Arc,
};

use dashmap::DashMap;
use cudarc::driver::sys::CUresult;
use rustc_hash::FxHasher;
use smallvec::SmallVec;
use vyre_driver::BackendError;

use super::allocations::cuda_check;

#[derive(Debug)]
pub(crate) struct ResidentBuffer {
    pub(crate) ptr: u64,
    pub(crate) byte_len: usize,
}

unsafe impl Send for ResidentBuffer {}
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
}

impl CudaResidentStore {
    pub(crate) fn new() -> Self {
        Self {
            buffers: DashMap::with_hasher(BuildHasherDefault::<FxHasher>::default()),
            inflight: Arc::new(DashMap::with_hasher(
                BuildHasherDefault::<FxHasher>::default(),
            )),
            next_id: AtomicU64::new(1),
        }
    }

    pub(crate) fn clear(&self) -> Result<(), BackendError> {
        let inflight = self.inflight_count();
        if inflight != 0 {
            return Err(BackendError::InvalidProgram {
                fix: format!(
                    "Fix: CUDA cleanup found {inflight} resident buffer handle reference(s) still bound to in-flight dispatches; wait for pending work before shutdown."
                ),
            });
        }
        self.buffers.clear();
        self.inflight.clear();
        Ok(())
    }

    pub(crate) fn allocate(&self, byte_len: usize) -> Result<CudaResidentBuffer, BackendError> {
        if byte_len == 0 {
            return Err(BackendError::InvalidProgram {
                fix: "Fix: CUDA resident buffers must have a non-zero byte length.".to_string(),
            });
        }
        let mut ptr = 0u64;
        unsafe {
            cuda_check(
                cudarc::driver::sys::cuMemAlloc_v2(&mut ptr, byte_len),
                "cuMemAlloc_v2",
            )?;
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
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
        self.buffers
            .remove(&handle.id)
            .ok_or_else(|| BackendError::InvalidProgram {
                fix: format!(
                    "Fix: CUDA resident buffer handle {} is not owned by this backend.",
                    handle.id
                ),
            })?;
        self.inflight.remove(&handle.id);
        Ok(())
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
        let mut ids = SmallVec::<[u64; 8]>::with_capacity(handles.len());
        for handle in handles {
            ids.push(handle.id);
        }
        for id in &ids {
            self.inflight
                .entry(*id)
                .or_insert_with(|| AtomicUsize::new(0))
                .fetch_add(1, Ordering::AcqRel);
        }
        let guard = ResidentUseGuard {
            inflight: Arc::clone(&self.inflight),
            ids,
        };
        for handle in handles {
            self.view(*handle)?;
        }
        Ok(guard)
    }

    pub(crate) fn handles_from_resources(
        &self,
        resources: &[vyre_driver::Resource],
    ) -> Result<SmallVec<[CudaResidentBuffer; 8]>, BackendError> {
        let mut handles = SmallVec::with_capacity(resources.len());
        for resource in resources {
            match resource {
                vyre_driver::Resource::Resident(id) => {
                    let buffer =
                        self.buffers
                            .get(id)
                            .ok_or_else(|| BackendError::InvalidProgram {
                                fix: format!(
                                    "Fix: CUDA compiled resident dispatch received unknown resident handle {id}."
                                ),
                            })?;
                    handles.push(CudaResidentBuffer {
                        id: *id,
                        byte_len: buffer.byte_len,
                    });
                }
                vyre_driver::Resource::Borrowed(_) => {
                    return Err(BackendError::UnsupportedFeature {
                        name: "cuda_compiled_persistent_borrowed_resource".to_string(),
                        backend: crate::CUDA_BACKEND_ID.to_string(),
                    });
                }
            }
        }
        Ok(handles)
    }

    fn inflight_for(&self, id: u64) -> usize {
        self.inflight
            .get(&id)
            .map(|count| count.load(Ordering::Acquire))
            .unwrap_or(0)
    }

    fn inflight_count(&self) -> usize {
        self.inflight
            .iter()
            .map(|entry| entry.value().load(Ordering::Acquire))
            .sum()
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
            if let Some(count) = self.inflight.get(id) {
                count
                    .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                        Some(value.saturating_sub(1))
                    })
                    .ok();
            }
        }
    }
}
