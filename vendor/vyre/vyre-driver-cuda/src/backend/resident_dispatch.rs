//! CUDA dispatch path for long-lived resident buffers.

use std::collections::HashSet;
use std::hash::BuildHasherDefault;
use std::sync::Arc;

use rustc_hash::FxHasher;
use smallvec::SmallVec;
use vyre_driver::binding::BindingRole;
use vyre_driver::{BackendError, DispatchConfig, PendingDispatch};
use vyre_foundation::ir::Program;

use super::allocations::{cuda_check, DispatchAllocations, HostTransferAllocations};
use super::dispatch::CudaBackend;
use super::module_cache::ModuleCacheKey;
use super::output_range::{cuda_output_readback, CudaOutputReadback};
use super::plan::CudaDispatchPlan;
use super::resident::CudaResidentBuffer;

pub(crate) struct CudaResidentDispatch {
    pub(crate) pending: crate::stream::CudaPendingDispatch,
    pub(crate) output_handles: SmallVec<[CudaResidentBuffer; 8]>,
    pub(crate) output_readbacks: SmallVec<[CudaOutputReadback; 8]>,
}

pub(crate) struct CudaResidentBatchDispatch {
    pub(crate) pending: crate::stream::CudaPendingDispatch,
    pub(crate) output_handles: SmallVec<[SmallVec<[CudaResidentBuffer; 8]>; 8]>,
    pub(crate) output_readbacks: SmallVec<[SmallVec<[CudaOutputReadback; 8]>; 8]>,
}

impl CudaBackend {
    /// Dispatch a Program asynchronously using caller-provided CUDA-resident buffers.
    pub fn dispatch_resident_async(
        &self,
        program: &Program,
        handles: &[CudaResidentBuffer],
        config: &DispatchConfig,
    ) -> Result<Box<dyn PendingDispatch>, BackendError> {
        Ok(Box::new(
            self.dispatch_resident_async_concrete(program, handles, config, false)?
                .pending,
        ))
    }

    fn dispatch_resident_async_concrete(
        &self,
        program: &Program,
        handles: &[CudaResidentBuffer],
        config: &DispatchConfig,
        capture_timing: bool,
    ) -> Result<CudaResidentDispatch, BackendError> {
        let prepared = self.prepare_resident_dispatch(program, handles, config)?;

        let ptx_src = self.ptx_for_program_cached(program, config)?;
        let module_key = self.module_cache_key(&ptx_src);
        self.dispatch_resident_async_concrete_with_ptx_key(
            program,
            handles,
            config,
            &ptx_src,
            module_key,
            capture_timing,
            None,
            &prepared,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn dispatch_resident_async_concrete_with_ptx_key(
        &self,
        program: &Program,
        handles: &[CudaResidentBuffer],
        _config: &DispatchConfig,
        ptx_src: &str,
        module_key: ModuleCacheKey,
        capture_timing: bool,
        static_params_ptr: Option<u64>,
        prepared: &CudaDispatchPlan,
    ) -> Result<CudaResidentDispatch, BackendError> {
        self.warmup()?;
        let required_handles = prepared
            .bindings
            .bindings
            .iter()
            .filter(|binding| binding.role != BindingRole::Shared)
            .count();
        if handles.len() != required_handles {
            return Err(BackendError::InvalidProgram {
                fix: format!(
                    "Fix: CUDA resident dispatch expected {required_handles} resident buffer handle(s) but received {}.",
                    handles.len()
                ),
            });
        }
        let stream = self.launch_resources.acquire_stream()?;
        let timing_events = if capture_timing {
            Some((
                self.launch_resources.acquire_timing_event()?,
                self.launch_resources.acquire_timing_event()?,
            ))
        } else {
            None
        };

        let resident_use = self.resident_store.mark_inflight(handles)?;
        let mut ptrs = SmallVec::<[u64; 8]>::with_capacity(program.buffers().len());
        ptrs.resize(program.buffers().len(), 0);
        let mut launch_ptrs =
            SmallVec::<[u64; 8]>::with_capacity(prepared.bindings.bindings.len());
        let mut next_handle = 0usize;
        let mut output_handles_by_index =
            SmallVec::<[(usize, CudaResidentBuffer, CudaOutputReadback); 8]>::with_capacity(
                prepared.output_binding_indices.len(),
            );
        for binding in &prepared.bindings.bindings {
            if binding.role == BindingRole::Shared {
                continue;
            }
            let handle = handles[next_handle];
            next_handle += 1;
            let resident = self.resident_store.view(handle)?;
            if let Some(expected) = binding.static_byte_len {
                if resident.byte_len < expected {
                    return Err(BackendError::InvalidProgram {
                        fix: format!(
                            "Fix: CUDA resident buffer `{}` expected at least {expected} bytes but handle {} has {} bytes.",
                            binding.name, handle.id, resident.byte_len
                        ),
                    });
                }
            }
            ptrs[binding.buffer_index] = resident.ptr;
            if resident.ptr == 0 {
                return Err(BackendError::InvalidProgram {
                    fix: format!(
                        "Fix: CUDA resident binding `{}` resolved to a null device pointer; resident launch arguments must preserve descriptor order.",
                        binding.name
                    ),
                });
            }
            launch_ptrs.push(resident.ptr);
            if let Some(output_index) = binding.output_index {
                let full_byte_len = binding
                    .static_byte_len
                    .ok_or_else(|| BackendError::InvalidProgram {
                        fix: format!(
                            "Fix: CUDA resident output `{}` needs a static byte length before readback.",
                            binding.name
                        ),
                    })?;
                let readback =
                    cuda_output_readback(&program.buffers()[binding.buffer_index], full_byte_len)?;
                output_handles_by_index.push((output_index, handle, readback));
            }
        }
        if output_handles_by_index.len() != prepared.output_binding_indices.len() {
            return Err(BackendError::InvalidProgram {
                fix: format!(
                    "Fix: CUDA resident dispatch expected {} output handle(s) but resolved {}.",
                    prepared.output_binding_indices.len(),
                    output_handles_by_index.len()
                ),
            });
        }
        output_handles_by_index.sort_unstable_by_key(|(output_index, _, _)| *output_index);
        let mut output_handles =
            SmallVec::<[CudaResidentBuffer; 8]>::with_capacity(output_handles_by_index.len());
        let mut output_readbacks =
            SmallVec::<[CudaOutputReadback; 8]>::with_capacity(output_handles_by_index.len());
        for (_, handle, readback) in output_handles_by_index {
            output_handles.push(handle);
            output_readbacks.push(readback);
        }

        let mut allocations =
            DispatchAllocations::new(program.buffers().len(), Arc::clone(&self.transient_pool));
        let param_bytes = prepared.launch.param_words.len() * std::mem::size_of::<u32>();
        let mut host_transfers = HostTransferAllocations::with_capacity(
            Arc::clone(&self.host_pool),
            usize::from(static_params_ptr.is_none()),
            0,
        );
        let params_ptr = match static_params_ptr {
            Some(ptr) => ptr,
            None => {
                let params_allocation = self.transient_pool.acquire(param_bytes)?;
                let params_ptr = params_allocation.ptr;
                let param_host_ptr = host_transfers.push_u32_words(&prepared.launch.param_words)?;
                unsafe {
                    cuda_check(
                        cudarc::driver::sys::cuMemcpyHtoDAsync_v2(
                            params_ptr,
                            param_host_ptr,
                            param_bytes,
                            stream.raw(),
                        ),
                        "cuMemcpyHtoDAsync_v2",
                    )?;
                }
                allocations.set_params(params_allocation);
                params_ptr
            }
        };

        if let Some((start_event, _)) = &timing_events {
            start_event.record(stream.raw())?;
        }
        // Fixpoint loop — see dispatch_borrowed_async_with_ptx_concrete
        // for the contract. Resolve the CUDA function and argument vector
        // once; fixpoint iterations are kernel replays, not relowering or
        // module-cache lookups.
        let func = self.resolve_launch_function(ptx_src, module_key, &prepared.launch)?;
        let mut params_ref = params_ptr;
        let mut kernel_args = Self::kernel_args(&mut launch_ptrs, &mut params_ref);
        for _ in 0..prepared.fixpoint_iterations {
            self.launch_resolved_function(
                func,
                &mut kernel_args,
                &prepared.launch,
                stream.raw(),
                false,
                prepared.cooperative,
            )?;
        }
        if let Some((_, end_event)) = &timing_events {
            end_event.record(stream.raw())?;
        }
        let event = self.launch_resources.acquire_event()?;
        event.record(stream.raw())?;
        let pending = if let Some((start_event, end_event)) = timing_events {
            crate::stream::CudaPendingDispatch::new_with_timing(
                Arc::clone(&self.ctx),
                Arc::clone(&self.launch_resources),
                event,
                stream,
                allocations,
                Some(resident_use),
                Some(host_transfers),
                Vec::new(),
                start_event,
                end_event,
            )
        } else {
            crate::stream::CudaPendingDispatch::new(
                Arc::clone(&self.ctx),
                Arc::clone(&self.launch_resources),
                event,
                stream,
                allocations,
                Some(resident_use),
                Some(host_transfers),
                Vec::new(),
            )
        };
        Ok(CudaResidentDispatch {
            pending,
            output_handles,
            output_readbacks,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn dispatch_resident_batch_async_concrete_with_ptx_key(
        &self,
        program: &Program,
        batches: &[SmallVec<[CudaResidentBuffer; 8]>],
        _config: &DispatchConfig,
        ptx_src: &str,
        module_key: ModuleCacheKey,
        static_params_ptr: Option<u64>,
        prepared: &CudaDispatchPlan,
    ) -> Result<CudaResidentBatchDispatch, BackendError> {
        if batches.is_empty() {
            return Err(BackendError::InvalidProgram {
                fix: "Fix: CUDA resident batch dispatch requires at least one resident handle tuple."
                    .to_string(),
            });
        }
        self.warmup()?;
        let required_handles = prepared
            .bindings
            .bindings
            .iter()
            .filter(|binding| binding.role != BindingRole::Shared)
            .count();
        let mut all_handles = SmallVec::<[CudaResidentBuffer; 32]>::with_capacity(
            batches.len().saturating_mul(required_handles),
        );
        for (batch_index, handles) in batches.iter().enumerate() {
            if handles.len() != required_handles {
                return Err(BackendError::InvalidProgram {
                    fix: format!(
                        "Fix: CUDA resident batch dispatch item {batch_index} expected {required_handles} resident buffer handle(s) but received {}.",
                        handles.len()
                    ),
                });
            }
            all_handles.extend(handles.iter().copied());
        }

        let stream = self.launch_resources.acquire_stream()?;
        let resident_use = self.resident_store.mark_inflight(&all_handles)?;
        let param_bytes = prepared.launch.param_words.len() * std::mem::size_of::<u32>();
        let mut allocations =
            DispatchAllocations::new(program.buffers().len(), Arc::clone(&self.transient_pool));
        let mut host_transfers =
            HostTransferAllocations::with_capacity(Arc::clone(&self.host_pool), 1, 0);
        let params_ptr = match static_params_ptr {
            Some(ptr) => ptr,
            None => {
                let params_allocation = self.transient_pool.acquire(param_bytes)?;
                let params_ptr = params_allocation.ptr;
                let param_host_ptr = host_transfers.push_u32_words(&prepared.launch.param_words)?;
                unsafe {
                    cuda_check(
                        cudarc::driver::sys::cuMemcpyHtoDAsync_v2(
                            params_ptr,
                            param_host_ptr,
                            param_bytes,
                            stream.raw(),
                        ),
                        "cuMemcpyHtoDAsync_v2",
                    )?;
                }
                allocations.set_params(params_allocation);
                params_ptr
            }
        };

        let func = self.resolve_launch_function(ptx_src, module_key, &prepared.launch)?;
        let mut output_handles_by_batch =
            SmallVec::<[SmallVec<[CudaResidentBuffer; 8]>; 8]>::with_capacity(batches.len());
        let mut output_readbacks_by_batch =
            SmallVec::<[SmallVec<[CudaOutputReadback; 8]>; 8]>::with_capacity(batches.len());
        let mut seen_output_handles =
            HashSet::<u64, BuildHasherDefault<FxHasher>>::with_capacity_and_hasher(
                batches.len().saturating_mul(prepared.output_binding_indices.len()),
                BuildHasherDefault::<FxHasher>::default(),
            );

        for (batch_index, handles) in batches.iter().enumerate() {
            let mut ptrs = SmallVec::<[u64; 8]>::with_capacity(program.buffers().len());
            ptrs.resize(program.buffers().len(), 0);
            let mut launch_ptrs =
                SmallVec::<[u64; 8]>::with_capacity(prepared.bindings.bindings.len());
            let mut next_handle = 0usize;
            let mut output_handles_by_index =
                SmallVec::<[(usize, CudaResidentBuffer, CudaOutputReadback); 8]>::with_capacity(
                    prepared.output_binding_indices.len(),
                );
            for binding in &prepared.bindings.bindings {
                if binding.role == BindingRole::Shared {
                    continue;
                }
                let handle = handles[next_handle];
                next_handle += 1;
                let resident = self.resident_store.view(handle)?;
                if let Some(expected) = binding.static_byte_len {
                    if resident.byte_len < expected {
                        return Err(BackendError::InvalidProgram {
                            fix: format!(
                                "Fix: CUDA resident batch dispatch item {batch_index} binding `{}` expected at least {expected} bytes but handle {} has {} bytes.",
                                binding.name, handle.id, resident.byte_len
                            ),
                        });
                    }
                }
                ptrs[binding.buffer_index] = resident.ptr;
                if resident.ptr == 0 {
                    return Err(BackendError::InvalidProgram {
                        fix: format!(
                            "Fix: CUDA resident batch dispatch item {batch_index} binding `{}` resolved to a null device pointer; resident launch arguments must preserve descriptor order.",
                            binding.name
                        ),
                    });
                }
                launch_ptrs.push(resident.ptr);
                if let Some(output_index) = binding.output_index {
                    let full_byte_len =
                        binding
                            .static_byte_len
                            .ok_or_else(|| BackendError::InvalidProgram {
                                fix: format!(
                                    "Fix: CUDA resident batch output `{}` needs a static byte length before readback.",
                                    binding.name
                                ),
                            })?;
                    let readback = cuda_output_readback(
                        &program.buffers()[binding.buffer_index],
                        full_byte_len,
                    )?;
                    output_handles_by_index.push((output_index, handle, readback));
                }
            }
            if output_handles_by_index.len() != prepared.output_binding_indices.len() {
                return Err(BackendError::InvalidProgram {
                    fix: format!(
                        "Fix: CUDA resident batch dispatch item {batch_index} expected {} output handle(s) but resolved {}.",
                        prepared.output_binding_indices.len(),
                        output_handles_by_index.len()
                    ),
                });
            }
            output_handles_by_index.sort_unstable_by_key(|(output_index, _, _)| *output_index);
            let mut output_handles =
                SmallVec::<[CudaResidentBuffer; 8]>::with_capacity(output_handles_by_index.len());
            let mut output_readbacks =
                SmallVec::<[CudaOutputReadback; 8]>::with_capacity(output_handles_by_index.len());
            for (_, handle, readback) in output_handles_by_index {
                if !seen_output_handles.insert(handle.id) {
                    return Err(BackendError::InvalidProgram {
                        fix: format!(
                            "Fix: CUDA resident batch dispatch cannot reuse output handle {} across submitted items; allocate one output resident buffer tuple per in-flight batch item so batched readback observes every result instead of the final overwrite.",
                            handle.id
                        ),
                    });
                }
                output_handles.push(handle);
                output_readbacks.push(readback);
            }

            let mut params_ref = params_ptr;
            let mut kernel_args = Self::kernel_args(&mut launch_ptrs, &mut params_ref);
            for _ in 0..prepared.fixpoint_iterations {
                self.launch_resolved_function(
                    func,
                    &mut kernel_args,
                    &prepared.launch,
                    stream.raw(),
                    false,
                    prepared.cooperative,
                )?;
            }
            output_handles_by_batch.push(output_handles);
            output_readbacks_by_batch.push(output_readbacks);
        }

        let event = self.launch_resources.acquire_event()?;
        event.record(stream.raw())?;
        let pending = crate::stream::CudaPendingDispatch::new(
            Arc::clone(&self.ctx),
            Arc::clone(&self.launch_resources),
            event,
            stream,
            allocations,
            Some(resident_use),
            Some(host_transfers),
            Vec::new(),
        );
        Ok(CudaResidentBatchDispatch {
            pending,
            output_handles: output_handles_by_batch,
            output_readbacks: output_readbacks_by_batch,
        })
    }

    /// Dispatch a Program using caller-provided CUDA-resident buffers.
    pub fn dispatch_resident(
        &self,
        program: &Program,
        handles: &[CudaResidentBuffer],
        config: &DispatchConfig,
    ) -> Result<(), BackendError> {
        self.dispatch_resident_async(program, handles, config)?
            .await_result()
            .map(|_| ())
    }

    /// Dispatch with CUDA-resident buffers and return ordered output readbacks.
    pub fn dispatch_resident_timed(
        &self,
        program: &Program,
        handles: &[CudaResidentBuffer],
        config: &DispatchConfig,
    ) -> Result<vyre_driver::TimedDispatchResult, BackendError> {
        let started = std::time::Instant::now();
        let enqueue_started = std::time::Instant::now();
        let resident_dispatch =
            self.dispatch_resident_async_concrete(program, handles, config, true)?;
        let enqueue_ns = enqueue_started.elapsed().as_nanos() as u64;
        let output_handles = resident_dispatch.output_handles;
        let output_readbacks = resident_dispatch.output_readbacks;
        let wait_started = std::time::Instant::now();
        let (_, device_ns) = resident_dispatch.pending.await_timed_result()?;
        let outputs = self.download_resident_readbacks_many(&output_handles, &output_readbacks)?;
        let wait_ns = wait_started.elapsed().as_nanos() as u64;
        Ok(vyre_driver::TimedDispatchResult {
            outputs,
            wall_ns: started.elapsed().as_nanos() as u64,
            device_ns,
            enqueue_ns: Some(enqueue_ns),
            wait_ns: Some(wait_ns),
        })
    }

    pub(crate) fn dispatch_resident_outputs_with_ptx_key(
        &self,
        program: &Program,
        handles: &[CudaResidentBuffer],
        config: &DispatchConfig,
        ptx_src: &str,
        module_key: ModuleCacheKey,
    ) -> Result<Vec<Vec<u8>>, BackendError> {
        let prepared = self.prepare_resident_dispatch(program, handles, config)?;
        let resident_dispatch = self.dispatch_resident_async_concrete_with_ptx_key(
            program, handles, config, ptx_src, module_key, false, None, &prepared,
        )?;
        let output_handles = resident_dispatch.output_handles;
        let output_readbacks = resident_dispatch.output_readbacks;
        resident_dispatch.pending.await_timed_result()?;
        self.download_resident_readbacks_many(&output_handles, &output_readbacks)
    }
}
