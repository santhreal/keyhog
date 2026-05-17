//! CUDA dispatch path for borrowed host buffers.

use std::ffi::c_void;
use std::sync::Arc;

use cudarc::driver::sys::CUstream;
use smallvec::SmallVec;
use vyre_driver::binding::BindingRole;
use vyre_driver::{BackendError, DispatchConfig, PendingDispatch};
use vyre_foundation::ir::Program;

use super::allocations::{cuda_check, DispatchAllocations, HostTransferAllocations};
use super::dispatch::CudaBackend;
use super::module_cache::ModuleCacheKey;
use super::output_range::cuda_output_readback;
use super::plan::CudaDispatchPlan;

#[derive(Clone, Copy)]
struct HostUpload {
    dst: u64,
    src: *const c_void,
    byte_len: usize,
}

#[derive(Clone, Copy)]
struct DeviceClear {
    dst: u64,
    byte_len: usize,
}

impl CudaBackend {
    /// Dispatch a vyre Program asynchronously on this CUDA device.
    pub fn dispatch_async(
        &self,
        program: &Program,
        inputs: &[Vec<u8>],
        config: &DispatchConfig,
    ) -> Result<Box<dyn PendingDispatch>, BackendError> {
        let borrowed_inputs: SmallVec<[&[u8]; 8]> = inputs.iter().map(Vec::as_slice).collect();
        self.dispatch_borrowed_async(program, &borrowed_inputs, config)
    }

    /// Dispatch a vyre Program asynchronously on this CUDA device with borrowed inputs.
    pub fn dispatch_borrowed_async(
        &self,
        program: &Program,
        inputs: &[&[u8]],
        config: &DispatchConfig,
    ) -> Result<Box<dyn PendingDispatch>, BackendError> {
        let trace = std::env::var_os("VYRE_CUDA_STAGE_TRACE").is_some();
        let start = std::time::Instant::now();
        if trace {
            eprintln!(
                "[cuda-trace] dispatch_borrowed_async start buffers={} inputs={}",
                program.buffers().len(),
                inputs.len()
            );
        }
        let prepared = self.prepare_host_dispatch(program, inputs, config)?;
        if trace {
            eprintln!(
                "[cuda-trace] +{}ms prepare_host_dispatch",
                start.elapsed().as_millis()
            );
        }
        let ptx_src = self.ptx_for_program_cached(program, config)?;
        if trace {
            eprintln!(
                "[cuda-trace] +{}ms ptx_for_program_cached bytes={}",
                start.elapsed().as_millis(),
                ptx_src.len()
            );
        }
        let module_key = self.module_cache_key(&ptx_src);

        self.dispatch_prepared_borrowed_async_with_ptx_key(
            program, inputs, &ptx_src, module_key, &prepared,
        )
    }

    /// Dispatch with backend-owned wall and CUDA event timing.
    pub fn dispatch_borrowed_timed(
        &self,
        program: &Program,
        inputs: &[&[u8]],
        config: &DispatchConfig,
    ) -> Result<vyre_driver::TimedDispatchResult, BackendError> {
        let prepared = self.prepare_host_dispatch(program, inputs, config)?;
        let ptx_src = self.ptx_for_program_cached(program, config)?;
        let module_key = self.module_cache_key(&ptx_src);
        self.dispatch_prepared_borrowed_timed_with_ptx_key(
            program, inputs, &ptx_src, module_key, &prepared,
        )
    }

    pub(crate) fn dispatch_borrowed_async_with_ptx_key(
        &self,
        program: &Program,
        inputs: &[&[u8]],
        config: &DispatchConfig,
        ptx_src: &str,
        module_key: ModuleCacheKey,
    ) -> Result<Box<dyn PendingDispatch>, BackendError> {
        let prepared = self.prepare_host_dispatch(program, inputs, config)?;
        self.dispatch_prepared_borrowed_async_with_ptx_key(
            program, inputs, ptx_src, module_key, &prepared,
        )
    }

    pub(crate) fn dispatch_borrowed_timed_with_ptx_key(
        &self,
        program: &Program,
        inputs: &[&[u8]],
        config: &DispatchConfig,
        ptx_src: &str,
        module_key: ModuleCacheKey,
    ) -> Result<vyre_driver::TimedDispatchResult, BackendError> {
        let prepared = self.prepare_host_dispatch(program, inputs, config)?;
        self.dispatch_prepared_borrowed_timed_with_ptx_key(
            program, inputs, ptx_src, module_key, &prepared,
        )
    }

    pub(crate) fn dispatch_prepared_borrowed_async_with_ptx_key(
        &self,
        program: &Program,
        inputs: &[&[u8]],
        ptx_src: &str,
        module_key: ModuleCacheKey,
        prepared: &CudaDispatchPlan,
    ) -> Result<Box<dyn PendingDispatch>, BackendError> {
        Ok(Box::new(self.dispatch_borrowed_async_with_ptx_concrete(
            program, inputs, ptx_src, module_key, false, prepared,
        )?))
    }

    pub(crate) fn dispatch_prepared_borrowed_timed_with_ptx_key(
        &self,
        program: &Program,
        inputs: &[&[u8]],
        ptx_src: &str,
        module_key: ModuleCacheKey,
        prepared: &CudaDispatchPlan,
    ) -> Result<vyre_driver::TimedDispatchResult, BackendError> {
        let started = std::time::Instant::now();
        let enqueue_started = std::time::Instant::now();
        let pending = self.dispatch_borrowed_async_with_ptx_concrete(
            program, inputs, ptx_src, module_key, true, prepared,
        )?;
        let enqueue_ns = enqueue_started.elapsed().as_nanos() as u64;
        let wait_started = std::time::Instant::now();
        let (outputs, device_ns) = pending.await_timed_result()?;
        let wait_ns = wait_started.elapsed().as_nanos() as u64;
        Ok(vyre_driver::TimedDispatchResult {
            outputs,
            wall_ns: started.elapsed().as_nanos() as u64,
            device_ns,
            enqueue_ns: Some(enqueue_ns),
            wait_ns: Some(wait_ns),
        })
    }

    fn dispatch_borrowed_async_with_ptx_concrete(
        &self,
        program: &Program,
        inputs: &[&[u8]],
        ptx_src: &str,
        module_key: ModuleCacheKey,
        capture_timing: bool,
        prepared: &CudaDispatchPlan,
    ) -> Result<crate::stream::CudaPendingDispatch, BackendError> {
        if prepared
            .bindings
            .bindings
            .iter()
            .any(|binding| binding.role == BindingRole::Persistent)
        {
            return Err(BackendError::UnsupportedFeature {
                name: "cuda_persistent_memory_binding".to_string(),
                backend: crate::CUDA_BACKEND_ID.to_string(),
            });
        }

        let trace = std::env::var_os("VYRE_CUDA_STAGE_TRACE").is_some();
        let start = std::time::Instant::now();
        self.warmup()?;
        if trace {
            eprintln!("[cuda-trace] +{}ms warmup", start.elapsed().as_millis());
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
        if trace {
            eprintln!(
                "[cuda-trace] +{}ms stream/events",
                start.elapsed().as_millis()
            );
        }

        let buffers = program.buffers();
        let mut allocations =
            DispatchAllocations::new(buffers.len(), Arc::clone(&self.transient_pool));
        let (transfer_capacity, output_capacity) = host_transfer_capacities(prepared);
        let mut host_transfers = HostTransferAllocations::with_capacity(
            Arc::clone(&self.host_pool),
            transfer_capacity,
            output_capacity,
        );
        let mut host_uploads =
            SmallVec::<[HostUpload; 8]>::with_capacity(host_upload_batch_capacity(prepared));
        let mut device_clears = SmallVec::<[DeviceClear; 8]>::new();

        for binding in &prepared.bindings.bindings {
            if binding.role == BindingRole::Shared {
                continue;
            }

            let byte_len = match binding.input_index {
                Some(input_index) => inputs[input_index].len(),
                None => binding.static_byte_len.ok_or_else(|| BackendError::InvalidProgram {
                    fix: format!(
                        "Fix: CUDA output `{}` needs a static byte length before launch; set BufferDecl::with_count or output_byte_range.",
                        binding.name
                    ),
                })?,
            };

            let allocation = self.transient_pool.acquire(byte_len)?;
            let dev_ptr = allocation.ptr;
            allocations.set_ptr(binding.buffer_index, allocation);

            if let Some(input_index) = binding.input_index {
                let host_ptr = host_transfers.push_upload(inputs[input_index])?;
                host_uploads.push(HostUpload {
                    dst: dev_ptr,
                    src: host_ptr,
                    byte_len: inputs[input_index].len(),
                });
            } else if byte_len != 0 {
                device_clears.push(DeviceClear {
                    dst: dev_ptr,
                    byte_len,
                });
            }
        }

        let param_bytes = prepared.launch.param_words.len() * std::mem::size_of::<u32>();
        let params_allocation = self.transient_pool.acquire(param_bytes)?;
        let params_buf_ptr = params_allocation.ptr;
        let param_host_ptr = host_transfers.push_u32_words(&prepared.launch.param_words)?;
        host_uploads.push(HostUpload {
            dst: params_buf_ptr,
            src: param_host_ptr,
            byte_len: param_bytes,
        });
        allocations.set_params(params_allocation);
        enqueue_host_uploads_async(&host_uploads, stream.raw())?;
        enqueue_device_clears_async(&device_clears, stream.raw())?;
        if trace {
            eprintln!(
                "[cuda-trace] +{}ms alloc/upload/clear",
                start.elapsed().as_millis()
            );
        }

        if let Some((start_event, _)) = &timing_events {
            start_event.record(stream.raw())?;
        }
        // Fixpoint loop: launch the kernel `fixpoint_iterations` times
        // on the same stream. CUDA serialises kernels within a single
        // stream so each iteration observes the previous iteration's
        // writes — the persistent-state contract that surgec's flows_to /
        // dominates / bounded_by_comparison BFS-on-CSR primitives rely
        // on to converge multi-hop reachability. `allocations` stays
        // device-resident across iterations, so the pointer vector is
        // materialized once and borrowed by each launch.
        let func = self.resolve_launch_function(ptx_src, module_key, &prepared.launch)?;
        if trace {
            eprintln!(
                "[cuda-trace] +{}ms resolve_launch_function",
                start.elapsed().as_millis()
            );
        }
        let mut ptr_values = SmallVec::<[u64; 8]>::with_capacity(prepared.bindings.bindings.len());
        for binding in &prepared.bindings.bindings {
            if binding.role == BindingRole::Shared {
                continue;
            }
            let ptr = allocations.ptr(binding.buffer_index);
            if ptr == 0 {
                return Err(BackendError::InvalidProgram {
                    fix: format!(
                        "Fix: CUDA launch binding `{}` has no device allocation; argument order must match the lowered kernel descriptor.",
                        binding.name
                    ),
                });
            }
            ptr_values.push(ptr);
        }
        let mut params_ref = params_buf_ptr;
        let mut kernel_args = Self::kernel_args(&mut ptr_values, &mut params_ref);
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
        if trace {
            eprintln!("[cuda-trace] +{}ms launch", start.elapsed().as_millis());
        }

        for &binding_index in &prepared.output_binding_indices {
            let binding = &prepared.bindings.bindings[binding_index];
            let full_byte_len = binding
                .static_byte_len
                .ok_or_else(|| BackendError::InvalidProgram {
                    fix: format!(
                        "Fix: CUDA output `{}` needs a static byte length before readback.",
                        binding.name
                    ),
                })?;
            let readback =
                cuda_output_readback(&buffers[binding.buffer_index], full_byte_len)?;
            let out_ptr = host_transfers.push_output(readback.byte_len)?;
            if readback.byte_len != 0 {
                let device_ptr = allocations
                    .ptr(binding.buffer_index)
                    .saturating_add(readback.device_offset as u64);
                unsafe {
                    cuda_check(
                        cudarc::driver::sys::cuMemcpyDtoHAsync_v2(
                            out_ptr,
                            device_ptr,
                            readback.byte_len,
                            stream.raw(),
                        ),
                        "cuMemcpyDtoHAsync_v2",
                    )?;
                }
            }
        }
        if let Some((_, end_event)) = &timing_events {
            end_event.record(stream.raw())?;
        }

        let event = self.launch_resources.acquire_event()?;
        event.record(stream.raw())?;
        if trace {
            eprintln!(
                "[cuda-trace] +{}ms readback/event",
                start.elapsed().as_millis()
            );
        }
        if let Some((start_event, end_event)) = timing_events {
            Ok(crate::stream::CudaPendingDispatch::new_with_timing(
                Arc::clone(&self.ctx),
                Arc::clone(&self.launch_resources),
                event,
                stream,
                allocations,
                None,
                Some(host_transfers),
                Vec::with_capacity(prepared.output_binding_indices.len()),
                start_event,
                end_event,
            ))
        } else {
            Ok(crate::stream::CudaPendingDispatch::new(
                Arc::clone(&self.ctx),
                Arc::clone(&self.launch_resources),
                event,
                stream,
                allocations,
                None,
                Some(host_transfers),
                Vec::with_capacity(prepared.output_binding_indices.len()),
            ))
        }
    }

    /// Dispatch a vyre Program on this CUDA device.
    pub fn dispatch(
        &self,
        program: &Program,
        inputs: &[Vec<u8>],
        config: &DispatchConfig,
    ) -> Result<Vec<Vec<u8>>, BackendError> {
        self.dispatch_async(program, inputs, config)?.await_result()
    }
}

#[inline]
fn host_transfer_capacities(prepared: &CudaDispatchPlan) -> (usize, usize) {
    let output_capacity = prepared.output_binding_indices.len();
    (
        host_upload_batch_capacity(prepared).saturating_add(output_capacity),
        output_capacity,
    )
}

#[inline]
fn host_upload_batch_capacity(prepared: &CudaDispatchPlan) -> usize {
    prepared.bindings.input_indices.len().saturating_add(1)
}

#[inline]
fn enqueue_host_uploads_async(
    uploads: &[HostUpload],
    stream: CUstream,
) -> Result<(), BackendError> {
    for upload in uploads {
        unsafe {
            cuda_check(
                cudarc::driver::sys::cuMemcpyHtoDAsync_v2(
                    upload.dst,
                    upload.src,
                    upload.byte_len,
                    stream,
                ),
                "cuMemcpyHtoDAsync_v2",
            )?;
        }
    }
    Ok(())
}

#[inline]
fn enqueue_device_clears_async(
    clears: &[DeviceClear],
    stream: CUstream,
) -> Result<(), BackendError> {
    for clear in clears {
        unsafe {
            cuda_check(
                cudarc::driver::sys::cuMemsetD8Async(clear.dst, 0, clear.byte_len, stream),
                "cuMemsetD8Async",
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{host_transfer_capacities, host_upload_batch_capacity};
    use crate::backend::CudaDispatchPlan;
    use smallvec::smallvec;
    use std::sync::Arc;
    use vyre_driver::binding::{Binding, BindingPlan, BindingRole};
    use vyre_driver::LaunchPlan;

    #[test]
    fn host_upload_batch_capacity_counts_inputs_once_plus_params() {
        let plan = CudaDispatchPlan {
            bindings: BindingPlan {
                bindings: vec![
                    Binding {
                        name: Arc::from("a"),
                        binding: 0,
                        buffer_index: 0,
                        role: BindingRole::Input,
                        element_size: 4,
                        preferred_alignment: 4,
                        element_count: 16,
                        static_byte_len: Some(64),
                        input_index: Some(0),
                        output_index: None,
                    },
                    Binding {
                        name: Arc::from("b"),
                        binding: 1,
                        buffer_index: 1,
                        role: BindingRole::InputOutput,
                        element_size: 4,
                        preferred_alignment: 4,
                        element_count: 16,
                        static_byte_len: Some(64),
                        input_index: Some(1),
                        output_index: Some(0),
                    },
                    Binding {
                        name: Arc::from("out"),
                        binding: 2,
                        buffer_index: 2,
                        role: BindingRole::Output,
                        element_size: 4,
                        preferred_alignment: 4,
                        element_count: 16,
                        static_byte_len: Some(64),
                        input_index: None,
                        output_index: Some(1),
                    },
                ],
                input_indices: vec![0, 1],
                output_indices: vec![1, 2],
                shared_indices: Vec::new(),
            },
            output_binding_indices: smallvec![1, 2],
            launch: LaunchPlan::new(),
            cooperative: false,
            fixpoint_iterations: 1,
        };

        assert_eq!(
            host_upload_batch_capacity(&plan),
            3,
            "two host inputs plus one params buffer must produce one contiguous H2D enqueue batch"
        );
        assert_eq!(
            host_transfer_capacities(&plan),
            (5, 2),
            "pinned-host transfer storage must reserve inputs + params + outputs without growth"
        );
    }
}
