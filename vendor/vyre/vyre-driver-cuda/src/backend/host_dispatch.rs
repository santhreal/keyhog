//! CUDA dispatch path for borrowed host buffers.

use std::ffi::c_void;
use std::sync::Arc;

use cudarc::driver::sys::CUstream;
use smallvec::SmallVec;
use vyre_driver::binding::BindingRole;
use vyre_driver::{BackendError, DispatchConfig, PendingDispatch};
use vyre_foundation::ir::Program;

use crate::numeric::{elapsed_nanos_u64, usize_to_u64};

use super::allocations::{cuda_check, DispatchAllocations, HostTransferAllocations};
use super::dispatch::CudaBackend;
use super::launch_params::launch_param_byte_len;
use super::module_cache::ModuleCacheKey;
use super::output_range::cuda_output_readback;
use super::plan::CudaDispatchPlan;
use super::staging_reserve::{reserve_smallvec, reserved_vec};

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

fn add_transfer_bytes(total: &mut u64, bytes: usize, label: &str) -> Result<(), BackendError> {
    let bytes = u64::try_from(bytes).map_err(|_| BackendError::InvalidProgram {
        fix: format!(
            "Fix: CUDA {label} transfer byte count exceeds u64; split the dispatch into bounded chunks."
        ),
    })?;
    *total = total
        .checked_add(bytes)
        .ok_or_else(|| BackendError::InvalidProgram {
            fix: format!(
                "Fix: CUDA {label} transfer byte accounting overflowed u64; split the dispatch into bounded chunks."
            ),
        })?;
    Ok(())
}

fn add_transfer_operation(total: &mut u64, label: &str) -> Result<(), BackendError> {
    *total = total
        .checked_add(1)
        .ok_or_else(|| BackendError::InvalidProgram {
            fix: format!(
                "Fix: CUDA {label} transfer operation accounting overflowed u64; split the dispatch into bounded chunks."
            ),
        })?;
    Ok(())
}

impl CudaBackend {
    /// Dispatch a vyre Program synchronously on this CUDA device with borrowed inputs.
    pub fn dispatch_borrowed(
        &self,
        program: &Program,
        inputs: &[&[u8]],
        config: &DispatchConfig,
    ) -> Result<Vec<Vec<u8>>, BackendError> {
        self.dispatch_borrowed_async(program, inputs, config)?
            .await_result()
    }

    /// Dispatch a vyre Program asynchronously on this CUDA device.
    pub fn dispatch_async(
        &self,
        program: &Program,
        inputs: &[Vec<u8>],
        config: &DispatchConfig,
    ) -> Result<Box<dyn PendingDispatch>, BackendError> {
        let mut borrowed_inputs = SmallVec::<[&[u8]; 8]>::new();
        reserve_smallvec(&mut borrowed_inputs, inputs.len(), "borrowed input")?;
        for input in inputs {
            borrowed_inputs.push(input.as_slice());
        }
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
        let enqueue_ns = elapsed_nanos_u64(enqueue_started, "host-dispatch enqueue latency")?;
        let wait_started = std::time::Instant::now();
        let (outputs, device_ns) = pending.await_timed_result()?;
        let wait_ns = elapsed_nanos_u64(wait_started, "host-dispatch wait latency")?;
        Ok(vyre_driver::TimedDispatchResult {
            outputs,
            wall_ns: elapsed_nanos_u64(started, "host-dispatch wall latency")?,
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
        self.validate_transient_dispatch_memory_budget(prepared, inputs, "CUDA host dispatch")?;

        let buffers = program.buffers();
        let mut allocations =
            DispatchAllocations::new(buffers.len(), Arc::clone(&self.transient_pool))?;
        let (transfer_capacity, output_capacity) = host_transfer_capacities(prepared)?;
        let mut host_transfers = HostTransferAllocations::with_capacity(
            Arc::clone(&self.host_pool),
            transfer_capacity,
            output_capacity,
        )?;
        let mut host_uploads = SmallVec::<[HostUpload; 8]>::new();
        reserve_smallvec(
            &mut host_uploads,
            host_upload_batch_capacity(prepared)?,
            "host upload",
        )?;
        let mut device_clears = SmallVec::<[DeviceClear; 8]>::new();
        reserve_smallvec(
            &mut device_clears,
            prepared.bindings.bindings.len(),
            "device clear",
        )?;
        let mut upload_bytes = 0_u64;
        let mut upload_operations = 0_u64;

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
            self.telemetry
                .record_transient_allocation_bytes(usize_to_u64(
                    allocation.byte_len,
                    "transient allocation byte count",
                )?);
            let dev_ptr = allocation.ptr;
            allocations.set_ptr(binding.buffer_index, allocation);

            if let Some(input_index) = binding.input_index {
                let input = inputs[input_index];
                let host_ptr = host_transfers.push_upload(input)?;
                add_transfer_bytes(&mut upload_bytes, input.len(), "host upload")?;
                if !input.is_empty() {
                    add_transfer_operation(&mut upload_operations, "host upload")?;
                }
                host_uploads.push(HostUpload {
                    dst: dev_ptr,
                    src: host_ptr,
                    byte_len: input.len(),
                });
            } else if byte_len != 0 {
                device_clears.push(DeviceClear {
                    dst: dev_ptr,
                    byte_len,
                });
            }
        }

        let param_bytes = launch_param_byte_len(&prepared.launch.param_words, "host dispatch")?;
        let params_buf_ptr = if param_bytes == 0 {
            0
        } else {
            let params_allocation = self.transient_pool.acquire(param_bytes)?;
            self.telemetry
                .record_transient_allocation_bytes(usize_to_u64(
                    params_allocation.byte_len,
                    "parameter allocation byte count",
                )?);
            let params_buf_ptr = params_allocation.ptr;
            let param_host_ptr = host_transfers.push_u32_words(&prepared.launch.param_words)?;
            host_uploads.push(HostUpload {
                dst: params_buf_ptr,
                src: param_host_ptr,
                byte_len: param_bytes,
            });
            add_transfer_bytes(&mut upload_bytes, param_bytes, "parameter upload")?;
            add_transfer_operation(&mut upload_operations, "parameter upload")?;
            self.telemetry.record_param_upload_bytes(usize_to_u64(
                param_bytes,
                "parameter upload byte count",
            )?);
            allocations.set_params(params_allocation);
            params_buf_ptr
        };

        let launch_resources = crate::stream::CudaLaunchResourceLease::acquire(
            Arc::clone(&self.launch_resources),
            capture_timing,
        )?;
        let stream_raw = launch_resources.stream_raw()?;
        if trace {
            eprintln!(
                "[cuda-trace] +{}ms stream/events",
                start.elapsed().as_millis()
            );
        }
        enqueue_host_uploads_async(&host_uploads, stream_raw)?;
        self.telemetry.record_host_to_device_bytes(upload_bytes);
        self.telemetry
            .record_host_upload_operations(upload_operations);
        enqueue_device_clears_async(&device_clears, stream_raw)?;
        if trace {
            eprintln!(
                "[cuda-trace] +{}ms alloc/upload/clear",
                start.elapsed().as_millis()
            );
        }

        if let Some((start_event, _)) = launch_resources.timing_events()? {
            start_event.record(stream_raw)?;
        }
        // Fixpoint loop: launch the kernel `fixpoint_iterations` times
        // on the same stream. CUDA serialises kernels within a single
        // stream so each iteration observes the previous iteration's
        // writes — the persistent-state contract that dataflow BFS-on-CSR
        // primitives rely on to converge multi-hop reachability.
        // `allocations` stays device-resident across iterations, so the
        // pointer vector is materialized once and borrowed by each launch.
        let func = self.resolve_launch_function(
            ptx_src,
            module_key,
            &prepared.launch,
            prepared.cooperative,
        )?;
        if trace {
            eprintln!(
                "[cuda-trace] +{}ms resolve_launch_function",
                start.elapsed().as_millis()
            );
        }
        let mut ptr_values = SmallVec::<[u64; 8]>::new();
        reserve_smallvec(
            &mut ptr_values,
            prepared.bindings.bindings.len(),
            "kernel pointer argument",
        )?;
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
        if trace {
            eprintln!(
                "[cuda-trace] +{}ms host args ptr_values={:x?} params=0x{params_buf_ptr:x} words={:?} grid={:?} workgroup={:?} element_count={}",
                start.elapsed().as_millis(),
                ptr_values,
                prepared.launch.param_words,
                prepared.launch.grid,
                prepared.launch.workgroup,
                prepared.launch.element_count
            );
        }
        let mut params_ref = params_buf_ptr;
        let mut kernel_args = Self::kernel_args(&mut ptr_values, &mut params_ref)?;
        for _ in 0..prepared.fixpoint_iterations {
            self.launch_resolved_function(
                func,
                &mut kernel_args,
                &prepared.launch,
                stream_raw,
                false,
                prepared.cooperative,
            )?;
        }
        if trace {
            eprintln!("[cuda-trace] +{}ms launch", start.elapsed().as_millis());
        }

        let mut readback_bytes = 0_u64;
        let mut readback_operations = 0_u64;
        for &binding_index in &prepared.output_binding_indices {
            let binding = &prepared.bindings.bindings[binding_index];
            let full_byte_len = match binding.static_byte_len {
                Some(len) => len,
                None => match binding.input_index {
                    Some(input_index) => inputs[input_index].len(),
                    None => {
                        return Err(BackendError::InvalidProgram {
                            fix: format!(
                                "Fix: CUDA output `{}` needs a static byte length before readback.",
                                binding.name
                            ),
                        });
                    }
                },
            };
            let readback = cuda_output_readback(&buffers[binding.buffer_index], full_byte_len)?;
            let out_ptr = host_transfers.push_output(readback.byte_len)?;
            if readback.byte_len != 0 {
                add_transfer_bytes(&mut readback_bytes, readback.byte_len, "output readback")?;
                add_transfer_operation(&mut readback_operations, "output readback")?;
                let base_ptr = allocations.ptr(binding.buffer_index);
                let device_ptr =
                    base_ptr
                        .checked_add(usize_to_u64(
                            readback.device_offset,
                            "host dispatch output readback device offset",
                        )?)
                        .ok_or_else(|| BackendError::InvalidProgram {
                            fix: format!(
                                "Fix: CUDA host dispatch readback pointer overflowed for output `{}` at device_ptr={base_ptr} offset={}. Rebuild the program with a valid output byte range or split the output buffer.",
                                binding.name, readback.device_offset
                            ),
                        })?;
                // SAFETY: FFI to libcuda.so. Pointer args were validated by
                // the matching alloc / store API; lifetimes are documented in
                // the surrounding function. cuda_check (or matching CUresult
                // guard) propagates non-success codes as BackendError.
                unsafe {
                    cuda_check(
                        cudarc::driver::sys::cuMemcpyDtoHAsync_v2(
                            out_ptr,
                            device_ptr,
                            readback.byte_len,
                            stream_raw,
                        ),
                        "cuMemcpyDtoHAsync_v2",
                    )?;
                }
            }
        }
        self.telemetry
            .record_device_to_host_readback(readback_bytes);
        self.telemetry
            .record_device_readback_operations(readback_operations);
        if let Some((_, end_event)) = launch_resources.timing_events()? {
            end_event.record(stream_raw)?;
        }

        let event = self.launch_resources.acquire_event()?;
        if let Err(error) = event.record(stream_raw) {
            self.launch_resources.release_event(event);
            return Err(error);
        }
        if trace {
            eprintln!(
                "[cuda-trace] +{}ms readback/event",
                start.elapsed().as_millis()
            );
        }
        let (stream, timing_events) = launch_resources.into_parts()?;
        let output_storage = reserved_vec(prepared.output_binding_indices.len(), "pending output")?;
        if let Some((start_event, end_event)) = timing_events {
            Ok(crate::stream::CudaPendingDispatch::new_with_timing(
                Arc::clone(&self.ctx),
                Arc::clone(&self.launch_resources),
                event,
                stream,
                allocations,
                None,
                Some(host_transfers),
                output_storage,
                start_event,
                end_event,
                Arc::clone(&self.telemetry),
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
                output_storage,
                Arc::clone(&self.telemetry),
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
        // Reject programs that ask for capabilities the live CUDA
        // backend doesn't expose BEFORE we attempt PTX emit. Without
        // this gate, indirect_dispatch / f16 / bf16 IR falls all the
        // way down to vyre-emit-ptx and surfaces a generic
        // "unsupported KernelOp kind" message that hides the
        // missing-capability contract the dispatch layer is supposed
        // to enforce.
        let required = vyre_foundation::program_caps::scan(program);
        let validation_caps = self.program_validation_caps();
        vyre_foundation::program_caps::check_backend_capabilities(
            validation_caps.backend_id,
            validation_caps.supports_subgroup_ops,
            validation_caps.supports_f16,
            validation_caps.supports_bf16,
            validation_caps.supports_indirect_dispatch,
            validation_caps.supports_trap_propagation,
            validation_caps.max_workgroup_size,
            &required,
        )
        .map_err(|error| BackendError::InvalidProgram {
            fix: error.to_string(),
        })?;
        self.dispatch_async(program, inputs, config)?.await_result()
    }
}

#[inline]
fn host_transfer_capacities(prepared: &CudaDispatchPlan) -> Result<(usize, usize), BackendError> {
    let output_capacity = prepared.output_binding_indices.len();
    let upload_capacity = host_upload_batch_capacity(prepared)?;
    let transfer_capacity =
        upload_capacity
            .checked_add(output_capacity)
            .ok_or_else(|| BackendError::InvalidProgram {
                fix: format!(
                    "Fix: CUDA host transfer capacity overflowed usize for {upload_capacity} upload slot(s) plus {output_capacity} output slot(s); split the dispatch."
                ),
            })?;
    Ok((transfer_capacity, output_capacity))
}

#[inline]
fn host_upload_batch_capacity(prepared: &CudaDispatchPlan) -> Result<usize, BackendError> {
    prepared
        .bindings
        .input_indices
        .len()
        .checked_add(usize::from(!prepared.launch.param_words.is_empty()))
        .ok_or_else(|| BackendError::InvalidProgram {
            fix: "Fix: CUDA host upload batch capacity overflowed usize while adding the params upload slot; split the dispatch."
                .to_string(),
        })
}

#[inline]
fn enqueue_host_uploads_async(
    uploads: &[HostUpload],
    stream: CUstream,
) -> Result<(), BackendError> {
    for upload in uploads {
        if upload.byte_len == 0 {
            continue;
        }
        // SAFETY: FFI to libcuda.so. Pointer args were validated by the
        // matching alloc / store API; lifetimes are documented in the
        // surrounding function. cuda_check (or matching CUresult guard)
        // propagates non-success codes as BackendError.
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
        // SAFETY: FFI to libcuda.so. Pointer args were validated by the
        // matching alloc / store API; lifetimes are documented in the
        // surrounding function. cuda_check (or matching CUresult guard)
        // propagates non-success codes as BackendError.
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
            host_upload_batch_capacity(&plan).expect("capacity must fit"),
            2,
            "zero-byte launch params must not reserve a fake H2D upload slot"
        );
        assert_eq!(
            host_transfer_capacities(&plan).expect("capacity must fit"),
            (4, 2),
            "pinned-host transfer storage must reserve inputs + outputs only when params are empty"
        );

        let mut plan_with_params = plan;
        plan_with_params.launch.param_words.push(7);
        assert_eq!(
            host_upload_batch_capacity(&plan_with_params).expect("capacity must fit"),
            3,
            "non-empty launch params must reserve one H2D upload slot"
        );
        assert_eq!(
            host_transfer_capacities(&plan_with_params).expect("capacity must fit"),
            (5, 2),
            "pinned-host transfer storage must reserve inputs + params + outputs when params exist"
        );
    }
}
