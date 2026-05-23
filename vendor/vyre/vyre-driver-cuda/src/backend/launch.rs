//! CUDA kernel launch FFI boundary.

use cudarc::driver::sys::{CUfunction, CUresult, CUstream};
use smallvec::SmallVec;
use vyre_driver::validation::validate_launch_geometry;
use vyre_driver::{BackendError, LaunchPlan};

use super::allocations::cuda_check;
use super::dispatch::CudaBackend;
use super::module_cache::ModuleCacheKey;
use crate::occupancy::cooperative_thread_residency_block_limit;

fn launch_axis_product(label: &str, dims: [u32; 3]) -> Result<u64, BackendError> {
    u64::from(dims[0])
        .checked_mul(u64::from(dims[1]))
        .and_then(|xy| xy.checked_mul(u64::from(dims[2])))
        .ok_or_else(|| BackendError::InvalidProgram {
            fix: format!(
                "Fix: CUDA launch {label} dimensions overflow u64 when multiplied: {dims:?}. Shard the dispatch before launch."
            ),
        })
}

fn cooperative_resident_block_capacity(
    active_blocks_per_sm: u64,
    sm_count: u32,
) -> Result<u64, BackendError> {
    active_blocks_per_sm
        .checked_mul(u64::from(sm_count))
        .ok_or_else(|| BackendError::InvalidProgram {
            fix: format!(
                "Fix: CUDA cooperative launch residency accounting overflowed for {active_blocks_per_sm} block(s)/SM across {sm_count} SMs. Inspect device capability reporting before launching."
            ),
        })
}

impl CudaBackend {
    pub(crate) fn resolve_launch_function(
        &self,
        ptx_src: &str,
        module_key: ModuleCacheKey,
        launch: &LaunchPlan,
        cooperative: bool,
    ) -> Result<CUfunction, BackendError> {
        validate_launch_geometry(launch.workgroup, launch.grid, self.launch_limits())?;
        self.validate_cooperative_residency(launch, cooperative)?;
        let func = self.module_for_ptx_with_key(ptx_src, module_key)?;
        self.validate_resolved_launch_function(func, launch, cooperative)?;
        Ok(func)
    }

    pub(crate) fn validate_resolved_launch_function(
        &self,
        func: CUfunction,
        launch: &LaunchPlan,
        cooperative: bool,
    ) -> Result<(), BackendError> {
        validate_launch_geometry(launch.workgroup, launch.grid, self.launch_limits())?;
        self.validate_cooperative_residency(launch, cooperative)?;
        self.validate_cooperative_function_residency(func, launch, cooperative)
    }

    fn validate_cooperative_residency(
        &self,
        launch: &LaunchPlan,
        cooperative: bool,
    ) -> Result<(), BackendError> {
        if !cooperative {
            return Ok(());
        }
        let total_blocks = launch_axis_product("grid", launch.grid)?;
        let threads_per_block = launch_axis_product("workgroup", launch.workgroup)?;
        let threads_per_block = u32::try_from(threads_per_block).map_err(|error| {
            BackendError::InvalidProgram {
                fix: format!(
                    "Fix: CUDA cooperative launch workgroup {:?} has {threads_per_block} thread slots, which does not fit u32: {error}. Use a smaller workgroup.",
                    launch.workgroup
                ),
            }
        })?;
        let resident_block_limit =
            cooperative_thread_residency_block_limit(&self.caps, threads_per_block);
        if resident_block_limit == 0 || total_blocks > resident_block_limit {
            let envelope = self.cooperative_residency_diagnostic(launch);
            return Err(BackendError::InvalidProgram {
                fix: format!(
                    "Fix: CUDA cooperative launch requires every block to be resident, but grid {:?} has {total_blocks} block(s) and this device can resident-fit at most {resident_block_limit} block(s) at workgroup {:?} by thread residency. Reduce grid size, reduce workgroup size, or split the cooperative phase before launch. Diagnostic: {envelope}",
                    launch.grid, launch.workgroup
                ),
            });
        }
        Ok(())
    }

    fn validate_cooperative_function_residency(
        &self,
        func: CUfunction,
        launch: &LaunchPlan,
        cooperative: bool,
    ) -> Result<(), BackendError> {
        if !cooperative {
            return Ok(());
        }
        let total_blocks = launch_axis_product("grid", launch.grid)?;
        let threads_per_block = launch_axis_product("workgroup", launch.workgroup)?;
        let block_size = i32::try_from(threads_per_block).map_err(|error| {
            BackendError::InvalidProgram {
                fix: format!(
                    "Fix: CUDA cooperative launch workgroup {:?} has {threads_per_block} thread slots, which does not fit i32 for occupancy analysis: {error}. Use a smaller workgroup.",
                    launch.workgroup
                ),
            }
        })?;
        let mut active_blocks_per_sm = 0_i32;
        // SAFETY: FFI to libcuda.so. `func` is the loaded entry returned by
        // `module_for_ptx_with_key`; block_size was checked above; dynamic
        // shared memory is zero because `launch_resolved_function` launches
        // with sharedMemBytes=0 on this path.
        unsafe {
            cuda_check(
                cudarc::driver::sys::cuOccupancyMaxActiveBlocksPerMultiprocessor(
                    &mut active_blocks_per_sm,
                    func,
                    block_size,
                    0,
                ),
                "cuOccupancyMaxActiveBlocksPerMultiprocessor",
            )?;
        }
        let active_blocks_per_sm = u64::try_from(active_blocks_per_sm).map_err(|error| {
            BackendError::InvalidProgram {
                fix: format!(
                    "Fix: CUDA cooperative occupancy returned negative active-block count for grid {:?}, workgroup {:?}: {error}. Inspect the loaded PTX resource usage.",
                    launch.grid, launch.workgroup
                ),
            }
        })?;
        let exact_resident_blocks = cooperative_resident_block_capacity(
            active_blocks_per_sm,
            self.caps.multi_processor_count_u32(),
        )?;
        if exact_resident_blocks == 0 || total_blocks > exact_resident_blocks {
            let envelope = self.cooperative_residency_diagnostic(launch);
            return Err(BackendError::InvalidProgram {
                fix: format!(
                    "Fix: CUDA cooperative launch requires every block to be resident, but grid {:?} has {total_blocks} block(s) and the loaded kernel can resident-fit at most {exact_resident_blocks} block(s) ({active_blocks_per_sm} block(s)/SM across {} SMs) after register/shared-memory occupancy analysis. Reduce grid size, reduce workgroup size, lower register/shared-memory pressure, or split the cooperative phase before launch. Diagnostic: {envelope}",
                    launch.grid,
                    self.caps.multi_processor_count_u32()
                ),
            });
        }
        Ok(())
    }

    fn cooperative_residency_diagnostic(&self, launch: &LaunchPlan) -> String {
        match self.diagnose_launch_plan("main", launch, true, self.lowers_tensor_core_ops()) {
            Ok(envelope) => envelope.stable_message(),
            Err(_) => "cuda-kernel-capability-v1|kernel=main|status=blocked|fix=cooperative_residency_diagnostic_unavailable"
                .to_string(),
        }
    }

    pub(crate) fn kernel_args(
        ptrs: &mut SmallVec<[u64; 8]>,
        params_ref: &mut u64,
    ) -> Result<SmallVec<[*mut std::ffi::c_void; 8]>, BackendError> {
        let arg_count = ptrs
            .len()
            .checked_add(1)
            .ok_or_else(|| BackendError::InvalidProgram {
                fix: "Fix: CUDA kernel argument count overflowed usize while appending the launch-parameter pointer. Split the dispatch before launch."
                    .to_string(),
            })?;
        let mut kernel_args: SmallVec<[*mut std::ffi::c_void; 8]> = SmallVec::new();
        kernel_args.try_reserve_exact(arg_count).map_err(|error| {
            BackendError::InvalidProgram {
                fix: format!(
                    "Fix: CUDA kernel argument table could not reserve {arg_count} pointer slot(s): {error:?}. Reduce binding count or split the dispatch before launch."
                ),
            }
        })?;
        for ptr in ptrs.iter_mut() {
            kernel_args.push(ptr as *mut _ as *mut std::ffi::c_void);
        }
        kernel_args.push(params_ref as *mut _ as *mut std::ffi::c_void);
        Ok(kernel_args)
    }

    pub(crate) fn launch_resolved_function(
        &self,
        func: CUfunction,
        kernel_args: &mut SmallVec<[*mut std::ffi::c_void; 8]>,
        launch: &LaunchPlan,
        stream: CUstream,
        synchronize: bool,
        cooperative: bool,
    ) -> Result<(), BackendError> {
        self.validate_resolved_launch_function(func, launch, cooperative)?;
        // SAFETY: FFI to libcuda.so. Pointer args were validated by the
        // matching alloc / store API; lifetimes are documented in the
        // surrounding function. cuda_check (or matching CUresult guard)
        // propagates non-success codes as BackendError.
        unsafe {
            let res = if cooperative {
                cudarc::driver::sys::cuLaunchCooperativeKernel(
                    func,
                    launch.grid[0],
                    launch.grid[1],
                    launch.grid[2],
                    launch.workgroup[0],
                    launch.workgroup[1],
                    launch.workgroup[2],
                    0,
                    stream,
                    kernel_args.as_mut_ptr(),
                )
            } else {
                cudarc::driver::sys::cuLaunchKernel(
                    func,
                    launch.grid[0],
                    launch.grid[1],
                    launch.grid[2],
                    launch.workgroup[0],
                    launch.workgroup[1],
                    launch.workgroup[2],
                    0,
                    stream,
                    kernel_args.as_mut_ptr(),
                    std::ptr::null_mut(),
                )
            };
            if res != CUresult::CUDA_SUCCESS {
                let launcher = if cooperative {
                    "cuLaunchCooperativeKernel"
                } else {
                    "cuLaunchKernel"
                };
                return Err(BackendError::DispatchFailed {
                    code: Some(crate::backend::allocations::cuda_result_code(res)),
                    message: format!(
                        "{launcher} failed with {res:?} for grid={:?}, workgroup={:?}, element_count={}, sm_{}. Fix: verify CUDA launch geometry against the probed device limits and inspect the emitted PTX for this Program.",
                        launch.grid,
                        launch.workgroup,
                        launch.element_count,
                        self.ptx_target_sm()
                    ),
                });
            }
            if synchronize {
                cuda_check(
                    cudarc::driver::sys::cuStreamSynchronize(stream),
                    "cuStreamSynchronize",
                )?;
                self.telemetry.record_sync_point();
            }
        }
        self.telemetry.record_kernel_launch(launch);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::CudaBackend;
    use smallvec::smallvec;

    #[test]
    fn kernel_args_preserves_descriptor_argument_slots() {
        let mut ptrs = smallvec![0_u64, 0x1000_u64, 0x2000_u64];
        let mut params = 0x3000_u64;
        let args = CudaBackend::kernel_args(&mut ptrs, &mut params)
            .expect("test kernel args should reserve");

        assert_eq!(args.len(), 4);
        assert_eq!(args[0] as *mut u64, &mut ptrs[0] as *mut u64);
        assert_eq!(args[1] as *mut u64, &mut ptrs[1] as *mut u64);
        assert_eq!(args[2] as *mut u64, &mut ptrs[2] as *mut u64);
        assert_eq!(args[3] as *mut u64, &mut params as *mut u64);
    }

    #[test]
    fn launch_axis_product_rejects_overflowing_dimensions() {
        let error = super::launch_axis_product("grid", [u32::MAX, u32::MAX, u32::MAX])
            .expect_err("Fix: CUDA launch dimension products must not silently overflow.");
        match error {
            vyre_driver::BackendError::InvalidProgram { fix } => {
                assert!(fix.contains("overflow u64"));
                assert!(fix.contains("grid"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn cooperative_resident_block_capacity_rejects_overflow() {
        let error = super::cooperative_resident_block_capacity(u64::MAX, 2)
            .expect_err("Fix: CUDA cooperative residency accounting must not saturate.");
        match error {
            vyre_driver::BackendError::InvalidProgram { fix } => {
                assert!(fix.contains("cooperative launch residency accounting overflowed"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn kernel_args_source_uses_checked_fallible_argument_table_reservation() {
        let source = include_str!("launch.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("launch source must contain production section before tests");

        assert!(
            production.contains("checked_add(1)")
                && production.contains("try_reserve_exact(arg_count)"),
            "Fix: CUDA launch argument table construction must use checked count math and fallible reservation."
        );
        assert!(
            !production.contains("SmallVec::with_capacity(ptrs.len() + 1)"),
            "Fix: CUDA launch argument table construction must not use infallible capacity growth on the release path."
        );
    }
}
