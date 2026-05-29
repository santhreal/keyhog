//! CUDA kernel launch FFI boundary.

use std::ffi::c_void;

use cudarc::driver::sys::{CUfunction, CUresult, CUstream};
use smallvec::SmallVec;
use vyre_driver::validation::validate_launch_geometry;
use vyre_driver::{BackendError, LaunchPlan};

use super::allocations::cuda_check;
use super::dispatch::CudaBackend;
use super::module_cache::ModuleCacheKey;
use super::staging_reserve::reserve_smallvec;
use crate::numeric::CUDA_NUMERIC;
use crate::occupancy::cooperative_thread_residency_block_limit;

fn launch_axis_product(label: &str, dims: [u32; 3]) -> Result<u64, BackendError> {
    CUDA_NUMERIC.checked_dim_product_u64(dims).ok_or_else(|| {
        BackendError::InvalidProgram {
            fix: format!(
                "Fix: CUDA launch {label} dimensions overflow u64 when multiplied: {dims:?}. Shard the dispatch before launch."
            ),
        }
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

fn validate_kernel_arg_slots(
    kernel_args: &[*mut c_void],
    label: &'static str,
) -> Result<(), BackendError> {
    if kernel_args.is_empty() {
        return Err(BackendError::InvalidProgram {
            fix: format!(
                "Fix: {label} received an empty CUDA kernel argument table; append launch parameters before launch."
            ),
        });
    }
    for (index, arg) in kernel_args.iter().enumerate() {
        if arg.is_null() {
            return Err(BackendError::InvalidProgram {
                fix: format!(
                    "Fix: {label} received a null CUDA kernel argument slot at index {index}; rebuild the launch argument table from live binding and parameter storage before launch."
                ),
            });
        }
    }
    Ok(())
}

pub(crate) fn launch_cuda_function(
    func: CUfunction,
    kernel_args: &mut [*mut c_void],
    launch: &LaunchPlan,
    stream: CUstream,
    cooperative: bool,
    ptx_target_sm: u32,
    label: &'static str,
) -> Result<(), BackendError> {
    if func.is_null() {
        return Err(BackendError::InvalidProgram {
            fix: format!(
                "Fix: {label} received a null CUDA function handle; load and resolve the PTX module entry before launch."
            ),
        });
    }
    if stream.is_null() {
        return Err(BackendError::InvalidProgram {
            fix: format!(
                "Fix: {label} received a null CUDA stream; use a backend-owned non-blocking stream instead of CUDA's legacy default stream."
            ),
        });
    }
    validate_kernel_arg_slots(kernel_args, label)?;
    // SAFETY: FFI to libcuda.so. `func` and `stream` are non-null CUDA
    // handles, `kernel_args` is non-empty with non-null slot pointers and
    // lives for the call, and CUDA validates the opaque handles and launch
    // geometry.
    let res = unsafe {
        if cooperative {
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
        }
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
                "{label}: {launcher} failed with {res:?} for grid={:?}, workgroup={:?}, element_count={}, sm_{ptx_target_sm}. Fix: verify CUDA launch geometry against the probed device limits and inspect the emitted PTX for this Program.",
                launch.grid,
                launch.workgroup,
                launch.element_count
            ),
        });
    }
    Ok(())
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
        let mut kernel_args: SmallVec<[*mut std::ffi::c_void; 8]> = SmallVec::new();
        Self::kernel_args_into(ptrs, params_ref, &mut kernel_args)?;
        Ok(kernel_args)
    }

    pub(crate) fn kernel_args_into(
        ptrs: &mut SmallVec<[u64; 8]>,
        params_ref: &mut u64,
        kernel_args: &mut SmallVec<[*mut std::ffi::c_void; 8]>,
    ) -> Result<(), BackendError> {
        let arg_count = ptrs
            .len()
            .checked_add(1)
            .ok_or_else(|| BackendError::InvalidProgram {
                fix: "Fix: CUDA kernel argument count overflowed usize while appending the launch-parameter pointer. Split the dispatch before launch."
                    .to_string(),
        })?;
        kernel_args.clear();
        reserve_smallvec(kernel_args, arg_count, "kernel argument pointer")?;
        for ptr in ptrs.iter_mut() {
            kernel_args.push(ptr as *mut _ as *mut std::ffi::c_void);
        }
        kernel_args.push(params_ref as *mut _ as *mut std::ffi::c_void);
        Ok(())
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
        self.launch_prevalidated_function(
            func,
            kernel_args,
            launch,
            stream,
            synchronize,
            cooperative,
        )
    }

    pub(crate) fn launch_prevalidated_function(
        &self,
        func: CUfunction,
        kernel_args: &mut SmallVec<[*mut std::ffi::c_void; 8]>,
        launch: &LaunchPlan,
        stream: CUstream,
        synchronize: bool,
        cooperative: bool,
    ) -> Result<(), BackendError> {
        let label = if cooperative {
            "cuLaunchCooperativeKernel"
        } else {
            "cuLaunchKernel"
        };
        launch_cuda_function(
            func,
            kernel_args.as_mut_slice(),
            launch,
            stream,
            cooperative,
            self.ptx_target_sm(),
            label,
        )?;
        if synchronize {
            crate::stream::synchronize_raw_stream(stream, "cuStreamSynchronize")?;
            self.telemetry.record_sync_point();
        }
        self.telemetry.record_kernel_launch(launch);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{launch_cuda_function, CudaBackend};
    use smallvec::{smallvec, SmallVec};
    use vyre_driver::LaunchPlan;

    #[test]
    fn kernel_args_preserves_descriptor_argument_slots() {
        let mut ptrs = smallvec![0_u64, 0x1000_u64, 0x2000_u64];
        let mut params = 0x3000_u64;
        let args = CudaBackend::kernel_args(&mut ptrs, &mut params)
            .expect("Fix: test kernel args should reserve");

        assert_eq!(args.len(), 4);
        assert_eq!(args[0] as *mut u64, &mut ptrs[0] as *mut u64);
        assert_eq!(args[1] as *mut u64, &mut ptrs[1] as *mut u64);
        assert_eq!(args[2] as *mut u64, &mut ptrs[2] as *mut u64);
        assert_eq!(args[3] as *mut u64, &mut params as *mut u64);
    }

    #[test]
    fn kernel_args_into_reuses_argument_table_capacity() {
        let mut ptrs = smallvec![0_u64, 0x1000_u64, 0x2000_u64, 0x3000_u64];
        let mut params = 0x4000_u64;
        let mut args = SmallVec::<[*mut std::ffi::c_void; 8]>::new();

        CudaBackend::kernel_args_into(&mut ptrs, &mut params, &mut args)
            .expect("Fix: first reusable kernel args build should succeed");
        let capacity = args.capacity();
        let first_param_slot = args[4];

        ptrs.truncate(2);
        CudaBackend::kernel_args_into(&mut ptrs, &mut params, &mut args)
            .expect("Fix: second reusable kernel args build should reuse staging");

        assert_eq!(args.len(), 3);
        assert_eq!(args.capacity(), capacity);
        assert_eq!(args[2], first_param_slot);
        assert_eq!(args[2] as *mut u64, &mut params as *mut u64);
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
            .expect("Fix: launch source must contain production section before tests");

        assert!(production.contains(concat!("CUDA_NUMERIC.", "checked_dim_product_u64")));
        assert!(!production.contains(concat!("vyre_driver::numeric::", "checked_dim_product_u64")));
        assert!(
            production.contains("checked_add(1)") && production.contains("reserve_smallvec("),
            "Fix: CUDA launch argument table construction must use checked count math and fallible reservation."
        );
        assert!(
            production.contains("fn kernel_args_into(") && production.contains("kernel_args.clear();"),
            "Fix: CUDA launch argument staging must support caller-owned reuse on multi-launch hot paths."
        );
        assert!(
            !production.contains("SmallVec::with_capacity(ptrs.len() + 1)"),
            "Fix: CUDA launch argument table construction must not use infallible capacity growth on the release path."
        );
    }

    #[test]
    fn launch_cuda_function_rejects_null_function_before_ffi() {
        let mut args = [std::ptr::NonNull::<std::ffi::c_void>::dangling().as_ptr()];
        let error = launch_cuda_function(
            std::ptr::null_mut(),
            &mut args,
            &LaunchPlan::new(),
            std::ptr::null_mut(),
            false,
            90,
            "unit launch",
        )
        .expect_err("Fix: CUDA launch helper must reject null function handles before FFI.");


        assert!(
            error.to_string().contains("null CUDA function handle"),
            "launch diagnostic must identify the invalid function handle: {error}"
        );
    }

    #[test]
    fn launch_cuda_function_rejects_null_argument_slot_before_ffi() {
        let mut args = [std::ptr::null_mut()];
        let error = launch_cuda_function(
            std::ptr::NonNull::<cudarc::driver::sys::CUfunc_st>::dangling().as_ptr(),
            &mut args,
            &LaunchPlan::new(),
            std::ptr::NonNull::<cudarc::driver::sys::CUstream_st>::dangling().as_ptr(),
            false,
            90,
            "unit launch",
        )
        .expect_err("Fix: CUDA launch helper must reject null kernel argument slots before FFI.");

        assert!(
            error
                .to_string()
                .contains("null CUDA kernel argument slot at index 0"),
            "launch diagnostic must identify the invalid argument slot: {error}"
        );
    }

    #[test]
    fn cuda_kernel_launch_ffi_is_single_sourced_for_graph_capture() {
        let launch = include_str!("launch.rs");
        let cuda_graph = include_str!("cuda_graph.rs");
        let kernel_ffi = concat!("cudarc::driver::sys::", "cuLaunchKernel(");
        let cooperative_ffi = concat!("cudarc::driver::sys::", "cuLaunchCooperativeKernel(");

        assert_eq!(
            launch.matches(kernel_ffi).count(),
            1,
            "Fix: raw cuLaunchKernel must stay behind launch_cuda_function."
        );
        assert_eq!(
            launch.matches(cooperative_ffi).count(),
            1,
            "Fix: raw cuLaunchCooperativeKernel must stay behind launch_cuda_function."
        );
        assert_eq!(
            cuda_graph.matches(kernel_ffi).count() + cuda_graph.matches(cooperative_ffi).count(),
            0,
            "Fix: cudaGraph capture must route kernel launches through launch_cuda_function."
        );
        assert!(
            launch.contains("fn launch_cuda_function(")
                && launch.contains("stream.is_null()")
                && launch.contains("kernel_args.is_empty()")
                && cuda_graph.contains("super::launch::launch_cuda_function("),
            "Fix: shared CUDA launch helper must own handle/argument guards and be used by graph capture."
        );
    }

    #[test]
    fn prevalidated_launch_api_preserves_safe_default_without_double_validation_hot_path() {
        let launch = include_str!("launch.rs");
        let host_dispatch = include_str!("host_dispatch.rs");
        let resident_dispatch = include_str!("resident_dispatch.rs");
        let egraph = include_str!("../egraph_kernel_plan.rs");

        assert!(
            launch.contains("fn launch_resolved_function(")
                && launch.contains("self.validate_resolved_launch_function(func, launch, cooperative)?;")
                && launch.contains("fn launch_prevalidated_function("),
            "Fix: CUDA launch API must keep a safe validating entrypoint and a separate prevalidated hot-path entrypoint."
        );
        assert!(
            host_dispatch.contains("self.launch_prevalidated_function(")
                && resident_dispatch.contains("self.launch_prevalidated_function("),
            "Fix: host and resident CUDA hot paths that already called resolve_launch_function must avoid duplicate geometry/residency validation."
        );
        assert!(
            resident_dispatch.matches("Self::kernel_args_into(").count() >= 2
                && resident_dispatch.contains("let mut kernel_args = SmallVec::<[*mut c_void; 8]>::new();"),
            "Fix: resident CUDA multi-launch hot paths must reuse caller-owned kernel argument staging instead of rebuilding a fresh SmallVec per launch."
        );
        assert!(
            egraph.contains("self.launch_resolved_function(")
                && !egraph.contains("self.launch_prevalidated_function("),
            "Fix: standalone e-graph CUDA kernels must keep the validating launch entrypoint unless they are explicitly prevalidated."
        );
    }
}

