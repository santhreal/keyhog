//! CUDA kernel launch FFI boundary.

use cudarc::driver::sys::{CUfunction, CUresult, CUstream};
use smallvec::SmallVec;
use vyre_driver::validation::validate_launch_geometry;
use vyre_driver::{BackendError, LaunchPlan};

use super::allocations::cuda_check;
use super::dispatch::CudaBackend;
use super::module_cache::ModuleCacheKey;

impl CudaBackend {
    pub(crate) fn resolve_launch_function(
        &self,
        ptx_src: &str,
        module_key: ModuleCacheKey,
        launch: &LaunchPlan,
    ) -> Result<CUfunction, BackendError> {
        let func = self.module_for_ptx_with_key(ptx_src, module_key)?;
        validate_launch_geometry(launch.workgroup, launch.grid, self.launch_limits())?;
        Ok(func)
    }

    pub(crate) fn kernel_args(
        ptrs: &mut SmallVec<[u64; 8]>,
        params_ref: &mut u64,
    ) -> SmallVec<[*mut std::ffi::c_void; 8]> {
        let mut kernel_args: SmallVec<[*mut std::ffi::c_void; 8]> =
            SmallVec::with_capacity(ptrs.len() + 1);
        for ptr in ptrs.iter_mut() {
            kernel_args.push(ptr as *mut _ as *mut std::ffi::c_void);
        }
        kernel_args.push(params_ref as *mut _ as *mut std::ffi::c_void);
        kernel_args
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
                    code: Some(res as i32),
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
            }
        }
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
        let args = CudaBackend::kernel_args(&mut ptrs, &mut params);

        assert_eq!(args.len(), 4);
        assert_eq!(args[0] as *mut u64, &mut ptrs[0] as *mut u64);
        assert_eq!(args[1] as *mut u64, &mut ptrs[1] as *mut u64);
        assert_eq!(args[2] as *mut u64, &mut ptrs[2] as *mut u64);
        assert_eq!(args[3] as *mut u64, &mut params as *mut u64);
    }
}
