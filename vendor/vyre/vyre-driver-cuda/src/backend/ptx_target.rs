//! PTX target selection against the live CUDA driver.

use cudarc::driver::sys::CUresult;
use smallvec::SmallVec;

pub(crate) fn select_loadable_ptx_target_sm(native_sm: u32) -> Result<u32, String> {
    let candidates = ptx_target_candidates(native_sm);
    let mut failures = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        match probe_ptx_target_sm(candidate) {
            Ok(()) => return Ok(candidate),
            Err(result) => failures.push(format!("sm_{candidate}: {result:?}")),
        }
    }
    Err(format!(
        "CUDA driver rejected every PTX target candidate for native sm_{native_sm}: {}. Fix: update the CUDA driver/PTX emitter pair so at least one modern PTX target can be JIT-loaded.",
        failures.join(", ")
    ))
}

fn ptx_target_candidates(native_sm: u32) -> SmallVec<[u32; 10]> {
    let mut candidates =
        SmallVec::<[u32; 10]>::from_buf([native_sm, 120, 110, 100, 90, 89, 86, 80, 75, 70]);
    candidates.retain(|candidate| *candidate > 0 && *candidate <= native_sm);
    candidates.sort_unstable_by(|a, b| b.cmp(a));
    candidates.dedup();
    candidates
}

fn probe_ptx_target_sm(target_sm: u32) -> Result<(), CUresult> {
    // Probe PTX must use the same `.version` as `vyre-emit-ptx::emitter`
    // — drift here would let the probe pick a candidate that the real
    // emitter then can't load. PTX 8.5 supports sm_70 through sm_120.
    let ptx = format!(
        ".version 8.5\n.target sm_{target_sm}\n.address_size 64\n.visible .entry main() {{\n\tret;\n}}\n\0"
    );
    let mut module = std::ptr::null_mut();
    let result = unsafe { cudarc::driver::sys::cuModuleLoadData(&mut module, ptx.as_ptr().cast()) };
    if result != CUresult::CUDA_SUCCESS {
        return Err(result);
    }
    if !module.is_null() {
        unsafe {
            let unload_result = cudarc::driver::sys::cuModuleUnload(module);
            if unload_result != CUresult::CUDA_SUCCESS {
                return Err(unload_result);
            }
        }
    }
    Ok(())
}
