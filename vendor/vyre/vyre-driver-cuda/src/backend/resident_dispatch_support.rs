//! Shared resident-dispatch contracts and checked accounting helpers.

use smallvec::SmallVec;
use vyre_driver::{BackendError, DispatchConfig};
use vyre_foundation::ir::Program;

use super::output_range::CudaOutputReadback;
use super::resident::CudaResidentBuffer;

pub(crate) struct CudaResidentDispatchStep<'a> {
    pub(crate) program: &'a Program,
    pub(crate) handles: &'a [CudaResidentBuffer],
    pub(crate) config: DispatchConfig,
}

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

pub(crate) fn checked_resident_dispatch_capacity_mul(
    lhs: usize,
    rhs: usize,
    label: &str,
) -> Result<usize, BackendError> {
    lhs.checked_mul(rhs).ok_or_else(|| BackendError::InvalidProgram {
        fix: format!(
            "Fix: CUDA resident {label} capacity overflowed usize for {lhs} x {rhs}; split the resident batch."
        ),
    })
}

pub(crate) fn checked_resident_dispatch_capacity_add(
    lhs: usize,
    rhs: usize,
    label: &str,
) -> Result<usize, BackendError> {
    lhs.checked_add(rhs).ok_or_else(|| BackendError::InvalidProgram {
        fix: format!(
            "Fix: CUDA resident {label} capacity overflowed usize for {lhs} + {rhs}; split the resident sequence."
        ),
    })
}

pub(crate) fn add_resident_dispatch_bytes(
    total: &mut u64,
    bytes: usize,
    label: &str,
) -> Result<(), BackendError> {
    let bytes = u64::try_from(bytes).map_err(|_| BackendError::InvalidProgram {
        fix: format!(
            "Fix: CUDA resident {label} byte count exceeds u64; split the resident dispatch."
        ),
    })?;
    *total = total
        .checked_add(bytes)
        .ok_or_else(|| BackendError::InvalidProgram {
            fix: format!(
                "Fix: CUDA resident {label} byte accounting overflowed u64; split the resident dispatch."
            ),
        })?;
    Ok(())
}

pub(crate) fn add_resident_dispatch_usize_count(
    total: &mut usize,
    label: &str,
) -> Result<(), BackendError> {
    *total = total
        .checked_add(1)
        .ok_or_else(|| BackendError::InvalidProgram {
            fix: format!(
                "Fix: CUDA resident {label} count overflowed usize; split the resident dispatch."
            ),
        })?;
    Ok(())
}

pub(crate) fn add_resident_dispatch_u64_count(
    total: &mut u64,
    label: &str,
) -> Result<(), BackendError> {
    *total = total
        .checked_add(1)
        .ok_or_else(|| BackendError::InvalidProgram {
            fix: format!(
                "Fix: CUDA resident {label} operation count overflowed u64; split the resident dispatch."
            ),
        })?;
    Ok(())
}
