use std::time::Instant;
use vyre_driver::BackendError;

pub(crate) fn usize_to_u64(value: usize, label: &str) -> Result<u64, BackendError> {
    u64::try_from(value).map_err(|source| BackendError::InvalidProgram {
        fix: format!(
            "Fix: CUDA {label} cannot fit u64: {source}; split the dispatch or resident transfer before telemetry/accounting."
        ),
    })
}

pub(crate) fn u128_to_u64(value: u128, label: &str) -> Result<u64, BackendError> {
    u64::try_from(value).map_err(|source| BackendError::InvalidProgram {
        fix: format!(
            "Fix: CUDA {label} cannot fit u64: {source}; timeout or split the dispatch before telemetry overflows."
        ),
    })
}

pub(crate) fn elapsed_nanos_u64(started: Instant, label: &str) -> Result<u64, BackendError> {
    u128_to_u64(started.elapsed().as_nanos(), label)
}

pub(crate) fn rounded_f64_to_u64(value: f64, label: &str) -> Result<u64, BackendError> {
    if !value.is_finite() || value < 0.0 || value > u64::MAX as f64 {
        return Err(BackendError::InvalidProgram {
            fix: format!(
                "Fix: CUDA {label} value {value} cannot fit u64; inspect device timing and split the dispatch before telemetry overflows."
            ),
        });
    }
    u64::try_from(value.round() as u128).map_err(|source| BackendError::InvalidProgram {
        fix: format!(
            "Fix: CUDA {label} rounded value cannot fit u64: {source}; inspect device timing and split the dispatch before telemetry overflows."
        ),
    })
}
