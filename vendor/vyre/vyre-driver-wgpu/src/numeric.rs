use vyre_driver::BackendError;

/// Convert a host `usize` into a GPU/API `u64` with a single loud boundary policy.
pub(crate) fn usize_to_u64(value: usize, label: &str) -> Result<u64, BackendError> {
    u64::try_from(value).map_err(|source| {
        BackendError::new(format!(
            "{label} cannot fit u64 at a GPU boundary: {source}. Fix: split the workload before crossing the host/device boundary."
        ))
    })
}

/// Convert a rounded finite nanosecond value into telemetry storage.
pub(crate) fn rounded_f64_to_u64(value: f64, label: &str) -> Result<u64, BackendError> {
    let rounded = value.round();
    if !rounded.is_finite() || rounded < 0.0 || rounded > u64::MAX as f64 {
        return Err(BackendError::new(format!(
            "{label} cannot fit u64 after rounding. Fix: inspect timestamp period and query results for device corruption."
        )));
    }
    Ok(rounded as u64)
}
