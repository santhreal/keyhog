//! Atomic accounting primitives for CUDA backend counters and byte budgets.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use vyre_driver::BackendError;

/// Add `value` to a `u64` counter without allowing wraparound or saturation.
pub(crate) fn checked_add_u64(
    counter: &AtomicU64,
    value: u64,
    overflow: impl Fn(u64, u64) -> BackendError,
) -> Result<(), BackendError> {
    if value == 0 {
        return Ok(());
    }
    let mut current = counter.load(Ordering::Relaxed);
    loop {
        let next = current
            .checked_add(value)
            .ok_or_else(|| overflow(current, value))?;
        match counter.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return Ok(()),
            Err(observed) => current = observed,
        }
    }
}

/// Subtract `value` from a `u64` byte counter without allowing underflow.
pub(crate) fn checked_sub_u64(
    counter: &AtomicU64,
    value: u64,
    underflow: impl Fn(u64, u64) -> BackendError,
) -> Result<(), BackendError> {
    let mut observed = counter.load(Ordering::Acquire);
    loop {
        let next = observed
            .checked_sub(value)
            .ok_or_else(|| underflow(observed, value))?;
        match counter.compare_exchange_weak(observed, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return Ok(()),
            Err(actual) => observed = actual,
        }
    }
}

/// Subtract `value` from a `usize` byte counter without allowing underflow.
pub(crate) fn checked_sub_usize(
    counter: &AtomicUsize,
    value: usize,
    underflow: impl Fn(usize, usize) -> BackendError,
) -> Result<(), BackendError> {
    let mut observed = counter.load(Ordering::Acquire);
    loop {
        let next = observed
            .checked_sub(value)
            .ok_or_else(|| underflow(observed, value))?;
        match counter.compare_exchange_weak(observed, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return Ok(()),
            Err(actual) => observed = actual,
        }
    }
}
