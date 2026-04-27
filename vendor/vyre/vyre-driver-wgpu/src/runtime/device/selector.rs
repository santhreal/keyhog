//! Adapter selection + enumeration (C5 refactor).
//!
//! The legacy [`super::device::cached_device`] singleton picks the
//! first adapter `wgpu::Instance::request_adapter` returns — fine for
//! a single-GPU dev box, useless for multi-GPU servers that need to
//! choose a specific device by vendor, index, or power preference.
//!
//! This module ships the explicit selection API:
//!
//! * [`enumerate_adapters`] — list every adapter wgpu reports.
//! * [`AdapterCriteria`] — match by device type, vendor, name
//!   substring, or power preference.
//! * [`select_adapter`] — pick one matching the criteria (returns
//!   the first match; callers wanting all matches iterate
//!   [`enumerate_adapters`] themselves).
//! * [`init_device_for_adapter`] — build a device+queue bound to the
//!   chosen adapter.
//! * `VYRE_ADAPTER_INDEX` — env override used by the backend
//!   auto-picker to route programs to a specific device without
//!   patching code.
//!
//! The legacy `cached_device()` still serves the default case: one
//! singleton device, first compatible adapter. Callers that want
//! multi-GPU now select an adapter by index before constructing a
//! device/queue pair.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};
use std::thread::{self, Thread};

use vyre_driver::error::{Error, Result};

/// Criteria used by [`select_adapter`].
#[derive(Debug, Default, Clone)]
pub struct AdapterCriteria {
    /// Prefer an adapter whose `device_type` matches.
    pub device_type: Option<wgpu::DeviceType>,
    /// Prefer an adapter whose vendor id matches.
    pub vendor: Option<u32>,
    /// Prefer an adapter whose name contains this substring
    /// (case-insensitive).
    pub name_contains: Option<String>,
    /// Prefer an adapter with this power policy.
    pub power: Option<wgpu::PowerPreference>,
}

impl AdapterCriteria {
    /// Build criteria for a high-performance discrete GPU.
    #[must_use]
    pub fn high_performance() -> Self {
        Self {
            device_type: Some(wgpu::DeviceType::DiscreteGpu),
            power: Some(wgpu::PowerPreference::HighPerformance),
            ..Self::default()
        }
    }

    /// Build criteria for a low-power integrated GPU (laptop
    /// battery savings).
    #[must_use]
    pub fn low_power() -> Self {
        Self {
            device_type: Some(wgpu::DeviceType::IntegratedGpu),
            power: Some(wgpu::PowerPreference::LowPower),
            ..Self::default()
        }
    }
}

/// List every adapter the wgpu instance reports.
#[must_use]
pub fn enumerate_adapters() -> Vec<wgpu::AdapterInfo> {
    let instance = wgpu::Instance::default();
    instance
        .enumerate_adapters(wgpu::Backends::all())
        .iter()
        .map(wgpu::Adapter::get_info)
        .collect()
}

/// Select the first adapter matching `criteria`. Returns its index
/// into [`enumerate_adapters`] plus its info.
///
/// # Errors
///
/// Returns `Error::Gpu` when no adapter matches.
pub fn select_adapter(criteria: &AdapterCriteria) -> Result<(usize, wgpu::AdapterInfo)> {
    let instance = wgpu::Instance::default();
    let adapters = instance.enumerate_adapters(wgpu::Backends::all());
    for (idx, adapter) in adapters.iter().enumerate() {
        let info = adapter.get_info();
        if adapter_matches(&info, criteria) {
            return Ok((idx, info));
        }
    }
    Err(Error::Gpu {
        message: format!(
            "no adapter matches criteria {criteria:?}. Fix: loosen the criteria or install drivers exposing the requested GPU class."
        ),
    })
}

fn adapter_matches(info: &wgpu::AdapterInfo, criteria: &AdapterCriteria) -> bool {
    if let Some(ty) = criteria.device_type {
        if info.device_type != ty {
            return false;
        }
    }
    if let Some(vendor) = criteria.vendor {
        if info.vendor != vendor {
            return false;
        }
    }
    if let Some(needle) = &criteria.name_contains {
        if !info.name.to_lowercase().contains(&needle.to_lowercase()) {
            return false;
        }
    }
    true
}

/// Initialize a device + queue bound to the adapter at `index`.
///
/// Pairs with [`enumerate_adapters`] / [`select_adapter`] to give
/// callers full control over which GPU the backend binds to.
///
/// # Errors
///
/// Returns `Error::Gpu` when `index` is out of range or device
/// creation fails.
pub fn init_device_for_adapter(
    index: usize,
) -> Result<(
    (wgpu::Device, wgpu::Queue),
    wgpu::AdapterInfo,
    crate::runtime::device::EnabledFeatures,
)> {
    wait_for_gpu(acquire_gpu_for_adapter(index))
}

/// Async variant of [`init_device_for_adapter`].
///
/// # Errors
///
/// Returns `Error::Gpu` when `index` is out of range or device
/// creation fails.
pub async fn acquire_gpu_for_adapter(
    index: usize,
) -> Result<(
    (wgpu::Device, wgpu::Queue),
    wgpu::AdapterInfo,
    crate::runtime::device::EnabledFeatures,
)> {
    let instance = wgpu::Instance::default();
    let adapters = instance.enumerate_adapters(wgpu::Backends::all());
    let adapter = adapters.get(index).ok_or_else(|| Error::Gpu {
        message: format!(
            "adapter index {index} out of range (saw {} adapters). Fix: call enumerate_adapters() first to see valid indices.",
            adapters.len()
        ),
    })?;
    let info = adapter.get_info();
    if !crate::capabilities::is_real_gpu(&info) {
        return Err(Error::Gpu {
            message: format!(
                "adapter index {index} resolved to `{}` with device type {:?}, which is not a real GPU execution target. Fix: choose a discrete, integrated, or virtual GPU adapter.",
                info.name, info.device_type
            ),
        });
    }
    super::device::request_device_for_adapter(adapter, "vyre device (selected)").await
}

/// Read the `VYRE_ADAPTER_INDEX` env override. `None` when unset or
/// unparseable.
#[must_use]
pub fn adapter_index_from_env() -> Option<usize> {
    std::env::var("VYRE_ADAPTER_INDEX")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
}

// --- poll-to-block helpers (duplicated from device.rs) -----------

struct ThreadWaker(Thread);

impl Wake for ThreadWaker {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.unpark();
    }
}

fn wait_for_gpu<T>(future: impl Future<Output = T>) -> T {
    let waker = Waker::from(Arc::new(ThreadWaker(thread::current())));
    let mut context = Context::from_waker(&waker);
    let mut future = Box::pin(future);
    loop {
        match Pin::as_mut(&mut future).poll(&mut context) {
            Poll::Ready(value) => return value,
            Poll::Pending => thread::park(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enumerate_is_non_panic_even_without_gpu() {
        // Safe on hosts without a GPU — returns empty vec, not a
        // panic.
        let _ = enumerate_adapters();
    }

    #[test]
    fn criteria_high_perf_has_discrete_preset() {
        let c = AdapterCriteria::high_performance();
        assert_eq!(c.device_type, Some(wgpu::DeviceType::DiscreteGpu));
        assert_eq!(c.power, Some(wgpu::PowerPreference::HighPerformance));
    }

    #[test]
    fn criteria_low_power_has_integrated_preset() {
        let c = AdapterCriteria::low_power();
        assert_eq!(c.device_type, Some(wgpu::DeviceType::IntegratedGpu));
    }

    // `std::env` is process-global, so the two tests that manipulate
    // `VYRE_ADAPTER_INDEX` serialize through a shared `Mutex`. Without
    // this they race under `cargo test`'s thread-pooled runner and one
    // test sees the other's `remove_var` between its `set_var` and
    // assertion, producing a flaky failure.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn env_override_parses_valid_index() {
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        std::env::set_var("VYRE_ADAPTER_INDEX", "3");
        assert_eq!(adapter_index_from_env(), Some(3));
        std::env::remove_var("VYRE_ADAPTER_INDEX");
    }

    #[test]
    fn env_override_rejects_garbage() {
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        std::env::set_var("VYRE_ADAPTER_INDEX", "not-a-number");
        assert_eq!(adapter_index_from_env(), None);
        std::env::remove_var("VYRE_ADAPTER_INDEX");
    }
}
