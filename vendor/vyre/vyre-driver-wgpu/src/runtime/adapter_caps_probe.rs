//! Adapter-caps probe (C-B10).
//!
//! Extracts a [`vyre::optimizer::AdapterCaps`] from a live
//! `wgpu::Adapter`. Passes registered in the vyre-core
//! `PassManager` read these caps to adapt: subgroup intrinsics fire
//! only when `supports_subgroup_ops == true`; the fusion pass
//! (C-B8) checks `max_shared_memory_bytes` before collapsing
//! kernels; the megakernel (C-B9) filters its `worker_count`
//! against `max_workgroup_size`.
//!
//! The probe is pure: it reads the adapter's `get_info()`,
//! `features()`, and `limits()` and projects into the substrate-neutral
//! [`vyre::optimizer::AdapterCaps`] shape. No dispatch happens.

use crate::runtime::device::EnabledFeatures;
use vyre_foundation::optimizer::AdapterCaps;

/// Probe a live wgpu adapter and return the substrate-neutral
/// caps `PassManager` consumers use.
#[must_use]
pub fn probe(adapter: &wgpu::Adapter) -> AdapterCaps {
    let features = adapter.features();
    let limits = adapter.limits();
    let info = adapter.get_info();

    let max_workgroup_size = [
        limits.max_compute_workgroup_size_x,
        limits.max_compute_workgroup_size_y,
        limits.max_compute_workgroup_size_z,
    ];
    AdapterCaps {
        backend: backend_id_for(info.backend),
        supports_subgroup_ops: crate::capabilities::supports_subgroup_for_adapter(
            features, &limits,
        ),
        supports_indirect_dispatch: crate::capabilities::supports_indirect_dispatch_limits(
            &info,
            u64::from(limits.max_storage_buffer_binding_size),
            max_workgroup_size,
        ),
        // wgpu exposes override constants unconditionally via naga;
        // the adapter-side gate is cheap.
        supports_specialization_constants: true,
        max_workgroup_size,
        max_invocations_per_workgroup: limits.max_compute_invocations_per_workgroup,
        max_shared_memory_bytes: limits.max_compute_workgroup_storage_size,
        max_storage_buffer_binding_size: u64::from(limits.max_storage_buffer_binding_size),
        subgroup_size: limits.min_subgroup_size,
    }
}

/// Project the already-created backend device into optimizer caps.
///
/// This is the capability source production planners should prefer: it uses
/// the feature set that was actually requested at device creation, including
/// post-creation checks such as the subgroup smoke pipeline probe.
#[must_use]
pub fn from_backend(
    adapter_info: &wgpu::AdapterInfo,
    device_limits: &wgpu::Limits,
    enabled: &EnabledFeatures,
) -> AdapterCaps {
    AdapterCaps {
        backend: backend_id_for(adapter_info.backend),
        supports_subgroup_ops: crate::capabilities::supports_subgroup_ops(enabled),
        supports_indirect_dispatch: crate::capabilities::supports_indirect_dispatch(
            adapter_info,
            enabled,
        ),
        supports_specialization_constants: crate::capabilities::validation_capabilities(
            adapter_info,
            enabled,
        )
        .supports_specialization_constants,
        max_workgroup_size: enabled.max_workgroup_size,
        max_invocations_per_workgroup: device_limits.max_compute_invocations_per_workgroup,
        max_shared_memory_bytes: device_limits.max_compute_workgroup_storage_size,
        max_storage_buffer_binding_size: enabled.max_storage_buffer_binding_size,
        subgroup_size: if crate::capabilities::supports_subgroup_ops(enabled) {
            enabled.min_subgroup_size
        } else {
            0
        },
    }
}

fn backend_id_for(backend: wgpu::Backend) -> &'static str {
    match backend {
        wgpu::Backend::Vulkan => "vulkan",
        wgpu::Backend::Metal => "metal",
        wgpu::Backend::Dx12 => "dx12",
        wgpu::Backend::Gl => "gl",
        wgpu::Backend::BrowserWebGpu => "webgpu",
        wgpu::Backend::Empty => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_id_maps_every_wgpu_backend() {
        assert_eq!(backend_id_for(wgpu::Backend::Vulkan), "vulkan");
        assert_eq!(backend_id_for(wgpu::Backend::Metal), "metal");
        assert_eq!(backend_id_for(wgpu::Backend::Dx12), "dx12");
        assert_eq!(backend_id_for(wgpu::Backend::Gl), "gl");
        assert_eq!(backend_id_for(wgpu::Backend::BrowserWebGpu), "webgpu");
        assert_eq!(backend_id_for(wgpu::Backend::Empty), "unknown");
    }
}
