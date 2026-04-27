//! Live wgpu capability decisions shared by validation and dispatch.

use crate::runtime::device::EnabledFeatures;
use vyre_foundation::validate::BackendCapabilities;

#[inline]
pub(crate) fn is_real_gpu(adapter_info: &wgpu::AdapterInfo) -> bool {
    matches!(
        adapter_info.device_type,
        wgpu::DeviceType::DiscreteGpu
            | wgpu::DeviceType::IntegratedGpu
            | wgpu::DeviceType::VirtualGpu
    )
}

/// Wgpu compute indirect dispatch is a core command-buffer operation; the
/// honest gate is whether this backend owns a real GPU device with enough
/// storage-buffer space for the required u32 x/y/z dispatch tuple.
#[inline]
pub(crate) fn supports_indirect_dispatch(
    adapter_info: &wgpu::AdapterInfo,
    enabled: &EnabledFeatures,
) -> bool {
    supports_indirect_dispatch_limits(
        adapter_info,
        enabled.max_storage_buffer_binding_size,
        enabled.max_workgroup_size,
    )
}

#[inline]
pub(crate) fn supports_indirect_dispatch_limits(
    adapter_info: &wgpu::AdapterInfo,
    max_storage_buffer_binding_size: u64,
    max_workgroup_size: [u32; 3],
) -> bool {
    is_real_gpu(adapter_info)
        && max_storage_buffer_binding_size >= 12
        && max_workgroup_size.iter().all(|axis| *axis > 0)
}

#[inline]
pub(crate) fn supports_subgroup_for_adapter(
    features: wgpu::Features,
    limits: &wgpu::Limits,
) -> bool {
    features.contains(wgpu::Features::SUBGROUP)
        && limits.min_subgroup_size > 0
        && limits.max_subgroup_size >= limits.min_subgroup_size
}

/// Subgroup support requires both the requested device feature and usable
/// subgroup-size limits for dispatch planning.
#[inline]
pub(crate) fn supports_subgroup_ops(enabled: &EnabledFeatures) -> bool {
    enabled.subgroup
        && enabled.min_subgroup_size > 0
        && enabled.max_subgroup_size >= enabled.min_subgroup_size
}

/// Capability snapshot consumed by foundation validation and execution
/// planning. Keep this as the single value-object constructor so trait
/// reports and planner checks cannot drift.
#[inline]
pub(crate) fn validation_capabilities(
    adapter_info: &wgpu::AdapterInfo,
    enabled: &EnabledFeatures,
) -> BackendCapabilities {
    BackendCapabilities {
        supports_subgroup_ops: supports_subgroup_ops(enabled),
        supports_indirect_dispatch: supports_indirect_dispatch(adapter_info, enabled),
        supports_specialization_constants: true,
    }
}
