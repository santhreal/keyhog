use super::wgpu_resident_timed_dispatch_supported;

/// Regression: resident timed dispatch may run only when both timestamp features are enabled on the device.
#[test]
fn resident_timed_dispatch_requires_both_timestamp_features() {
    let complete =
        wgpu::Features::TIMESTAMP_QUERY | wgpu::Features::TIMESTAMP_QUERY_INSIDE_ENCODERS;
    assert!(wgpu_resident_timed_dispatch_supported(complete));
}

/// Regression: adapters without timestamp queries must use the exact untimed fused scan rather than failing the GPU route.
#[test]
fn resident_timed_dispatch_rejects_adapters_without_timestamp_queries() {
    assert!(!wgpu_resident_timed_dispatch_supported(
        wgpu::Features::empty()
    ));
    assert!(!wgpu_resident_timed_dispatch_supported(
        wgpu::Features::TIMESTAMP_QUERY_INSIDE_ENCODERS
    ));
}

/// Regression: a base timestamp query alone cannot support encoder timestamp writes and must not select the timed path.
#[test]
fn resident_timed_dispatch_rejects_partial_timestamp_support() {
    assert!(!wgpu_resident_timed_dispatch_supported(
        wgpu::Features::TIMESTAMP_QUERY
    ));
}

/// WHY: CUDA ordinal order can change independently of PCI order, so persisted
/// multi-device routes must use the driver-reported bus identity.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires a live NVIDIA GPU and CUDA driver"]
fn live_cuda_census_uses_driver_reported_pci_identity() {
    let census = super::enumerate_gpu_device_census().expect("enumerate live GPU census");
    let cuda = census
        .eligible
        .iter()
        .filter_map(|index| census.exposures.get(*index))
        .find(|device| device.api == crate::gpu::device_set::GpuApi::Cuda)
        .expect("eligible CUDA device");
    assert!(cuda.physical_identity.starts_with("pci:"));
    assert!(cuda.topology_identity.starts_with(&cuda.physical_identity));
    assert_ne!(cuda.device_id, 0);
    assert!(cuda.ineligible_reason.is_none());
}
