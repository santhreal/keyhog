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
