use keyhog::testing::{CliTestApi as _, API};
use keyhog_scanner::hw_probe::ScanBackend;

#[test]
fn explicit_backend_trim_and_lowercase() {
    assert_eq!(
        API.explicit_backend_override(Some("  GPU-WGPU  ")).unwrap(),
        Some(ScanBackend::GpuWgpu)
    );
}
