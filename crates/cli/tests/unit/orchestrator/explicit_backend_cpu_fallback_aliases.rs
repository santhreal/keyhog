use keyhog::testing::{CliTestApi as _, API};
use keyhog_scanner::hw_probe::ScanBackend;

#[test]
fn explicit_backend_cpu_fallback_aliases() {
    assert_eq!(
        API.explicit_backend_override(Some("scalar")).unwrap(),
        Some(ScanBackend::CpuFallback)
    );
}
