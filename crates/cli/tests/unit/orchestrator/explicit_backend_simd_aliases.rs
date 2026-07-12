use keyhog::testing::{CliTestApi as _, API};
use keyhog_scanner::hw_probe::ScanBackend;

#[test]
fn explicit_backend_simd_aliases() {
    assert_eq!(
        API.explicit_backend_override(Some("hyperscan")).unwrap(),
        Some(ScanBackend::SimdCpu)
    );
}
