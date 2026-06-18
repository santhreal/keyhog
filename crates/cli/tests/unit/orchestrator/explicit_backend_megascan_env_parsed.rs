use keyhog::testing::{CliTestApi as _, API};
use keyhog_scanner::hw_probe::ScanBackend;

#[test]
fn explicit_backend_megascan_env_parsed() {
    assert_eq!(
        API.explicit_backend_override(Some("mega-scan")).unwrap(),
        Some(ScanBackend::MegaScan)
    );
}
