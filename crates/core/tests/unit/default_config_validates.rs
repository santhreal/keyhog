//! Migrated from `src/config.rs` - default scan config passes validation.

use keyhog_core::ScanConfig;

#[test]
fn default_config_validates() {
    keyhog_core::testing::CoreTestApi::scan_config_validate(
        &keyhog_core::testing::TestApi,
        &ScanConfig::default(),
    )
    .expect("default ScanConfig must validate without error");
}
