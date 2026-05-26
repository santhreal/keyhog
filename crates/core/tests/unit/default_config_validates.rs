//! Migrated from `src/config.rs` — default scan config passes validation.

use keyhog_core::ScanConfig;

#[test]
fn default_config_validates() {
    ScanConfig::default()
        .validate()
        .expect("default ScanConfig must validate without error");
}
