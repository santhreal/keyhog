//! Migrated from `src/config.rs` - fast preset caps recursive decode depth at 2.

use keyhog_core::ScanConfig;

#[test]
fn fast_preset_lowers_decode_depth() {
    assert_eq!(ScanConfig::fast().max_decode_depth, 2);
}
