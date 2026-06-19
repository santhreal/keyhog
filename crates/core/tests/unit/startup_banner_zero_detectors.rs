//! Migrated from `src/banner.rs` - zero detector count renders without panic.


#[test]
fn startup_banner_zero_detector_count_renders() {
    let mut buf = Vec::new();
    keyhog_core::testing::CoreTestApi::report_banner(&keyhog_core::testing::TestApi, &mut buf, false, false, 0).expect("banner write");
    let output = String::from_utf8(buf).expect("utf8 banner");
    assert!(output.contains("0 detectors"));
}
