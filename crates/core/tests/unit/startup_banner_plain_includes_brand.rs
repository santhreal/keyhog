//! Migrated from `src/banner.rs` - plain banner includes brand and detector count.

#[test]
fn startup_banner_plain_includes_brand_and_detector_count() {
    let mut buf = Vec::new();
    keyhog_core::testing::CoreTestApi::report_banner(
        &keyhog_core::testing::TestApi,
        &mut buf,
        false,
        false,
        42,
    )
    .expect("banner write");
    let output = String::from_utf8(buf).expect("utf8 banner");
    assert!(output.contains("K E Y H O G"));
    assert!(output.contains("42 detectors"));
    assert!(output.contains("by santh"));
}
