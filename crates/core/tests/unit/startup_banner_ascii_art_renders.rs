//! Migrated from `src/banner.rs` - ASCII art mode emits braille dots.

#[test]
fn startup_banner_ascii_art_renders_when_enabled() {
    let mut buf = Vec::new();
    keyhog_core::testing::CoreTestApi::report_banner(
        &keyhog_core::testing::TestApi,
        &mut buf,
        false,
        true,
        1,
    )
    .expect("banner write");
    let output = String::from_utf8(buf).expect("utf8 banner");
    assert!(output.contains('⠀'));
}
