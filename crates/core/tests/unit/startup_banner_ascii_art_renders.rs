//! Migrated from `src/banner.rs` — ASCII art mode emits braille dots.

use keyhog_core::banner::print_banner;

#[test]
fn startup_banner_ascii_art_renders_when_enabled() {
    let mut buf = Vec::new();
    print_banner(&mut buf, false, true, 1).expect("banner write");
    let output = String::from_utf8(buf).expect("utf8 banner");
    assert!(output.contains('⠀'));
}
