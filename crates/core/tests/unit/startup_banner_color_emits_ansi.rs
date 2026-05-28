//! Migrated from `src/banner.rs` - color mode emits ANSI escape sequences.

use keyhog_core::banner::print_banner;

#[test]
fn startup_banner_color_emits_ansi_sequences() {
    let mut buf = Vec::new();
    print_banner(&mut buf, true, false, 1).expect("banner write");
    let output = String::from_utf8(buf).expect("utf8 banner");
    assert!(output.contains("["));
}
