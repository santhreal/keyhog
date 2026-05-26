//! KH-GAP-006: main.rs routes SCANNER_PANICKED to EXIT_SYSTEM_ERROR.

#[test]
fn main_maps_scanner_panic_to_system_exit() {
    let main_rs = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/main.rs"));
    assert!(main_rs.contains("SCANNER_PANICKED"));
    assert!(main_rs.contains("EXIT_SYSTEM_ERROR"));
}
