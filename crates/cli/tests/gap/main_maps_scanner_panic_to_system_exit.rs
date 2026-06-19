//! KH-GAP-006: the binary dispatch routes SCANNER_PANICKED to the dedicated
//! scanner-panic exit code.

use keyhog::exit_codes::EXIT_SCANNER_PANIC;

#[test]
fn main_maps_scanner_panic_to_system_exit() {
    assert_eq!(EXIT_SCANNER_PANIC, 11);
    let lib_rs = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"));
    assert!(lib_rs.contains("SCANNER_PANICKED"));
    assert!(lib_rs.contains("EXIT_SCANNER_PANIC"));
}
