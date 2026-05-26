//! KH-GAP-006: main.rs defines distinct user (2) and system (3) exit codes.

#[test]
fn main_defines_user_and_system_exit_codes() {
    let main_rs = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/main.rs"));
    assert!(main_rs.contains("const EXIT_USER_ERROR: u8 = 2"));
    assert!(main_rs.contains("const EXIT_SYSTEM_ERROR: u8 = 3"));
    assert!(!main_rs.contains("EXIT_RUNTIME_ERROR"));
}
