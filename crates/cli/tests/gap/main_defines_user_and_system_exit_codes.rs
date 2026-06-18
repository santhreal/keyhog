//! KH-GAP-006: main.rs defines distinct user (2) and system (3) exit codes.

use keyhog::exit_codes::{EXIT_SYSTEM_ERROR, EXIT_USER_ERROR};

#[test]
fn main_defines_user_and_system_exit_codes() {
    let exit_codes = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/exit_codes.rs"));
    assert_eq!(EXIT_USER_ERROR, 2);
    assert_eq!(EXIT_SYSTEM_ERROR, 3);
    assert!(exit_codes.contains("EXIT_USER_ERROR"));
    assert!(exit_codes.contains("EXIT_SYSTEM_ERROR"));
    let main_rs = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/main.rs"));
    assert!(!main_rs.contains("const EXIT_USER_ERROR"));
    assert!(!main_rs.contains("const EXIT_SYSTEM_ERROR"));
    assert!(!main_rs.contains("EXIT_RUNTIME_ERROR"));
}
