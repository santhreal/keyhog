//! KH-GAP-006: Santh exit codes - 2 user error, 3 system error,
//! 11 scanner panic.

use keyhog::exit_codes::{EXIT_SCANNER_PANIC, EXIT_SYSTEM_ERROR, EXIT_USER_ERROR};

#[test]
fn system_errors_use_exit_code_three() {
    let exit_codes =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/exit_codes.rs"))
            .expect("exit_codes.rs");
    let lib_src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"))
        .expect("lib.rs");

    assert_eq!(EXIT_USER_ERROR, 2);
    assert_eq!(EXIT_SYSTEM_ERROR, 3);
    assert_eq!(EXIT_SCANNER_PANIC, 11);

    assert!(
        exit_codes.contains("EXIT_SYSTEM_ERROR"),
        "KH-GAP-006: CLI must define EXIT_SYSTEM_ERROR (3)"
    );
    assert!(
        exit_codes.contains("EXIT_USER_ERROR"),
        "KH-GAP-006: CLI must define EXIT_USER_ERROR (2)"
    );
    assert!(
        lib_src.contains("SCANNER_PANICKED") && lib_src.contains("EXIT_SCANNER_PANIC"),
        "KH-GAP-006: scanner panic must map to the dedicated scanner-panic exit code"
    );
}
