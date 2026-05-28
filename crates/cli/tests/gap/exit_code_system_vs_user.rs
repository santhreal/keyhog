//! KH-GAP-006: Santh exit codes - 2 user error, 3 system error.

#[test]
fn system_errors_use_exit_code_three() {
    let main_src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/main.rs"))
        .expect("main.rs");

    assert!(
        main_src.contains("EXIT_SYSTEM_ERROR"),
        "KH-GAP-006: CLI must define EXIT_SYSTEM_ERROR (3)"
    );
    assert!(
        main_src.contains("EXIT_USER_ERROR"),
        "KH-GAP-006: CLI must define EXIT_USER_ERROR (2)"
    );
    assert!(
        main_src.contains("SCANNER_PANICKED"),
        "KH-GAP-006: scanner panic must map to system exit code"
    );
}
