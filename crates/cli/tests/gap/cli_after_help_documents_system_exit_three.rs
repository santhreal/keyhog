//! KH-GAP-099: Global `--help` must document exit 3 for scanner system errors, not audit-only.

#[test]
fn cli_after_help_documents_system_error_exit_three() {
    let args_rs = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/args.rs"));
    assert!(
        args_rs.contains("System error (scanner panic)")
            || args_rs.contains("system error"),
        "Cli after_help must document exit 3 for scanner/system failures"
    );
    assert!(
        !args_rs.contains("3   `detectors --audit` flagged a detector quality issue"),
        "after_help must not describe exit 3 as audit-only while main.rs uses 3 for system errors"
    );
}
