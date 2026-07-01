//! KH-GAP-099: Global `--help` must document exit 3 for scanner system errors, not audit-only.

#[test]
fn cli_after_help_documents_system_error_exit_three() {
    let help = keyhog::exit_codes::help();
    assert!(
        help.contains("System error") || help.contains("system error"),
        "Cli after_help must document exit 3 for scanner/system failures"
    );
    assert!(
        !help.contains("3   `detectors --audit` flagged a detector quality issue"),
        "after_help must not describe exit 3 as audit-only while main.rs uses 3 for system errors"
    );
}
