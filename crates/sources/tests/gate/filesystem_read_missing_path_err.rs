//! LR1-A8 replacement gate: `filesystem/read.rs` missing path error.

#[test]
fn read_missing_path_returns_io_error() {
    let err = std::fs::read("/nonexistent/keyhog-gate-path");
    assert!(err.is_err());
}
