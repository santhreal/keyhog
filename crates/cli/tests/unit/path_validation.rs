//! Micro gate for `cli/path_validation.rs`.

use keyhog::testing::{CliTestApi as _, API};
use std::path::Path;

#[test]
fn validate_cli_path_arg_rejects_missing_path() {
    let missing = Path::new("/tmp/keyhog-path-validation-missing-xyzzy");
    let err = API.validate_cli_path_arg(missing, "scan path").unwrap_err();
    assert!(
        err.to_string().contains("does not exist"),
        "missing path must error clearly; got {err}"
    );
}

#[test]
fn validate_cli_path_arg_accepts_existing_file() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("exists.txt");
    std::fs::write(&file, "ok").unwrap();
    API.validate_cli_path_arg(&file, "scan path").unwrap();
}
