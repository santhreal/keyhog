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

#[cfg(unix)]
#[test]
fn validate_cli_path_arg_rejects_non_utf8_path_before_stat() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(OsStr::from_bytes(b"bad\xffname.txt"));
    let err = API.validate_cli_path_arg(&path, "scan path").unwrap_err();
    assert!(
        err.to_string().contains("UTF-8"),
        "non-UTF-8 path must identify filename encoding before filesystem probing; got {err}"
    );
}
