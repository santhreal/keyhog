//! LR1-A8 replacement gate: `path_validation.rs` existing directory.

use keyhog::testing::{CliTestApi as _, API};

#[test]
fn validate_cli_path_arg_accepts_existing_directory() {
    let dir = tempfile::tempdir().unwrap();
    let result = API.validate_cli_path_arg(dir.path(), "scan");
    assert!(
        result.is_ok(),
        "existing scan target must pass validation: {:?}",
        result.err()
    );
}
