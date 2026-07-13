use keyhog::testing::{CliTestApi as _, API};

/// A real EXTENSIONLESS file (`Dockerfile`, `Makefile`, `LICENSE`, `go`, …) must
/// anchor the allowlist at its PARENT directory. The `is_file()` filesystem
/// probe in `allowlist_root` is LOAD-BEARING here: the non-existent-path shape
/// heuristic classifies a path as a file ONLY when it carries an extension, so
/// an extensionless file would fall through the heuristic to the
/// `(no-extension, Some(parent)) => treat-as-directory` arm and wrongly anchor
/// `.keyhogignore` loading INSIDE the file's own path. The existing
/// `allowlist_root_*` tests all use NON-existent paths (exercising the
/// heuristic), so this is the first to prove the real-FS `is_file()` branch
/// overrides the extension guess. Regressing it means `keyhog scan ./Dockerfile`
/// silently loads the allowlist from `./Dockerfile/` instead of `.`: real
/// suppressions stop applying (recall/precision drift).
#[test]
fn allowlist_root_real_extensionless_file_uses_parent() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let file = tmp.path().join("Dockerfile"); // no extension
    std::fs::write(&file, b"FROM scratch\n").expect("write extensionless file");

    assert_eq!(
        API.allowlist_root_for_test(&file),
        tmp.path(),
        "a real extensionless file must anchor the allowlist at its parent dir \
         (is_file overrides the extension heuristic)"
    );
}
