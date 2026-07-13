use keyhog::testing::{CliTestApi as _, API};

/// A real DIRECTORY whose name contains a dot (`my.config`, `v1.2`, a checkout
/// named `repo.git`, a Python `venv.d`, …) must anchor the allowlist at ITSELF.
/// The `is_dir()` filesystem probe in `allowlist_root` is LOAD-BEARING: the
/// non-existent-path shape heuristic treats ANY dotted path that has a parent as
/// a file: `(has_extension, Some(parent)) => parent`: so without the real-FS
/// check a dotted directory would wrongly anchor `.keyhogignore` at its PARENT,
/// loading a sibling tree's allowlist over the scanned directory's own. The
/// existing `allowlist_root_*` tests use only NON-existent paths (the heuristic
/// path), so this is the first to prove the real-FS `is_dir()` branch overrides
/// the extension guess for a dotted directory name.
#[test]
fn allowlist_root_real_dotted_directory_stays_itself() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().join("my.config"); // dotted directory name
    std::fs::create_dir(&dir).expect("create dotted directory");

    assert_eq!(
        API.allowlist_root_for_test(&dir),
        dir.as_path(),
        "a real dotted-name directory must anchor the allowlist at itself \
         (is_dir overrides the extension heuristic)"
    );
}
