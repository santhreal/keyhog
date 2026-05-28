//! KH-GAP-114: sources adversarial Windows paths must not be empty stubs.

use std::path::PathBuf;

#[test]
fn adversarial_windows_symlink_oracles_are_real() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/adversarial");
    let files = [
        "archive_symlink_target_swap_attempt.rs",
        "plain_file_symlink_refused.rs",
        "walker_symlink_escape_outside_root.rs",
        "permission_denied_subtree_scan_continues.rs",
    ];
    for name in files {
        let src = std::fs::read_to_string(dir.join(name)).unwrap_or_else(|_| panic!("{name}"));
        assert!(
            src.contains("support::oracle_"),
            "{name} must delegate to shared adversarial oracle (not an empty Windows stub)"
        );
        assert!(
            !src.contains("#[cfg(not(unix))]"),
            "{name} must not host empty #[cfg(not(unix))] stub bodies"
        );
    }
}
