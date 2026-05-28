//! KH-GAP-104: README/site document `hook install --no-daemon` but the hook
//! subcommand does not define that flag (`--no-daemon` lives on `scan`).

use crate::e2e::support::binary;
use std::path::PathBuf;
use std::process::Command;

fn repo_root() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d
}

#[test]
fn hook_install_exposes_no_daemon_or_readme_stops_documenting_it() {
    let readme = std::fs::read_to_string(repo_root().join("README.md")).expect("README.md");
    let help = Command::new(binary())
        .args(["hook", "install", "--help"])
        .output()
        .expect("spawn hook install --help");
    let help_text = String::from_utf8_lossy(&help.stdout);

    let readme_documents_flag = readme.contains("hook install --no-daemon");
    let hook_defines_flag = help_text.contains("--no-daemon");

    assert!(
        !readme_documents_flag || hook_defines_flag,
        "README must not document hook install --no-daemon unless hook install --help defines it; \
         readme_documents={readme_documents_flag}, hook_defines={hook_defines_flag}"
    );
}
