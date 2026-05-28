//! KH-GAP-143: site/hooks.html documents phantom `hook install --no-daemon`
//! and `--severity` flags that clap rejects (KH-GAP-104 fixed README only).

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d
}

#[test]
fn site_hooks_pages_do_not_document_phantom_hook_install_flags() {
    for rel in ["site/hooks.html", "site/pages/hooks.html"] {
        let html = std::fs::read_to_string(repo_root().join(rel)).expect(rel);
        assert!(
            !html.contains("hook install --no-daemon"),
            "{rel} must not document phantom hook install --no-daemon"
        );
        assert!(
            !html.contains("hook install --severity"),
            "{rel} must not document phantom hook install --severity"
        );
    }
}
