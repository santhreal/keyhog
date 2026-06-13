//! Vyre roadmap docs must track the workspace-pinned crate version.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d
}

fn workspace_vyre_pin(manifest: &str) -> String {
    // The `vyre` dependency line appears in one of two equivalent forms:
    //   * bare-string pin:      vyre = "=0.6.1"
    //   * inline table (carrying a path override during a vyre migration):
    //                           vyre = { version = "=0.6.1", path = "..." }
    // Both embed the exact pin as the `"=<version>"` literal, so locate the
    // `vyre =` line and extract the version after `"=` regardless of layout —
    // the previous `strip_prefix("vyre = \"=")` only matched the bare-string
    // form and panicked on the inline-table form the workspace actually uses.
    manifest
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("vyre =") || line.starts_with("vyre="))
        .find_map(|line| {
            let after = line.split_once("\"=")?.1;
            after
                .split_once('"')
                .map(|(version, _)| version.to_string())
        })
        .expect(
            "root Cargo.toml must pin vyre as `vyre = \"=X.Y.Z\"` or \
             `vyre = { version = \"=X.Y.Z\", .. }`",
        )
}

#[test]
fn vyre_usage_doc_matches_workspace_pin() {
    let root = repo_root();
    let manifest = std::fs::read_to_string(root.join("Cargo.toml")).expect("root Cargo.toml");
    let doc = std::fs::read_to_string(root.join("docs/vyre-usage.md")).expect("docs/vyre-usage.md");
    let version = workspace_vyre_pin(&manifest);

    assert!(
        doc.contains(&format!("vyre v{version}")),
        "docs/vyre-usage.md must state the workspace vyre pin v{version}"
    );
    assert!(
        !doc.contains("Vyre is not on crates.io"),
        "docs/vyre-usage.md must not claim Vyre is unpublished while Cargo.toml uses crates.io pins"
    );
    assert!(
        !doc.contains("vendored vyre v0.6.0"),
        "docs/vyre-usage.md must not describe the active audit as v0.6.0"
    );
}
