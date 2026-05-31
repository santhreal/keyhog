//! Vyre roadmap docs must track the workspace-pinned crate version.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d
}

fn workspace_vyre_pin(manifest: &str) -> String {
    manifest
        .lines()
        .find_map(|line| {
            let trimmed = line.trim();
            trimmed
                .strip_prefix("vyre = \"=")
                .and_then(|rest| rest.split_once('"').map(|(version, _)| version.to_string()))
        })
        .expect("root Cargo.toml must pin vyre")
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
