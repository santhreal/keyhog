//! KH-GAP-074: fuzz targets are not invoked by any CI workflow.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

#[test]
fn ci_workflows_invoke_fuzz_targets_or_cargo_fuzz() {
    let workflows_dir = repo_root().join(".github/workflows");
    let mut combined = String::new();
    for entry in std::fs::read_dir(&workflows_dir).expect("list workflows") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) == Some("yml") {
            combined.push_str(&std::fs::read_to_string(&path).expect("read workflow"));
        }
    }

    let wired = combined.contains("cargo fuzz")
        || combined.contains("fuzz/")
        || combined.contains("scanner_target")
        || combined.contains("decode_target");

    assert!(
        wired,
        "no .github/workflows/*.yml references cargo-fuzz or fuzz/ targets — \
         fuzz corpus never runs in CI (KH-GAP-074)"
    );
}
