//! KH-GAP-080: CI must unset CC so distcc/ccache wrappers cannot poison builds.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

#[test]
fn every_cargo_workflow_step_unsets_cc_before_build() {
    let workflows_dir = repo_root().join(".github/workflows");
    let mut offenders: Vec<String> = Vec::new();

    for entry in std::fs::read_dir(&workflows_dir).expect("list workflows") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("yml") {
            continue;
        }
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let text = std::fs::read_to_string(&path).expect("read workflow");
        let runs_cargo = text.contains("cargo build")
            || text.contains("cargo test")
            || text.contains("cargo check")
            || text.contains("cargo clippy");
        if !runs_cargo {
            continue;
        }
        let has_cc_guard = text.contains("env -u CC")
            || text.contains("unset CC")
            || text.contains("CC: \"\"") && text.contains("env:");
        if !has_cc_guard {
            offenders.push(name);
        }
    }

    assert!(
        offenders.is_empty(),
        "workflows invoking cargo must unset CC (distcc guard per KEYHOG_LINUX_QUALITY_PROGRAM); \
         missing in: {offenders:?} (KH-GAP-080)"
    );
}
