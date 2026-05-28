//! KH-GAP-163: R5 adversarial expansion keeps one #[test] per file (expansion dirs only).

use std::path::PathBuf;

#[test]
fn adversarial_rs_files_each_have_single_test_attr() {
    let adv = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/adversarial");
    let mut offenders = Vec::new();
    for entry in walkdir_rs(&adv) {
        if should_skip(&entry) {
            continue;
        }
        let text = std::fs::read_to_string(&entry).expect("read");
        let count = text.matches("#[test]").count();
        if count != 1 {
            offenders.push((entry.display().to_string(), count));
        }
    }
    assert!(
        offenders.is_empty(),
        "KH-GAP-163: expected one #[test] per R5 adversarial rs file: {offenders:?}"
    );
}

fn should_skip(path: &PathBuf) -> bool {
    let s = path.to_string_lossy();
    if s.contains("/engine_cases/") {
        return true;
    }
    if let Some(parent) = path.parent() {
        if parent.file_name().and_then(|n| n.to_str()) == Some("adversarial") {
            return true;
        }
    }
    matches!(
        path.file_name().and_then(|n| n.to_str()),
        Some("oracle_support.rs" | "megakernel_support.rs" | "engine.rs" | "mod.rs")
    )
}

fn walkdir_rs(root: &PathBuf) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(root).expect("read_dir") {
        let entry = entry.expect("entry");
        let path = entry.path();
        if path.is_dir() {
            out.extend(walkdir_rs(&path));
        } else if path.extension().and_then(|s| s.to_str()) == Some("rs")
            && path.file_name().and_then(|s| s.to_str()) != Some("mod.rs")
        {
            out.push(path);
        }
    }
    out
}
