//! KH-GAP-149: Top50 near-miss modules wired in adversarial/mod.rs.

use std::path::PathBuf;

#[test]
fn r5_top50_near_miss_wired_in_adversarial_mod() {
    let tests = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/adversarial");
    let mod_rs = std::fs::read_to_string(tests.join("mod.rs")).expect("mod.rs");
    let missing: Vec<String> = std::fs::read_dir(&tests)
        .expect("read_dir")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
            name.starts_with("top50_") && name.contains("_near_miss") && name.ends_with(".rs")
        })
        .filter(|p| {
            let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("");
            !mod_rs.contains(&format!("mod {stem};"))
        })
        .map(|p| p.display().to_string())
        .collect();
    assert!(
        missing.is_empty(),
        "KH-GAP-149: unwired top50 near-miss modules: {missing:?}"
    );
}
