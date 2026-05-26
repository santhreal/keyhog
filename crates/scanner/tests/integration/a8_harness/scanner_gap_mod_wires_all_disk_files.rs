//! LR2-A8 harness integration: gap/mod.rs matches disk

#[test]
fn gap_mod_covers_every_gap_rs_except_mod() {
    let gap_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/gap");
    let mod_src = std::fs::read_to_string(gap_dir.join("mod.rs")).expect("mod.rs");
    for entry in std::fs::read_dir(&gap_dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|s| s.to_str()) != Some("rs") { continue; }
        let stem = path.file_stem().unwrap().to_str().unwrap();
        if stem == "mod" { continue; }
        assert!(mod_src.contains(&format!("pub mod {stem};")), "gap/mod.rs missing {stem}");
    }
}
