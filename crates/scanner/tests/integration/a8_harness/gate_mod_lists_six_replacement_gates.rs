//! LR2-A8 harness integration: LR1-A8 gate count for scanner

#[test]
fn gate_mod_has_six_files() {
    let gate_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/gate");
    let count = std::fs::read_dir(&gate_dir).unwrap().filter(|e| {
        e.as_ref().unwrap().path().extension().map(|x| x == "rs").unwrap_or(false)
            && e.as_ref().unwrap().file_name() != "mod.rs"
    }).count();
    assert_eq!(count, 6, "scanner gate/ must retain six replacement tests");
}
