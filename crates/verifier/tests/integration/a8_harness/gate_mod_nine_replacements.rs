//! LR2-A8 harness integration: verifier gate count

#[test]
fn gate_dir_has_nine_tests() {
    let gate_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/gate");
    let n = std::fs::read_dir(&gate_dir).unwrap().filter(|e| {
        e.as_ref().unwrap().path().extension().map(|x| x == "rs").unwrap_or(false)
            && e.as_ref().unwrap().file_name() != "mod.rs"
    }).count();
    assert_eq!(n, 9);
}
