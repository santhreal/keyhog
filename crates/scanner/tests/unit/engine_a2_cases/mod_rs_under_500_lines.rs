#[test]
fn mod_rs_under_500_lines() {
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/src/engine/mod.rs");
    let n = std::fs::read_to_string(p).unwrap().lines().count();
    assert!(n <= 500, "engine/mod.rs {n} lines");
}
