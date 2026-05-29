#[test]
fn mod_rs_under_500_lines() {
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/src/engine/mod.rs");
    let n = std::fs::read_to_string(p).unwrap().lines().count();
    // Advisory cap (Santh STANDARD.md): warn, do not fail CI.
    if n > 500 {
        eprintln!("engine/mod.rs {n} lines");
    }
}
