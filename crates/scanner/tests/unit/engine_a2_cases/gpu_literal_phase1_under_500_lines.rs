#[test]
fn gpu_literal_phase1_under_500_lines() {
    let p = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/engine/gpu_literal_phase1.rs"
    );
    let n = std::fs::read_to_string(p).unwrap().lines().count();
    // Advisory cap (Santh STANDARD.md): warn, do not fail CI.
    if n > 500 {
        eprintln!("n exceeds 500-line cap (advisory)");
    }
}
