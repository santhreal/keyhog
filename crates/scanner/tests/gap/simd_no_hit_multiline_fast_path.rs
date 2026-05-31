use std::path::PathBuf;

fn scanner_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn simd_no_hit_multiline_branch_does_not_reenter_full_scan() {
    let src = std::fs::read_to_string(scanner_root().join("src/engine/scan.rs"))
        .expect("scan source readable");
    let multiline = src
        .find("Multiline fallback: files with concatenation indicators")
        .expect("SIMD no-hit multiline branch must exist");
    let fallback = src
        .find("Task #69 follow-up: scan_fallback_patterns")
        .expect("SIMD no-hit fallback branch must exist");
    let branch = &src[multiline..fallback];

    assert!(
        !branch.contains("return self.scan(chunk);"),
        "SIMD no-hit multiline path must not re-enter full scan/postprocess decode"
    );
    assert!(
        branch.contains("prepared.preprocessed.text.as_bytes() != chunk.data.as_bytes()")
            && branch.contains("scan_prepared_with_triggered("),
        "SIMD no-hit multiline path must scan changed preprocessed text without decode recursion"
    );
}
