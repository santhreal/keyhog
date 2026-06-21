use std::path::PathBuf;

fn scanner_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn simd_no_hit_multiline_branch_does_not_reenter_full_scan() {
    let src = std::fs::read_to_string(scanner_root().join("src/engine/scan_coalesced.rs"))
        .expect("coalesced scan source readable");
    // The SIMD-coalesced phase-2 no-hit branch: a chunk that fired no phase-1
    // trigger but was admitted by `should_scan_no_hit_chunk`. The old code had
    // two separate branches (a "Multiline fallback" branch + a "Task #69
    // follow-up" branch); they were unified into one no-hit path that scans the
    // (possibly drifted) preprocessed text directly via the triggered path —
    // which also covers the multiline-concatenation / decode-append case. The
    // invariant this gate protects is unchanged: that path must NOT re-enter
    // `self.scan(chunk)` (which would re-run preprocessing + decode recursion and
    // double the work), and it MUST scan drifted preprocessed text via
    // `scan_prepared_with_triggered`, gated by the raw-vs-preprocessed drift
    // check.
    let start = src
        .find("&& !self.should_scan_no_hit_chunk(chunk)")
        .expect("SIMD no-hit branch must gate unadmitted no-trigger chunks");
    let end = src
        .find("let phase2_elapsed = phase2_start.elapsed();")
        .expect("phase-2 boundary-reassembly tail must follow the no-hit branch");
    assert!(
        start < end,
        "no-hit branch must precede the reassembly tail"
    );
    let branch = &src[start..end];

    assert!(
        !branch.contains("return self.scan(chunk);"),
        "SIMD no-hit branch must not re-enter full scan/postprocess decode"
    );
    assert!(
        branch.contains("prepared.preprocessed.text.as_bytes() == chunk.data.as_bytes()")
            && branch.contains("scan_prepared_with_triggered("),
        "SIMD no-hit branch must scan drifted preprocessed text via the triggered \
         path (raw-vs-preprocessed drift guard + scan_prepared_with_triggered), \
         not decode recursion"
    );
}
