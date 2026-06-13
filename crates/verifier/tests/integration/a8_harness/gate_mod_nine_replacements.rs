//! LR2-A8 harness integration: verifier gate-dir wiring coherence + retention floor.
//!
//! Replaces a brittle `assert_eq!(count, 9)` magic-constant tripwire with the
//! invariant the count was a proxy for:
//!   1. WIRING — every `tests/gate/*.rs` file (except `mod.rs`) is declared as a
//!      `mod <name>;` in `tests/gate/mod.rs`. An unwired gate file is a silently
//!      dead test; a dangling `mod` would already fail to compile. This never
//!      breaks when a real gate is added, so it needs no maintenance bump.
//!   2. RETENTION — the LR1-A8 migration created 9 replacement gates; that
//!      baseline set may never be silently dropped. New gates only raise the
//!      count, so the floor never needs bumping for legitimate additions.

/// LR1-A8 migration baseline for the verifier crate. A floor, not an exact count:
/// deletions below it fail, additions above it are fine.
const GATE_RETENTION_FLOOR: usize = 9;

#[test]
fn gate_dir_files_are_wired_and_meet_floor() {
    let gate_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/gate");

    let mut files: Vec<String> = std::fs::read_dir(&gate_dir)
        .expect("read tests/gate")
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".rs") && n != "mod.rs")
        .map(|n| n.trim_end_matches(".rs").to_string())
        .collect();
    files.sort();

    let mod_src = std::fs::read_to_string(gate_dir.join("mod.rs")).expect("read tests/gate/mod.rs");
    let mut declared: Vec<String> = mod_src
        .lines()
        .map(str::trim)
        .filter_map(|l| l.strip_prefix("pub mod ").or_else(|| l.strip_prefix("mod ")))
        .map(|rest| rest.trim_end_matches(';').trim().to_string())
        .collect();
    declared.sort();

    assert_eq!(
        files, declared,
        "verifier tests/gate/: every gate .rs file must be wired in mod.rs (no dead/unwired gate)"
    );
    assert!(
        files.len() >= GATE_RETENTION_FLOOR,
        "verifier tests/gate/ must retain >= {GATE_RETENTION_FLOOR} replacement tests, found {}",
        files.len()
    );
}
