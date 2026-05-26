//! Contract: majority of detector contracts ship at least one [[evasion]] fixture.

use std::path::PathBuf;

fn contracts_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("contracts")
}

#[test]
fn contracts_evasion_coverage_meets_minimum_floor() {
    // Floor raised by LR1-A9 (+5 hand-written evasion TOMLs). Target is
    // eventual 891/891; this gate prevents regressions while bulk backfill
    // continues.
    const MIN_WITH_EVASION: usize = 760;

    let mut total = 0usize;
    let mut with_evasion = 0usize;
    for entry in std::fs::read_dir(contracts_dir()).expect("contracts dir") {
        let path = entry.expect("dir entry").path();
        if path.parent().and_then(|p| p.file_name()) != Some(std::ffi::OsStr::new("contracts")) {
            continue;
        }
        if path.extension().and_then(|s| s.to_str()) != Some("toml") {
            continue;
        }
        total += 1;
        let text = std::fs::read_to_string(&path).expect("read contract");
        if text.contains("[[evasion]]") {
            with_evasion += 1;
        }
    }

    assert!(
        with_evasion >= MIN_WITH_EVASION,
        "only {with_evasion}/{total} contracts ship [[evasion]] — floor is {MIN_WITH_EVASION}"
    );
}
