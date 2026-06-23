//! Gate ScanState match dedup: borrow-sort identity, no large-N clone HashSet.

#[test]
fn scan_state_into_matches_dedups_by_borrowed_identity_for_all_sizes() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/scanner_config.rs");
    let src = std::fs::read_to_string(path).expect("scanner_config source readable");
    let body = src
        .split("pub(crate) fn into_matches(self) -> Vec<keyhog_core::RawMatch>")
        .nth(1)
        .and_then(|tail| tail.split("\n    }\n}").next())
        .expect("ScanState::into_matches body present");

    assert!(
        src.contains("fn raw_match_identity_cmp(")
            && src.contains("fn same_raw_match_identity(")
            && body.contains("matches.sort_by(raw_match_identity_cmp);")
            && body.contains("matches.dedup_by(|a, b| same_raw_match_identity(a, b));"),
        "ScanState::into_matches should dedup every size through borrowed identity sorting"
    );
    assert!(
        !body.contains("std::collections::HashSet<(std::sync::Arc<str>, SensitiveString, usize)>")
            && !body.contains("std::sync::Arc::clone(&m.detector_id)")
            && !body.contains("m.credential.clone()")
            && !body.contains("matches.len() <= 64"),
        "ScanState::into_matches must not restore the large-N HashSet clone path"
    );
}
