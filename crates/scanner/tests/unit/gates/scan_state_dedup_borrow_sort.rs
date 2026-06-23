//! Gate ScanState match dedup: borrow-sort identity, no large-N clone HashSet.

#[test]
fn scan_state_into_matches_dedups_by_borrowed_identity_for_all_sizes() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/scan_state.rs");
    let src = std::fs::read_to_string(path).expect("scan_state source readable");
    let scanner_config = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/scanner_config.rs"
    ))
    .expect("scanner_config source readable");
    let body = src
        .split("pub(crate) fn into_matches(self) -> Vec<keyhog_core::RawMatch>")
        .nth(1)
        .and_then(|tail| tail.split("\n    }\n}").next())
        .expect("ScanState::into_matches body present");

    assert!(
        src.contains("pub(crate) struct ScanState")
            && src.contains("pub(crate) struct RawMatchPriority")
            && src.contains("pub(crate) struct MlPendingMatch")
            && src.contains("fn detector_candidate(")
            && src.contains("fn entropy_authoritative(")
            && src.contains("struct MatchIdentity<'a>")
            && src.contains("impl<'a> From<&'a keyhog_core::RawMatch> for MatchIdentity<'a>")
            && src.contains("fn raw_match_identity_cmp(")
            && src.contains("fn same_raw_match_identity(")
            && src.contains("MatchIdentity::from(a).cmp(&MatchIdentity::from(b))")
            && src.contains("MatchIdentity::from(a) == MatchIdentity::from(b)")
            && body.contains("matches.sort_by(raw_match_identity_cmp);")
            && body.contains("matches.dedup_by(|a, b| same_raw_match_identity(a, b));"),
        "ScanState::into_matches should dedup every size through named borrowed identity sorting"
    );
    assert!(
        !scanner_config.contains("struct ScanState")
            && !scanner_config.contains("struct RawMatchPriority")
            && !scanner_config.contains("struct MlPendingMatch"),
        "scanner_config.rs must not regain runtime scan-state ownership"
    );
    assert!(
        !body.contains("std::collections::HashSet<(std::sync::Arc<str>, SensitiveString, usize)>")
            && !body.contains("std::sync::Arc::clone(&m.detector_id)")
            && !body.contains("m.credential.clone()")
            && !body.contains("matches.len() <= 64"),
        "ScanState::into_matches must not restore the large-N HashSet clone path"
    );
}
