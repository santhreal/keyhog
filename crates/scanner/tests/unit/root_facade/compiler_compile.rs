use aho_corasick::AhoCorasickBuilder;
use keyhog_scanner::testing::{
    phase2_keyword_matches_for_test, phase2_keyword_storage_snapshot_for_test,
};

/// WHY: cloning every detector-authored keyword into the temporary keyword
/// catalog doubled its live string bytes during scanner construction.
#[test]
fn raw_phase2_keywords_borrow_the_canonical_compile_state_strings() {
    let snapshot = phase2_keyword_storage_snapshot_for_test(
        r"SERVICE_API_KEY[:=][A-Z0-9]{16}",
        vec!["SERVICE_API_KEY".to_owned()],
    );

    assert_eq!(snapshot.mapping, vec![vec![0]]);
    assert_eq!(snapshot.keywords, ["SERVICE_API_KEY"]);
    assert_eq!(snapshot.borrowed, [true]);
    assert_eq!(
        snapshot.borrowed_points_to_input,
        [true],
        "borrowed keyword must point at the canonical compile-state allocation"
    );
}

/// WHY: repeated-separator regexes need their synthesized stem to own its bytes
/// while raw keywords remain borrowed and both retain exact pattern mappings.
#[test]
fn derived_phase2_stems_own_only_synthesized_bytes() {
    let snapshot = phase2_keyword_storage_snapshot_for_test(
        r"SERVICE[_\-.]+API[_\-.]+KEY[:=][A-Z0-9]{16}",
        vec!["SERVICE_API_KEY".to_owned()],
    );

    assert_eq!(snapshot.mapping, vec![vec![0], vec![0]]);
    assert_eq!(snapshot.keywords, ["SERVICE_API_KEY", "service"]);
    assert_eq!(snapshot.borrowed, [true, false]);
    assert_eq!(snapshot.borrowed_points_to_input, [true, false]);
}

/// WHY: the compact prefix table replaces the phase-two Aho-Corasick gate, so
/// it must preserve ASCII-insensitive substring admission across rows sharing
/// the same two-byte bucket.
#[test]
fn compact_phase2_keyword_index_finds_casefolded_shared_prefixes() {
    assert_eq!(
        phase2_keyword_matches_for_test(&["TOKEN_A", "TOKEN_B"], "prefix token_b suffix TOKEN_A"),
        Some(vec![1, 0])
    );
}

/// WHY: phase-two activation and autoroute evidence require the same
/// earliest-end, non-overlapping selection as Aho-Corasick when one keyword
/// prefixes another.
#[test]
fn compact_phase2_keyword_index_preserves_standard_match_selection() {
    assert_eq!(
        phase2_keyword_matches_for_test(
            &["TOKEN", "TOKEN_VALUE"],
            "prefix token_value suffix TOKEN"
        ),
        Some(vec![0, 0])
    );
}

/// WHY: the replacement index must retain standard Aho-Corasick iterator
/// semantics across shared prefixes, repeated matches, case folds, later-start
/// short rows, empty text, and non-ASCII neighbors.
#[test]
fn compact_phase2_keyword_index_matches_reference_aho_semantics() {
    let keywords = ["TOKEN", "TOKEN_VALUE", "VALUE", "AB", "ABC"];
    let reference = AhoCorasickBuilder::new()
        .ascii_case_insensitive(true)
        .build(keywords)
        .expect("reference automaton");

    for haystack in [
        "",
        "x",
        "token_value",
        "xxTOKEN_VALUEyy token",
        "zabcab",
        "zzzzabTOKENvalue",
        "unicode-λ-token-value",
    ] {
        let expected = reference
            .find_iter(haystack)
            .map(|matched| matched.pattern().as_usize())
            .collect::<Vec<_>>();
        assert_eq!(
            phase2_keyword_matches_for_test(&keywords, haystack),
            Some(expected),
            "haystack: {haystack:?}"
        );
    }
}

/// WHY: an unindexable short literal must disable keyword gating rather than
/// disappear from admission and silently suppress its detector.
#[test]
fn compact_phase2_keyword_index_fails_open_for_short_literals() {
    assert_eq!(phase2_keyword_matches_for_test(&["x"], "x"), None);
}
