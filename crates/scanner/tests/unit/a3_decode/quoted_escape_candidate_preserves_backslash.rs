//! Quoted candidate extraction must preserve escape markers for escape decoders.

use keyhog_scanner::testing::extracted_value_strings_for_test;

#[test]
fn quoted_escape_candidate_preserves_backslash() {
    let candidates =
        extracted_value_strings_for_test(r#"let token = "\x41\u0042"; let other = "plain";"#);

    assert!(
        candidates
            .iter()
            .any(|candidate| candidate == r"\x41\u0042"),
        "quoted escape candidate must retain backslashes for hex/unicode decoders; got: {candidates:?}"
    );
    assert!(
        !candidates.iter().any(|candidate| candidate == "x41u0042"),
        "quoted extraction must not strip escape markers; got: {candidates:?}"
    );
}
