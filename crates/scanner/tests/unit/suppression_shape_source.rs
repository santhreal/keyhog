use super::*;

/// Intent pin for the `CREDENTIAL_KEYWORD_NEEDLES` unification: `passwd`
/// is a canonical credential keyword (same set the entropy keyword list and
/// the TS non-null identifier gate use), so a camel-cased dotted candidate
/// carrying a `passwd` segment IS a source identifier and must suppress.
/// If someone narrows the canonical set and drops `passwd`, this fails.
#[test]
fn dotted_source_identifier_suppresses_camel_passwd_segment() {
    assert!(
        looks_like_dotted_source_identifier("userDb.passwd.value"),
        "camel-cased dotted candidate with a passwd segment must be a source identifier",
    );
}

/// Guardrail on the widening: `passwd` alone (no camel segment, no known
/// receiver) must NOT suppress, so the passwd inclusion does not silently
/// swallow flat dotted credential paths.
#[test]
fn dotted_passwd_without_camel_or_receiver_does_not_suppress() {
    assert!(
        !looks_like_dotted_source_identifier("db.passwd.field"),
        "a flat passwd dotted path with no camel segment must not be suppressed",
    );
}

/// Single-pass rewrite must preserve the 2..=5 segment-count window and the
/// empty-segment / non-alnum rejections.
#[test]
fn dotted_source_identifier_segment_count_and_body_bounds() {
    // 6 dotted segments is over the 5-segment ceiling → not an identifier.
    assert!(!looks_like_dotted_source_identifier("aB.cD.eF.gH.iJ.kL"));
    // Single segment (no dot) is under the floor.
    assert!(!looks_like_dotted_source_identifier("userDbPasswd"));
    // Empty segment rejects regardless of count.
    assert!(!looks_like_dotted_source_identifier("userDb..passwd"));
    // Non-alnum body byte rejects.
    assert!(!looks_like_dotted_source_identifier("userDb.pass-wd.value"));
}

/// First-segment receiver match short-circuits to true without needing a
/// camel/credential segment (the `first` capture in the single pass).
#[test]
fn dotted_source_identifier_receiver_first_segment() {
    assert!(looks_like_dotted_source_identifier(&format!(
        "{}.field",
        SOURCE_RECEIVERS[0].as_str()
    )));
}

#[test]
fn generated_template_interpolation_prefix_is_source_syntax() {
    let randomness = TokenRandomness::for_candidate("__vlist$");
    assert!(looks_like_source_code_expression_with_randomness(
        "__vlist$",
        &randomness
    ));
    assert!(!looks_like_template_interpolation_prefix("realSecret$"));
}
