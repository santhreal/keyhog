//! Gate: entropy plausibility has one typed-context production entry point.

use super::support::*;

#[test]
fn entropy_plausibility_uses_typed_context_entry_points() {
    let src = scanner_src();
    let owner = read(&src.join("entropy/plausibility.rs"));
    let keywords = read(&src.join("entropy/keywords.rs"));
    assert!(
        owner.contains("pub(crate) struct PlausibilityContext"),
        "entropy::plausibility must own the typed plausibility context"
    );
    assert!(
        owner.contains("pub(crate) fn is_candidate_plausible(")
            && owner.contains("context: PlausibilityContext"),
        "is_candidate_plausible must take PlausibilityContext"
    );
    assert!(
        owner.contains("pub(crate) fn is_secret_plausible(")
            && owner.contains("context: PlausibilityContext"),
        "is_secret_plausible must take PlausibilityContext"
    );
    assert!(
        owner.contains("pub(crate) fn passes_secret_strength_checks(")
            && owner.contains("context: PlausibilityContext"),
        "passes_secret_strength_checks must take PlausibilityContext"
    );
    assert!(
        owner.contains("crate::placeholder_words::contains_placeholder_word_with_entropy_hint(")
            && owner.contains(
                "crate::placeholder_words::bytes_contain_entropy_placeholder_marker(bytes)"
            ),
        "entropy::plausibility must consume the shared placeholder owner instead of duplicating marker lists"
    );
    for forbidden_marker in [
        "\"EXAMPLE\"",
        "\"YOUR_\"",
        "\"REPLACE_ME\"",
        "\"CHANGE_ME\"",
        "\"INSERT_HERE\"",
        "\"FAKE_\"",
        "\"DUMMY_\"",
        "\"MOCK_\"",
        "\"SECRET_KEY\"",
        "\"1234567890\"",
    ] {
        assert!(
            !owner.contains(forbidden_marker),
            "entropy::plausibility must not own placeholder marker literal {forbidden_marker}"
        );
    }

    for forbidden in [
        "pub(crate) struct PlausibilityContext",
        "pub(crate) fn is_candidate_plausible(",
        "pub(crate) fn is_secret_plausible(",
        "pub(crate) fn passes_secret_strength_checks(",
        "pub(crate) fn is_isolated_bare_secret_plausible(",
        "fn is_known_non_secret",
        "fn passes_plausibility_checks",
        "fn is_placeholder_ci",
    ] {
        assert!(
            !keywords.contains(forbidden),
            "entropy::keywords must not own plausibility body `{forbidden}`"
        );
    }

    for forbidden in [
        "fn is_candidate_plausible_with_context",
        "fn is_secret_plausible_with_context",
        "fn is_candidate_plausible_with_lift",
        "fn is_secret_plausible_with_lift",
        "fn passes_strict_secret_checks",
    ] {
        assert!(
            !owner.contains(forbidden),
            "entropy::plausibility must not reintroduce overload `{forbidden}`"
        );
    }

    let mut files = Vec::new();
    collect_rs_files(&src, &mut files);
    let mut offenders = Vec::new();
    for path in files {
        let rel = path.strip_prefix(&src).unwrap_or(&path);
        let code = read(&path);
        for forbidden in [
            "is_candidate_plausible_with_context",
            "is_secret_plausible_with_context",
            "is_candidate_plausible_with_lift",
            "is_secret_plausible_with_lift",
            "passes_strict_secret_checks",
        ] {
            if code.contains(forbidden) {
                offenders.push(format!("{} contains {forbidden}", rel.display()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "entropy plausibility overloads returned:\n{}",
        offenders.join("\n")
    );
}
