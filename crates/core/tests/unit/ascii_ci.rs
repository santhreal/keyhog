use keyhog_core::{
    contains_bytes_ignore_ascii_case, contains_ignore_ascii_case, starts_with_ignore_ascii_case,
};

#[test]
fn ascii_ci_helpers_match_without_allocating_casefolded_strings() {
    assert!(contains_ignore_ascii_case(
        "GitHub Personal Access Token",
        "github"
    ));
    assert!(contains_ignore_ascii_case(
        "GitHub Personal Access Token",
        "PERSONAL"
    ));
    assert!(contains_ignore_ascii_case(
        "GitHub Personal Access Token",
        ""
    ));
    assert!(!contains_ignore_ascii_case("GitHub", "gitlab"));

    assert!(contains_bytes_ignore_ascii_case(
        "AWS Session Token",
        b"session"
    ));
    assert!(contains_bytes_ignore_ascii_case(
        "AWS Session Token",
        b"AWS"
    ));
    assert!(contains_bytes_ignore_ascii_case("AWS Session Token", b""));
    assert!(!contains_bytes_ignore_ascii_case("AWS", b"azure"));

    assert!(starts_with_ignore_ascii_case("OpenAI", "open"));
    assert!(!starts_with_ignore_ascii_case("OpenAI", "ai"));
}
