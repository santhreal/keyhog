//! Encoded credentials nested inside a structured URL value remain decode candidates.

use keyhog_scanner::decode::find_base64_strings;

#[test]
fn nested_url_credential_base64_found() {
    let blob = "WHk5S21QcTJMdlduQjd0Ug==";
    let text = format!("repo='https://ci-bot:{blob}@git.example.org/team/repo.git'");

    let matches = find_base64_strings(&text, 12);

    assert_eq!(
        matches
            .iter()
            .filter(|candidate| candidate.value == blob)
            .count(),
        1,
        "the URL envelope must not hide its base64 credential"
    );
}
