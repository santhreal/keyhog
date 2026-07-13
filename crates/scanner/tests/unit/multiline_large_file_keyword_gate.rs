//! Contract for the large-file keyword gate in multiline concatenation
//! detection (`multiline::has_concatenation_indicators`). Files over
//! `LARGE_FILE_KEYWORD_GATE_BYTES` (4096) only run multiline-concat reassembly
//! when a secret-related keyword is present. That keyword match is now
//! ASCII-case-insensitive: env-style credentials use all-caps keys
//! (`SECRET=`, `TOKEN=`, `PASSWORD=`, `CREDENTIAL=`) at least as often as the
//! title/lowercase forms, and the previous case-sensitive probe silently skipped
//! their reassembly. These tests pin every casing, the keyword set, the
//! no-keyword skip, and the small-file bypass.

use keyhog_scanner::testing::multiline::has_concatenation_indicators_for_test as has_concat;

/// Neutral filler, no secret keyword, no concat indicator, no structural lead
/// char, padded well past the 4096-byte large-file gate so the keyword gate
/// engages. The payload (with the keyword and/or concat indicator) is appended.
fn large_body_with(payload: &str) -> String {
    let filler = "plain data row\n".repeat(350); // 15 * 350 = 5250 bytes > 4096
    format!("{filler}{payload}\n")
}

// ── keyword casings on a large file (each needs a real concat indicator) ─────

#[test]
fn large_file_lowercase_secret_passes() {
    assert!(has_concat(&large_body_with("secret = \"a\" + \"b\"")));
}

#[test]
fn large_file_titlecase_secret_passes() {
    assert!(has_concat(&large_body_with("Secret = \"a\" + \"b\"")));
}

#[test]
fn large_file_uppercase_secret_passes() {
    // All-caps key (missed by the old case-sensitive `ecret` probe).
    assert!(has_concat(&large_body_with("SECRET = \"a\" + \"b\"")));
}

#[test]
fn large_file_mixed_case_secret_passes() {
    assert!(has_concat(&large_body_with("SeCrEt = \"a\" + \"b\"")));
}

#[test]
fn large_file_uppercase_token_passes() {
    assert!(has_concat(&large_body_with("TOKEN = \"a\" + \"b\"")));
}

#[test]
fn large_file_titlecase_token_passes() {
    assert!(has_concat(&large_body_with("Token = \"a\" + \"b\"")));
}

#[test]
fn large_file_uppercase_password_passes() {
    assert!(has_concat(&large_body_with("PASSWORD = \"a\" + \"b\"")));
}

#[test]
fn large_file_lowercase_password_passes() {
    assert!(has_concat(&large_body_with("password = \"a\" + \"b\"")));
}

#[test]
fn large_file_uppercase_credential_passes() {
    assert!(has_concat(&large_body_with("CREDENTIAL = \"a\" + \"b\"")));
}

#[test]
fn large_file_titlecase_credential_passes() {
    assert!(has_concat(&large_body_with("Credential = \"a\" + \"b\"")));
}

#[test]
fn large_file_uppercase_api_key_passes() {
    assert!(has_concat(&large_body_with("API_KEY = \"a\" + \"b\"")));
}

#[test]
fn large_file_lowercase_api_key_passes() {
    assert!(has_concat(&large_body_with("api_key = \"a\" + \"b\"")));
}

#[test]
fn large_file_mixed_case_api_key_passes() {
    assert!(has_concat(&large_body_with("Api_Key = \"a\" + \"b\"")));
}

#[test]
fn large_file_keyword_embedded_in_identifier_passes() {
    // The keyword need not be standalone. `MY_SECRET_VALUE` contains SECRET.
    assert!(has_concat(&large_body_with(
        "MY_SECRET_VALUE = \"a\" + \"b\""
    )));
}

// ── different concat-indicator kinds with an all-caps keyword ────────────────

#[test]
fn large_file_uppercase_token_with_backslash_continuation_passes() {
    assert!(has_concat(&large_body_with("TOKEN = \"abc\" \\")));
}

#[test]
fn large_file_uppercase_secret_with_template_interpolation_concat_passes() {
    // A string literal spliced into a template literal (`${"…"}`) is a
    // concat-evasion signal; pair it with an all-caps keyword.
    assert!(has_concat(&large_body_with("SECRET = `${\"abc\"}`")));
}

// ── the keyword gate genuinely gates (large file, no keyword ⇒ skipped) ──────

#[test]
fn large_file_concat_without_keyword_is_skipped() {
    // Real concat indicator present but no secret keyword ⇒ gate returns false.
    assert!(!has_concat(&large_body_with("value = \"a\" + \"b\"")));
}

#[test]
fn large_file_keyword_without_concat_indicator_is_false() {
    // Keyword present but nothing that looks like concatenation.
    assert!(!has_concat(&large_body_with("SECRET = xyz")));
}

#[test]
fn large_file_neither_keyword_nor_concat_is_false() {
    assert!(!has_concat(&large_body_with("value = xyz")));
}

// ── small files bypass the keyword gate entirely ────────────────────────────

#[test]
fn small_file_concat_without_keyword_passes() {
    // Under the 4096-byte threshold the keyword gate does not apply.
    assert!(has_concat("value = \"a\" + \"b\""));
}

#[test]
fn small_file_uppercase_secret_concat_passes() {
    assert!(has_concat("SECRET = \"a\" + \"b\""));
}
