/// Extended checksum tests: boundary conditions and hostile inputs.
///
/// The existing `checksum.rs` covers happy-path and basic negative paths.
/// This file adds: off-by-one lengths, non-alphanumeric bodies, empty strings,
/// very long payloads, stripe boundary cases, and gitlab token coverage.
use keyhog_scanner::checksum::{
    ChecksumResult, ChecksumValidator, GithubClassicPatValidator, GithubFineGrainedPatValidator,
    GitlabTokenValidator, NpmTokenValidator, PypiTokenValidator, SlackTokenValidator,
    StripeTokenValidator,
};

// ── GitHub classic PAT boundaries ─────────────────────────────────────────────

#[test]
fn github_classic_payload_35_chars_not_applicable() {
    // Payload must be exactly 36 chars; 35 → NotApplicable (not enough entropy)
    let token = concat!("gh", "p_").to_string() + &"A".repeat(35);
    assert_eq!(
        GithubClassicPatValidator.validate(&token),
        ChecksumResult::NotApplicable
    );
}

#[test]
fn github_classic_payload_37_chars_not_applicable() {
    // 37 chars → wrong length → NotApplicable
    let token = concat!("gh", "p_").to_string() + &"A".repeat(37);
    assert_eq!(
        GithubClassicPatValidator.validate(&token),
        ChecksumResult::NotApplicable
    );
}

#[test]
fn github_classic_empty_string_not_applicable() {
    assert_eq!(
        GithubClassicPatValidator.validate(""),
        ChecksumResult::NotApplicable
    );
}

#[test]
fn github_classic_body_with_special_chars_is_invalid() {
    // 36-char payload containing non-alphanumeric → Invalid (not NotApplicable)
    let token = concat!("gh", "p_").to_string() + &"A".repeat(29) + "!" + "AAAAAA";
    assert_eq!(
        GithubClassicPatValidator.validate(&token),
        ChecksumResult::Invalid
    );
}

// ── npm token boundaries ──────────────────────────────────────────────────────

#[test]
fn npm_empty_string_not_applicable() {
    assert_eq!(
        NpmTokenValidator.validate(""),
        ChecksumResult::NotApplicable
    );
}

#[test]
fn npm_payload_35_chars_not_applicable() {
    let token = "npm_".to_string() + &"A".repeat(35);
    assert_eq!(
        NpmTokenValidator.validate(&token),
        ChecksumResult::NotApplicable
    );
}

#[test]
fn npm_payload_with_special_chars_is_invalid() {
    // 36-char payload with non-alphanumeric → Invalid
    let token = "npm_".to_string() + &"A".repeat(30) + "!AAAAA";
    assert_eq!(NpmTokenValidator.validate(&token), ChecksumResult::Invalid);
}

// ── Stripe token ──────────────────────────────────────────────────────────────

#[test]
fn stripe_sk_live_short_payload_invalid() {
    // Payload only 23 chars — below 24 minimum
    let token = "sk_live_".to_string() + &"A".repeat(23);
    assert_eq!(
        StripeTokenValidator.validate(&token),
        ChecksumResult::Invalid
    );
}

#[test]
fn stripe_sk_live_exact_24_chars_valid() {
    let token = "sk_live_".to_string() + &"A".repeat(24);
    assert_eq!(StripeTokenValidator.validate(&token), ChecksumResult::Valid);
}

#[test]
fn stripe_sk_test_exact_48_chars_valid() {
    let token = "sk_test_".to_string() + &"A".repeat(48);
    assert_eq!(StripeTokenValidator.validate(&token), ChecksumResult::Valid);
}

#[test]
fn stripe_sk_live_49_chars_invalid() {
    // 49 chars — above 48 maximum
    let token = "sk_live_".to_string() + &"A".repeat(49);
    assert_eq!(
        StripeTokenValidator.validate(&token),
        ChecksumResult::Invalid
    );
}

#[test]
fn stripe_pk_live_valid() {
    let token = "pk_live_".to_string() + &"B".repeat(30);
    assert_eq!(StripeTokenValidator.validate(&token), ChecksumResult::Valid);
}

#[test]
fn stripe_rk_test_valid() {
    let token = "rk_test_".to_string() + &"C".repeat(30);
    assert_eq!(StripeTokenValidator.validate(&token), ChecksumResult::Valid);
}

#[test]
fn stripe_unknown_prefix_not_applicable() {
    assert_eq!(
        StripeTokenValidator.validate("wk_live_AAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        ChecksumResult::NotApplicable
    );
}

#[test]
fn stripe_empty_is_not_applicable() {
    assert_eq!(
        StripeTokenValidator.validate(""),
        ChecksumResult::NotApplicable
    );
}

#[test]
fn stripe_body_with_special_chars_invalid() {
    let token = "sk_live_".to_string() + &"A".repeat(23) + "!";
    assert_eq!(
        StripeTokenValidator.validate(&token),
        ChecksumResult::Invalid
    );
}

// ── Slack token boundaries ────────────────────────────────────────────────────

#[test]
fn slack_xoxb_too_short_is_invalid() {
    // xoxb- with only 5-digit numeric segments (below the 10-digit minimum)
    assert_eq!(
        SlackTokenValidator.validate(concat!("xox", "b-12345-12345-abcdefghijklmno")),
        ChecksumResult::Invalid
    );
}

#[test]
fn slack_empty_string_not_applicable() {
    assert_eq!(
        SlackTokenValidator.validate(""),
        ChecksumResult::NotApplicable
    );
}

#[test]
fn slack_xoxb_with_non_alnum_body_invalid() {
    // Valid numeric segments, but body has special chars
    assert_eq!(
        SlackTokenValidator.validate(concat!(
            "xox",
            "b-1234567890-1234567890-abc!@#defghijklmnopq"
        )),
        ChecksumResult::Invalid
    );
}

// ── GitLab token ──────────────────────────────────────────────────────────────

#[test]
fn gitlab_valid_personal_access_token() {
    // glpat- followed by 20 alphanumeric chars (standard personal access token)
    let token = "glpat-".to_string() + &"A".repeat(20);
    let result = GitlabTokenValidator.validate(&token);
    // Should be Valid or NotApplicable — not Invalid (format is correct)
    assert_ne!(
        result,
        ChecksumResult::Invalid,
        "valid glpat format must not be Invalid"
    );
}

#[test]
fn gitlab_unknown_prefix_not_applicable() {
    assert_eq!(
        GitlabTokenValidator.validate("notgitlab_something"),
        ChecksumResult::NotApplicable
    );
}

#[test]
fn gitlab_empty_is_not_applicable() {
    assert_eq!(
        GitlabTokenValidator.validate(""),
        ChecksumResult::NotApplicable
    );
}

// ── PyPI boundary ─────────────────────────────────────────────────────────────

#[test]
fn pypi_exactly_20_char_base64_is_invalid_too_short_decoded() {
    // 20-char URL-safe b64 decodes to ~14 bytes — below 32 minimum
    use base64::Engine;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(vec![0u8; 14]);
    let token = format!("pypi-{b64}");
    assert_eq!(PypiTokenValidator.validate(&token), ChecksumResult::Invalid);
}

#[test]
fn pypi_long_valid_base64_is_valid() {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(vec![0u8; 64]);
    let token = format!("pypi-{b64}");
    assert_eq!(PypiTokenValidator.validate(&token), ChecksumResult::Valid);
}

// ── GitHub fine-grained PAT ───────────────────────────────────────────────────

#[test]
fn github_fine_grained_wrong_left_length_invalid() {
    // Left segment must be exactly 22 chars; 21 here → Invalid
    let token = "github_pat_".to_string() + &"A".repeat(21) + "_" + &"B".repeat(59);
    assert_eq!(
        GithubFineGrainedPatValidator.validate(&token),
        ChecksumResult::Invalid
    );
}

#[test]
fn github_fine_grained_wrong_right_length_invalid() {
    // Right segment must be exactly 59 chars; 58 here → Invalid
    let token = "github_pat_".to_string() + &"A".repeat(22) + "_" + &"B".repeat(58);
    assert_eq!(
        GithubFineGrainedPatValidator.validate(&token),
        ChecksumResult::Invalid
    );
}

#[test]
fn github_fine_grained_three_underscore_segments_invalid() {
    // Three underscore-separated parts instead of two → Invalid
    let token = "github_pat_AAA_BBB_CCC";
    assert_eq!(
        GithubFineGrainedPatValidator.validate(token),
        ChecksumResult::Invalid
    );
}

#[test]
fn github_fine_grained_empty_not_applicable() {
    assert_eq!(
        GithubFineGrainedPatValidator.validate(""),
        ChecksumResult::NotApplicable
    );
}

// ── validator_id sanity checks ────────────────────────────────────────────────

#[test]
fn validator_ids_are_non_empty() {
    assert!(!GithubClassicPatValidator.validator_id().is_empty());
    assert!(!GithubFineGrainedPatValidator.validator_id().is_empty());
    assert!(!NpmTokenValidator.validator_id().is_empty());
    assert!(!SlackTokenValidator.validator_id().is_empty());
    assert!(!StripeTokenValidator.validator_id().is_empty());
    assert!(!PypiTokenValidator.validator_id().is_empty());
    assert!(!GitlabTokenValidator.validator_id().is_empty());
}
