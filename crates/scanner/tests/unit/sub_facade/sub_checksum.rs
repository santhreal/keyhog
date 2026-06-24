//! Standalone unit coverage for `keyhog_scanner::checksum`.
//!
//! Real valid-vs-corrupted token verdicts, asserting the exact
//! `ChecksumResult` enum and the confidence-adjustment semantics. The valid
//! `ghp_`/`npm_`/`github_pat_` tokens carry CRC32 checksums computed offline
//! with the SAME `crc32` + `base62_encode_u32` the validators use, so a
//! `Valid` here is real cryptographic agreement, not a fabricated shape.

use keyhog_scanner::testing::checksum::{
    CHECKSUM_VALID_FLOOR, ChecksumResult, GithubClassicPatValidator, GithubFineGrainedPatValidator,
    GitlabTokenValidator, NpmTokenValidator, PypiTokenValidator, SlackTokenValidator,
    StripeTokenValidator, checksum_adjusted_confidence, validate_checksum,
};

// ghp_ + 30-char entropy + 6-char base62 CRC32 of the 30-char body.
// entropy = "abcdefghij0123456789ABCDEFGHIJ", checksum = "30qLFK" (computed offline).
const GHP_VALID: &str = "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";
// Same body, deliberately wrong trailing checksum.
const GHP_BAD_CRC: &str = "ghp_abcdefghij0123456789ABCDEFGHIJ000000";
const NPM_VALID: &str = "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";
const NPM_BAD_CRC: &str = "npm_abcdefghij0123456789ABCDEFGHIJ000000";
// github_pat_ + 22 alnum + '_' + 59 alnum, where the 59-char right segment is
// 53-char entropy + 6-char CRC (right-segment validation path).
const GH_PAT_VALID: &str =
    "github_pat_AbCdEfGhIjKlMnOpQrStUv_Zz9876543210AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcde3ZXt5t";

// ---------------------------------------------------------------------------
// GitHub classic PAT validator
// ---------------------------------------------------------------------------

#[test]
fn github_classic_valid_crc_is_valid() {
    let v = GithubClassicPatValidator;
    assert_eq!(v.validate(GHP_VALID), ChecksumResult::Valid);
    assert_eq!(v.validator_id(), "github-classic-pat");
}

#[test]
fn github_classic_bad_crc_is_invalid() {
    let v = GithubClassicPatValidator;
    assert_eq!(v.validate(GHP_BAD_CRC), ChecksumResult::Invalid);
}

#[test]
fn github_classic_overlong_payload_is_invalid() {
    let v = GithubClassicPatValidator;
    let overlong = format!("{GHP_VALID}X");
    assert_eq!(v.validate(&overlong), ChecksumResult::Invalid);
    assert_eq!(validate_checksum(&overlong), ChecksumResult::Invalid);
}

#[test]
fn github_classic_wrong_prefix_not_applicable() {
    let v = GithubClassicPatValidator;
    assert_eq!(
        v.validate("xoxb-not-a-github-token"),
        ChecksumResult::NotApplicable
    );
}

#[test]
fn github_classic_wrong_length_not_applicable() {
    let v = GithubClassicPatValidator;
    // ghp_ with a 10-char (not 36) payload: format doesn't match the family.
    assert_eq!(v.validate("ghp_short12"), ChecksumResult::NotApplicable);
}

#[test]
fn github_classic_non_alnum_payload_invalid() {
    let v = GithubClassicPatValidator;
    // 36-char payload but contains '-' (non-alphanumeric).
    let bad = "ghp_abcdefghij0123456789ABCDEFGHI-30qLFK";
    assert_eq!(bad.len(), GHP_VALID.len());
    assert_eq!(v.validate(bad), ChecksumResult::Invalid);
}

// ---------------------------------------------------------------------------
// GitHub fine-grained PAT validator
// ---------------------------------------------------------------------------

#[test]
fn github_fine_grained_valid_crc_is_valid() {
    let v = GithubFineGrainedPatValidator;
    assert_eq!(v.validate(GH_PAT_VALID), ChecksumResult::Valid);
    assert_eq!(v.validator_id(), "github-fine-grained-pat");
}

#[test]
fn github_fine_grained_wrong_prefix_not_applicable() {
    let v = GithubFineGrainedPatValidator;
    assert_eq!(v.validate(GHP_VALID), ChecksumResult::NotApplicable);
}

#[test]
fn github_fine_grained_wrong_segment_lengths_invalid() {
    let v = GithubFineGrainedPatValidator;
    // Right side too short.
    assert_eq!(
        v.validate("github_pat_AbCdEfGhIjKlMnOpQrStUv_short"),
        ChecksumResult::Invalid
    );
}

#[test]
fn github_fine_grained_extra_separator_invalid() {
    let v = GithubFineGrainedPatValidator;
    assert_eq!(
        v.validate(
            "github_pat_AbCdEfGhIjKlMnOpQrStUv_Zz9876543210AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcde_3ZXt5t"
        ),
        ChecksumResult::Invalid
    );
}

#[test]
fn github_fine_grained_missing_separator_invalid() {
    let v = GithubFineGrainedPatValidator;
    assert_eq!(
        v.validate(
            "github_pat_AbCdEfGhIjKlMnOpQrStUvZz9876543210AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcde3ZXt5t"
        ),
        ChecksumResult::Invalid
    );
}

// ---------------------------------------------------------------------------
// npm token validator
// ---------------------------------------------------------------------------

#[test]
fn npm_valid_crc_is_valid() {
    let v = NpmTokenValidator;
    assert_eq!(v.validate(NPM_VALID), ChecksumResult::Valid);
    assert_eq!(v.validator_id(), "npm-access-token");
}

#[test]
fn npm_bad_crc_is_invalid() {
    let v = NpmTokenValidator;
    assert_eq!(v.validate(NPM_BAD_CRC), ChecksumResult::Invalid);
}

#[test]
fn npm_wrong_length_not_applicable() {
    let v = NpmTokenValidator;
    assert_eq!(v.validate("npm_tooshort"), ChecksumResult::NotApplicable);
}

// ---------------------------------------------------------------------------
// PyPI token validator (macaroon shape, not CRC)
// ---------------------------------------------------------------------------

#[test]
fn pypi_short_payload_invalid() {
    let v = PypiTokenValidator;
    assert_eq!(v.validate("pypi-short"), ChecksumResult::Invalid);
    assert_eq!(v.validator_id(), "pypi-api-token");
}

#[test]
fn pypi_decodes_to_long_blob_valid() {
    // base64 of 48 'A' bytes (>= 32 decoded bytes), >= 20 payload chars.
    use base64::Engine;
    let payload = base64::engine::general_purpose::STANDARD.encode([0x41u8; 48]);
    let token = format!("pypi-{}", payload);
    let v = PypiTokenValidator;
    assert_eq!(v.validate(&token), ChecksumResult::Valid);
}

#[test]
fn pypi_wrong_prefix_not_applicable() {
    let v = PypiTokenValidator;
    assert_eq!(v.validate("ghp_xxx"), ChecksumResult::NotApplicable);
}

// ---------------------------------------------------------------------------
// Stripe validator (structural, no public CRC)
// ---------------------------------------------------------------------------

#[test]
fn stripe_well_formed_live_key_structurally_valid() {
    let v = StripeTokenValidator;
    // sk_live_ + 28 alphanumeric chars (>= 24, <= 128).
    let token = "sk_live_4eC39HqLyjWDarjtT1zdp7dcABCD";
    assert!(token.len() > 8 + 24);
    assert_eq!(v.validate(token), ChecksumResult::StructurallyValid);
    assert_eq!(v.validator_id(), "stripe-api-key");
}

#[test]
fn stripe_short_body_invalid() {
    let v = StripeTokenValidator;
    assert_eq!(v.validate("sk_live_tooShort"), ChecksumResult::Invalid);
}

#[test]
fn stripe_non_alnum_body_invalid() {
    let v = StripeTokenValidator;
    // 24+ chars but contains '-'.
    assert_eq!(
        v.validate("sk_live_4eC39HqLyjWDarjtT1zdp7-c"),
        ChecksumResult::Invalid
    );
}

#[test]
fn stripe_wrong_prefix_not_applicable() {
    let v = StripeTokenValidator;
    assert_eq!(v.validate("npm_xxx"), ChecksumResult::NotApplicable);
}

// ---------------------------------------------------------------------------
// GitLab validator (structural band)
// ---------------------------------------------------------------------------

#[test]
fn gitlab_classic_20_char_body_structurally_valid() {
    let v = GitlabTokenValidator;
    // glpat- + exactly 20 base64url body chars.
    let token = "glpat-abcdefghij0123456789";
    assert_eq!(&token[6..], "abcdefghij0123456789");
    assert_eq!(token[6..].len(), 20);
    assert_eq!(v.validate(token), ChecksumResult::StructurallyValid);
    assert_eq!(v.validator_id(), "gitlab-token");
}

#[test]
fn gitlab_too_short_body_invalid() {
    let v = GitlabTokenValidator;
    // glpat- + 10 chars (< 20 floor) -> fabricated/truncated.
    assert_eq!(v.validate("glpat-shorttoken"), ChecksumResult::Invalid);
}

#[test]
fn gitlab_bad_charset_invalid() {
    let v = GitlabTokenValidator;
    // Contains a space -> a char no GitLab token can carry.
    assert_eq!(
        v.validate("glpat-abcdefghij 123456789"),
        ChecksumResult::Invalid
    );
}

#[test]
fn gitlab_runner_token_structurally_valid() {
    let v = GitlabTokenValidator;
    // glrt- + 16-char floor body.
    assert_eq!(
        v.validate("glrt-abcdefghij012345"),
        ChecksumResult::StructurallyValid
    );
}

#[test]
fn gitlab_wrong_prefix_not_applicable() {
    let v = GitlabTokenValidator;
    assert_eq!(v.validate("ghp_xxx"), ChecksumResult::NotApplicable);
}

// ---------------------------------------------------------------------------
// Slack validator (regex-shape)
// ---------------------------------------------------------------------------

#[test]
fn slack_bot_three_segment_valid() {
    let v = SlackTokenValidator;
    // xoxb-{digits}-{digits}-{alnum 24..}
    let token = "xoxb-1234567890-0987654321-abcdefghijABCDEFGHIJ1234";
    assert_eq!(v.validate(token), ChecksumResult::Valid);
    assert_eq!(v.validator_id(), "slack-token");
}

#[test]
fn slack_bot_malformed_invalid() {
    let v = SlackTokenValidator;
    // xoxb- prefix but the rest is non-conforming -> Invalid (not NotApplicable).
    assert_eq!(v.validate("xoxb-not-a-real-token"), ChecksumResult::Invalid);
}

#[test]
fn slack_unknown_prefix_not_applicable() {
    let v = SlackTokenValidator;
    assert_eq!(v.validate("ghp_xxx"), ChecksumResult::NotApplicable);
}

// ---------------------------------------------------------------------------
// validate_checksum dispatcher + checksum_adjusted_confidence
// ---------------------------------------------------------------------------

#[test]
fn dispatcher_routes_valid_ghp() {
    assert_eq!(validate_checksum(GHP_VALID), ChecksumResult::Valid);
}

#[test]
fn dispatcher_routes_invalid_ghp() {
    assert_eq!(validate_checksum(GHP_BAD_CRC), ChecksumResult::Invalid);
}

#[test]
fn dispatcher_unknown_token_not_applicable() {
    assert_eq!(
        validate_checksum("this is just prose with no token"),
        ChecksumResult::NotApplicable
    );
}

#[test]
fn dispatcher_routes_structural_valid_without_checksum_floor() {
    let stripe = "sk_live_4eC39HqLyjWDarjtT1zdp7dcABCD";
    let gitlab = "glpat-abcdefghij0123456789";

    assert_eq!(validate_checksum(stripe), ChecksumResult::StructurallyValid);
    assert_eq!(validate_checksum(gitlab), ChecksumResult::StructurallyValid);
    assert_eq!(checksum_adjusted_confidence(0.2, stripe), Some(0.2));
    assert_eq!(checksum_adjusted_confidence(0.2, gitlab), Some(0.2));
}

#[test]
fn adjusted_confidence_floors_valid_token() {
    // A confirmed token's confidence is floored at CHECKSUM_VALID_FLOOR (0.9).
    let out = checksum_adjusted_confidence(0.2, GHP_VALID);
    assert_eq!(out, Some(CHECKSUM_VALID_FLOOR));
    assert_eq!(CHECKSUM_VALID_FLOOR, 0.9);
    // A higher-than-floor input is preserved (max semantics).
    let out_high = checksum_adjusted_confidence(0.97, GHP_VALID);
    assert_eq!(out_high, Some(0.97));
}

#[test]
fn adjusted_confidence_drops_invalid_token() {
    // Invalid CRC -> None -> caller DROPS the match.
    assert_eq!(checksum_adjusted_confidence(0.95, GHP_BAD_CRC), None);
}

#[test]
fn adjusted_confidence_passthrough_not_applicable() {
    // No checksum to consult -> confidence passes through unchanged.
    assert_eq!(
        checksum_adjusted_confidence(0.42, "no token here"),
        Some(0.42)
    );
}
