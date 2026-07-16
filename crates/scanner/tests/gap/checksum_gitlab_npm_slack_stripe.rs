//! Gap coverage for the gitlab / npm / slack / stripe checksum validators.
//!
//! Every expected value below is DERIVED from the real source under
//! `crates/scanner/src/checksum/{gitlab,npm,slack,stripe}.rs`:
//!
//!   - GitLab (`gitlab.rs`): structural, charset+length only.
//!       * `glpat-` body in 20..=64 (alnum/`-`/`_`)        -> Valid
//!       * `glpat-` body < 20                              -> Invalid
//!       * `glpat-` body > 64                              -> NotApplicable
//!       * `glpat-` body with a forbidden char             -> Invalid
//!       * `glcbt-` / `glrt-` body in 16..=64              -> Valid
//!       * `glcbt-` / `glrt-` body < 16                    -> Invalid
//!       * `glcbt-` / `glrt-` body > 64                    -> NotApplicable
//!       * any other prefix                                -> NotApplicable
//!   - npm (`npm.rs`): `npm_` + 36 chars; CRC32-over-first-30 base62(6).
//!       * not 36 chars (incl. no prefix)                  -> NotApplicable
//!       * 36 chars but non-alnum                          -> Invalid
//!       * 36 alnum with matching CRC trailer              -> Valid
//!       * 36 alnum with wrong trailer                     -> Invalid
//!   - Slack (`slack.rs`): strict regex per family.
//!       * `xoxb-[0-9]{10,15}-[0-9]{10,15}-[A-Za-z0-9]{15,40}` -> Valid
//!       * `xoxp-[0-9]{10,15}-[0-9]{10,15}(-[0-9]{10,13})?-[A-Za-z0-9]{24,40}` -> Valid
//!       * `xoxb-`/`xoxp-` that violate the regex          -> Invalid
//!       * any other prefix                                -> NotApplicable
//!   - Stripe (`stripe.rs`): family + alnum + 24..=128 len.
//!       * known prefix, body 24..=128 alnum               -> Valid
//!       * known prefix, body <24 or >128                  -> Invalid
//!       * known prefix, body with non-alnum               -> Invalid
//!       * unknown prefix                                  -> NotApplicable
//!
//! The npm valid fixtures are minted through
//! `keyhog_scanner::testing::checksum::npm_token_with_checksum`, which calls the
//! same production CRC32/base62 owner as the validator instead of carrying a
//! second algorithm copy in this test.

use keyhog_scanner::testing::checksum::{
    npm_token_with_checksum, validate_checksum, ChecksumResult, GitlabTokenValidator,
    NpmTokenValidator, SlackTokenValidator, StripeTokenValidator,
};

/// Build a npm token whose 6-char base62 CRC trailer matches its 30-char
/// entropy body. `entropy` MUST be exactly 30 ascii-alphanumeric chars.
fn make_valid_npm(entropy: &str) -> String {
    assert_eq!(entropy.len(), 30, "npm entropy must be 30 chars");
    let token = npm_token_with_checksum(entropy);
    assert_eq!(
        token.len(),
        "npm_".len() + 36,
        "npm token must be prefix + 30 entropy + 6 checksum"
    );
    token
}

// ══════════════════════════════ GitLab ═══════════════════════════════════

// ---- glpat- classic / routable band: Valid ----

#[test]
fn gitlab_glpat_classic_20_valid() {
    // body == GITLAB_BODY_MIN (20) -> Valid
    let token = format!("glpat-{}", "A".repeat(20));
    assert_eq!(
        GitlabTokenValidator.validate(&token),
        ChecksumResult::StructurallyValid
    );
}

#[test]
fn gitlab_glpat_routable_64_valid() {
    // body == GITLAB_BODY_MAX (64) -> Valid (upper boundary inclusive)
    let token = format!("glpat-{}", "z".repeat(64));
    assert_eq!(
        GitlabTokenValidator.validate(&token),
        ChecksumResult::StructurallyValid
    );
}

#[test]
fn gitlab_glpat_routable_mid_40_valid() {
    // 40-char routable-band body with the full legal alphabet -> Valid
    let token = format!("glpat-{}", "aZ09-_aZ09-_aZ09-_aZ09-_aZ09-_aZ09-_aZ09");
    assert_eq!(token.len(), "glpat-".len() + 40);
    assert_eq!(
        GitlabTokenValidator.validate(&token),
        ChecksumResult::StructurallyValid
    );
}

#[test]
fn gitlab_glpat_body_with_dash_and_underscore_valid() {
    // '-' and '_' are explicitly allowed by gitlab_body_charset_ok.
    let body = format!("{}-_{}", "A".repeat(10), "B".repeat(10)); // 22 chars
    assert_eq!(body.len(), 22);
    let token = format!("glpat-{body}");
    assert_eq!(
        GitlabTokenValidator.validate(&token),
        ChecksumResult::StructurallyValid
    );
}

// ---- glpat- below floor: Invalid ----

#[test]
fn gitlab_glpat_19_below_floor_invalid() {
    // body == 19 (< GITLAB_BODY_MIN) -> Invalid (truncated/fabricated)
    let token = format!("glpat-{}", "A".repeat(19));
    assert_eq!(
        GitlabTokenValidator.validate(&token),
        ChecksumResult::Invalid
    );
}

#[test]
fn gitlab_glpat_empty_body_invalid() {
    // "glpat-" with zero body chars: charset_ok on "" is true, len 0 < 20.
    assert_eq!(
        GitlabTokenValidator.validate("glpat-"),
        ChecksumResult::Invalid
    );
}

// ---- glpat- above ceiling: NotApplicable ----

#[test]
fn gitlab_glpat_65_above_ceiling_not_applicable() {
    // body == 65 (> GITLAB_BODY_MAX) -> NotApplicable (unmodelled, not dropped)
    let token = format!("glpat-{}", "A".repeat(65));
    assert_eq!(
        GitlabTokenValidator.validate(&token),
        ChecksumResult::NotApplicable
    );
}

#[test]
fn gitlab_glpat_very_long_200_not_applicable() {
    let token = format!("glpat-{}", "A".repeat(200));
    assert_eq!(
        GitlabTokenValidator.validate(&token),
        ChecksumResult::NotApplicable
    );
}

// ---- glpat- forbidden charset: Invalid (regardless of length) ----

#[test]
fn gitlab_glpat_bad_char_in_band_invalid() {
    // '!' is not alnum/'-'/'_' -> Invalid even though length is in band.
    let token = format!("glpat-{}!{}", "A".repeat(15), "A".repeat(10)); // body len 26
    assert_eq!(
        GitlabTokenValidator.validate(&token),
        ChecksumResult::Invalid
    );
}

#[test]
fn gitlab_glpat_bad_char_overrides_long_length_invalid() {
    // Charset check happens BEFORE length: a 100-char body with a bad char is
    // Invalid, not NotApplicable.
    let token = format!("glpat-{}!{}", "A".repeat(50), "A".repeat(49)); // body 100, has '!'
    assert_eq!(
        GitlabTokenValidator.validate(&token),
        ChecksumResult::Invalid
    );
}

#[test]
fn gitlab_glpat_space_in_body_invalid() {
    let token = format!("glpat-{} {}", "A".repeat(10), "A".repeat(10)); // space at idx 10
    assert_eq!(
        GitlabTokenValidator.validate(&token),
        ChecksumResult::Invalid
    );
}

// ---- glcbt- / glrt- runner / CI-build band (floor 16) ----

#[test]
fn gitlab_glcbt_16_floor_valid() {
    // glcbt- floor is 16 (not 20) -> 16-char body is Valid.
    let token = format!("glcbt-{}", "A".repeat(16));
    assert_eq!(
        GitlabTokenValidator.validate(&token),
        ChecksumResult::StructurallyValid
    );
}

#[test]
fn gitlab_glrt_16_floor_valid() {
    let token = format!("glrt-{}", "A".repeat(16));
    assert_eq!(
        GitlabTokenValidator.validate(&token),
        ChecksumResult::StructurallyValid
    );
}

#[test]
fn gitlab_glcbt_64_ceiling_valid() {
    let token = format!("glcbt-{}", "A".repeat(64));
    assert_eq!(
        GitlabTokenValidator.validate(&token),
        ChecksumResult::StructurallyValid
    );
}

#[test]
fn gitlab_glrt_15_below_floor_invalid() {
    // glrt- body 15 (< 16) -> Invalid. Note: 15 < 20 so this proves the
    // runner floor of 16, not the classic floor of 20, is in effect.
    let token = format!("glrt-{}", "A".repeat(15));
    assert_eq!(
        GitlabTokenValidator.validate(&token),
        ChecksumResult::Invalid
    );
}

#[test]
fn gitlab_glrt_18_between_runner_and_classic_floor_valid() {
    // 18 chars: below the classic glpat floor (20) but at/above the runner
    // floor (16). For glrt- this MUST be Valid (the distinct floor matters).
    let token = format!("glrt-{}", "A".repeat(18));
    assert_eq!(
        GitlabTokenValidator.validate(&token),
        ChecksumResult::StructurallyValid
    );
}

#[test]
fn gitlab_glcbt_65_above_ceiling_not_applicable() {
    let token = format!("glcbt-{}", "A".repeat(65));
    assert_eq!(
        GitlabTokenValidator.validate(&token),
        ChecksumResult::NotApplicable
    );
}

#[test]
fn gitlab_glcbt_bad_char_invalid() {
    let token = format!("glcbt-{}#{}", "A".repeat(10), "A".repeat(10));
    assert_eq!(
        GitlabTokenValidator.validate(&token),
        ChecksumResult::Invalid
    );
}

// ---- unknown / no prefix: NotApplicable ----

#[test]
fn gitlab_no_known_prefix_not_applicable() {
    assert_eq!(
        GitlabTokenValidator.validate("glsomething-AAAAAAAAAAAAAAAAAAAA"),
        ChecksumResult::NotApplicable
    );
}

#[test]
fn gitlab_bare_glpat_without_dash_not_applicable() {
    // "glpat" without the trailing '-' does not match strip_prefix("glpat-").
    let token = format!("glpat{}", "A".repeat(20));
    assert_eq!(
        GitlabTokenValidator.validate(&token),
        ChecksumResult::NotApplicable
    );
}

#[test]
fn gitlab_validator_id_is_gitlab_personal_access_token() {
    assert_eq!(
        GitlabTokenValidator.validator_id(),
        "gitlab-personal-access-token"
    );
}

// ══════════════════════════════ npm ══════════════════════════════════════

#[test]
fn npm_valid_token_matching_crc_is_valid() {
    // Entropy chosen to be 30 alnum chars; trailer computed by the real algo.
    let token = make_valid_npm("abcdefghijklmnopqrstuvwxyz0123");
    assert_eq!(NpmTokenValidator.validate(&token), ChecksumResult::Valid);
}

#[test]
fn npm_valid_token_all_a_entropy_is_valid() {
    // Adversarial low-entropy body: still Valid because the CRC trailer matches.
    let token = make_valid_npm(&"A".repeat(30));
    assert_eq!(NpmTokenValidator.validate(&token), ChecksumResult::Valid);
}

#[test]
fn npm_valid_token_via_aggregator_is_valid() {
    // The registry order is github*, npm, slack, pypi, stripe, gitlab.
    // No earlier validator claims an `npm_` token, so npm must win.
    let token = make_valid_npm("Z9zzZ9zzZ9zzZ9zzZ9zzZ9zzZ9zzZ9");
    assert_eq!(validate_checksum(&token), ChecksumResult::Valid);
}

#[test]
fn npm_wrong_trailer_is_invalid() {
    // Take a valid token and corrupt its last char so the CRC no longer matches.
    let valid = make_valid_npm("abcdefghijklmnopqrstuvwxyz0123");
    let last = valid.chars().last().unwrap();
    // Pick a different alnum replacement for the trailing checksum char.
    let replacement = if last == 'A' { 'B' } else { 'A' };
    let mut corrupted: String = valid[..valid.len() - 1].to_string();
    corrupted.push(replacement);
    assert_eq!(corrupted.len(), valid.len());
    assert_ne!(corrupted, valid);
    assert_eq!(
        NpmTokenValidator.validate(&corrupted),
        ChecksumResult::Invalid
    );
}

#[test]
fn npm_all_a_36_body_is_invalid() {
    // `npm_` + 36 'A': alnum, length 36, but CRC of 30 'A' is not "AAAAAA".
    // Derive the real expected trailer to prove the mismatch.
    let valid = npm_token_with_checksum(&"A".repeat(30));
    assert!(
        !valid.ends_with("AAAAAA"),
        "fixture premise must remain true"
    );
    let token = format!("npm_{}", "A".repeat(36));
    assert_eq!(NpmTokenValidator.validate(&token), ChecksumResult::Invalid);
}

#[test]
fn npm_no_prefix_not_applicable() {
    assert_eq!(
        NpmTokenValidator.validate("npx_abcdefghijklmnopqrstuvwxyz0123456789"),
        ChecksumResult::NotApplicable
    );
}

#[test]
fn npm_empty_not_applicable() {
    assert_eq!(
        NpmTokenValidator.validate(""),
        ChecksumResult::NotApplicable
    );
}

#[test]
fn npm_payload_35_chars_not_applicable() {
    // length != 36 short-circuits to NotApplicable BEFORE charset/crc checks.
    let token = format!("npm_{}", "A".repeat(35));
    assert_eq!(
        NpmTokenValidator.validate(&token),
        ChecksumResult::NotApplicable
    );
}

#[test]
fn npm_payload_37_chars_not_applicable() {
    let token = format!("npm_{}", "A".repeat(37));
    assert_eq!(
        NpmTokenValidator.validate(&token),
        ChecksumResult::NotApplicable
    );
}

#[test]
fn npm_payload_36_with_special_char_invalid() {
    // length 36 but a non-alnum char -> Invalid (not NotApplicable).
    let token = format!("npm_{}!{}", "A".repeat(30), "AAAAA"); // 30 + 1 + 5 = 36
    assert_eq!(NpmTokenValidator.validate(&token), ChecksumResult::Invalid);
}

#[test]
fn npm_payload_36_with_underscore_in_body_invalid() {
    // '_' is NOT ascii-alphanumeric, so a 36-char body containing it is Invalid.
    let token = format!("npm_{}_{}", "A".repeat(30), "AAAAA"); // underscore at index 30
    assert_eq!(NpmTokenValidator.validate(&token), ChecksumResult::Invalid);
}

#[test]
fn npm_validator_id_is_npm_access_token() {
    assert_eq!(NpmTokenValidator.validator_id(), "npm-access-token");
}

#[test]
fn npm_crc_algorithm_self_consistency_loop() {
    // Proptest-style: for a spread of 30-char entropy bodies, the validator must
    // accept the token built with the mirrored algorithm and reject the same
    // body with a deliberately-wrong trailer.
    let bodies = [
        "000000000000000000000000000000",
        "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzz00",
        "abcdefghij0123456789ABCDEFGHIJ",
        "Quick0Brown0Fox0Jumps0Over0Lazy",
    ];
    for raw in bodies {
        let body: String = raw.chars().take(30).collect();
        // Pad in case the literal was shorter than 30 (keep alnum).
        let body = format!("{body}{}", "0".repeat(30 - body.len()));
        assert_eq!(body.len(), 30);

        let good = make_valid_npm(&body);
        assert_eq!(
            NpmTokenValidator.validate(&good),
            ChecksumResult::Valid,
            "matching trailer must be Valid for body {body}"
        );

        // Flip the first checksum char to a guaranteed-different alnum char.
        let trailer_start = good.len() - 6;
        let c = good.as_bytes()[trailer_start] as char;
        let repl = if c == '0' { '1' } else { '0' };
        let mut bad = good[..trailer_start].to_string();
        bad.push(repl);
        bad.push_str(&good[trailer_start + 1..]);
        assert_eq!(bad.len(), good.len());
        assert_eq!(
            NpmTokenValidator.validate(&bad),
            ChecksumResult::Invalid,
            "corrupted trailer must be Invalid for body {body}"
        );
    }
}

// ══════════════════════════════ Slack ════════════════════════════════════

// ---- xoxb- bot: Valid ----

#[test]
fn slack_xoxb_min_segments_valid() {
    // 10-digit, 10-digit, 15-char alnum: all minimum lengths -> Valid.
    let token = format!(
        "xoxb-{}-{}-{}",
        "0".repeat(10),
        "1".repeat(10),
        "a".repeat(15)
    );
    assert_eq!(
        SlackTokenValidator.validate(&token),
        ChecksumResult::StructurallyValid
    );
}

#[test]
fn slack_xoxb_max_segments_valid() {
    // 15-digit, 15-digit, 40-char alnum: all maximum lengths -> Valid.
    let token = format!(
        "xoxb-{}-{}-{}",
        "9".repeat(15),
        "8".repeat(15),
        "Z9aZ9aZ9aZ9aZ9aZ9aZ9aZ9aZ9aZ9aZ9aZ9aZ9aZ"
    );
    // verify the alnum segment is exactly 40
    assert_eq!(token.rsplit('-').next().unwrap().len(), 40);
    assert_eq!(
        SlackTokenValidator.validate(&token),
        ChecksumResult::StructurallyValid
    );
}

#[test]
fn slack_xoxb_mixed_case_alnum_segment_valid() {
    let token = format!(
        "xoxb-{}-{}-{}",
        "123456789012", "210987654321", "AbCdEf0123456789Xyz"
    );
    assert_eq!(
        SlackTokenValidator.validate(&token),
        ChecksumResult::StructurallyValid
    );
}

// ---- xoxb- bot: Invalid (regex violations) ----

#[test]
fn slack_xoxb_first_segment_9_digits_invalid() {
    // 9 digits is below the {10,15} minimum -> Invalid.
    let token = format!(
        "xoxb-{}-{}-{}",
        "0".repeat(9),
        "1".repeat(10),
        "a".repeat(15)
    );
    assert_eq!(
        SlackTokenValidator.validate(&token),
        ChecksumResult::Invalid
    );
}

#[test]
fn slack_xoxb_first_segment_16_digits_invalid() {
    // 16 digits exceeds {10,15} max -> Invalid (anchored $).
    let token = format!(
        "xoxb-{}-{}-{}",
        "0".repeat(16),
        "1".repeat(10),
        "a".repeat(15)
    );
    assert_eq!(
        SlackTokenValidator.validate(&token),
        ChecksumResult::Invalid
    );
}

#[test]
fn slack_xoxb_secret_14_chars_invalid() {
    // alnum secret 14 chars is below {15,40} -> Invalid.
    let token = format!(
        "xoxb-{}-{}-{}",
        "0".repeat(10),
        "1".repeat(10),
        "a".repeat(14)
    );
    assert_eq!(
        SlackTokenValidator.validate(&token),
        ChecksumResult::Invalid
    );
}

#[test]
fn slack_xoxb_secret_41_chars_invalid() {
    let token = format!(
        "xoxb-{}-{}-{}",
        "0".repeat(10),
        "1".repeat(10),
        "a".repeat(41)
    );
    assert_eq!(
        SlackTokenValidator.validate(&token),
        ChecksumResult::Invalid
    );
}

#[test]
fn slack_xoxb_secret_with_dash_invalid() {
    // '-' is not in [a-zA-Z0-9]; it would also split into an extra segment.
    let token = format!(
        "xoxb-{}-{}-{}",
        "0".repeat(10),
        "1".repeat(10),
        "aaaaaaa-aaaaaaa"
    );
    assert_eq!(
        SlackTokenValidator.validate(&token),
        ChecksumResult::Invalid
    );
}

#[test]
fn slack_xoxb_letters_in_numeric_segment_invalid() {
    // The first two segments must be [0-9]; a letter there breaks the match.
    let token = format!(
        "xoxb-{}-{}-{}",
        "12345abcde", "1234567890", "abcdefghijklmno"
    );
    assert_eq!(
        SlackTokenValidator.validate(&token),
        ChecksumResult::Invalid
    );
}

#[test]
fn slack_xoxb_trailing_garbage_invalid() {
    // Anchored regex: trailing junk after an otherwise-valid token fails.
    let token = format!(
        "xoxb-{}-{}-{} trailing",
        "0".repeat(10),
        "1".repeat(10),
        "a".repeat(15)
    );
    assert_eq!(
        SlackTokenValidator.validate(&token),
        ChecksumResult::Invalid
    );
}

#[test]
fn slack_xoxb_two_segments_only_invalid() {
    // Missing the alnum secret segment entirely.
    let token = format!("xoxb-{}-{}", "0".repeat(10), "1".repeat(10));
    assert_eq!(
        SlackTokenValidator.validate(&token),
        ChecksumResult::Invalid
    );
}

// ---- xoxp- user: Valid (with and without optional middle group) ----

#[test]
fn slack_xoxp_without_optional_group_min_valid() {
    // xoxp-{10}-{10}-{24 alnum} (optional group absent) -> Valid.
    let token = format!(
        "xoxp-{}-{}-{}",
        "0".repeat(10),
        "1".repeat(10),
        "a".repeat(24)
    );
    assert_eq!(
        SlackTokenValidator.validate(&token),
        ChecksumResult::StructurallyValid
    );
}

#[test]
fn slack_xoxp_with_optional_group_valid() {
    // xoxp-{12}-{12}-{12 digits optional}-{30 alnum} -> Valid.
    let token = format!(
        "xoxp-{}-{}-{}-{}",
        "123456789012",
        "210987654321",
        "1".repeat(12),
        "a".repeat(30)
    );
    assert_eq!(
        SlackTokenValidator.validate(&token),
        ChecksumResult::StructurallyValid
    );
}

#[test]
fn slack_xoxp_optional_group_min_10_digits_valid() {
    // optional group lower bound is {10,13}: exactly 10 digits is Valid.
    let token = format!(
        "xoxp-{}-{}-{}-{}",
        "0".repeat(10),
        "1".repeat(10),
        "2".repeat(10),
        "b".repeat(24)
    );
    assert_eq!(
        SlackTokenValidator.validate(&token),
        ChecksumResult::StructurallyValid
    );
}

#[test]
fn slack_xoxp_optional_group_max_13_digits_valid() {
    let token = format!(
        "xoxp-{}-{}-{}-{}",
        "0".repeat(10),
        "1".repeat(10),
        "2".repeat(13),
        "b".repeat(24)
    );
    assert_eq!(
        SlackTokenValidator.validate(&token),
        ChecksumResult::StructurallyValid
    );
}

#[test]
fn slack_xoxp_secret_max_40_valid() {
    let token = format!(
        "xoxp-{}-{}-{}",
        "0".repeat(10),
        "1".repeat(10),
        "z".repeat(40)
    );
    assert_eq!(
        SlackTokenValidator.validate(&token),
        ChecksumResult::StructurallyValid
    );
}

// ---- xoxp- user: Invalid ----

#[test]
fn slack_xoxp_secret_23_chars_invalid() {
    // User secret minimum is {24,40}; 23 chars -> Invalid (this is the key
    // difference from the bot regex, which allows 15).
    let token = format!(
        "xoxp-{}-{}-{}",
        "0".repeat(10),
        "1".repeat(10),
        "a".repeat(23)
    );
    assert_eq!(
        SlackTokenValidator.validate(&token),
        ChecksumResult::Invalid
    );
}

#[test]
fn slack_xoxp_optional_group_9_digits_invalid() {
    // optional group is {10,13}; a 9-digit middle group cannot satisfy it and
    // also can't be re-read as the secret (secret must be alnum >=24).
    let token = format!(
        "xoxp-{}-{}-{}-{}",
        "0".repeat(10),
        "1".repeat(10),
        "2".repeat(9),
        "b".repeat(24)
    );
    assert_eq!(
        SlackTokenValidator.validate(&token),
        ChecksumResult::Invalid
    );
}

#[test]
fn slack_xoxp_optional_group_14_digits_invalid() {
    let token = format!(
        "xoxp-{}-{}-{}-{}",
        "0".repeat(10),
        "1".repeat(10),
        "2".repeat(14),
        "b".repeat(24)
    );
    assert_eq!(
        SlackTokenValidator.validate(&token),
        ChecksumResult::Invalid
    );
}

#[test]
fn slack_xoxp_secret_with_special_char_invalid() {
    let token = format!(
        "xoxp-{}-{}-{}",
        "0".repeat(10),
        "1".repeat(10),
        "aaaaaaaaaa!aaaaaaaaaaaaaa"
    );
    assert_eq!(
        SlackTokenValidator.validate(&token),
        ChecksumResult::Invalid
    );
}

// ---- prefix routing ----

#[test]
fn slack_unknown_prefix_not_applicable() {
    assert_eq!(
        SlackTokenValidator.validate("xoxr-1234567890-1234567890-abcdefghijklmno"),
        ChecksumResult::NotApplicable
    );
}

#[test]
fn slack_no_prefix_not_applicable() {
    assert_eq!(
        SlackTokenValidator.validate("not-a-slack-token"),
        ChecksumResult::NotApplicable
    );
}

#[test]
fn slack_xoxb_prefix_only_is_invalid_not_notapplicable() {
    // starts_with("xoxb-") is true, so we enter the bot branch; the regex
    // fails -> Invalid (NOT NotApplicable). Proves prefix routing precedes regex.
    assert_eq!(
        SlackTokenValidator.validate("xoxb-"),
        ChecksumResult::Invalid
    );
}

#[test]
fn slack_xoxp_prefix_only_is_invalid() {
    assert_eq!(
        SlackTokenValidator.validate("xoxp-"),
        ChecksumResult::Invalid
    );
}

#[test]
fn slack_validator_id_is_slack_bot_token() {
    assert_eq!(SlackTokenValidator.validator_id(), "slack-bot-token");
}

// ══════════════════════════════ Stripe ═══════════════════════════════════

#[test]
fn stripe_all_detector_owned_prefixes_valid_at_24() {
    for prefix in ["sk_live_", "sk_test_", "rk_live_", "rk_test_"] {
        let token = format!("{prefix}{}", "A".repeat(24));
        assert_eq!(
            StripeTokenValidator.validate(&token),
            ChecksumResult::StructurallyValid,
            "{prefix} with 24-char body must be structurally valid"
        );
    }
}

#[test]
fn stripe_body_24_lower_boundary_valid() {
    let token = format!("sk_live_{}", "a".repeat(24));
    assert_eq!(
        StripeTokenValidator.validate(&token),
        ChecksumResult::StructurallyValid
    );
}

#[test]
fn stripe_body_128_upper_boundary_valid() {
    // 128 is the inclusive max.
    let token = format!("sk_live_{}", "A".repeat(128));
    assert_eq!(
        StripeTokenValidator.validate(&token),
        ChecksumResult::StructurallyValid
    );
}

#[test]
fn stripe_body_23_below_min_invalid() {
    let token = format!("sk_live_{}", "A".repeat(23));
    assert_eq!(
        StripeTokenValidator.validate(&token),
        ChecksumResult::Invalid
    );
}

#[test]
fn stripe_body_129_above_max_invalid() {
    let token = format!("sk_live_{}", "A".repeat(129));
    assert_eq!(
        StripeTokenValidator.validate(&token),
        ChecksumResult::Invalid
    );
}

#[test]
fn stripe_body_with_dash_invalid() {
    // '-' is not ascii-alphanumeric -> Invalid even at a legal length.
    let token = format!("sk_live_{}-{}", "A".repeat(12), "A".repeat(12)); // body 25, has '-'
    assert_eq!(
        StripeTokenValidator.validate(&token),
        ChecksumResult::Invalid
    );
}

#[test]
fn stripe_body_with_underscore_invalid() {
    // A trailing underscore inside the body is non-alnum -> Invalid.
    let token = format!("sk_test_{}_{}", "A".repeat(12), "A".repeat(12));
    assert_eq!(
        StripeTokenValidator.validate(&token),
        ChecksumResult::Invalid
    );
}

#[test]
fn stripe_mixed_alnum_body_valid() {
    let token = format!("rk_test_{}", "aB0cD1eF2gH3iJ4kL5mN6oP7");
    assert_eq!(token.len(), "rk_test_".len() + 24);
    assert_eq!(
        StripeTokenValidator.validate(&token),
        ChecksumResult::StructurallyValid
    );
}

#[test]
fn stripe_unknown_prefix_not_applicable() {
    // 'wk_live_' is not a recognised family.
    assert_eq!(
        StripeTokenValidator.validate(&format!("wk_live_{}", "A".repeat(24))),
        ChecksumResult::NotApplicable
    );
}

#[test]
fn stripe_mode_typo_not_applicable() {
    // 'sk_prod_' is not in the prefix list -> NotApplicable.
    assert_eq!(
        StripeTokenValidator.validate(&format!("sk_prod_{}", "A".repeat(24))),
        ChecksumResult::NotApplicable
    );
}

#[test]
fn stripe_empty_not_applicable() {
    assert_eq!(
        StripeTokenValidator.validate(""),
        ChecksumResult::NotApplicable
    );
}

#[test]
fn stripe_prefix_only_empty_body_invalid() {
    // 'sk_live_' with zero body: prefix matches, len 0 < 24 -> Invalid.
    assert_eq!(
        StripeTokenValidator.validate("sk_live_"),
        ChecksumResult::Invalid
    );
}

#[test]
fn stripe_validator_id_is_stripe_secret_key() {
    assert_eq!(StripeTokenValidator.validator_id(), "stripe-secret-key");
}

// ═══════════════════ cross-validator routing via aggregator ═══════════════

#[test]
fn aggregator_stripe_valid_routes_through() {
    // No github/npm/slack/pypi validator claims a stripe key; stripe wins.
    let token = format!("sk_live_{}", "A".repeat(24));
    assert_eq!(validate_checksum(&token), ChecksumResult::StructurallyValid);
}

#[test]
fn aggregator_slack_invalid_short_routes_through_as_invalid() {
    // A malformed xoxb- token: slack returns Invalid, which wins (first
    // non-NotApplicable result is returned).
    let token = "xoxb-123-456-short";
    assert_eq!(validate_checksum(token), ChecksumResult::Invalid);
}

#[test]
fn aggregator_unrelated_token_not_applicable() {
    // No validator in the registry claims this shape.
    assert_eq!(
        validate_checksum("AKIA1234567890ABCDEF"),
        ChecksumResult::NotApplicable
    );
}

#[test]
fn aggregator_gitlab_glpat_valid_routes_through() {
    let token = format!("glpat-{}", "A".repeat(20));
    assert_eq!(validate_checksum(&token), ChecksumResult::StructurallyValid);
}

// ── Property tier: Stripe band + charset ──────────────────────────────────────
// GitLab/npm/slack validators each already have a dedicated proptest file; Stripe
// did NOT. The fixed vectors above pin its boundaries at fixed points, these SWEEP
// the structural contract (stripe.rs: known prefix + `24..=128` ascii-alnum body):
// a known prefix with an in-band alnum body is StructurallyValid; an under-24 or
// over-128 alnum body is Invalid; an in-band body carrying a non-alnum byte is
// Invalid; and an unknown prefix is NotApplicable. Traced against
// `StripeTokenValidator`. No proptest before.

use proptest::prelude::*;

const STRIPE_PREFIXES: &[&str] = &["sk_live_", "sk_test_", "rk_live_", "rk_test_"];
const UNKNOWN_STRIPE_PREFIXES: &[&str] = &[
    "wk_live_", "sk_prod_", "ak_live_", "sk_dev_", "tk_test_", "sklive_",
];

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    /// A known prefix with a 24..=128 ascii-alnum body is StructurallyValid.
    #[test]
    fn stripe_in_band_alnum_body_is_structurally_valid(
        pi in 0usize..STRIPE_PREFIXES.len(),
        body in "[A-Za-z0-9]{24,128}",
    ) {
        let token = format!("{}{body}", STRIPE_PREFIXES[pi]);
        prop_assert_eq!(StripeTokenValidator.validate(&token), ChecksumResult::StructurallyValid);
    }

    /// A known prefix with an under-24 alnum body (incl. empty) is Invalid.
    #[test]
    fn stripe_below_floor_body_is_invalid(
        pi in 0usize..STRIPE_PREFIXES.len(),
        body in "[A-Za-z0-9]{0,23}",
    ) {
        let token = format!("{}{body}", STRIPE_PREFIXES[pi]);
        prop_assert_eq!(StripeTokenValidator.validate(&token), ChecksumResult::Invalid);
    }

    /// A known prefix with an over-128 alnum body is Invalid.
    #[test]
    fn stripe_above_ceiling_body_is_invalid(
        pi in 0usize..STRIPE_PREFIXES.len(),
        body in "[A-Za-z0-9]{129,160}",
    ) {
        let token = format!("{}{body}", STRIPE_PREFIXES[pi]);
        prop_assert_eq!(StripeTokenValidator.validate(&token), ChecksumResult::Invalid);
    }

    /// A known prefix with an in-band-length body carrying a non-alnum byte is
    /// Invalid (charset gate).
    #[test]
    fn stripe_non_alnum_in_band_body_is_invalid(
        pi in 0usize..STRIPE_PREFIXES.len(),
        a in "[A-Za-z0-9]{12,60}",
        b in "[A-Za-z0-9]{12,60}",
    ) {
        // len = a + 1 ('!') + b, in [25, 121] -> in the 24..=128 length band.
        let token = format!("{}{a}!{b}", STRIPE_PREFIXES[pi]);
        prop_assert_eq!(StripeTokenValidator.validate(&token), ChecksumResult::Invalid);
    }

    /// An unknown Stripe-shaped prefix is NotApplicable (not this validator's).
    #[test]
    fn stripe_unknown_prefix_is_not_applicable(
        pi in 0usize..UNKNOWN_STRIPE_PREFIXES.len(),
        body in "[A-Za-z0-9]{24,128}",
    ) {
        let token = format!("{}{body}", UNKNOWN_STRIPE_PREFIXES[pi]);
        prop_assert_eq!(StripeTokenValidator.validate(&token), ChecksumResult::NotApplicable);
    }
}
