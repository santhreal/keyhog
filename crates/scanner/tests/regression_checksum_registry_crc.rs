//! Regression: scanner checksum registry: CRC32 / base62 verification.
//!
//! Locks the embedded-checksum gate against silent drift. Every fixture below
//! is a KNOWN-GOOD value computed independently (Python `zlib.crc32`, the
//! standard CRC32 with poly 0xEDB88320, init/xorout 0xFFFF_FFFF) and base62
//! encoded with the module's own alphabet
//! `0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz`.
//!
//! Coverage: valid-checksum token passes (exact `Valid`), one-char-corrupted
//! variant fails (exact `Invalid`), CRC/base62 math matches a hardcoded oracle,
//! a prefix outside the registry returns `NotApplicable`, structural-only
//! families (`glpat-`, `glrt-`, stripe) return `StructurallyValid`, and the
//! confidence-policy mapping (Valid→floor 0.9, Invalid→drop) holds.
//!
//! Uses the `doc(hidden)` `testing::checksum` facade, the same surface the
//! existing `unit/checksum_extended.rs` target consumes.

use keyhog_scanner::testing::checksum::{
    base62_encode_u32, checksum_adjusted_confidence, crc32_base62_suffix,
    github_classic_pat_with_checksum, github_fine_grained_pat_with_checksum,
    npm_token_with_checksum, standard_crc32, validate_checksum, ChecksumResult,
    GithubClassicPatValidator, GithubFineGrainedPatValidator, GitlabTokenValidator,
    NpmTokenValidator, StripeTokenValidator, CHECKSUM_VALID_FLOOR,
};

// ── CRC32 / base62 primitive oracles ──────────────────────────────────────────

#[test]
fn crc32_matches_known_test_vectors() {
    // Standard CRC32 (zlib) reference vectors.
    assert_eq!(standard_crc32(b""), 0, "CRC32 of empty input is 0");
    assert_eq!(
        standard_crc32(b"abc"),
        891_568_578,
        "CRC32(\"abc\") reference vector"
    );
    // CRC32 of a 30-char all-'A' body (reused by the GitHub/npm fixtures below).
    assert_eq!(
        standard_crc32(&[b'A'; 30]),
        830_433_819,
        "CRC32 of 30 'A' bytes"
    );
}

#[test]
fn base62_encode_padding_and_carry_boundaries() {
    // Module alphabet is digits→UPPER→lower, width-padded with leading '0'.
    assert_eq!(base62_encode_u32(0, 6), "000000", "zero pads to all-zero");
    assert_eq!(base62_encode_u32(1, 6), "000001");
    assert_eq!(
        base62_encode_u32(61, 6),
        "00000z",
        "61 is last single digit"
    );
    assert_eq!(
        base62_encode_u32(62, 6),
        "000010",
        "62 carries to next place"
    );
    assert_eq!(base62_encode_u32(3844, 6), "000100", "62^2 = 3844");
    // CRC32(\"abc\") encoded to a 6-char base62 suffix.
    assert_eq!(base62_encode_u32(891_568_578, 6), "0yKviM");
}

#[test]
fn crc32_base62_suffix_composes_the_two_primitives() {
    // suffix == base62(crc32(body)) (the exact suffix GitHub/npm embed).
    assert_eq!(
        crc32_base62_suffix(&[b'A'; 30], 6),
        "0uCPlr",
        "base62(830433819) over 6 chars"
    );
    assert_eq!(
        crc32_base62_suffix(&[b'A'; 30], 6),
        base62_encode_u32(standard_crc32(&[b'A'; 30]), 6),
        "suffix helper == manual composition of the two primitives"
    );
}

// ── GitHub classic PAT: valid / corrupted / fixture ───────────────────────────

#[test]
fn github_classic_valid_checksum_passes() {
    // ghp_ + 30-char body + base62 CRC32 suffix "0uCPlr".
    let body = "A".repeat(30);
    let token = github_classic_pat_with_checksum(&body);
    assert_eq!(
        token, "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",
        "builder must emit the known-good token literal"
    );
    let result = GithubClassicPatValidator.validate(&token);
    assert_eq!(result, ChecksumResult::Valid);
    // Exact bool per the mandate: the checksum gate says "pass" = true.
    let passes = result == ChecksumResult::Valid;
    assert_eq!(passes, true, "valid-checksum ghp_ token passes the gate");
}

#[test]
fn github_classic_one_char_corrupted_suffix_fails() {
    // Same valid token, but flip the final suffix char 'r' -> 's'. Still fully
    // ascii-alphanumeric (so it reaches the CRC comparison, not the charset
    // guard), but the embedded CRC no longer matches the body -> Invalid.
    let corrupted = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0uCPls";
    assert_eq!(corrupted.len(), 40, "prefix(4) + body(30) + suffix(6)");
    let result = GithubClassicPatValidator.validate(corrupted);
    assert_eq!(result, ChecksumResult::Invalid);
    let passes = result == ChecksumResult::Valid;
    assert_eq!(passes, false, "one-char-corrupted checksum fails the gate");
}

#[test]
fn github_classic_second_independent_fixture_valid() {
    // A distinct mixed-case body, independently CRC'd: crc=997462050 -> "15VFRa".
    let body = "0123456789abcdefghijklmnOPQRST";
    assert_eq!(body.len(), 30);
    assert_eq!(standard_crc32(body.as_bytes()), 997_462_050);
    let token = github_classic_pat_with_checksum(body);
    assert_eq!(token, "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");
    assert_eq!(
        GithubClassicPatValidator.validate(&token),
        ChecksumResult::Valid
    );
}

// ── npm token: shares the GitHub CRC design ───────────────────────────────────

#[test]
fn npm_valid_checksum_passes_and_corrupted_fails() {
    let body = "A".repeat(30);
    let token = npm_token_with_checksum(&body);
    assert_eq!(token, "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");
    assert_eq!(NpmTokenValidator.validate(&token), ChecksumResult::Valid);

    // Corrupt one body char (A->B at index 0): CRC over the body changes, but
    // the embedded suffix stays "0uCPlr" -> mismatch -> Invalid.
    let corrupted = "npm_BAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0uCPlr";
    assert_eq!(corrupted.len(), 40);
    assert_eq!(
        NpmTokenValidator.validate(corrupted),
        ChecksumResult::Invalid
    );
}

// ── GitHub fine-grained PAT: CRC over the right segment body ───────────────────

#[test]
fn github_fine_grained_valid_checksum_passes() {
    // github_pat_{22}_{53-body}{6-suffix}; CRC is computed over the 53-char
    // right body. crc("B"*53)=618367032 -> base62 "0fqbVo".
    let left = "A".repeat(22);
    let right_body = "B".repeat(53);
    let token = github_fine_grained_pat_with_checksum(&left, &right_body);
    assert_eq!(
        token,
        "github_pat_AAAAAAAAAAAAAAAAAAAAAA_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB0fqbVo"
    );
    assert_eq!(standard_crc32(right_body.as_bytes()), 618_367_032);
    assert_eq!(
        GithubFineGrainedPatValidator.validate(&token),
        ChecksumResult::Valid
    );
}

#[test]
fn github_fine_grained_one_char_corrupted_suffix_fails() {
    // Flip final suffix char 'o' -> 'p'. Right segment stays 59 alnum chars, so
    // it clears the shape checks and fails purely on the CRC mismatch.
    let corrupted =
        "github_pat_AAAAAAAAAAAAAAAAAAAAAA_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB0fqbVp";
    assert_eq!(
        GithubFineGrainedPatValidator.validate(corrupted),
        ChecksumResult::Invalid
    );
}

// ── GitLab: structural-only (no recomputed CRC), must never claim Valid ────────

#[test]
fn gitlab_glpat_classic_20_is_structurally_valid() {
    // A structurally-shaped `glpat-` is StructurallyValid, NOT Valid (GitLab
    // publishes no verifiable classic checksum) and NOT Invalid.
    let token = "glpat-".to_string() + &"A".repeat(20);
    assert_eq!(
        GitlabTokenValidator.validate(&token),
        ChecksumResult::StructurallyValid
    );
}

#[test]
fn gitlab_glpat_too_short_is_invalid_and_too_long_not_applicable() {
    // 19 body chars: below the 20 floor -> positively malformed -> Invalid.
    let short = "glpat-".to_string() + &"A".repeat(19);
    assert_eq!(
        GitlabTokenValidator.validate(&short),
        ChecksumResult::Invalid
    );
    // 65 body chars: above the 64 ceiling -> a shape we don't model -> defer.
    let long = "glpat-".to_string() + &"A".repeat(65);
    assert_eq!(
        GitlabTokenValidator.validate(&long),
        ChecksumResult::NotApplicable
    );
}

#[test]
fn gitlab_routable_glrt_within_band_structurally_valid() {
    // Routable runner token: 16-char floor applies; 20 chars is in-band.
    let token = "glrt-".to_string() + &"A".repeat(20);
    assert_eq!(
        GitlabTokenValidator.validate(&token),
        ChecksumResult::StructurallyValid
    );
    // 15 chars is one below the routable floor -> Invalid.
    let too_short = "glrt-".to_string() + &"A".repeat(15);
    assert_eq!(
        GitlabTokenValidator.validate(&too_short),
        ChecksumResult::Invalid
    );
}

// ── Stripe: structural family, never checksum-Valid ───────────────────────────

#[test]
fn stripe_sk_live_in_band_is_structurally_valid_not_checksum_valid() {
    let token = "sk_live_".to_string() + &"A".repeat(24);
    let result = StripeTokenValidator.validate(&token);
    assert_eq!(result, ChecksumResult::StructurallyValid);
    // Explicitly assert it does NOT earn the cryptographic-proof verdict.
    assert_ne!(result, ChecksumResult::Valid);
}

// ── Registry dispatch: unregistered prefixes fall through to NotApplicable ─────

#[test]
fn registry_returns_not_applicable_for_prefix_outside_registry() {
    // No validator claims these -> the registry-level fold returns NotApplicable.
    assert_eq!(
        validate_checksum("just-a-random-string-1234567890"),
        ChecksumResult::NotApplicable
    );
    assert_eq!(
        // AWS-style key: real credential shape, but no checksum validator registered.
        validate_checksum("AKIAIOSFODNN7EXAMPLE"),
        ChecksumResult::NotApplicable
    );
    assert_eq!(validate_checksum(""), ChecksumResult::NotApplicable);
}

#[test]
fn registry_dispatch_routes_valid_token_to_valid() {
    // The top-level registry function must reach the GitHub validator and
    // return its Valid verdict (not merely per-validator behavior).
    let token = github_classic_pat_with_checksum(&"A".repeat(30));
    assert_eq!(validate_checksum(&token), ChecksumResult::Valid);
    // And a corrupted twin dispatches to Invalid at the registry level.
    assert_eq!(
        validate_checksum("ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0uCPls"),
        ChecksumResult::Invalid
    );
}

// ── Confidence-policy mapping keyed off the checksum verdict ───────────────────

#[test]
fn checksum_adjusted_confidence_floors_valid_and_drops_invalid() {
    assert_eq!(CHECKSUM_VALID_FLOOR, 0.9, "floor constant is exactly 0.9");

    let valid = github_classic_pat_with_checksum(&"A".repeat(30));
    // Valid + low incoming confidence -> floored up to CHECKSUM_VALID_FLOOR.
    let floored = checksum_adjusted_confidence(0.5, &valid).expect("valid token is kept");
    assert!(
        (floored - 0.9).abs() < 1e-9,
        "valid checksum floors 0.5 -> 0.9, got {floored}"
    );
    // Valid + already-high confidence -> unchanged (max, not overwrite).
    let high = checksum_adjusted_confidence(0.97, &valid).expect("valid token is kept");
    assert!((high - 0.97).abs() < 1e-9, "0.97 stays 0.97, got {high}");

    // Invalid -> None: the caller DROPS the match.
    assert_eq!(
        checksum_adjusted_confidence(0.97, "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0uCPls"),
        None,
        "corrupted-checksum match is dropped"
    );

    // StructurallyValid -> pass through unchanged (no floor, no drop).
    let structural = "sk_live_".to_string() + &"A".repeat(24);
    let passthrough =
        checksum_adjusted_confidence(0.42, &structural).expect("structural token kept");
    assert!(
        (passthrough - 0.42).abs() < 1e-9,
        "structural passes 0.42 through, got {passthrough}"
    );

    // NotApplicable -> pass through unchanged.
    let na = checksum_adjusted_confidence(0.42, "no-checksum-here").expect("kept");
    assert!((na - 0.42).abs() < 1e-9, "not-applicable passes through");
}
