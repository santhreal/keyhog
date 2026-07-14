use super::HASH_ALGO_INTEGRITY_LABELS;
use super::TEMPLATE_PLACEHOLDER_MAX_LEN;
use super::{
    generic_base64_candidate_is_ambiguous, is_dash_segmented_alnum_decoy,
    is_structured_dotted_token, is_uuid_v4_shape, looks_like_aws_iam_arn,
    looks_like_bare_hex_digest, looks_like_base64_integrity_body,
    looks_like_bracketed_template_placeholder, looks_like_dashed_serial_key,
    looks_like_entropy_canonical_non_secret_shape, looks_like_entropy_uuid_shape,
    looks_like_generic_random_base64_blob_decoy, looks_like_prefixed_hash_digest,
    looks_like_prefixed_masked_sequence, looks_like_random_byte_base64_blob,
    looks_like_trimmed_aws_iam_arn, strip_hash_algo_prefix,
};
use crate::suppression::decision::decoded_benign_text_reason;
// Imported separately: rustfmt groups the UPPER_SNAKE const after the
// lower-snake fn names in a `use` list, so keep it on its own line.
use super::HIGH_ENTROPY_BASE64_CUTOFF;

/// A real `sha512-` npm SRI integrity body (proven suppressed by the
/// `regression_reverse_integrity_decoy_suppression` corpus): standard
/// base64, `==` padded, length a multiple of four, well over the 40-char
/// integrity floor.
const NPM_SRI_BODY: &str =
    "1msyKcoKgxiewdylfpoWNSrFFW3ojqO5LKa5wDu1Ivsn9KJyenY5VvFVFvg3LtJWzI3b3d8GNNngKmP1Zdzpfy==";

#[test]
fn prefixed_masked_sequence_matches_mask_plus_fake_run_case_insensitively() {
    // Mask prefix (XXX / *** / xxx) AND a fake ascending run, in any case.
    assert!(looks_like_prefixed_masked_sequence("XXXXX1234567890"));
    assert!(looks_like_prefixed_masked_sequence("xxx_abcdefgh_key"));
    assert!(looks_like_prefixed_masked_sequence("***0123456789zz"));
    // "ABCDEFGHIJ" must still match via the subsuming "abcdefgh" needle.
    assert!(looks_like_prefixed_masked_sequence("XXXabcdefghij"));
    // Uppercase fake run under an uppercase mask (the old to_ascii_uppercase
    // path) must remain a match through the case-insensitive ci_find.
    assert!(looks_like_prefixed_masked_sequence("XXXABCDEFGH"));
}

#[test]
fn prefixed_masked_sequence_matches_trailing_ellipsis() {
    assert!(looks_like_prefixed_masked_sequence("ghp_1a2b3c4..."));
    assert!(looks_like_prefixed_masked_sequence("sk_live_abcd1234…"));
}

#[test]
fn prefixed_masked_sequence_rejects_partial_signals() {
    // Mask prefix but NO fake sequence: not a placeholder.
    assert!(!looks_like_prefixed_masked_sequence("XXXrandomtokenbody"));
    // Fake sequence but NO mask prefix: a real-looking token containing a
    // run must not be suppressed by this gate.
    assert!(!looks_like_prefixed_masked_sequence("1234567890realbody"));
    assert!(!looks_like_prefixed_masked_sequence("abcdefghkey"));
    // Empty / short bodies.
    assert!(!looks_like_prefixed_masked_sequence(""));
    assert!(!looks_like_prefixed_masked_sequence("xx"));
}

#[test]
fn structured_dotted_token_accepts_jwt_like_shape() {
    assert!(is_structured_dotted_token(
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        ));
}

#[test]
fn structured_dotted_token_accepts_discord_style_shape() {
    assert!(is_structured_dotted_token(
        "MTIzNDU2Nzg5MDEyMzQ1Njc4.Oabc12.xYz0123456789abcDEFghijk_lmnop"
    ));
}

#[test]
fn structured_dotted_token_rejects_property_chains() {
    assert!(!is_structured_dotted_token("this.someService.copilotToken"));
    assert!(!is_structured_dotted_token("example.com"));
    assert!(!is_structured_dotted_token("alpha.beta.gamma.delta"));
}

#[test]
fn dashed_serial_key_accepts_exact_five_by_five_shape() {
    assert!(looks_like_dashed_serial_key(
        "JQQJN-VBWHG-XBC8R-2MV9F-CD7P9"
    ));
    assert!(looks_like_dashed_serial_key(
        "jqqjn-vbwhg-xbc8r-2mv9f-cd7p9"
    ));
}

#[test]
fn dashed_serial_key_rejects_broken_boundaries() {
    for value in [
        "JQQJN-VBWHG-XBC8R-2MV9F-CD7P",
        "JQQJN-VBWHG-XBC8R-2MV9F-CD7P99",
        "JQQJN--VBWHG-XBC8R-2MV9F-CD7P",
        "JQQJN_VBWHG-XBC8R-2MV9F-CD7P9",
        "JQQJN-VBWHG-XBC8R-2MV9F-CD7P!",
    ] {
        assert!(
            !looks_like_dashed_serial_key(value),
            "broken 5x5 serial boundary must not suppress: {value}"
        );
    }
}

#[test]
fn entropy_license_serial_remains_uppercase_only() {
    assert!(looks_like_entropy_canonical_non_secret_shape(
        "JQQJN-VBWHG-XBC8R-2MV9F-CD7P9"
    ));
    assert!(
            !looks_like_entropy_canonical_non_secret_shape("jqqjn-vbwhg-xbc8r-2mv9f-cd7p9"),
            "entropy generation intentionally keeps lowercase dashed keys outside the canonical serial decoy set"
        );
}

#[test]
fn random_byte_base64_blob_accepts_pure_alnum_decoy() {
    assert!(looks_like_random_byte_base64_blob(
        "VqsjpzT2Jauz6vo76xb5vNB8XXxfBTQyNX6G5Kx1AEEk"
    ));
}

#[test]
fn random_byte_base64_blob_rejects_slash_bearing_token() {
    assert!(!looks_like_random_byte_base64_blob(
        "PvgsQdw6b5r9JqFzmaVkh/PBOtxkvFtq3OLNhcdqlOcoSqgnQx"
    ));
}

#[test]
fn random_byte_base64_blob_rejects_urlsafe_token_shape() {
    assert!(!looks_like_random_byte_base64_blob(
        "ghp_0123456789abcdefghijklmnopqrstuvwxyzABCDEF"
    ));
}

#[test]
fn aws_iam_arn_accepts_full_and_trimmed_resource_identifiers() {
    assert!(looks_like_aws_iam_arn(
        "arn:aws:iam::123456789012:role/ReadOnly"
    ));
    assert!(looks_like_aws_iam_arn(
        "arn:aws-us-gov:iam::123456789012:instance-profile/Worker"
    ));
    assert!(looks_like_trimmed_aws_iam_arn(
        "aws-cn:iam::123456789012:user/alice"
    ));
}

#[test]
fn aws_iam_arn_rejects_non_iam_secret_references() {
    assert!(!looks_like_aws_iam_arn(
        "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db"
    ));
    assert!(!looks_like_aws_iam_arn(
        "arn:aws:iam::123456789012:server-certificate/cert"
    ));
    assert!(!looks_like_trimmed_aws_iam_arn(
        "arn:aws:iam::123456789012:role/ReadOnly"
    ));
}

// ---- strip_hash_algo_prefix: the case-insensitive label strip ----

#[test]
fn strip_hash_algo_prefix_strips_lowercase_sha256() {
    assert_eq!(strip_hash_algo_prefix("sha256:deadbeef"), Some("deadbeef"));
}

#[test]
fn strip_hash_algo_prefix_strips_uppercase_sha256() {
    // ssh-keygen -lf renders `SHA256:<base64>`; certutil emits upper-case.
    // The lower-case-only match used to leak these back out.
    assert_eq!(strip_hash_algo_prefix("SHA256:deadbeef"), Some("deadbeef"));
}

#[test]
fn strip_hash_algo_prefix_strips_mixed_case_sha256() {
    assert_eq!(strip_hash_algo_prefix("Sha256:body"), Some("body"));
    assert_eq!(strip_hash_algo_prefix("sHa256:body"), Some("body"));
}

#[test]
fn strip_hash_algo_prefix_strips_embedded_lowercase_docker_digest() {
    // Value extractor surfaces `nginx@sha256:<hex>` as one string that does
    // NOT start with the algo label - substring match is intentional.
    assert_eq!(
        strip_hash_algo_prefix("nginx@sha256:cafebabe"),
        Some("cafebabe")
    );
}

#[test]
fn strip_hash_algo_prefix_strips_embedded_uppercase_digest() {
    assert_eq!(
        strip_hash_algo_prefix("nginx@SHA256:cafebabe"),
        Some("cafebabe")
    );
}

#[test]
fn strip_hash_algo_prefix_strips_sha512_dash_both_cases() {
    assert_eq!(strip_hash_algo_prefix("sha512-Zm9vYmFy"), Some("Zm9vYmFy"));
    assert_eq!(strip_hash_algo_prefix("SHA512-Zm9vYmFy"), Some("Zm9vYmFy"));
}

#[test]
fn strip_hash_algo_prefix_strips_sha256_dash_both_cases() {
    assert_eq!(strip_hash_algo_prefix("sha256-Zm9v"), Some("Zm9v"));
    assert_eq!(strip_hash_algo_prefix("SHA256-Zm9v"), Some("Zm9v"));
}

#[test]
fn strip_hash_algo_prefix_strips_sha1_both_cases() {
    assert_eq!(strip_hash_algo_prefix("sha1:0badf00d"), Some("0badf00d"));
    assert_eq!(strip_hash_algo_prefix("SHA1:0badf00d"), Some("0badf00d"));
}

#[test]
fn strip_hash_algo_prefix_strips_md5_both_cases() {
    assert_eq!(strip_hash_algo_prefix("md5:abcd"), Some("abcd"));
    assert_eq!(strip_hash_algo_prefix("MD5:abcd"), Some("abcd"));
}

#[test]
fn strip_hash_algo_prefix_returns_none_without_label() {
    assert_eq!(strip_hash_algo_prefix("randomtokenbody"), None);
    // `sha:` is NOT a label (bare algo family, no `256`/`512`/`384` digits).
    assert_eq!(strip_hash_algo_prefix("sha:foo"), None);
    // `sha224-` is deliberately absent from the SRI owner set too.
    assert_eq!(strip_hash_algo_prefix("sha224-foo"), None);
}

#[test]
fn strip_hash_algo_prefix_strips_sha384_dash_both_cases() {
    // THE FIX: `sha384-` is the recommended SRI algorithm and lives in the
    // ONE owner `HASH_ALGO_INTEGRITY_LABELS`; the report-time strip now binds
    // that owner instead of a diverging {sha512-,sha256-} subset that dropped
    // it. Previously this returned None and leaked sha384 SRI at report time.
    assert_eq!(strip_hash_algo_prefix("sha384-Zm9vYmFy"), Some("Zm9vYmFy"));
    assert_eq!(strip_hash_algo_prefix("SHA384-Zm9vYmFy"), Some("Zm9vYmFy"));
}

#[test]
fn strip_hash_algo_prefix_first_label_in_array_order_wins() {
    // LABELS are scanned in array order (sha256: before md5:), so the
    // earlier-in-array label wins even when it appears later in the string.
    assert_eq!(strip_hash_algo_prefix("md5:AAAA sha256:BBBB"), Some("BBBB"));
}

#[test]
fn strip_hash_algo_prefix_empty_body() {
    assert_eq!(strip_hash_algo_prefix("sha256:"), Some(""));
    assert_eq!(strip_hash_algo_prefix("SHA256:"), Some(""));
}

#[test]
fn strip_hash_algo_prefix_multibyte_body_does_not_panic() {
    // The label is ASCII so the slice boundary is codepoint-safe even when
    // the body tail is multibyte UTF-8.
    assert_eq!(strip_hash_algo_prefix("sha256:café☕"), Some("café☕"));
    assert_eq!(strip_hash_algo_prefix("SHA256:café☕"), Some("café☕"));
}

#[test]
fn strip_hash_algo_prefix_ssh_keygen_fingerprint_line() {
    // `ssh-keygen -lf key.pub` output: "256 SHA256:<base64> user@host".
    assert_eq!(
        strip_hash_algo_prefix("256 SHA256:abcDEF012+/ghi comment"),
        Some("abcDEF012+/ghi comment")
    );
}

// ---- looks_like_prefixed_hash_digest: end-to-end suppression contract ----

#[test]
fn prefixed_hash_digest_lowercase_docker_64hex_true() {
    let v = format!("sha256:{}", "a".repeat(64));
    assert!(looks_like_prefixed_hash_digest(&v));
}

#[test]
fn prefixed_hash_digest_uppercase_label_64hex_true() {
    // THE FIX end-to-end: upper-case label + lower-case 64-hex body.
    let v = format!("SHA256:{}", "a".repeat(64));
    assert!(looks_like_prefixed_hash_digest(&v));
}

#[test]
fn prefixed_hash_digest_uppercase_label_uppercase_hex_certutil_true() {
    // Windows certutil emits `SHA256` + UPPER-case hex; is_uniform_hex
    // accepts uniform upper-case, so the whole thing suppresses.
    let v = format!("SHA256:{}", "A".repeat(64));
    assert!(looks_like_prefixed_hash_digest(&v));
}

#[test]
fn prefixed_hash_digest_sha512_128hex_both_cases_true() {
    assert!(looks_like_prefixed_hash_digest(&format!(
        "sha512:{}",
        "b".repeat(128)
    )));
    assert!(looks_like_prefixed_hash_digest(&format!(
        "SHA512:{}",
        "B".repeat(128)
    )));
}

#[test]
fn prefixed_hash_digest_sha1_40hex_both_cases_true() {
    assert!(looks_like_prefixed_hash_digest(&format!(
        "sha1:{}",
        "c".repeat(40)
    )));
    assert!(looks_like_prefixed_hash_digest(&format!(
        "SHA1:{}",
        "c".repeat(40)
    )));
}

#[test]
fn prefixed_hash_digest_npm_integrity_base64_both_cases_true() {
    assert!(looks_like_prefixed_hash_digest(&format!(
        "sha512-{NPM_SRI_BODY}"
    )));
    assert!(looks_like_prefixed_hash_digest(&format!(
        "SHA512-{NPM_SRI_BODY}"
    )));
}

#[test]
fn prefixed_hash_digest_short_body_below_base64_floor_false() {
    // Bodies shorter than the 40-char base64-integrity floor that are also
    // not a {32,40,64,128}-length hex digest are not suppressed by this shape.
    assert!(!looks_like_prefixed_hash_digest(&format!(
        "sha256:{}",
        "a".repeat(30)
    )));
}

#[test]
fn prefixed_hash_digest_md5_32hex_both_cases_true() {
    // `md5:`/`sha1:` are in the label set; the 32-hex md5 body must suppress
    // (previously omitted from the body-length set, leaking `md5:<32hex>`).
    assert!(looks_like_prefixed_hash_digest(&format!(
        "md5:{}",
        "a".repeat(32)
    )));
    assert!(looks_like_prefixed_hash_digest(&format!(
        "MD5:{}",
        "A".repeat(32)
    )));
    // Embedded form the value extractor surfaces (`file@md5:<hex>`).
    assert!(looks_like_prefixed_hash_digest(&format!(
        "blob@md5:{}",
        "d".repeat(32)
    )));
    // A 31-hex body is not a digest length and below the base64 floor.
    assert!(!looks_like_prefixed_hash_digest(&format!(
        "md5:{}",
        "a".repeat(31)
    )));
}

#[test]
fn prefixed_hash_digest_non_base64_char_body_false() {
    // A 40-char body clears the integrity floor, but a non-base64 byte
    // ('!') makes it neither a hex digest nor a valid base64 integrity blob,
    // so the broad base64 arm cannot suppress it either.
    let v = format!("sha256:{}!", "z".repeat(39));
    assert!(!looks_like_prefixed_hash_digest(&v));
}

#[test]
fn prefixed_hash_digest_unpadded_remainder_one_body_false() {
    // A 41-char unpadded body has length % 4 == 1, which standard base64
    // never produces, so it is not a valid integrity blob (and 41 is not a
    // hex digest length). Pins the base64-shape boundary of the caller.
    let v = format!("sha256:{}", "a".repeat(41));
    assert!(!looks_like_prefixed_hash_digest(&v));
}

#[test]
fn prefixed_hash_digest_requires_the_label() {
    // A bare 64-hex value with NO algo label is NOT this shape (the
    // ambiguous bare-hex arm handles it, anchor-gated).
    assert!(!looks_like_prefixed_hash_digest(&"a".repeat(64)));
}

// ---- looks_like_bracketed_template_placeholder: single-owner brace/angle gate ----

#[test]
fn bracketed_template_placeholder_matches_brace_angle_and_dollar_forms() {
    assert!(looks_like_bracketed_template_placeholder("{placeholder}"));
    assert!(looks_like_bracketed_template_placeholder(
        "<your-token-here>"
    ));
    assert!(looks_like_bracketed_template_placeholder("${SECRET_TOKEN}"));
}

#[test]
fn bracketed_template_placeholder_rejects_unwrapped_and_overlong() {
    // No wrapping markers: a real token must not be suppressed.
    assert!(!looks_like_bracketed_template_placeholder(
        "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
    ));
    // Opening marker without the matching close.
    assert!(!looks_like_bracketed_template_placeholder("{unterminated"));
    // Exactly at the length ceiling is accepted; one over is rejected.
    let at_cap = format!("{{{}}}", "a".repeat(TEMPLATE_PLACEHOLDER_MAX_LEN - 2));
    assert_eq!(at_cap.len(), TEMPLATE_PLACEHOLDER_MAX_LEN);
    assert!(looks_like_bracketed_template_placeholder(&at_cap));
    let over_cap = format!("{{{}}}", "a".repeat(TEMPLATE_PLACEHOLDER_MAX_LEN - 1));
    assert_eq!(over_cap.len(), TEMPLATE_PLACEHOLDER_MAX_LEN + 1);
    assert!(!looks_like_bracketed_template_placeholder(&over_cap));
}

// ---- HIGH_ENTROPY_BASE64_CUTOFF: single-owner shared entropy boundary ----

#[test]
fn high_entropy_base64_cutoff_value_is_locked() {
    // The two generic-base64 decoy gates below share this exact bits/char
    // boundary; both were byte-identical `4.8` locals before being hoisted
    // to this one module-level const.
    assert_eq!(HIGH_ENTROPY_BASE64_CUTOFF, 4.8);
}

#[test]
fn both_generic_base64_gates_pivot_on_the_shared_cutoff() {
    // 40-char standard-base64 value engineered to clear BOTH gates'
    // downstream shape checks at once: length in the [40, 300] band, both
    // `+` and `/` present, length a multiple of four, and 38 distinct
    // alphanumeric chars (>= the 32-char diversity floor). Because every
    // structural predicate is satisfied, the ONLY thing that decides each
    // gate's verdict here is the entropy comparison against the shared
    // HIGH_ENTROPY_BASE64_CUTOFF.
    let value = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL+/";
    assert_eq!(value.len(), 40);

    let just_below = HIGH_ENTROPY_BASE64_CUTOFF - 0.1;

    // Below the cutoff: the decoy gate fires (low-entropy byte-distribution
    // blob), the ambiguous gate does NOT (too low to be an ambiguous
    // high-entropy candidate).
    assert!(looks_like_generic_random_base64_blob_decoy(
        value, just_below
    ));
    assert!(!generic_base64_candidate_is_ambiguous(value, just_below));

    // Exactly AT the shared cutoff both flip in lockstep: the decoy gate
    // stops firing (`entropy >= cutoff` short-circuits to false) and the
    // ambiguous gate starts firing (`entropy >= cutoff` proceeds to the
    // shape/diversity check, which passes). Their agreement at this single
    // numeric boundary is what proves both read the same const.
    assert!(!looks_like_generic_random_base64_blob_decoy(
        value,
        HIGH_ENTROPY_BASE64_CUTOFF
    ));
    assert!(generic_base64_candidate_is_ambiguous(
        value,
        HIGH_ENTROPY_BASE64_CUTOFF
    ));
}

/// Single-pass rewrite of the dash-group scan must preserve both decoy
/// arms and the empty-group rejection.
#[test]
fn dash_segmented_alnum_decoy_arms_preserved() {
    // Fixed-width upper/digit serial (>=3 groups, each exactly 5).
    assert!(is_dash_segmented_alnum_decoy("ABCDE-12345-FG7HI"));
    // Multi-part all-alpha, non-random identifier.
    assert!(is_dash_segmented_alnum_decoy("alpha-beta-gamma"));
    // Empty group (`foo--bar`) rejects regardless of the arms.
    assert!(!is_dash_segmented_alnum_decoy("ABCDE--12345"));
    // No dash → not a dash-segmented shape.
    assert!(!is_dash_segmented_alnum_decoy("ABCDE12345FG7HI"));
}

// ---- sha384 SRI: ONE label owner, suppressed via BOTH entry points ----

#[test]
fn sha384_sri_suppressed_via_both_report_time_and_entropy_entry_points() {
    // A `sha384-<base64 integrity body>` value. Before the strip/owner
    // unification, the report-time `looks_like_prefixed_hash_digest` entry
    // point dropped `sha384-` (its dash-label subset diverged from the SRI
    // owner) and LEAKED this back out as a false positive, while the
    // entropy-generation entry point suppressed it, a same-set/different-
    // value split. Both must now agree.
    let lower = format!("sha384-{NPM_SRI_BODY}");
    let upper = format!("SHA384-{NPM_SRI_BODY}");

    // Entry point 1: report-time bare-value suppression.
    assert!(
        looks_like_prefixed_hash_digest(&lower),
        "sha384 SRI must suppress at report time (the leak this fix closes)"
    );
    assert!(
        looks_like_prefixed_hash_digest(&upper),
        "case-insensitive SHA384 label must also suppress at report time"
    );

    // Entry point 2: entropy-generation canonical-non-secret gate.
    assert!(
        looks_like_entropy_canonical_non_secret_shape(&lower),
        "sha384 SRI must stay a canonical non-secret at entropy generation"
    );

    // The label owner really does carry sha384- (guards against a future
    // edit silently dropping it from the ONE owner again).
    assert!(HASH_ALGO_INTEGRITY_LABELS.contains(&"sha384-"));
}

#[test]
fn base64_integrity_body_floor_is_exactly_forty_for_both_gates() {
    // The 40-char floor both integrity gates bind through the single owner
    // `looks_like_base64_integrity_body`. Use pad-free slices of a valid
    // base64 body so ONLY the length floor, not the base64 %4 shape rule
    // decides: 36 chars is a valid base64 shape (36 % 4 == 0) yet below the
    // floor, 40 chars clears it.
    let under_floor = &NPM_SRI_BODY[..36];
    let at_floor = &NPM_SRI_BODY[..40];
    assert_eq!(
        under_floor.len() % 4,
        0,
        "isolate the floor, not the %4 rule"
    );
    assert!(
        !looks_like_base64_integrity_body(under_floor),
        "a valid-shaped 36-char base64 body is below the 40-char integrity floor"
    );
    assert!(
        looks_like_base64_integrity_body(at_floor),
        "exactly 40 chars clears the integrity floor"
    );
}

// ---- decoded hash digest: the decoded path binds the SAME length owner ----

#[test]
fn decoded_bare_hex_digest_owner_covers_md5_and_sha1_lengths() {
    // `looks_like_bare_hex_digest` is the ONE length owner the base64-decoded
    // suppression path (`decision::decoded_benign_text_reason`) delegates to.
    // The decoded path previously used a divergent {56,64,72,128} set that
    // DROPPED md5 (32) and sha1 (40), leaking base64-wrapped digests. The
    // owner must cover the full set both paths bind.
    for len in [32usize, 40, 48, 56, 64, 72, 128] {
        assert!(
            looks_like_bare_hex_digest(&"a".repeat(len)),
            "{len}-hex is a bare digest length in the unified owner set"
        );
    }
    // Boundary twins just outside the set are NOT digests.
    for len in [31usize, 33, 41, 47, 127] {
        assert!(
            !looks_like_bare_hex_digest(&"a".repeat(len)),
            "{len}-hex is outside the unified digest length set"
        );
    }
}

#[test]
fn decoded_md5_and_sha1_are_suppressed_end_to_end() {
    // base64("d41d8cd98f00b204e9800998ecf8427e"), the empty-string md5, a
    // 32-hex digest. The decoded path must strip the base64 wrapper and
    // suppress it as a bare hash digest (md5 32-hex was the leaking length).
    assert_eq!(
        decoded_benign_text_reason("ZDQxZDhjZDk4ZjAwYjIwNGU5ODAwOTk4ZWNmODQyN2U="),
        Some("decoded_bare_hash_digest"),
        "base64-wrapped md5 (32-hex) must suppress via the decoded digest arm"
    );
    // base64("da39a3ee5e6b4b0d3255bfef95601890afd80709"), empty-string sha1,
    // a 40-hex digest (the other length the old decoded set dropped).
    assert_eq!(
        decoded_benign_text_reason("ZGEzOWEzZWU1ZTZiNGIwZDMyNTViZmVmOTU2MDE4OTBhZmQ4MDcwOQ=="),
        Some("decoded_bare_hash_digest"),
        "base64-wrapped sha1 (40-hex) must suppress via the decoded digest arm"
    );
    // Negative twin: base64 of a 39-hex string. 39 is OUTSIDE the unified
    // digest length set, so the digest arm provably cannot fire, a real hex
    // token of a non-digest length must not be swallowed by this arm.
    assert_ne!(
        decoded_benign_text_reason("M2Y4YTFjOWUyYjdkNDA1MTZhOGMzZTlmMWIyZDRhNmM4ZTBmMWEy"),
        Some("decoded_bare_hash_digest"),
        "a 39-hex decoded value is not a digest length and must not suppress here"
    );
}

// ---- UUID shape: ONE case-uniform owner shared by both callers ----

#[test]
fn uuid_shape_owner_agrees_on_case_across_both_callers() {
    // `looks_like_entropy_uuid_shape` delegates to `is_uuid_v4_shape`, so the
    // two must return byte-identical verdicts for EVERY input, a mixed-case
    // UUID must never be a non-secret in one path and a live candidate in the
    // other (the divergence this unification closed).
    let uniform_lower = "a1b2c3d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d";
    let uniform_upper = "A1B2C3D4-5E6F-4A7B-8C9D-0E1F2A3B4C5D";
    let evil_mixed = "a1b2c3d4-5e6f-4a7b-8C9d-0e1f2a3b4c5d";

    for value in [uniform_lower, uniform_upper, evil_mixed] {
        assert_eq!(
            is_uuid_v4_shape(value),
            looks_like_entropy_uuid_shape(value),
            "both UUID callers must agree on {value:?} (one owner)"
        );
    }

    // Uniform-case UUIDs ARE the canonical non-secret shape.
    assert!(is_uuid_v4_shape(uniform_lower));
    assert!(is_uuid_v4_shape(uniform_upper));
    // Evil mixed-case UUID is rejected by BOTH (real digests/UUIDs are never
    // emitted MiXeD-case), so it is not silently treated as a non-secret.
    assert!(!is_uuid_v4_shape(evil_mixed));
    assert!(!looks_like_entropy_uuid_shape(evil_mixed));
}
