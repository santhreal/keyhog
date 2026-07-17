//! Precision: decoy / placeholder twins for the ~40 named + generic
//! detectors must NOT fire as real findings. Every assertion is derived
//! from the real suppression cascade in
//! `crates/scanner/src/suppression/{api,decision,doc_markers,shape/}.rs`
//! and the entropy decoy gates in
//! `crates/scanner/src/entropy/{keywords,scanner}.rs`.
//!
//! Two surfaces are exercised:
//!   * `known_example_suppressed`: the generic / EXAMPLE
//!     entry point (bypass_shape_gates = false, weak_anchor = false).
//!   * `named_detector_suppressed`: the service-anchored
//!     entry point (bypass_shape_gates depends on the detector id).
//! Plus the leaf predicates exposed through `keyhog_scanner::testing`.
//!
//! For each decoy class we assert the decoy is suppressed AND that a real
//! credential twin of the SAME shape is NOT suppressed (the negative twin),
//! so a test passing on a function that always returns `true` is impossible.

use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::known_example_suppressed;
use keyhog_scanner::testing::named_detector_suppressed;

use keyhog_scanner::testing::entropy_keywords::{
    entropy_value_looks_like_prose, is_dash_segmented_alnum_decoy, looks_like_english_prose,
    passes_secret_strength_checks,
};
use keyhog_scanner::testing::entropy_scanner::{
    candidate_is_plausible, credential_keyword_context, is_canonical_non_secret_shape,
};
use keyhog_scanner::testing::looks_like_standard_base64_blob;
use keyhog_scanner::testing::shape::{
    looks_like_credential_colliding_punctuation, looks_like_punctuation_decorated_identifier,
    looks_like_syntactic_punctuation_marker,
};

// ── helpers ──────────────────────────────────────────────────────────

/// Suppress through the generic / EXAMPLE entry point (no service anchor,
/// shape gates engaged). Default placeholder list is empty.
fn suppress_generic(cred: &str) -> bool {
    known_example_suppressed(cred, None, CodeContext::Assignment)
}

/// Suppress through the named-detector entry point with a service-anchored
/// detector id (shape gates bypassed for strongly-anchored ids).
fn suppress_named(cred: &str, detector_id: &str) -> bool {
    named_detector_suppressed(cred, None, CodeContext::Assignment, None, detector_id)
}

/// Build the production credential-keyword anchor used by the entropy path.
fn cred_ctx() -> keyhog_scanner::testing::entropy_scanner::KeywordContext {
    credential_keyword_context("api_key")
}

// ── YOUR_KEY_HERE / instructional-fragment decoys ───────────────────

#[test]
fn your_key_here_instructional_fragment_suppressed() {
    // check_markers' Tier-B instructional_fragments contains "YOUR_"
    // with a leading-word-boundary requirement. "YOUR_API_KEY_HERE" starts
    // at offset 0 (boundary = none → allowed) → Suppress.
    assert!(suppress_generic("YOUR_API_KEY_HERE"));
    assert!(suppress_generic("YOUR-API-KEY-HERE")); // "YOUR-" fragment
    assert!(suppress_generic("YOUR_TOKEN_GOES_HERE"));
}

#[test]
fn replace_change_insert_fragments_suppressed() {
    // Tier-B instructional_fragments = YOUR_, YOUR-, INSERT, CHANGE, REPLACE.
    assert!(suppress_generic("REPLACE_WITH_REAL_KEY"));
    assert!(suppress_generic("CHANGE_THIS_VALUE_NOW"));
    assert!(suppress_generic("INSERT_TOKEN_HERE_PLEASE"));
}

#[test]
fn instructional_fragment_requires_leading_boundary_real_cred_survives() {
    // Negative twin: "CHANGE" must sit on a word boundary. A real-looking
    // base64 token that merely embeds the letters "change" mid-word with a
    // preceding alphanumeric does NOT trip the fragment gate. Use a token
    // whose only "change" occurrence is preceded by an alphanumeric so the
    // boundary check fails, and which is not otherwise a recognised decoy
    // shape (mixed alphanum, no 5+ runs, not pure hex, has a digit).
    // "aXchange9Qm7Kp2" (the substring CHANGE is preceded by 'X').
    assert!(!suppress_generic("aXchange9Qm7Kp2"));
}

// ── EXAMPLE / EXAMPLEKEY decoys vs reserved example.com domain ───────

#[test]
fn example_suffix_token_suppressed_for_every_anchor() {
    // EXAMPLE handling lives in check_markers and fires for both the
    // generic and named entry points (it is checked before any tier gate).
    assert!(suppress_generic("AKIAIOSFODNN7EXAMPLE"));
    assert!(suppress_named("AKIAIOSFODNN7EXAMPLE", "aws-access-key-id"));
    assert!(suppress_generic("wJalrXUtnFEMIK7MDENGEXAMPLEKEY"));
}

#[test]
fn example_token_buried_in_known_prefix_suppressed() {
    // DOC_MARKER_SUBSTRINGS scan runs BEFORE the known-prefix Allow,
    // so a marker buried inside a ghp_ token still suppresses.
    assert!(suppress_generic("ghp_EXAMPLE_TOKEN_FROM_DOCS"));
    assert!(suppress_generic("sk_live_PLACEHOLDER_NOT_A_REAL_KEY"));
}

#[test]
fn example_dot_com_domain_is_not_suppressed_as_marker() {
    // EXAMPLE is explicitly NOT suppressed when it is the reserved
    // example.com / example.org domain (RFC 2606), guarded by
    // `!credential.contains("example.com")`. A bare email-shaped value
    // at example.com is instead suppressed by the email-address gate,
    // so use a non-email value that contains example.com to prove the
    // EXAMPLE marker itself does not fire here.
    // "client.example.com/oauth" contains '/' → url_or_path gate is Tier-B
    // only; through the generic path it would be scheme/path shaped. To
    // isolate the marker behaviour, assert the marker exemption directly:
    // a value containing "example.com" and otherwise a plain credential
    // shape with a digit must not be suppressed by the EXAMPLE marker.
    // "Tok3nForexample.comService", contains example.com, no path '/',
    // has digit, mixed case, no 5+ runs, not hex.
    assert!(!suppress_generic("Tok3nForexample.comService"));
}

// ── xxxxx / XXXXX masking decoys ─────────────────────────────────────

#[test]
fn five_x_mask_run_suppressed_generic() {
    // decision: `!bypass_shape_gates && upper.contains("XXXXX")`.
    assert!(suppress_generic("password_XXXXXXX"));
    assert!(suppress_generic("token_xxxxxxxxxxxx"));
    assert!(suppress_generic("APIKEYxxxxx1234"));
}

#[test]
fn x_dominated_body_suppressed() {
    // 20-char string of all 'x'. The `upper.contains("XXXXX")` mask gate
    // fires first; context::is_known_example_credential (len>=16 and
    // x_count > 3/4) is the deeper backstop for the same shape.
    assert!(suppress_generic("xxxxxxxxxxxxxxxxxxxx"));
}

#[test]
fn xxxxx_mask_not_suppressed_for_service_anchored_detector() {
    // Negative-direction twin for the gate split: the XXXXX masking gate
    // is `!bypass_shape_gates`. A strongly-anchored named detector
    // (aws-secret-access-key is not generic-/entropy-/weak) sets
    // bypass_shape_gates = true, so the masking gate does NOT fire.
    // The value still must clear the EXAMPLE / doc-marker checks (it does:
    // pure base62-ish with an XXXXX run, no markers, no known prefix).
    // This proves the decoy gates are correctly gated, not unconditional.
    assert!(!suppress_named(
        "AbcdXXXXX1234Defg5678Hijk9012Mnop",
        "aws-secret-access-key"
    ));
    // But the SAME value through the generic path IS suppressed (XXXXX).
    assert!(suppress_generic("AbcdXXXXX1234Defg5678Hijk9012Mnop"));
}

// ── 0000 / repeated-identical-run decoys ─────────────────────────────

#[test]
fn zero_filled_short_credential_suppressed() {
    // decision: len<20 && has_three_or_more_consecutive_identical.
    assert!(suppress_generic("0000000000000000")); // 16 zeros
    assert!(suppress_generic("token000000")); // 6-zero run, len 11
}

#[test]
fn long_run_of_identical_chars_suppressed() {
    // has_n_or_more_consecutive_identical(_, 5) for len>=20 values.
    // 24 'a's: pure-identical, no prefix → suppressed.
    assert!(suppress_generic("aaaaaaaaaaaaaaaaaaaaaaaa"));
    // repeated-block mask: three 4+ alnum runs.
    assert!(suppress_generic("aaaa1111bbbb2222cccc"));
}

#[test]
fn dash_runs_are_not_counted_as_repetitive() {
    // has_n_or_more_consecutive_identical explicitly excludes b'-'.
    // A value with a 6-dash run but otherwise real shape must rely on
    // OTHER gates; here it is a 5x5 serial-ish but with double dashes →
    // dashed_serial requires exactly len 29 / 5 groups, double dash breaks
    // it. So a long dashed token that is NOT a serial and has a digit and
    // mixed case must NOT be suppressed by the identical-run gate alone.
    // "Ab1------Cd2Ef3Gh4Jk5" : the only 5+ run is dashes (ignored).
    assert!(!suppress_generic("Ab1------Cd2Ef3Gh4Jk5"));
}

// ── sequential / monotonic decoys ────────────────────────────────────

#[test]
fn fake_dominant_sequence_suppressed() {
    // decision FAKE_SEQUENCES with seq_ratio > 0.4.
    // "1234567890" is 10 chars; total 12 → ratio 0.83 > 0.4 → suppress.
    assert!(suppress_generic("ab1234567890"));
    assert!(suppress_generic("ABCDEFGHIJxy")); // ABCDEFGHIJ ratio 0.83
}

#[test]
fn bare_monotonic_hex_suppressed() {
    // A bare 32-char ascending-hex value (no service prefix) is a
    // documentation placeholder. It is suppressed by the bare-hex-digest
    // gate (len 32, uniform lower hex) on the generic path; the
    // is_hex_sequential_placeholder arm of is_known_example_credential is
    // the deeper backstop for the same shape. Either way → suppressed.
    assert!(suppress_generic("0123456789abcdef0123456789abcdef"));
}

#[test]
fn repeated_pair_body_is_sequential_placeholder() {
    // is_sequential_placeholder (via is_known_example_credential, decision
    // step 6): a bare body of >=8 chars where every 2-char chunk equals the
    // first pair. "abababababababab" (16 chars, no prefix) → suppressed.
    assert!(suppress_generic("abababababababab"));
}

#[test]
fn clean_known_prefix_sequential_body_takes_allow_fast_path() {
    // Truthful negative twin documenting the prefix-trust ordering: the
    // known-prefix Allow fast-path in `check_markers` runs BEFORE the
    // decision tree's `is_known_example_credential` (step 6). A `sk-`
    // prefixed token whose body is a sequential pair-run is NOT a masked
    // sequence (no trailing `...`, no XXX/*** lead), so check_markers
    // returns Allow and the value is NOT suppressed, the prefix is treated
    // as positive evidence. (A real `sk-` OpenAI key with incidentally
    // repeating chars must not be dropped here.)
    assert!(!suppress_generic("sk-abababababababab"));
    // Same for a `ghp_`-prefixed monotonic-hex body: the body is not a
    // masked sequence, so the Allow fast-path wins over the
    // is_hex_sequential_placeholder backstop.
    assert!(!suppress_generic("ghp_0123456789abcdef0123456789abcdef"));
}

#[test]
fn fake_sequence_as_small_substring_does_not_suppress() {
    // Negative twin: a long real credential where "1234567890" is only a
    // small fraction (ratio <= 0.4) must NOT be suppressed by the
    // FAKE_SEQUENCES gate. 40-char base62 with the sequence embedded =
    // ratio 10/40 = 0.25. Must also avoid 5+ identical runs and hex-digest.
    // "Qz1234567890RtbKpLmNoVwXyAbCdEfGhJkMnPq" (len 39, ratio ~0.256).
    let cred = "Qz1234567890RtbKpLmNoVwXyAbCdEfGhJkMnPq";
    assert!(
        !suppress_generic(cred),
        "ratio {} should be <=0.4",
        10.0 / cred.len() as f64
    );
}

// ── low-entropy / pure-identifier decoys ─────────────────────────────

#[test]
fn pure_identifier_camelcase_suppressed_generic() {
    // api::looks_like_pure_identifier (Tier-B, generic path): no digit,
    // 8..=40 alpha, <=1 separator. "getParameter" → suppressed.
    assert!(suppress_named("getParameter", "generic-secret"));
    assert!(suppress_named("Benutzername", "generic-password"));
    assert!(suppress_named("sk_SRP_user_pwd_new_null", "generic-secret")); // >=2 underscores
}

#[test]
fn pure_identifier_not_suppressed_for_service_anchor() {
    // Negative-direction twin: the same identifier shape through a
    // strongly-anchored detector bypasses Tier-B, so it is NOT dropped
    // by looks_like_pure_identifier (the regex anchor is the evidence).
    // "getParameter" under a real service id is not generic/entropy/weak.
    assert!(!suppress_named("getParameter", "aws-secret-access-key"));
}

#[test]
fn word_separated_identifier_with_digits_suppressed_generic() {
    // api::looks_like_word_separated_identifier (Tier-B): every word <=10.
    assert!(suppress_named("s3_secret_access_key", "generic-secret"));
    assert!(suppress_named("X-Shopify-Access-Token", "generic-secret"));
}

#[test]
fn real_credential_with_long_random_segment_not_word_identifier() {
    // Negative twin: a Stripe-style key has a >10-char random segment, so
    // looks_like_word_separated_identifier returns false and it is not
    // suppressed even on the generic path. (sk_live_ is also a known prefix
    // whose body is not a masked sequence → Allow short-circuits earlier.)
    assert!(!suppress_named(
        "sk_live_4eC39HqLyjWDarjtT1zdp7dc",
        "generic-secret"
    ));
}

// ── hash-digest / UUID / serial canonical decoys ─────────────────────

#[test]
fn bare_hex_digest_suppressed_generic_but_not_named_hex_key() {
    // decision: looks_like_bare_hex_digest gated on !bypass_shape_gates.
    // A 32-char and 40-char uniform-lowercase-hex value is an md5 / sha1 /
    // git-sha digest on the unanchored generic path → suppressed.
    let hex32 = "7f3a9c1e4b8d2f6a0e5c9b3d7a1f8e2c"; // 32 lower hex, random
    let hex40 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"; // 40 lower hex
    assert!(suppress_generic(hex32));
    assert!(suppress_generic(hex40));
    // Negative-direction twin: the SAME 32-hex value under a strongly-
    // anchored service detector (algolia-admin-api-key is NOT generic-/
    // entropy-/weak/residual) sets bypass_shape_gates = true, so the
    // ambiguous bare-hex gate does NOT fire, a real 32-hex Algolia admin
    // key survives. (The value is random hex, not the empty-input digest,
    // so is_known_example_credential does not flag it either.)
    assert!(!suppress_named(hex32, "algolia-admin-api-key"));
}

#[test]
fn prefixed_hash_digest_always_suppressed_even_named() {
    // decision: looks_like_prefixed_hash_digest is ALWAYS-fire (not gated).
    let body = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    let docker = format!("sha256:{body}");
    assert!(suppress_generic(&docker));
    // Even with a service anchor, the algo-labelled digest fires.
    assert!(suppress_named(&docker, "aws-secret-access-key"));
}

#[test]
fn uuid_v4_shape_suppressed_generic() {
    // decision: is_uuid_v4_shape gated on !bypass_shape_gates.
    let uuid = "ce7ee1d0-e8b6-4d3f-96b0-be7b0bd7b8ac"; // 36, lower hex + dashes
    assert!(suppress_generic(uuid));
    // Negative-direction: a service-anchored UUID detector keeps it.
    assert!(!suppress_named(uuid, "heroku-api-key"));
}

#[test]
fn mixed_case_hex_is_not_treated_as_hash_digest() {
    // is_uniform_hex rejects mixed-case hex. A 32-char MiXeD-case hex
    // value is NOT a bare-hex-digest decoy, so it must NOT be suppressed
    // by that gate on the generic path. It also has no 5+ runs, no marker,
    // no fake sequence. (No digit-vs-letter requirement, hex letters count.)
    // "aB1cD2eF3aB4cD5eF6aB7cD8eF9aB0cD1" len 33, make it exactly 32:
    assert!(!suppress_generic("aB1cD2eF3aB4cD5eF6aB7cD8eF9aB0cD"));
}

#[test]
fn dashed_serial_license_key_always_suppressed() {
    // decision: looks_like_dashed_serial_key is ALWAYS-fire. Exactly 29
    // chars, 5 groups of 5 alnum.
    let serial = "JQQJN-VBWHG-XBC8R-2MV9F-CD7P9";
    assert_eq!(serial.len(), 29);
    assert!(suppress_generic(serial));
    assert!(suppress_named(serial, "aws-secret-access-key"));
    assert!(suppress_generic("ABCDE-FGHIJ-KLMNO-PQRST-UVWXY"));
}

#[test]
fn near_serial_shapes_do_not_match_dashed_serial() {
    // shape::looks_like_dashed_serial_key requires len==29 AND
    // exactly 5 groups. A 4-group or wrong-length value must not be caught
    // by THIS gate. Use a 4-group value with a digit, mixed case, no runs:
    // "Ab1cD-Ef2gH-Ij3kL-Mn4oP" (len 23, 4 groups). Should NOT suppress.
    assert!(!suppress_generic("Ab1cD-Ef2gH-Ij3kL-Mn4oP"));
}

// ── RFC 7519 example JWT decoy ───────────────────────────────────────

#[test]
fn rfc7519_example_jwt_prefix_suppressed() {
    // check_markers / decision both gate on RFC7519_EXAMPLE_JWT_PREFIX.
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkw\
               MSIsIm5hbWUiOiJKb2huIERvZSIsImlhdCI6MTUxNjIzOTAyMn0.SflKxwRJ";
    assert!(suppress_generic(jwt));
    // Embedded after a keyword prefix (contains, not starts_with).
    let embedded = format!("auth_token={jwt}");
    assert!(suppress_generic(&embedded));
}

// ── template-placeholder / brace decoys ──────────────────────────────

#[test]
fn brace_and_angle_template_placeholders_suppressed() {
    // decision 5e3: bracketed `{...}` / `<...>` / `${...}` and len<=80.
    assert!(suppress_generic("{{api_key}}"));
    assert!(suppress_generic("<your-token-here>"));
    assert!(suppress_generic("${SECRET_TOKEN}"));
}

#[test]
fn html_color_code_suppressed() {
    // decision 5e2: `#` + 3/6/8 hex digits.
    assert!(suppress_generic("#a1b2c3"));
    assert!(suppress_generic("#FFF"));
    assert!(suppress_generic("#deadbeef")); // 8 hex
}

#[test]
fn iam_role_arn_identifier_suppressed() {
    // decision 5e1: arn:aws:iam:: ... :role/.
    assert!(suppress_generic(
        "arn:aws:iam::783664492816:role/ReaderRole"
    ));
    assert!(suppress_generic("arn:aws-cn:iam::123456789012:user/bob"));
    // Negative: a NON-iam ARN namespace (secretsmanager) is a credential
    // reference and must NOT be suppressed by this narrow gate.
    assert!(!suppress_generic(
        "arn:aws:secretsmanager:us-east-1:123:secret:Prod9xKqRtLmNoVwXyAbCd"
    ));
}

// ── filler / symbolic-only decoys ────────────────────────────────────

#[test]
fn entirely_filler_symbol_credentials_suppressed() {
    // decision: all chars in {x,X,*,-,.}; and symbolic-only <=2 distinct.
    assert!(suppress_generic("****************"));
    assert!(suppress_generic("----------------"));
    assert!(suppress_generic("................"));
    assert!(suppress_generic("xXxXxXxXxXxX"));
}

#[test]
fn real_symbolic_password_not_suppressed_as_filler() {
    // Negative twin: a rich-symbol password has >2 distinct non-alnum
    // chars and contains alphanumerics, so neither the all-filler nor the
    // <=2-distinct-symbol gate fires. Mixed case + digits + many symbols.
    // "P@ssw0rd!#$%Zx9" (has alnum so the symbolic-only gate is skipped).
    assert!(!suppress_generic("P@ssw0rd!#Zx9Qm7"));
}

// ── prose / English-text decoys (entropy keyword gates) ──────────────

#[test]
fn long_pure_lowercase_is_prose() {
    // shape::looks_like_english_prose branch 1: all lowercase, len>=16.
    assert!(looks_like_english_prose(
        "thequickbrownfoxjumpsoverthelazydog"
    ));
    assert!(entropy_value_looks_like_prose("configurationmanagerhelper"));
}

#[test]
fn multi_word_alphabetic_is_prose() {
    // branch 2: 2+ alpha tokens, one lowercase run >=3.
    assert!(looks_like_english_prose("Session opened with handle XYZ"));
    assert!(looks_like_english_prose(
        "this is the description of something"
    ));
}

#[test]
fn fifteen_char_lowercase_below_floor_is_not_prose() {
    // Negative twin / boundary: len 15 < 16 floor → not prose.
    assert!(!looks_like_english_prose("configurationm")); // 14
    assert!(!looks_like_english_prose("abcdefghijklmno")); // 15
    assert!(looks_like_english_prose("abcdefghijklmnop")); // 16 → prose
}

#[test]
fn high_entropy_mixed_credential_is_not_prose() {
    // Negative twin: a real high-entropy token with a digit / mixed case
    // is never prose.
    assert!(!looks_like_english_prose(
        "Hk9PqRsTuVwXyZAbCdEfGhIjKlMnOpQr"
    ));
    assert!(!looks_like_english_prose(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaa1234"
    ));
}

#[test]
fn prose_multi_word_in_assignment_value_suppressed_generic() {
    // decision 5e0: len>30, >=2 whitespace, has a 3+ lowercase word run.
    assert!(suppress_generic(
        "Session opened with handle XYZ. See documentation."
    ));
}

// ── strict-secret entropy gate: decoys rejected, real symbolic admitted ──

#[test]
fn dash_segmented_alnum_decoys_rejected_by_strict_gate() {
    // keywords::passes_secret_strength_checks -> is_dash_segmented_alnum_decoy.
    // The 5x5 serial measures ~4.58 entropy (above the 4.5 floor) yet must
    // still be rejected, in BOTH credential and non-credential context.
    let decoys = [
        "A1B2C-D3E4F-G5H6I-J7K8L-M9N0P",
        "ABCDE-FGHIJ-KLMNO-PQRST-UVWXY",
        "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX",
        "00000-00000-00000-00000-00000",
        "my-service-prod-key-name-here",
    ];
    for d in decoys {
        assert!(
            !passes_secret_strength_checks(d, true),
            "decoy {d:?} must be rejected in credential context"
        );
        assert!(
            !passes_secret_strength_checks(d, false),
            "decoy {d:?} must be rejected without anchor"
        );
        assert!(is_dash_segmented_alnum_decoy(d), "{d:?} is dash-segmented");
    }
}

#[test]
fn symbolic_password_admitted_only_with_anchor() {
    // Positive recall: a 3.5-4.5 entropy symbolic password is admitted in
    // credential context (anchor + symbol relaxation) ...
    assert!(passes_secret_strength_checks("1E1B3b4Ho$U4kYBi", true));
    assert!(passes_secret_strength_checks(
        "Y6NPMwS*rWGUv!JQnSG6a#D14",
        true
    ));
    // ... but the SAME sub-4.5 symbolic value without an anchor stays
    // rejected (the relaxation requires is_credential_context).
    assert!(!passes_secret_strength_checks("1E1B3b4Ho$U4kYBi", false));
}

#[test]
fn pure_lowercase_repetition_rejected_even_with_anchor() {
    // Adversarial: low-entropy pure-lowercase repetition (entropy ~3.0)
    // fails both the prose/identifier path and the entropy floor, so it is
    // rejected even with a credential anchor.
    assert!(!passes_secret_strength_checks(
        "passwordispasswordispassword",
        true
    ));
}

#[test]
fn repeated_block_rejection_is_detector_owned() {
    use keyhog_core::DetectorPlausibilityPolicySpec;
    use keyhog_scanner::testing::entropy_keywords::passes_secret_strength_checks_with_plausibility_policy;

    let repeated = "passwordispasswordispassword";
    let policy = DetectorPlausibilityPolicySpec {
        mixed_alnum_floor: 4.0,
        symbolic_entropy_floor: 3.5,
        second_half_entropy_floor: 2.5,
        mixed_alnum_min_len: 20,
        isolated_mixed_entropy_floor: 3.65,
        isolated_symbolic_min_len: 18,
        isolated_symbolic_min_symbols: 2,
        isolated_symbolic_requires_non_underscore: true,
        isolated_colon_left_min_len: 20,
        isolated_colon_right_min_len: 16,
        leading_slash_base64_entropy_floor: 4.8,
        keyword_free_operator_margin: None,
        reject_repeated_blocks: true,
        allow_alphabetic_credential: true,
        reject_program_identifiers: true,
        reject_source_symbol_identifiers: true,
        reject_dash_segmented_alnum: true,
    };
    assert!(!passes_secret_strength_checks_with_plausibility_policy(
        repeated, true, policy
    ));
    assert!(passes_secret_strength_checks_with_plausibility_policy(
        repeated,
        true,
        DetectorPlausibilityPolicySpec {
            reject_repeated_blocks: false,
            ..policy
        }
    ));
}

#[test]
fn plausibility_shape_switches_are_detector_owned() {
    use keyhog_core::DetectorPlausibilityPolicySpec;
    use keyhog_scanner::testing::entropy_keywords::passes_secret_strength_checks_with_plausibility_policy as passes;

    let policy = DetectorPlausibilityPolicySpec {
        mixed_alnum_floor: 4.0,
        symbolic_entropy_floor: 3.5,
        second_half_entropy_floor: 2.5,
        mixed_alnum_min_len: 20,
        isolated_mixed_entropy_floor: 3.65,
        isolated_symbolic_min_len: 18,
        isolated_symbolic_min_symbols: 2,
        isolated_symbolic_requires_non_underscore: true,
        isolated_colon_left_min_len: 20,
        isolated_colon_right_min_len: 16,
        leading_slash_base64_entropy_floor: 4.8,
        keyword_free_operator_margin: None,
        reject_repeated_blocks: true,
        allow_alphabetic_credential: true,
        reject_program_identifiers: true,
        reject_source_symbol_identifiers: true,
        reject_dash_segmented_alnum: true,
    };
    let alphabetic = "ufnlbbavawsdeecn";
    assert!(passes(alphabetic, true, policy));
    assert!(!passes(
        alphabetic,
        true,
        DetectorPlausibilityPolicySpec {
            allow_alphabetic_credential: false,
            ..policy
        }
    ));
    assert!(!passes("BulkUpdateApiKeyResponse", true, policy));
    assert!(passes(
        "BulkUpdateApiKeyResponse",
        true,
        DetectorPlausibilityPolicySpec {
            reject_program_identifiers: false,
            ..policy
        }
    ));
    let serial = "A1B2C-D3E4F-G5H6I-J7K8L-M9N0P";
    assert!(!passes(serial, true, policy));
    assert!(passes(
        serial,
        true,
        DetectorPlausibilityPolicySpec {
            reject_dash_segmented_alnum: false,
            ..policy
        }
    ));
}

#[test]
fn dash_segmented_helper_only_pure_dash_alnum() {
    // is_dash_segmented_alnum_decoy contract.
    assert!(is_dash_segmented_alnum_decoy("A1B2C-D3E4F-G5H6I"));
    assert!(!is_dash_segmented_alnum_decoy("Y6NPMwS*rWGUv!JQ")); // symbol, no dash
    assert!(!is_dash_segmented_alnum_decoy("sk-proj-AbC9$xZ")); // dash but `$`
    assert!(!is_dash_segmented_alnum_decoy("nodashvalue1234")); // no dash
    assert!(!is_dash_segmented_alnum_decoy("-leading-dash")); // empty leading group
    assert!(!is_dash_segmented_alnum_decoy("trailing-dash-")); // empty trailing group
}

// ── canonical-non-secret shape (entropy scanner) ─────────────────────

#[test]
fn canonical_non_secret_shapes_classified() {
    // entropy::scanner::is_canonical_non_secret_shape.
    assert!(is_canonical_non_secret_shape(
        "ce7ee1d0-e8b6-4d3f-96b0-be7b0bd7b8ac"
    )); // uuid
    assert!(is_canonical_non_secret_shape(
        "d41d8cd98f00b204e9800998ecf8427e"
    )); // md5 32-hex
    assert!(is_canonical_non_secret_shape(&"a".repeat(64))); // sha256 length hex
    assert!(is_canonical_non_secret_shape("sha512-abc/DEF+12==")); // npm SRI (valid padded base64, len%4==0)
    assert!(is_canonical_non_secret_shape(
        "JQQJN-VBWHG-XBC8R-2MV9F-CD7P9"
    )); // license
}

#[test]
fn real_random_token_is_not_canonical_non_secret() {
    // Negative twin: a 40-char base62 token with mixed case + digits is NOT
    // a canonical non-secret shape (not 32/40/64/128 hex, has letters
    // g-z, not a UUID, not SRI-prefixed, not a 29-char serial).
    assert!(!is_canonical_non_secret_shape(
        "Zx9QmRtbKpLmNoVwXyAbCdEfGhJkMnPqRsTuVwYz"
    ));
}

#[test]
fn candidate_is_plausible_drops_canonical_shapes_under_anchor() {
    // entropy::scanner::candidate_is_plausible: in credential context, a
    // canonical non-secret shape is dropped even though entropy clears the
    // (low) threshold. SHA-1 entropy is high, but the digest shape wins. A
    // 32-hex value is intentionally not used: generic-api-key owns 128-bit
    // key material under `api_key` in its detector TOML.
    let ctx = cred_ctx();
    let sha1 = "356a192b7913b04c54574d18c28d46e6395428ab";
    let ent = keyhog_scanner::entropy::shannon_entropy(sha1.as_bytes());
    assert!(ent >= ctx.threshold, "entropy {ent} must clear threshold");
    assert!(!candidate_is_plausible(sha1, ent, &ctx, &[]));
    // A real random base62 secret of comparable length IS plausible under
    // the anchor (len >= MIN_PASSWORD_LEN(8), not a canonical shape).
    let real = "Zx9QmRtbKpLmNoVwXyAbCd";
    let ent2 = keyhog_scanner::entropy::shannon_entropy(real.as_bytes());
    assert!(candidate_is_plausible(real, ent2, &ctx, &[]));
}

#[test]
fn candidate_below_entropy_threshold_not_plausible() {
    // Boundary: entropy strictly below context.threshold → not plausible
    // regardless of shape. A 8-char all-same string has entropy 0.
    let ctx = cred_ctx();
    assert!(!candidate_is_plausible("aaaaaaaa", 0.0, &ctx, &[]));
}

// ── punctuation-decorated decoys (shape) ─────────────────────────────

#[test]
fn syntactic_punctuation_markers_classified() {
    // shape::looks_like_syntactic_punctuation_marker (Tier-A, universal).
    assert!(looks_like_syntactic_punctuation_marker("--api-secret"));
    assert!(looks_like_syntactic_punctuation_marker("&password"));
    assert!(looks_like_syntactic_punctuation_marker("@api_key"));
    assert!(looks_like_syntactic_punctuation_marker("$API_KEY"));
    assert!(looks_like_syntactic_punctuation_marker("Password:"));
}

#[test]
fn syntactic_marker_does_not_fire_on_real_anchored_secret() {
    // Negative twin: `@gAdtFo%B!tcnSl` starts with `@` but the tail carries
    // credential symbols (%, !), so the pure-identifier-tail requirement
    // fails and it is NOT a syntactic marker. Real secret survives.
    assert!(!looks_like_syntactic_punctuation_marker("@gAdtFo%B!tcnSl"));
    // A single leading `-` (xoxb-style) is allowed, not `--`.
    assert!(!looks_like_syntactic_punctuation_marker("-xoxb-token-123"));
    // 5+ dashes is a PEM marker, not a CLI flag.
    assert!(!looks_like_syntactic_punctuation_marker("-----BEGINKEY"));
}

#[test]
fn credential_colliding_punctuation_is_tier_b_only() {
    // shape::looks_like_credential_colliding_punctuation: leading `/` or `!`.
    assert!(looks_like_credential_colliding_punctuation("/ZM9abcdef"));
    assert!(looks_like_credential_colliding_punctuation("!t1c!_session"));
    // Combined predicate is the union.
    assert!(looks_like_punctuation_decorated_identifier("/ZM9abcdef"));
    assert!(looks_like_punctuation_decorated_identifier("--api-secret"));
}

#[test]
fn slash_led_value_suppressed_generic_but_not_named() {
    // The `/`-led collision is Tier-B (looks_like_credential_colliding_
    // punctuation in api.rs). Generic path suppresses; a strongly-anchored
    // service detector keeps it (the regex already proved it's the body).
    // Use a `/`-led value that is NOT a 2+segment path (single segment) so
    // it isn't also caught by looks_like_url_or_path_segment.
    let v = "/ZM9aQ7bKpLmNoVwXyAb";
    assert!(suppress_named(v, "generic-secret"));
    assert!(!suppress_named(v, "aws-secret-access-key"));
}

// ── standard-base64 random-blob decoy ────────────────────────────────

#[test]
fn standard_base64_protobuf_blob_classified() {
    // shape::looks_like_standard_base64_blob: len in [40,80], standard
    // base64 alphabet, has +/ OR padding OR mult-4 high diversity.
    // 48-char standard base64 with `+`, `/` and `=` padding.
    let blob = "QUJDREVG+2hpamtsbW5vcHFy/3N0dXZ3eHl6MDEyMzQ1Njc=";
    assert_eq!(blob.len(), 48);
    assert!(looks_like_standard_base64_blob(blob));
    // Suppressed on the generic path (Tier-B b64-blob gate).
    assert!(suppress_generic(blob));
}

#[test]
fn base64_blob_outside_length_band_not_classified() {
    // Boundary twin: the gate band is [40, 80]. A 39-char value is BELOW
    // the floor → not a blob; an 84-char value is ABOVE → not a blob.
    let short = "QUJDREVG+2hpamtsbW5vcHFy/3N0dXZ3eHl6MDE"; // 39
    assert_eq!(short.len(), 39);
    assert!(!looks_like_standard_base64_blob(short));
    let long = "A".repeat(84);
    assert!(!looks_like_standard_base64_blob(&long));
}

#[test]
fn url_safe_token_is_not_standard_base64_blob() {
    // Negative twin: a base64URL token (uses `-`/`_`, not `+`/`/`) is NOT a
    // standard-base64 blob, the `-`/`_` bytes fall in the `_ => return false`
    // arm of is_random_base64_blob's alphabet scan.
    let urlsafe = "abcDEF-_ghiJKL012345mnoPQR678-_stuVWX9012abc"; // 44, has -_
    assert!(urlsafe.contains('-') && urlsafe.contains('_'));
    assert!(!looks_like_standard_base64_blob(urlsafe));
}

// ── base64-decode-and-recheck of wrapped decoys ──────────────────────

#[test]
fn base64_wrapped_example_marker_suppressed_via_recheck() {
    // decision step 9: a base64 wrapper that decodes to a known marker is
    // suppressed by the inner re-run. b64("ghp_EXAMPLE_TOKEN_FROM_DOCS").
    let wrapped = "Z2hwX0VYQU1QTEVfVE9LRU5fRlJPTV9ET0NT";
    assert!(suppress_generic(wrapped));
}

#[test]
fn base64_wrapped_iam_arn_suppressed() {
    // Decodes to arn:aws:iam::783664492816:role/ReaderRole. This 56-char
    // padded standard-base64 wrapper is in the [40,80] blob band AND has
    // `=` padding, so the b64-blob gate (step 5f) already suppresses it;
    // the decode-and-recheck (step 9) is the backstop for the IAM-ARN
    // payload. Either way the finding must be suppressed.
    let wrapped = "YXJuOmF3czppYW06Ojc4MzY2NDQ5MjgxNjpyb2xlL1JlYWRlclJvbGU=";
    assert!(suppress_generic(wrapped));
}

// ── PEM hard-bypass: NOT a decoy, must survive every shape gate ──────

#[test]
fn pem_framed_private_key_never_suppressed() {
    // decision: `-----BEGIN` returns false immediately (the frame IS the
    // signal). OPENSSH keys contain AAAA runs that would otherwise trip the
    // identical-run masks (the bypass protects real recall).
    let openssh = "-----BEGIN OPENSSH PRIVATE KEY-----\n\
                   b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAA";
    assert!(!suppress_generic(openssh));
    assert!(!suppress_named(openssh, "private-key"));
}

// ── EXAMPLE exemption for reserved domains in a path-like value ──────

#[test]
fn known_prefix_clean_token_allowed_not_suppressed() {
    // check_markers known-prefix Allow fast-path: a clean ghp_ token whose
    // body is NOT a masked sequence returns Allow (false), so a real GitHub
    // PAT shaped value is never dropped as a decoy.
    assert!(!suppress_generic(
        "ghp_16C7e42F292c6912E7710c838347Ae178B4a"
    ));
    // But a ghp_ token whose body ends in `...` IS a masked sequence.
    assert!(suppress_generic("ghp_1a2b3c4..."));
}

#[test]
fn trailing_ellipsis_body_is_masked_sequence() {
    // shape::looks_like_prefixed_masked_sequence: trailing "..." after
    // a known prefix → masked. sk_live_ + ellipsis.
    assert!(suppress_generic("sk_live_abcd1234..."));
    // Unicode horizontal ellipsis is also caught.
    assert!(suppress_generic("ghp_abcdef…"));
}

// ── Shared placeholder words / TODO / FIXME markers ─────────────────

#[test]
fn universal_placeholder_words_suppressed() {
    // Shared Tier-B placeholder vocabulary (word-boundary token match).
    assert!(suppress_generic("DUMMY_API_KEY_VALUE"));
    assert!(suppress_generic("THIS_IS_A_FAKE_KEY"));
    assert!(suppress_generic("MOCK_TOKEN_FOR_TESTS"));
    assert!(suppress_generic("SAMPLE_SECRET_VALUE"));
    assert!(suppress_generic("REAL_PLACEHOLDER_TOKEN"));
    assert!(suppress_generic("PLEASE_CHANGEME_NOW"));
}

#[test]
fn developer_markers_override_prefix_trust() {
    // check_markers: TODO / FIXME tokens suppress even on prefixed tokens.
    assert!(suppress_generic("ghp_TODO_real_token_here"));
    assert!(suppress_generic("api FIXME insert key"));
}

// ── property-style sweep: a decoy corpus must yield zero admits ──────

#[test]
fn decoy_corpus_property_all_suppressed_generic() {
    // Differential / property sweep: a hand-built corpus of decoy twins for
    // the major shape families. EVERY entry must be suppressed by the
    // generic entry point. Each entry is annotated with the gate that fires.
    let decoys: &[&str] = &[
        "YOUR_API_KEY_HERE",                         // instructional fragment
        "REPLACE_WITH_TOKEN",                        // REPLACE fragment
        "AKIAIOSFODNN7EXAMPLE",                      // EXAMPLE suffix
        "ghp_EXAMPLE_TOKEN_FROM_DOCS",               // buried EXAMPLE marker
        "DUMMY_SECRET_VALUE",                        // DUMMY word
        "MOCK_API_TOKEN_HERE",                       // MOCK word
        "password_XXXXXXX",                          // XXXXX mask
        "xxxxxxxxxxxxxxxxxxxx",                      // x-dominated
        "0000000000000000",                          // zero-filled <20
        "aaaaaaaaaaaaaaaaaaaaaaaa",                  // identical run >=20
        "0123456789abcdef0123456789abcdef",          // monotonic hex
        "ab1234567890",                              // dominant fake seq
        "d41d8cd98f00b204e9800998ecf8427e",          // md5 hex
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",  // sha1 hex
        "ce7ee1d0-e8b6-4d3f-96b0-be7b0bd7b8ac",      // uuid
        "JQQJN-VBWHG-XBC8R-2MV9F-CD7P9",             // license serial
        "{{api_key}}",                               // template
        "<your-token-here>",                         // angle template
        "${SECRET_TOKEN}",                           // ${} template
        "#a1b2c3",                                   // html color
        "arn:aws:iam::783664492816:role/ReaderRole", // IAM ARN
        "****************",                          // filler symbols
        "----------------",                          // dash filler
    ];
    let leaked: Vec<&&str> = decoys.iter().filter(|d| !suppress_generic(d)).collect();
    assert!(
        leaked.is_empty(),
        "these decoys leaked (were not suppressed): {leaked:?}"
    );
    assert_eq!(decoys.len(), 23, "corpus size guard");
}

#[test]
fn real_credential_corpus_property_none_suppressed() {
    // Negative-twin sweep: real-credential shapes for the same families must
    // NOT be suppressed by the generic entry point. A test that always
    // returns true would fail this whole block.
    let reals: &[&str] = &[
        "ghp_16C7e42F292c6912E7710c838347Ae178B4a", // real GitHub PAT shape
        "sk_live_4eC39HqLyjWDarjtT1zdp7dc",         // Stripe live key
        "Qz1234567890RtbKpLmNoVwXyAbCdEfGhJkMnPq", // 39-char, seq as small substring, not a b64 blob (len%4!=0, no pad)
        "aB1cD2eF3aB4cD5eF6aB7cD8eF9aB0cD",        // mixed-case hex (not digest)
        "P@ssw0rd!#Zx9Qm7",                        // rich-symbol password
    ];
    let dropped: Vec<&&str> = reals.iter().filter(|r| suppress_generic(r)).collect();
    assert!(
        dropped.is_empty(),
        "these real credentials were wrongly suppressed: {dropped:?}"
    );
}

// ── Property tier ────────────────────────────────────────────────────────────
// The fixed vectors pin `is_dash_segmented_alnum_decoy` and
// `looks_like_standard_base64_blob` at a handful of literals; these SWEEP the two
// leaf predicates over their structural domains. Both invariants are traced to
// source (no arithmetic mirror):
//
//  * `is_dash_segmented_alnum_decoy` (suppression/shape/canonical.rs:590): reject
//    if no `-`, if any byte is not alnum-or-`-`, or if any dash group is empty;
//    then `group_count >= 3 && all_len5_upperdigit` is a DETERMINISTIC accept
//    (the 5×N serial family, it never consults token randomness), while the
//    all-alpha branch does. So a `>=3` run of exactly-5 `[A-Z0-9]` groups is
//    ALWAYS a decoy, a `<3`-group value never is, and any injected symbol /
//    empty group / missing dash disqualifies unconditionally, all randomness-
//    independent, so no flake.
//  * `looks_like_standard_base64_blob` == `is_random_base64_blob(v, 40, 80, 32)`
//    (decode_structure.rs:148): length outside [40,80] returns false BEFORE any
//    shape parse (a content-independent universal); and an in-band, mult-of-4,
//    standard-alphabet body carrying a `+` hits the `has_plus` admit (standard_
//    base64_shape returns Some: no urlsafe byte, remainder 0) → always a blob.
// No proptest before.

use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    /// >=3 groups of exactly-5 `[A-Z0-9]` chars joined by `-` ALWAYS hit the
    /// deterministic branch-5 serial admit (independent of token randomness).
    #[test]
    fn five_by_n_upper_digit_serial_is_dash_decoy(
        groups in prop::collection::vec("[A-Z0-9]{5}", 3..=8),
    ) {
        let value = groups.join("-");
        prop_assert!(
            is_dash_segmented_alnum_decoy(&value),
            "{value:?} is a >=3-group 5x5 upper/digit serial"
        );
    }

    /// Fewer than 3 groups can never be a dash-decoy: both accept branches
    /// require `group_count >= 3` (a 1-group value has no dash at all → the
    /// first guard rejects it; a 2-group value fails the count).
    #[test]
    fn under_three_serial_groups_is_not_dash_decoy(
        groups in prop::collection::vec("[A-Z0-9]{5}", 1..=2),
    ) {
        let value = groups.join("-");
        prop_assert!(!is_dash_segmented_alnum_decoy(&value));
    }

    /// A single injected non-alnum, non-dash byte trips the charset gate, so an
    /// otherwise-perfect serial is never a dash-decoy.
    #[test]
    fn any_symbol_byte_disqualifies_dash_decoy(
        groups in prop::collection::vec("[A-Z0-9]{5}", 3..=6),
        sym in prop::sample::select(vec!['$', '*', '.', '_', '/', '!', '@', '%']),
        pos in 0usize..17,
    ) {
        let mut value = groups.join("-");
        let at = pos % value.len(); // all-ASCII ⇒ every byte index is a boundary
        value.insert(at, sym);
        prop_assert!(
            !is_dash_segmented_alnum_decoy(&value),
            "{value:?} carries a non-alnum, non-dash byte"
        );
    }

    /// An empty dash group (leading / trailing / doubled dash) fails the
    /// non-empty-group gate even around a perfect serial.
    #[test]
    fn empty_dash_group_disqualifies(
        groups in prop::collection::vec("[A-Z0-9]{5}", 3..=6),
        variant in 0u8..3,
    ) {
        let core = groups.join("-");
        let value = match variant {
            0 => format!("-{core}"),           // leading empty group
            1 => format!("{core}-"),           // trailing empty group
            _ => core.replacen('-', "--", 1),  // doubled dash → empty middle group
        };
        prop_assert!(!is_dash_segmented_alnum_decoy(&value));
    }

    /// No `-` at all → rejected by the first guard, for any alnum body.
    #[test]
    fn no_dash_is_not_dash_decoy(body in "[A-Za-z0-9]{1,40}") {
        prop_assert!(!is_dash_segmented_alnum_decoy(&body));
    }

    /// In-band (mult-of-4, len∈[40,80]), standard-alphabet body carrying a `+`
    /// hits the `has_plus` admit → always a standard-base64 blob.
    #[test]
    fn in_band_plus_bearing_body_is_base64_blob(
        n in prop::sample::select(vec![40usize, 44, 48, 52, 56, 60, 64, 68, 72, 76, 80]),
        body in "[A-Za-z0-9]{120}",
        plus_at in 0usize..40,
    ) {
        // Take n-1 standard-alphabet chars (no `-`/`_`/`=`), then insert one `+`
        // ⇒ length n (mult-of-4, in band), has_plus, no urlsafe byte, no padding.
        let mut v: String = body.chars().take(n - 1).collect();
        let at = plus_at % v.len();
        v.insert(at, '+');
        prop_assert_eq!(v.len(), n);
        prop_assert!(
            looks_like_standard_base64_blob(&v),
            "{v:?} (len {n}, has +) must classify as a standard-base64 blob"
        );
    }

    /// A value shorter than the 40-char floor is never a blob, the length band
    /// is checked before any shape parse, so this holds for any content.
    #[test]
    fn below_floor_is_never_base64_blob(v in "[A-Za-z0-9+/]{0,39}") {
        prop_assert!(!looks_like_standard_base64_blob(&v));
    }

    /// A value longer than the 80-char ceiling is never a blob (same universal
    /// band guard).
    #[test]
    fn above_ceiling_is_never_base64_blob(v in "[A-Za-z0-9+/]{81,140}") {
        prop_assert!(!looks_like_standard_base64_blob(&v));
    }
}

// ── Property tier: is_random_token fail-safe floors ──────────────────────────
// `is_random_token` (suppression/token_randomness.rs. CLEAN source) is the
// randomness discriminator that LIFTS the identifier-suppression gate: a false
// `true` verdict recovers a code reference (`password = getUserName`) as a
// credential (an FP). Its soundness rests on three fail-safe floors, each
// provable from source WITHOUT re-implementing the English-bigram model, a value
// is NEVER classified random when any floor is unmet, so the gate keeps
// suppressing (precision-safe, "soundness over reach"):
//   * < MIN_ALPHA(6) alphabetic chars   → mean_bigram_logprob None → false (:106)
//   * pairs == 0 (no adjacent letters)  → mean_bigram_logprob None → false (:106)
//   * < MIN_DISTINCT_LETTERS(3) letters → false regardless of bigram score (:131)
// We deliberately do NOT sweep the reverse "random letters ⇒ random" (that IS
// model-dependent, a random `[a-z]` run may read as pronounceable); only the
// guaranteed fail-safe direction, which is the load-bearing safety contract.
// No proptest for this predicate before.

#[cfg(feature = "entropy")]
mod random_token_floor_tests {
    use super::*;
    use keyhog_scanner::testing::entropy_isolated::is_random_token;

    proptest! {
            #![proptest_config(ProptestConfig::with_cases(2_000))]

        /// Fewer than 6 alphabetic chars ⇒ the bigram statistic is None ⇒ never
        /// random, for any digit padding around the (≤5) letters.
        #[test]
        fn under_min_alpha_is_never_random(
            letters in "[a-z]{0,5}",
            pad in "[0-9]{0,20}",
        ) {
            let value = format!("{pad}{letters}{pad}"); // total letters == letters.len() ≤ 5
            prop_assert!(!is_random_token(&value), "{value:?} has <6 alphabetic chars");
        }

        /// Letters never adjacent (each separated by a digit) ⇒ pairs==0 ⇒ None ⇒
        /// never random, even with many (>=6) alphabetic chars total.
        #[test]
        fn no_adjacent_letter_pair_is_never_random(
            letters in prop::collection::vec("[a-z]", 6..=20),
        ) {
            let value = letters.join("7"); // single letters glued by a digit
            prop_assert!(!is_random_token(&value), "{value:?} has no adjacent letter pair");
        }

        /// Fewer than 3 distinct letters ⇒ never random regardless of length or
        /// bigram improbability (a repetitive / alternating MASK, not a random token).
        #[test]
        fn under_min_distinct_letters_is_never_random(
            a in "[a-z]",
            b in "[a-z]",
            reps in 4usize..40,
        ) {
            let one = a.repeat(reps); // 1 distinct letter
            prop_assert!(!is_random_token(&one), "{one:?} has 1 distinct letter");
            let alt = format!("{a}{b}").repeat(reps); // ≤2 distinct letters
            prop_assert!(!is_random_token(&alt), "{alt:?} has ≤2 distinct letters");
        }
    }
}

// ── Property tier: looks_like_english_prose structural floors ─────────────────
// `looks_like_english_prose` (suppression/shape/prose.rs), used to drop prose
// captured under a weak anchor. Contract from source: len<16 → false; else an
// ALL-lowercase run → true (branch 1); else `split_whitespace` needs >=2 all-
// alphabetic tokens with a >=3-char lowercase word (branch 2). A WHITESPACE-FREE
// value is a single token, so branch 2 (count>=2) can never fire ⇒ a single
// token is prose IFF it is all-lowercase AND >=16 bytes. All three below encode
// that characterization directly, no heuristic mirror. No proptest before.

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    /// Anything under the 16-byte floor is never prose, for any printable content.
    #[test]
    fn below_16_bytes_is_never_prose(v in "[ -~]{0,15}") {
        prop_assert!(!looks_like_english_prose(&v));
    }

    /// An all-lowercase run of >=16 bytes is always prose (branch 1).
    #[test]
    fn all_lowercase_16plus_is_prose(v in "[a-z]{16,60}") {
        prop_assert!(looks_like_english_prose(&v));
    }

    /// A single (whitespace-free) token carrying any uppercase or digit is never
    /// prose: branch 1 needs all-lowercase, and branch 2 needs >=2 tokens which a
    /// whitespace-free value can never have.
    #[test]
    fn whitespace_free_non_lowercase_token_is_not_prose(
        lead in "[a-z]{8,20}",
        marker in "[A-Z0-9]",
        tail in "[a-z]{8,20}",
    ) {
        let v = format!("{lead}{marker}{tail}"); // >=17 bytes, no whitespace, not all-lowercase
        prop_assert!(!looks_like_english_prose(&v), "{v:?} is a single non-lowercase token");
    }
}

// ── Property tier: is_canonical_non_secret_shape hex-digest band ──────────────
// `is_canonical_non_secret_shape` (entropy/scanner.rs → suppression/shape/
// canonical.rs) = uuid OR canonical-hex-digest OR SRI-integrity OR 5x5-serial.
// The hex-digest branch is crisp: `matches!(len, 32|40|64|128) && all
// ascii_hexdigit`. So a hex string (mixed case ok) of a canonical digest length
// is always a canonical non-secret shape (md5/sha1/sha256/sha512 lengths), and a
// hex string of a NON-canonical length carrying no dash/sha-prefix hits none of
// the four branches. Derived from source. No proptest for this predicate before.

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    /// A hex string (mixed case ok) of a canonical digest length (32/40/64/128)
    /// is always a canonical non-secret shape.
    #[test]
    fn canonical_length_hex_is_non_secret_shape(
        len in prop::sample::select(vec![32usize, 40, 64, 128]),
        seed in "[0-9a-fA-F]{128}",
    ) {
        let v: String = seed.chars().take(len).collect();
        prop_assert_eq!(v.len(), len);
        prop_assert!(is_canonical_non_secret_shape(&v), "{v:?} (hex len {len})");
    }

    /// A hex string shorter than the smallest canonical digest length (32), and
    /// carrying no dash / sha-prefix (hits none of the four canonical branches).
    #[test]
    fn sub_canonical_hex_is_not_non_secret_shape(v in "[0-9a-f]{16,31}") {
        prop_assert!(!is_canonical_non_secret_shape(&v), "{v:?} is sub-canonical hex");
    }
}

// ── Property tier: looks_like_credential_colliding_punctuation lead gate ──────
// `looks_like_credential_colliding_punctuation` (suppression/shape/mod.rs:530):
// empty → false; first byte `!` or `/` → true; else a TS non-null identifier
// (ends with `!`, len>=9, alnum/`_` body). So ANY non-empty value whose first
// byte is `!` or `/` is colliding punctuation, and a value that neither leads
// with `!`/`/` nor ends with `!` cannot be. Derived from source. No proptest
// for this predicate before.

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    /// Any non-empty value whose first byte is `!` or `/` is colliding punctuation,
    /// for any tail (the lead-byte check short-circuits before the identifier arm).
    #[test]
    fn leading_bang_or_slash_is_colliding_punctuation(
        lead in prop::sample::select(vec!['!', '/']),
        tail in "[ -~]{0,30}",
    ) {
        let v = format!("{lead}{tail}");
        prop_assert!(
            looks_like_credential_colliding_punctuation(&v),
            "{v:?} leads with {lead}"
        );
    }

    /// A value that neither leads with `!`/`/` nor ends with `!` is never colliding
    /// punctuation (the TS-non-null arm requires a trailing `!`).
    #[test]
    fn no_lead_punct_no_trailing_bang_is_not_colliding(v in "[a-z][a-z0-9_]{4,20}") {
        prop_assert!(!looks_like_credential_colliding_punctuation(&v), "{v:?}");
    }
}

// ── Property tier: looks_like_syntactic_punctuation_marker sigil/flag arms ────
// `looks_like_syntactic_punctuation_marker` (suppression/shape/mod.rs:468): a
// leading `&`/`@`/`$`/`*` followed by a PURE-identifier tail (alnum/`_`) is a
// grammar marker (C ptr / attribute / shell var / deref), and a `--X` with
// X != `-` is a CLI flag. Both are early short-circuit accepts, so these
// positive characterizations hold regardless of the predicate's later arms.
// Derived from source. No proptest for this predicate before.

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    /// A leading `&`/`@`/`$`/`*` with a pure-identifier tail is a syntactic marker.
    #[test]
    fn sigil_prefixed_pure_identifier_is_marker(
        sigil in prop::sample::select(vec!['&', '@', '$', '*']),
        ident in "[A-Za-z0-9_]{1,20}",
    ) {
        let v = format!("{sigil}{ident}");
        prop_assert!(looks_like_syntactic_punctuation_marker(&v), "{v:?}");
    }

    /// A `--X` CLI-flag shape (X not another dash) is a syntactic marker.
    #[test]
    fn double_dash_flag_is_marker(rest in "[A-Za-z0-9_][A-Za-z0-9_-]{1,18}") {
        let v = format!("--{rest}");
        prop_assert!(looks_like_syntactic_punctuation_marker(&v), "{v:?}");
    }
}

// ── Property tier: strength gate ⇔ dash-segmented decoy (cross-predicate) ─────
// The fixed vectors reject a few specific 5×5 serials in both contexts; this
// SWEEPS the whole 5×N upper/digit serial family and COUPLES two predicates:
// `passes_secret_strength_checks` routes through `is_dash_segmented_alnum_decoy`
// (entropy/keywords.rs), so a value that is a dash-segmented decoy is rejected
// by the strength gate REGARDLESS of credential context. A drift that let a 5×N
// serial pass the strength gate (recall→FP) would break this coupling. No
// proptest for this pairing before.

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1_000))]

    /// A >=5-group 5×5 upper/digit serial is a dash-segmented decoy AND is
    /// rejected by the strength gate in BOTH credential and non-credential context.
    #[test]
    fn dash_segmented_serial_fails_strength_in_both_contexts(
        groups in prop::collection::vec("[A-Z0-9]{5}", 5..=8),
    ) {
        let v = groups.join("-");
        prop_assert!(is_dash_segmented_alnum_decoy(&v), "{v:?} should be a dash decoy");
        prop_assert!(!passes_secret_strength_checks(&v, true), "{v:?} in cred ctx");
        prop_assert!(!passes_secret_strength_checks(&v, false), "{v:?} no anchor");
    }
}
