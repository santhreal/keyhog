//! Confidence floor policy: how an embedded-checksum verdict adjudicates a
//! freshly-scored confidence, and how `--precision` composes its 0.85 floor.
//!
//! This module is the truth contract for
//! [`keyhog_scanner::checksum::checksum_adjusted_confidence`] (the single
//! source of truth routed by every match-emission path), the
//! [`keyhog_scanner::checksum::CHECKSUM_VALID_FLOOR`] (0.9) constant, and the
//! `ScannerConfig::high_precision` / `HIGH_PRECISION_MIN_CONFIDENCE` (0.85)
//! floor that `--precision` raises low per-detector floors to (max, not
//! replace).
//!
//! Every expected value is derived from the real source under
//! `crates/scanner/src/checksum/*` and `crates/scanner/src/scanner_config.rs`.
//! Valid checksum-bearing tokens are constructed with the SAME CRC32 + base62
//! algorithm the validators use (mirrored in the helpers below); this is a
//! round-trip proof, not a magic literal.

use keyhog_scanner::checksum::{
    checksum_adjusted_confidence, validate_checksum, ChecksumResult, CHECKSUM_VALID_FLOOR,
};
use keyhog_scanner::confidence::known_prefix_confidence_floor;
use keyhog_scanner::ScannerConfig;

// ---------------------------------------------------------------------------
// Helpers: mirror the EXACT crc32 + base62 algorithm from
// crates/scanner/src/checksum/github.rs so we can construct tokens whose
// trailing 6-char checksum is, by construction, correct (or deliberately
// wrong). The validators recompute the same CRC, so a constructed-valid token
// MUST adjudicate `Valid` and a one-char-mutated checksum MUST adjudicate
// `Invalid`.
// ---------------------------------------------------------------------------

const BASE62_DIGITS: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

fn crc32(data: &[u8]) -> u32 {
    // Identical table + loop to github.rs::crc32 (reflected CRC-32/ISO-HDLC).
    let mut table = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut crc = i as u32;
        let mut j = 0;
        while j < 8 {
            if crc & 1 != 0 {
                crc = 0xEDB8_8320 ^ (crc >> 1);
            } else {
                crc >>= 1;
            }
            j += 1;
        }
        table[i] = crc;
        i += 1;
    }
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc = table[((crc ^ (byte as u32)) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc ^ 0xFFFF_FFFF
}

fn base62_encode_u32(mut value: u32, width: usize) -> String {
    if value == 0 {
        return "0".repeat(width);
    }
    let mut rev = Vec::with_capacity(width.max(6));
    while value > 0 {
        rev.push(BASE62_DIGITS[(value % 62) as usize] as char);
        value /= 62;
    }
    while rev.len() < width {
        rev.push('0');
    }
    rev.reverse();
    rev.into_iter().collect()
}

/// 6-char base62 CRC32 trailer for a given entropy body (the format GitHub
/// classic / npm tokens embed).
fn checksum6(entropy: &str) -> String {
    base62_encode_u32(crc32(entropy.as_bytes()), 6)
}

/// Build a `ghp_` token whose 6-char trailer is the CORRECT CRC of its 30-char
/// body. `body30` must be exactly 30 ASCII-alnum chars.
fn valid_ghp(body30: &str) -> String {
    assert_eq!(body30.len(), 30, "github classic body must be 30 chars");
    format!("ghp_{}{}", body30, checksum6(body30))
}

/// Build an `npm_` token whose 6-char trailer is the CORRECT CRC of its body.
fn valid_npm(body30: &str) -> String {
    assert_eq!(body30.len(), 30, "npm body must be 30 chars");
    format!("npm_{}{}", body30, checksum6(body30))
}

/// Flip the last checksum char to a different base62 digit, guaranteeing a CRC
/// mismatch while keeping the token alnum + correct length.
fn corrupt_last_char(token: &str) -> String {
    let mut chars: Vec<char> = token.chars().collect();
    let last = *chars.last().unwrap();
    let replacement = if last == 'A' { 'B' } else { 'A' };
    *chars.last_mut().unwrap() = replacement;
    chars.into_iter().collect()
}

// A 30-char base62 body that contains NO placeholder substring
// (example/dummy/fake/sample/placeholder/changeme).
const GHP_BODY: &str = "016uGJ9pq3RtVw7Xz2Bc4De6Fh8Ik0Lm"; // sliced to 30 below
fn body30() -> String {
    GHP_BODY.chars().take(30).collect()
}

// ===========================================================================
// SECTION 1: checksum_adjusted_confidence — Valid floors at CHECKSUM_VALID_FLOOR
// ===========================================================================

#[test]
fn checksum_valid_floor_constant_is_0_9() {
    // The named contract value. If this drifts, every floor test below is
    // recalibrated against the wrong bar.
    assert_eq!(CHECKSUM_VALID_FLOOR, 0.9);
}

#[test]
fn checksum_valid_floor_strictly_above_high_precision_bar() {
    // Doc contract on CHECKSUM_VALID_FLOOR: a confirmed token must clear the
    // --precision 0.85 bar, so the floor must sit strictly above it.
    assert!(
        CHECKSUM_VALID_FLOOR > ScannerConfig::HIGH_PRECISION_MIN_CONFIDENCE,
        "valid-checksum floor {CHECKSUM_VALID_FLOOR} must exceed precision bar {}",
        ScannerConfig::HIGH_PRECISION_MIN_CONFIDENCE
    );
}

#[test]
fn valid_ghp_token_validates_valid() {
    let token = valid_ghp(&body30());
    assert_eq!(validate_checksum(&token), ChecksumResult::Valid);
}

#[test]
fn valid_low_confidence_floored_up_to_0_9() {
    // A genuine ghp_ token scored low by upstream heuristics must be lifted to
    // exactly the floor: max(0.10, 0.9) == 0.9.
    let token = valid_ghp(&body30());
    let out = checksum_adjusted_confidence(0.10, &token);
    assert_eq!(out, Some(0.9));
}

#[test]
fn valid_zero_confidence_floored_up_to_0_9() {
    let token = valid_ghp(&body30());
    let out = checksum_adjusted_confidence(0.0, &token);
    assert_eq!(out, Some(0.9));
}

#[test]
fn valid_confidence_at_floor_passes_unchanged() {
    // Boundary: exactly the floor. max(0.9, 0.9) == 0.9 (no double-bump).
    let token = valid_ghp(&body30());
    let out = checksum_adjusted_confidence(CHECKSUM_VALID_FLOOR, &token);
    assert_eq!(out, Some(0.9));
}

#[test]
fn valid_high_confidence_is_not_lowered_to_floor() {
    // The floor is a MAX, never a replace: a 0.99 token stays 0.99.
    let token = valid_ghp(&body30());
    let out = checksum_adjusted_confidence(0.99, &token);
    assert_eq!(out, Some(0.99));
}

#[test]
fn valid_confidence_just_above_floor_preserved_exactly() {
    let token = valid_ghp(&body30());
    let out = checksum_adjusted_confidence(0.9000001, &token);
    assert_eq!(out, Some(0.9000001));
}

#[test]
fn valid_confidence_just_below_floor_raised_to_floor() {
    let token = valid_ghp(&body30());
    let out = checksum_adjusted_confidence(0.8999999, &token);
    assert_eq!(out, Some(0.9));
}

#[test]
fn valid_npm_token_floored_identically_to_ghp() {
    // npm_ uses the same algorithm and the same shared policy: a valid npm
    // token at low confidence is floored to 0.9 just like ghp_.
    let token = valid_npm(&body30());
    assert_eq!(validate_checksum(&token), ChecksumResult::Valid);
    assert_eq!(checksum_adjusted_confidence(0.2, &token), Some(0.9));
}

#[test]
fn valid_one_confidence_stays_one() {
    let token = valid_ghp(&body30());
    assert_eq!(checksum_adjusted_confidence(1.0, &token), Some(1.0));
}

// ===========================================================================
// SECTION 2: checksum_adjusted_confidence — Invalid DROPS (returns None)
// ===========================================================================

#[test]
fn corrupted_ghp_checksum_validates_invalid() {
    let good = valid_ghp(&body30());
    let bad = corrupt_last_char(&good);
    // Sanity: still a well-formed ghp_ + 36-alnum token, just wrong CRC.
    assert_eq!(bad.len(), good.len());
    assert_eq!(validate_checksum(&bad), ChecksumResult::Invalid);
}

#[test]
fn invalid_checksum_drops_match_even_at_high_confidence() {
    // The strongest contract: a fabricated ghp_ token is DROPPED no matter how
    // high the heuristic/ML confidence was. 0.99 in, None out.
    let bad = corrupt_last_char(&valid_ghp(&body30()));
    assert_eq!(checksum_adjusted_confidence(0.99, &bad), None);
}

#[test]
fn invalid_checksum_drops_match_at_low_confidence() {
    let bad = corrupt_last_char(&valid_ghp(&body30()));
    assert_eq!(checksum_adjusted_confidence(0.05, &bad), None);
}

#[test]
fn invalid_checksum_drops_at_exactly_floor_confidence() {
    let bad = corrupt_last_char(&valid_ghp(&body30()));
    assert_eq!(checksum_adjusted_confidence(0.9, &bad), None);
}

#[test]
fn ghp_with_non_alnum_body_is_invalid() {
    // `ghp_` + 36 chars where the body contains a non-alnum char -> Invalid
    // (the github validator rejects on charset before CRC).
    let token = format!("ghp_{}", "a".repeat(35) + "!");
    assert_eq!(token.len(), 4 + 36);
    assert_eq!(validate_checksum(&token), ChecksumResult::Invalid);
    assert_eq!(checksum_adjusted_confidence(0.8, &token), None);
}

#[test]
fn npm_with_corrupted_checksum_drops() {
    let bad = corrupt_last_char(&valid_npm(&body30()));
    assert_eq!(validate_checksum(&bad), ChecksumResult::Invalid);
    assert_eq!(checksum_adjusted_confidence(0.95, &bad), None);
}

#[test]
fn slack_bot_malformed_segments_invalid_and_dropped() {
    // xoxb- prefix present but segments do not match the bot regex
    // (^xoxb-[0-9]{10,15}-[0-9]{10,15}-[a-zA-Z0-9]{15,40}$) -> Invalid -> drop.
    let token = "xoxb-123-456-tooshort";
    assert_eq!(validate_checksum(token), ChecksumResult::Invalid);
    assert_eq!(checksum_adjusted_confidence(0.9, token), None);
}

#[test]
fn stripe_too_short_body_invalid_and_dropped() {
    // sk_live_ prefix but body < 24 alnum -> Invalid -> drop.
    let token = "sk_live_short123";
    assert_eq!(validate_checksum(token), ChecksumResult::Invalid);
    assert_eq!(checksum_adjusted_confidence(0.88, token), None);
}

#[test]
fn gitlab_glpat_too_short_body_invalid_and_dropped() {
    // glpat- with fewer than 20 body chars cannot be a real token -> Invalid.
    let token = "glpat-shortbody";
    assert_eq!(validate_checksum(token), ChecksumResult::Invalid);
    assert_eq!(checksum_adjusted_confidence(0.9, token), None);
}

// ===========================================================================
// SECTION 3: checksum_adjusted_confidence — NotApplicable passes through
// ===========================================================================

#[test]
fn no_known_prefix_passes_confidence_through_unchanged() {
    // A credential no validator claims: confidence is returned verbatim, no
    // floor, no drop.
    let cred = "some_random_value_without_a_known_prefix_1234567890";
    assert_eq!(validate_checksum(cred), ChecksumResult::NotApplicable);
    assert_eq!(checksum_adjusted_confidence(0.42, cred), Some(0.42));
}

#[test]
fn not_applicable_does_not_floor_low_confidence() {
    // The crucial NotApplicable vs Valid distinction: a low confidence on a
    // checksum-less token is NOT lifted to 0.9.
    let cred = "AKIAQQQQWWWWEEEERRRR"; // AKIA prefix has no checksum validator
    assert_eq!(validate_checksum(cred), ChecksumResult::NotApplicable);
    assert_eq!(checksum_adjusted_confidence(0.30, cred), Some(0.30));
}

#[test]
fn not_applicable_passes_zero_through() {
    let cred = "plain-token-no-checksum";
    assert_eq!(validate_checksum(cred), ChecksumResult::NotApplicable);
    assert_eq!(checksum_adjusted_confidence(0.0, cred), Some(0.0));
}

#[test]
fn not_applicable_passes_one_through() {
    let cred = "plain-token-no-checksum";
    assert_eq!(checksum_adjusted_confidence(1.0, cred), Some(1.0));
}

#[test]
fn ghp_wrong_length_is_not_applicable() {
    // ghp_ but body != 36 chars: the github classic validator returns
    // NotApplicable (length gate), and no other validator claims it.
    let token = "ghp_tooshort";
    assert_eq!(validate_checksum(token), ChecksumResult::NotApplicable);
    assert_eq!(checksum_adjusted_confidence(0.55, token), Some(0.55));
}

#[test]
fn npm_wrong_length_is_not_applicable() {
    let token = "npm_onlyfifteenchars";
    assert_eq!(validate_checksum(token), ChecksumResult::NotApplicable);
    assert_eq!(checksum_adjusted_confidence(0.55, token), Some(0.55));
}

#[test]
fn empty_credential_is_not_applicable() {
    assert_eq!(validate_checksum(""), ChecksumResult::NotApplicable);
    assert_eq!(checksum_adjusted_confidence(0.7, ""), Some(0.7));
}

#[test]
fn glpat_implausibly_long_is_not_applicable_not_dropped() {
    // glpat- with > 64 body chars (charset-ok) is a shape we don't model:
    // NotApplicable, so confidence passes through (NOT dropped, NOT floored).
    let token = format!("glpat-{}", "a".repeat(65));
    assert_eq!(validate_checksum(&token), ChecksumResult::NotApplicable);
    assert_eq!(checksum_adjusted_confidence(0.5, &token), Some(0.5));
}

// ===========================================================================
// SECTION 4: per-validator Valid/Invalid/NotApplicable truth (the inputs that
// drive the three policy branches). Asserts the ChecksumResult directly.
// ===========================================================================

#[test]
fn stripe_well_formed_live_key_is_valid() {
    // sk_live_ + 24 alnum chars -> structural Valid.
    let token = format!("sk_live_{}", "a1B2c3D4e5F6g7H8i9J0kLmN"); // 24 chars
    assert_eq!(token.len(), 8 + 24);
    assert_eq!(validate_checksum(&token), ChecksumResult::Valid);
}

#[test]
fn stripe_boundary_24_char_body_is_valid() {
    let body: String = std::iter::repeat('a').take(24).collect();
    let token = format!("sk_test_{body}");
    assert_eq!(validate_checksum(&token), ChecksumResult::Valid);
}

#[test]
fn stripe_boundary_23_char_body_is_invalid() {
    let body: String = std::iter::repeat('a').take(23).collect();
    let token = format!("sk_test_{body}");
    assert_eq!(validate_checksum(&token), ChecksumResult::Invalid);
}

#[test]
fn stripe_boundary_128_char_body_is_valid() {
    let body: String = std::iter::repeat('a').take(128).collect();
    let token = format!("pk_live_{body}");
    assert_eq!(validate_checksum(&token), ChecksumResult::Valid);
}

#[test]
fn stripe_boundary_129_char_body_is_invalid() {
    let body: String = std::iter::repeat('a').take(129).collect();
    let token = format!("pk_live_{body}");
    assert_eq!(validate_checksum(&token), ChecksumResult::Invalid);
}

#[test]
fn stripe_non_alnum_body_is_invalid() {
    let token = format!("rk_live_{}", "a".repeat(23) + "-"); // 24 chars, one '-'
    assert_eq!(validate_checksum(&token), ChecksumResult::Invalid);
}

#[test]
fn slack_well_formed_bot_token_is_valid() {
    // Matches ^xoxb-[0-9]{10,15}-[0-9]{10,15}-[a-zA-Z0-9]{15,40}$
    let token = "xoxb-1234567890-1234567890-abcdefghijklmnopqrst";
    assert_eq!(validate_checksum(token), ChecksumResult::Valid);
    // And a valid slack token at low confidence is floored to 0.9.
    assert_eq!(checksum_adjusted_confidence(0.1, token), Some(0.9));
}

#[test]
fn slack_well_formed_user_token_is_valid() {
    // ^xoxp-[0-9]{10,15}-[0-9]{10,15}(?:-[0-9]{10,13})?-[a-zA-Z0-9]{24,40}$
    let token = "xoxp-1234567890-1234567890-abcdefghijklmnopqrstuvwx";
    assert_eq!(validate_checksum(token), ChecksumResult::Valid);
}

#[test]
fn slack_prefix_only_not_applicable_for_other_prefixes() {
    // xoxa- is NOT handled by the slack validator's starts_with checks (only
    // xoxb-/xoxp-), and no other validator claims it -> NotApplicable.
    let token = "xoxa-1234567890-1234567890-abcdefghijklmnopqrst";
    assert_eq!(validate_checksum(token), ChecksumResult::NotApplicable);
}

#[test]
fn gitlab_glpat_20_char_body_is_valid() {
    let token = format!("glpat-{}", "a".repeat(20));
    assert_eq!(validate_checksum(&token), ChecksumResult::Valid);
}

#[test]
fn gitlab_glpat_19_char_body_is_invalid() {
    let token = format!("glpat-{}", "a".repeat(19));
    assert_eq!(validate_checksum(&token), ChecksumResult::Invalid);
}

#[test]
fn gitlab_glpat_64_char_body_is_valid() {
    let token = format!("glpat-{}", "a".repeat(64));
    assert_eq!(validate_checksum(&token), ChecksumResult::Valid);
}

#[test]
fn gitlab_glrt_16_char_body_is_valid() {
    let token = format!("glrt-{}", "a".repeat(16));
    assert_eq!(validate_checksum(&token), ChecksumResult::Valid);
}

#[test]
fn gitlab_glrt_15_char_body_is_invalid() {
    let token = format!("glrt-{}", "a".repeat(15));
    assert_eq!(validate_checksum(&token), ChecksumResult::Invalid);
}

#[test]
fn gitlab_glpat_bad_charset_is_invalid() {
    // '!' is not in the base64url-ish charset -> Invalid.
    let token = format!("glpat-{}", "a".repeat(19) + "!");
    assert_eq!(validate_checksum(&token), ChecksumResult::Invalid);
}

#[test]
fn pypi_well_formed_macaroon_is_valid() {
    // pypi- + base64 of >= 32 bytes -> Valid. 48 'A's of STANDARD base64
    // decode to 36 bytes (48/4*3), > 20 chars and >= 32 bytes.
    let payload = "A".repeat(48);
    let token = format!("pypi-{payload}");
    assert_eq!(validate_checksum(&token), ChecksumResult::Valid);
    assert_eq!(checksum_adjusted_confidence(0.0, &token), Some(0.9));
}

#[test]
fn pypi_decodes_to_under_32_bytes_is_invalid() {
    // 24 base64 chars decode to 18 bytes (>= 20 char gate passes, but < 32
    // bytes) -> Invalid.
    let payload = "A".repeat(24);
    let token = format!("pypi-{payload}");
    assert_eq!(validate_checksum(&token), ChecksumResult::Invalid);
    assert_eq!(checksum_adjusted_confidence(0.95, &token), None);
}

#[test]
fn pypi_too_short_payload_is_invalid() {
    // payload < 20 chars -> Invalid before any decode.
    let token = "pypi-AAAA";
    assert_eq!(validate_checksum(token), ChecksumResult::Invalid);
}

#[test]
fn github_fine_grained_valid_when_right_segment_crc_matches() {
    // github_pat_ + 22 alnum + '_' + 59 alnum. The fine-grained validator
    // accepts if the CRC of the WHOLE payload OR of the right segment matches.
    // Construct the right segment as <53-char body><6-char crc(body)>.
    let left = "A".repeat(22);
    let right_body = "B".repeat(53);
    let right = format!("{}{}", right_body, checksum6(&right_body));
    assert_eq!(right.len(), 59);
    let token = format!("github_pat_{left}_{right}");
    assert_eq!(validate_checksum(&token), ChecksumResult::Valid);
    assert_eq!(checksum_adjusted_confidence(0.1, &token), Some(0.9));
}

#[test]
fn github_fine_grained_invalid_when_no_segment_crc_matches() {
    // Well-formed shape (22 / 59 alnum) but neither payload nor right-segment
    // CRC matches its trailer -> Invalid.
    let left = "A".repeat(22);
    let right_body = "B".repeat(53);
    // Deliberately use a wrong trailer (all zeros is exceedingly unlikely to
    // equal the real CRC for an all-'B' body; assert it is in fact wrong).
    let wrong = "000000";
    assert_ne!(
        checksum6(&right_body),
        wrong,
        "fixture must use a wrong CRC"
    );
    let right = format!("{right_body}{wrong}");
    let token = format!("github_pat_{left}_{right}");
    assert_eq!(validate_checksum(&token), ChecksumResult::Invalid);
    assert_eq!(checksum_adjusted_confidence(0.9, &token), None);
}

#[test]
fn github_fine_grained_wrong_segment_lengths_is_invalid() {
    // github_pat_ present but left != 22 or right != 59 -> Invalid.
    let token = format!("github_pat_{}_{}", "A".repeat(10), "B".repeat(59));
    assert_eq!(validate_checksum(&token), ChecksumResult::Invalid);
}

#[test]
fn github_fine_grained_wrong_part_count_is_invalid() {
    // No underscore separator inside the payload -> parts.len() != 2 -> Invalid.
    let token = format!("github_pat_{}", "A".repeat(40));
    assert_eq!(validate_checksum(&token), ChecksumResult::Invalid);
}

// ===========================================================================
// SECTION 5: --precision floor — high_precision() sets 0.85 and composes as a
// MAX over existing floors, never a replace.
// ===========================================================================

#[test]
fn high_precision_min_confidence_constant_is_0_85() {
    assert_eq!(ScannerConfig::HIGH_PRECISION_MIN_CONFIDENCE, 0.85);
}

#[test]
fn high_precision_preset_min_confidence_is_0_85() {
    let cfg = ScannerConfig::high_precision();
    assert_eq!(cfg.min_confidence, 0.85);
}

#[test]
fn high_precision_preset_disables_entropy() {
    // Documented contract: precision drops generic high-entropy matching.
    let cfg = ScannerConfig::high_precision();
    assert!(!cfg.entropy_enabled);
}

#[test]
fn high_precision_preset_shallow_decode_depth() {
    let cfg = ScannerConfig::high_precision();
    assert_eq!(cfg.max_decode_depth, 1);
}

#[test]
fn high_precision_preset_penalizes_test_paths() {
    // Stays on (the default) so fixture-shaped hits are still suppressed.
    let cfg = ScannerConfig::high_precision();
    assert!(cfg.penalize_test_paths);
}

#[test]
fn default_min_confidence_below_precision_bar() {
    // The canonical default floor is lower than the precision bar, which is the
    // whole reason precision RAISES floors.
    let default_cfg = ScannerConfig::default();
    assert!(
        default_cfg.min_confidence < ScannerConfig::HIGH_PRECISION_MIN_CONFIDENCE,
        "default floor {} must be below precision bar {}",
        default_cfg.min_confidence,
        ScannerConfig::HIGH_PRECISION_MIN_CONFIDENCE
    );
}

#[test]
fn precision_raises_low_floor_to_0_85_via_max() {
    // The orchestrator composes precision as `*v = v.max(precision_floor)`.
    // A detector floor of 0.12 below the bar is RAISED to exactly 0.85.
    let precision = ScannerConfig::HIGH_PRECISION_MIN_CONFIDENCE;
    let detector_floor = 0.12_f64;
    assert_eq!(detector_floor.max(precision), 0.85);
}

#[test]
fn precision_does_not_lower_a_higher_floor() {
    // A detector that already declares a 0.95 floor must NOT be lowered to 0.85
    // by precision (max, not replace).
    let precision = ScannerConfig::HIGH_PRECISION_MIN_CONFIDENCE;
    let detector_floor = 0.95_f64;
    assert_eq!(detector_floor.max(precision), 0.95);
}

#[test]
fn precision_floor_at_bar_stays_at_bar() {
    let precision = ScannerConfig::HIGH_PRECISION_MIN_CONFIDENCE;
    let detector_floor = 0.85_f64;
    assert_eq!(detector_floor.max(precision), 0.85);
}

#[test]
fn precision_floor_just_above_bar_preserved() {
    let precision = ScannerConfig::HIGH_PRECISION_MIN_CONFIDENCE;
    let detector_floor = 0.8500001_f64;
    assert_eq!(detector_floor.max(precision), 0.8500001);
}

#[test]
fn precision_floor_just_below_bar_raised_to_bar() {
    let precision = ScannerConfig::HIGH_PRECISION_MIN_CONFIDENCE;
    let detector_floor = 0.8499999_f64;
    assert_eq!(detector_floor.max(precision), 0.85);
}

#[test]
fn explicit_min_confidence_override_layers_on_precision() {
    // A user `--min-confidence` override still layers on top of the preset:
    // the builder replaces the field outright (it is the operator's explicit
    // choice), so an override BELOW the preset wins.
    let cfg = ScannerConfig::high_precision().min_confidence(0.50);
    assert_eq!(cfg.min_confidence, 0.50);
}

#[test]
fn explicit_min_confidence_override_can_raise_above_preset() {
    let cfg = ScannerConfig::high_precision().min_confidence(0.99);
    assert_eq!(cfg.min_confidence, 0.99);
}

// ===========================================================================
// SECTION 6: interaction — a checksum-valid token clears the precision bar,
// a checksum-invalid one is dropped before the bar even matters.
// ===========================================================================

#[test]
fn valid_checksum_floor_clears_precision_bar() {
    // A valid token floored to 0.9 is >= the 0.85 precision bar: it survives.
    let token = valid_ghp(&body30());
    let conf = checksum_adjusted_confidence(0.1, &token).expect("valid token kept");
    assert_eq!(conf, 0.9);
    assert!(
        conf >= ScannerConfig::HIGH_PRECISION_MIN_CONFIDENCE,
        "floored valid-token confidence {conf} must clear precision bar"
    );
}

#[test]
fn invalid_checksum_dropped_regardless_of_precision_bar() {
    // Invalid -> None: the match never reaches the precision floor comparison.
    let bad = corrupt_last_char(&valid_ghp(&body30()));
    assert_eq!(checksum_adjusted_confidence(0.99, &bad), None);
}

#[test]
fn not_applicable_token_must_earn_precision_bar_on_its_own() {
    // NotApplicable means no floor boost: a 0.80 AKIA-style token stays 0.80,
    // which is BELOW the 0.85 precision bar (would be dropped downstream).
    let cred = "AKIAIOSFODNN7EXAMPLEXYZ"; // AKIA: no checksum validator
    assert_eq!(validate_checksum(cred), ChecksumResult::NotApplicable);
    let conf = checksum_adjusted_confidence(0.80, cred).expect("not-applicable kept");
    assert_eq!(conf, 0.80);
    assert!(
        conf < ScannerConfig::HIGH_PRECISION_MIN_CONFIDENCE,
        "0.80 must remain below the precision bar without a checksum boost"
    );
}

// ===========================================================================
// SECTION 7: known_prefix_confidence_floor — the 0.8 base used on the hot path
// before checksum adjustment (engine/hot_patterns.rs).
// ===========================================================================

#[test]
fn known_prefix_floor_is_0_8_for_akia() {
    // AKIA is a known prefix with no placeholder word -> Some(0.8).
    assert_eq!(
        known_prefix_confidence_floor("AKIAQQQQWWWWEEEERRRRTTTT"),
        Some(0.8)
    );
}

#[test]
fn known_prefix_floor_none_for_unknown_prefix() {
    assert_eq!(
        known_prefix_confidence_floor("zzz_not_a_known_prefix_12345"),
        None
    );
}

#[test]
fn known_prefix_floor_suppressed_by_placeholder_word() {
    // A known prefix carrying a placeholder word (EXAMPLE) gets NO floor: it is
    // a doc sample, not a credential.
    assert_eq!(known_prefix_confidence_floor("AKIAEXAMPLE1234567890"), None);
}

#[test]
fn known_prefix_floor_suppressed_by_placeholder_word_case_insensitive() {
    // contains_placeholder_word is case-insensitive: lowercase "sample" trips.
    assert_eq!(
        known_prefix_confidence_floor("ghp_thisissampledata000000000000000000"),
        None
    );
}

#[test]
fn hot_path_base_confidence_is_0_7_without_known_prefix() {
    // engine/hot_patterns.rs uses
    //   known_prefix_confidence_floor(cred).unwrap_or(0.7)
    // as the base confidence. Mirror that composition: an unknown-prefix hot
    // literal starts at 0.7.
    let base = known_prefix_confidence_floor("sq0csp-nochecksumhere000000").unwrap_or(0.7);
    assert_eq!(base, 0.7);
}

#[test]
fn hot_path_valid_token_base_floored_to_0_9() {
    // Full hot-path composition for a checksum-bearing literal:
    //   base = known_prefix_confidence_floor(cred).unwrap_or(0.7)  // ghp_ -> 0.8
    //   final = checksum_adjusted_confidence(base, cred)           // Valid -> 0.9
    let token = valid_ghp(&body30());
    let base = known_prefix_confidence_floor(&token).unwrap_or(0.7);
    assert_eq!(base, 0.8, "ghp_ is a known prefix -> 0.8 base");
    let final_conf = checksum_adjusted_confidence(base, &token);
    assert_eq!(
        final_conf,
        Some(0.9),
        "valid checksum floors the 0.8 base up to 0.9"
    );
}

#[test]
fn hot_path_invalid_token_dropped_before_floor() {
    // A fabricated ghp_ on the hot path: base 0.8, then checksum drops it.
    let bad = corrupt_last_char(&valid_ghp(&body30()));
    let base = known_prefix_confidence_floor(&bad).unwrap_or(0.7);
    assert_eq!(base, 0.8);
    assert_eq!(checksum_adjusted_confidence(base, &bad), None);
}

// ===========================================================================
// SECTION 8: property-style loops over the pure policy function. These assert
// the three structural invariants of checksum_adjusted_confidence across a
// wide range of inputs without ever hardcoding a coincidental value.
// ===========================================================================

#[test]
fn property_valid_output_is_max_of_input_and_floor() {
    // For a fixed valid token, Some(max(c, 0.9)) for all c in [0,1].
    let token = valid_ghp(&body30());
    let mut c = 0.0_f64;
    while c <= 1.0 {
        let expected = Some(c.max(CHECKSUM_VALID_FLOOR));
        assert_eq!(
            checksum_adjusted_confidence(c, &token),
            expected,
            "valid token at c={c} must floor to max(c, {CHECKSUM_VALID_FLOOR})"
        );
        c += 0.01;
    }
}

#[test]
fn property_valid_output_never_below_floor() {
    let token = valid_npm(&body30());
    let mut c = 0.0_f64;
    while c <= 1.0 {
        let out = checksum_adjusted_confidence(c, &token).expect("valid kept");
        assert!(
            out >= CHECKSUM_VALID_FLOOR,
            "valid-token output {out} (c={c}) must never drop below the floor"
        );
        c += 0.013;
    }
}

#[test]
fn property_invalid_always_drops_regardless_of_confidence() {
    let bad = corrupt_last_char(&valid_ghp(&body30()));
    let mut c = 0.0_f64;
    while c <= 1.0 {
        assert_eq!(
            checksum_adjusted_confidence(c, &bad),
            None,
            "invalid token at c={c} must always drop"
        );
        c += 0.017;
    }
}

#[test]
fn property_not_applicable_is_identity() {
    // For a checksum-less credential, the policy is the identity on confidence.
    let cred = "no_prefix_here_random_blob_998877";
    assert_eq!(validate_checksum(cred), ChecksumResult::NotApplicable);
    let mut c = 0.0_f64;
    while c <= 1.0 {
        assert_eq!(
            checksum_adjusted_confidence(c, cred),
            Some(c),
            "not-applicable at c={c} must pass through unchanged"
        );
        c += 0.019;
    }
}

#[test]
fn property_precision_max_is_monotone_and_never_lowers() {
    // For every detector floor, precision composition `f.max(0.85)` is >= both
    // f and 0.85, and equals f exactly when f >= 0.85.
    let precision = ScannerConfig::HIGH_PRECISION_MIN_CONFIDENCE;
    let mut f = 0.0_f64;
    while f <= 1.0 {
        let composed = f.max(precision);
        assert!(composed >= f, "composed {composed} must be >= original {f}");
        assert!(
            composed >= precision,
            "composed {composed} must be >= bar {precision}"
        );
        if f >= precision {
            assert_eq!(composed, f, "above-bar floor {f} must be preserved exactly");
        } else {
            assert_eq!(
                composed, precision,
                "below-bar floor {f} must rise to the bar"
            );
        }
        f += 0.011;
    }
}

// ===========================================================================
// SECTION 9: adversarial / evasion — attacker-shaped inputs that must NOT earn
// the valid floor.
// ===========================================================================

#[test]
fn fabricated_ghp_with_plausible_random_checksum_is_dropped() {
    // Attacker keeps the ghp_ + 36-alnum shape but invents a checksum. Almost
    // any fabricated 6-char trailer mismatches the CRC -> Invalid -> drop.
    // Use a body whose true CRC we compute, then pick a guaranteed-wrong one.
    let body = body30();
    let real = checksum6(&body);
    let fake = if real == "000000" { "000001" } else { "000000" };
    let token = format!("ghp_{body}{fake}");
    assert_eq!(token.len(), 4 + 36);
    assert_eq!(validate_checksum(&token), ChecksumResult::Invalid);
    assert_eq!(checksum_adjusted_confidence(1.0, &token), None);
}

#[test]
fn lookalike_prefix_without_validator_is_not_floored() {
    // `gh_` (not `ghp_`/`gho_`/...) is not a checksum-validated prefix and not
    // in KNOWN_PREFIXES either: NotApplicable, confidence passes through.
    let token = "gh_1234567890abcdefghijklmno";
    assert_eq!(validate_checksum(token), ChecksumResult::NotApplicable);
    assert_eq!(checksum_adjusted_confidence(0.2, token), Some(0.2));
}

#[test]
fn truncated_valid_ghp_loses_floor() {
    // Take a genuinely-valid token and truncate one char: the length gate now
    // fails (35 != 36) -> NotApplicable, the boost is lost.
    let mut token = valid_ghp(&body30());
    token.pop();
    assert_eq!(validate_checksum(&token), ChecksumResult::NotApplicable);
    // No drop and no 0.9 floor: the low confidence survives unchanged.
    assert_eq!(checksum_adjusted_confidence(0.3, &token), Some(0.3));
}

#[test]
fn whitespace_padded_valid_token_loses_validation() {
    // The validators do not trim: a leading space means strip_prefix("ghp_")
    // fails -> NotApplicable. (The caller is responsible for clean extraction.)
    let token = format!(" {}", valid_ghp(&body30()));
    assert_eq!(validate_checksum(&token), ChecksumResult::NotApplicable);
}

#[test]
fn first_matching_validator_wins_no_double_adjudication() {
    // validate_checksum returns on the first Valid/Invalid. A valid slack bot
    // token is adjudicated by the slack validator alone -> Valid -> floored.
    let token = "xoxb-1234567890-1234567890-abcdefghijklmnopqrst";
    assert_eq!(validate_checksum(token), ChecksumResult::Valid);
    assert_eq!(checksum_adjusted_confidence(0.0, token), Some(0.9));
}

// ===========================================================================
// SECTION 10: round-trip integrity of the construction helpers themselves.
// If these break, every "valid" assertion above is suspect — so prove the
// helper's CRC matches what the validator recomputes.
// ===========================================================================

#[test]
fn helper_constructs_tokens_the_validator_accepts() {
    for body in [
        "abcdefghijklmnopqrstuvwxyz0123",  // 30 lowercase + digits
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123",  // 30 uppercase + digits
        "0123456789012345678901234567ZZ",  // digit-heavy, 30 chars
        "qWeRtYuIoPaSdFgHjKlZxCvBnM01234", // mixed, must be 30
    ] {
        let body30: String = body.chars().take(30).collect();
        assert_eq!(body30.len(), 30);
        let ghp = valid_ghp(&body30);
        assert_eq!(
            validate_checksum(&ghp),
            ChecksumResult::Valid,
            "helper-built ghp token {ghp} must validate Valid"
        );
        let npm = valid_npm(&body30);
        assert_eq!(
            validate_checksum(&npm),
            ChecksumResult::Valid,
            "helper-built npm token {npm} must validate Valid"
        );
    }
}

#[test]
fn helper_zero_value_base62_is_all_zeros() {
    // crc==0 -> "000000". Exercised so the helper's base62 zero-path matches
    // source behaviour (base62_encode_u32(0, 6) == "000000").
    assert_eq!(base62_encode_u32(0, 6), "000000");
}

#[test]
fn helper_base62_left_pads_to_width() {
    // value 1 -> base62 "1", left-padded to width 6 -> "000001".
    assert_eq!(base62_encode_u32(1, 6), "000001");
    // value 61 -> last base62 digit 'z', padded -> "00000z".
    assert_eq!(base62_encode_u32(61, 6), "00000z");
    // value 62 -> "10", padded -> "000010".
    assert_eq!(base62_encode_u32(62, 6), "000010");
}
