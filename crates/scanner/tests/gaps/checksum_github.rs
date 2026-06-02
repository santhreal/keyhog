//! Integration tests for the GitHub classic PAT CRC32 checksum validator.
//!
//! Source under test: `crates/scanner/src/checksum/github.rs`
//! (`GithubClassicPatValidator`), routed through the public surface
//! `keyhog_scanner::checksum`.
//!
//! Format the validator enforces:
//!   `ghp_` + 36-char payload, where payload = 30-char entropy + 6-char base62
//!   CRC32 checksum, the CRC32 computed over the 30-char ENTROPY bytes only.
//!
//! Verdict matrix derived directly from the source:
//!   * `strip_prefix("ghp_")` fails                 -> NotApplicable
//!   * payload.len() != 36                          -> NotApplicable
//!   * payload has any non-ascii-alphanumeric char  -> Invalid
//!   * trailing-6 base62 CRC matches entropy CRC     -> Valid
//!   * otherwise (well-formed but wrong checksum)    -> Invalid
//!
//! Every expected value here is derived from a standalone replica of the exact
//! table-driven CRC32 (poly 0xEDB88320, init/final 0xFFFF_FFFF) and the
//! left-zero-padded base62 encoder in the source, cross-checked against
//! hardcoded golden constants so a silent drift in the replica is itself caught.

use keyhog_scanner::checksum::{
    validate_checksum, ChecksumResult, ChecksumValidator, GithubClassicPatValidator,
};

// ── Reference replica of the source's CRC32 / base62 (proptest oracle) ──────
// Mirrors `github::crc32` byte-for-byte: standard reflected CRC32.
const BASE62_DIGITS: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

fn ref_crc32(data: &[u8]) -> u32 {
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

// Mirrors `github::base62_encode_u32`.
fn ref_base62(mut value: u32, width: usize) -> String {
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

/// Correct 6-char base62 CRC32 checksum for a 30-char entropy body.
fn checksum_for(entropy: &str) -> String {
    ref_base62(ref_crc32(entropy.as_bytes()), 6)
}

/// Build a well-formed, checksum-VALID classic PAT for the given 30-char entropy.
fn valid_token(entropy: &str) -> String {
    assert_eq!(entropy.len(), 30, "entropy must be exactly 30 chars");
    format!("ghp_{}{}", entropy, checksum_for(entropy))
}

fn classic() -> GithubClassicPatValidator {
    GithubClassicPatValidator
}

// Golden 30-char entropy bodies whose checksums were computed offline with the
// exact source algorithm (zlib-compatible CRC32 + base62). Hardcoded here so
// the test's own replica can't silently diverge from the source unnoticed.
const E_ALPHA: &str = "abcdefghijklmnopqrstuvwxyz1234"; // cs = 3Tcn6I
const E_ZERO: &str = "000000000000000000000000000000"; // cs = 2C8GjS
const E_MIX: &str = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5"; // cs = 0Zb5Hm

// ── Replica integrity: the oracle must reproduce the golden constants ───────

#[test]
fn ref_replica_matches_golden_checksums() {
    // If these drift, every derived expectation below is suspect; fail loud.
    assert_eq!(checksum_for(E_ALPHA), "3Tcn6I");
    assert_eq!(checksum_for(E_ZERO), "2C8GjS");
    assert_eq!(checksum_for(E_MIX), "0Zb5Hm");
}

#[test]
fn ref_crc32_known_vectors() {
    // Standard CRC32 reference vectors.
    assert_eq!(ref_crc32(b""), 0x0000_0000);
    assert_eq!(ref_crc32(b"a"), 0xE8B7_BE43);
    assert_eq!(ref_crc32(b"abc"), 0x3524_41C2);
    assert_eq!(
        ref_crc32(b"The quick brown fox jumps over the lazy dog"),
        0x414F_A339
    );
}

#[test]
fn ref_base62_padding_and_zero() {
    assert_eq!(ref_base62(0, 6), "000000");
    assert_eq!(ref_base62(1, 6), "000001");
    assert_eq!(ref_base62(61, 6), "00000z");
    assert_eq!(ref_base62(62, 6), "000010");
    // width never truncates a value that needs more than `width` digits.
    assert_eq!(ref_base62(u32::MAX, 6), ref_base62(u32::MAX, 6));
    assert!(ref_base62(u32::MAX, 6).len() >= 6);
}

// ── POSITIVE: valid tokens -> Valid ─────────────────────────────────────────

#[test]
fn golden_alpha_token_is_valid() {
    let tok = "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";
    assert_eq!(tok.len(), 40);
    assert_eq!(classic().validate(tok), ChecksumResult::Valid);
}

#[test]
fn golden_zero_entropy_token_is_valid() {
    // All-zero entropy is a legitimate 30-char alnum body; its CRC is nonzero.
    let tok = "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";
    assert_eq!(tok.len(), 40);
    assert_eq!(classic().validate(tok), ChecksumResult::Valid);
}

#[test]
fn golden_mixed_entropy_token_is_valid() {
    let tok = "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";
    assert_eq!(tok.len(), 40);
    assert_eq!(classic().validate(tok), ChecksumResult::Valid);
}

#[test]
fn constructed_valid_token_roundtrips() {
    let tok = valid_token(E_ALPHA);
    assert_eq!(tok, "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");
    assert_eq!(classic().validate(&tok), ChecksumResult::Valid);
}

#[test]
fn valid_token_through_registry_is_valid() {
    // The registry (`validate_checksum`) puts the classic validator first and
    // `ghp_` is claimed by no other validator, so the verdict must match.
    let tok = valid_token(E_ALPHA);
    assert_eq!(validate_checksum(&tok), ChecksumResult::Valid);
}

// ── NEGATIVE TWIN: one-char entropy corruption -> Invalid (dropped) ─────────

#[test]
fn entropy_last_char_flipped_is_invalid() {
    // Flip the final entropy char '4' -> '5'; checksum no longer matches.
    // (Correct cs for the corrupted body would be 3iPq72, not 3Tcn6I.)
    let tok = "ghp_abcdefghijklmnopqrstuvwxyz12353Tcn6I";
    assert_eq!(tok.len(), 40);
    assert_eq!(classic().validate(tok), ChecksumResult::Invalid);
}

#[test]
fn entropy_first_char_flipped_is_invalid() {
    let mut entropy: Vec<char> = E_ALPHA.chars().collect();
    entropy[0] = if entropy[0] == 'x' { 'y' } else { 'x' };
    let corrupted: String = entropy.into_iter().collect();
    // Keep the ORIGINAL (now-wrong) checksum.
    let tok = format!("ghp_{}{}", corrupted, checksum_for(E_ALPHA));
    assert_eq!(tok.len(), 40);
    // Sanity: corruption actually changed the expected checksum.
    assert_ne!(checksum_for(&corrupted), checksum_for(E_ALPHA));
    assert_eq!(classic().validate(&tok), ChecksumResult::Invalid);
}

#[test]
fn checksum_first_char_flipped_is_invalid() {
    // Corrupt the checksum portion instead of the body.
    let tok = "ghp_abcdefghijklmnopqrstuvwxyz1234ZTcn6I"; // '3' -> 'Z'
    assert_eq!(tok.len(), 40);
    assert_eq!(classic().validate(tok), ChecksumResult::Invalid);
}

#[test]
fn checksum_last_char_flipped_is_invalid() {
    let cs = checksum_for(E_ALPHA); // "3Tcn6I"
    let mut bytes: Vec<char> = cs.chars().collect();
    let last = bytes.len() - 1;
    bytes[last] = if bytes[last] == 'Z' { 'Y' } else { 'Z' };
    let bad_cs: String = bytes.into_iter().collect();
    let tok = format!("ghp_{}{}", E_ALPHA, bad_cs);
    assert_eq!(tok.len(), 40);
    assert_ne!(bad_cs, cs);
    assert_eq!(classic().validate(&tok), ChecksumResult::Invalid);
}

#[test]
fn all_zero_checksum_on_real_body_is_invalid() {
    // "000000" is the checksum only for an entropy whose CRC==0; ours is not.
    let tok = format!("ghp_{}000000", E_ALPHA);
    assert_eq!(tok.len(), 40);
    assert_ne!(checksum_for(E_ALPHA), "000000");
    assert_eq!(classic().validate(&tok), ChecksumResult::Invalid);
}

#[test]
fn wrong_checksum_through_registry_is_invalid() {
    let tok = "ghp_abcdefghijklmnopqrstuvwxyz1234ZTcn6I";
    assert_eq!(validate_checksum(tok), ChecksumResult::Invalid);
}

// ── BOUNDARY: payload length -> NotApplicable (only 36 is in-family) ─────────

#[test]
fn payload_one_short_is_not_applicable() {
    let tok = format!("ghp_{}", "a".repeat(35)); // payload len 35
    assert_eq!(classic().validate(&tok), ChecksumResult::NotApplicable);
}

#[test]
fn payload_one_long_is_not_applicable() {
    let tok = format!("ghp_{}", "a".repeat(37)); // payload len 37
    assert_eq!(classic().validate(&tok), ChecksumResult::NotApplicable);
}

#[test]
fn empty_payload_is_not_applicable() {
    // "ghp_" with nothing after it: payload len 0.
    assert_eq!(classic().validate("ghp_"), ChecksumResult::NotApplicable);
}

#[test]
fn payload_far_too_long_is_not_applicable() {
    let tok = format!("ghp_{}", "a".repeat(100));
    assert_eq!(classic().validate(&tok), ChecksumResult::NotApplicable);
}

#[test]
fn payload_36_minus_and_plus_one_boundary() {
    // Exactly 36 alnum -> in-family (here checksum won't match -> Invalid),
    // while 35 and 37 fall out of the family (-> NotApplicable). This pins the
    // `!= 36` boundary precisely.
    let body36 = "a".repeat(36);
    let body35 = "a".repeat(35);
    let body37 = "a".repeat(37);
    assert_eq!(
        classic().validate(&format!("ghp_{}", body36)),
        ChecksumResult::Invalid
    );
    assert_eq!(
        classic().validate(&format!("ghp_{}", body35)),
        ChecksumResult::NotApplicable
    );
    assert_eq!(
        classic().validate(&format!("ghp_{}", body37)),
        ChecksumResult::NotApplicable
    );
}

#[test]
fn length_check_precedes_alnum_check() {
    // A short payload containing a non-alnum char is NotApplicable (length
    // rejected first), NOT Invalid. Order matters in the source.
    let tok = "ghp_aaaa-aaaa"; // payload len 9, contains '-'
    assert_eq!(classic().validate(tok), ChecksumResult::NotApplicable);
}

// ── ADVERSARIAL / EVASION: non-alnum 36-char payload -> Invalid ─────────────

#[test]
fn non_alnum_hyphen_in_payload_is_invalid() {
    // Length is exactly 36, so we pass the length gate, then the alnum gate
    // rejects with Invalid (never reaching the checksum math).
    let payload = format!("{}-", "a".repeat(35));
    assert_eq!(payload.len(), 36);
    let tok = format!("ghp_{}", payload);
    assert_eq!(classic().validate(&tok), ChecksumResult::Invalid);
}

#[test]
fn non_alnum_underscore_in_payload_is_invalid() {
    let payload = format!("{}_{}", "a".repeat(17), "a".repeat(18));
    assert_eq!(payload.len(), 36);
    let tok = format!("ghp_{}", payload);
    assert_eq!(classic().validate(&tok), ChecksumResult::Invalid);
}

#[test]
fn non_alnum_space_in_payload_is_invalid() {
    let payload = format!("{} {}", "a".repeat(17), "a".repeat(18));
    assert_eq!(payload.len(), 36);
    assert_eq!(
        classic().validate(&format!("ghp_{}", payload)),
        ChecksumResult::Invalid
    );
}

#[test]
fn non_ascii_alnum_unicode_digit_is_not_applicable() {
    // U+0660 ARABIC-INDIC DIGIT ZERO is alphanumeric to Unicode but NOT
    // ascii-alphanumeric; the source uses `is_ascii_alphanumeric`. It is also
    // 2 bytes in UTF-8, so a 36-CHAR payload ending in it is 37 BYTES. The
    // source gates on `payload.len()` (the BYTE length) BEFORE the alnum check,
    // so `37 != 36` short-circuits to NotApplicable and the alnum gate is never
    // reached. This pins the byte-vs-char distinction in the length gate.
    let payload = format!("{}\u{0660}", "a".repeat(35));
    assert_eq!(payload.chars().count(), 36);
    assert_eq!(payload.len(), 37); // byte length: 35 ASCII + 2-byte U+0660
    let tok = format!("ghp_{}", payload);
    assert_eq!(classic().validate(&tok), ChecksumResult::NotApplicable);
}

#[test]
fn non_ascii_alnum_at_36_bytes_is_invalid() {
    // Companion to the above: when the non-ascii-alphanumeric char keeps the
    // payload at exactly 36 BYTES, the length gate passes and the alnum gate
    // fires -> Invalid. U+00E9 (e-acute) is 2 bytes and Unicode-alphabetic but
    // not ascii-alphanumeric; 34 ASCII + one 2-byte char = 36 bytes (35 chars).
    let payload = format!("{}\u{00E9}", "a".repeat(34));
    assert_eq!(payload.len(), 36); // 34 ASCII + 2-byte U+00E9
    assert!(!payload.chars().all(|c| c.is_ascii_alphanumeric()));
    let tok = format!("ghp_{}", payload);
    assert_eq!(classic().validate(&tok), ChecksumResult::Invalid);
}

#[test]
fn non_alnum_in_checksum_region_is_invalid() {
    // Valid 30-char entropy + a 6-char region containing a non-alnum char.
    let bad_tail = "3Tcn6-"; // would-be checksum with a '-'
    let payload = format!("{}{}", E_ALPHA, bad_tail);
    assert_eq!(payload.len(), 36);
    assert_eq!(
        classic().validate(&format!("ghp_{}", payload)),
        ChecksumResult::Invalid
    );
}

// ── PREFIX handling -> NotApplicable when prefix absent/wrong ───────────────

#[test]
fn missing_prefix_is_not_applicable() {
    // Strip the leading "ghp_" from an otherwise-valid token.
    let tok = "abcdefghijklmnopqrstuvwxyz12343Tcn6I";
    assert_eq!(classic().validate(tok), ChecksumResult::NotApplicable);
}

#[test]
fn uppercase_prefix_is_not_applicable() {
    // `strip_prefix` is case-sensitive: "GHP_" is not "ghp_".
    let tok = "GHP_abcdefghijklmnopqrstuvwxyz12343Tcn6I";
    assert_eq!(classic().validate(tok), ChecksumResult::NotApplicable);
}

#[test]
fn fine_grained_prefix_not_claimed_by_classic() {
    // `github_pat_...` is the fine-grained family, not classic.
    let tok = "github_pat_aaaaaaaaaaaaaaaaaaaaaa_bbbbbbb";
    assert_eq!(classic().validate(tok), ChecksumResult::NotApplicable);
}

#[test]
fn empty_string_is_not_applicable() {
    assert_eq!(classic().validate(""), ChecksumResult::NotApplicable);
}

#[test]
fn prefix_only_substring_is_not_applicable() {
    assert_eq!(classic().validate("ghp"), ChecksumResult::NotApplicable);
    assert_eq!(classic().validate("gh"), ChecksumResult::NotApplicable);
    assert_eq!(classic().validate("ghp_"), ChecksumResult::NotApplicable);
}

#[test]
fn prefix_in_middle_is_not_applicable() {
    // strip_prefix anchors at the start; an internal "ghp_" does not count.
    let tok = format!("XXghp_{}", "a".repeat(36));
    assert_eq!(classic().validate(&tok), ChecksumResult::NotApplicable);
}

// ── validator identity ──────────────────────────────────────────────────────

#[test]
fn validator_id_is_stable() {
    assert_eq!(classic().validator_id(), "github-classic-pat");
}

// ── REGISTRY: ghp_ family is adjudicated only by the classic validator ──────

#[test]
fn registry_not_applicable_for_unknown_token() {
    // A token claimed by no validator returns NotApplicable from the registry.
    assert_eq!(
        validate_checksum("totally-random-not-a-token"),
        ChecksumResult::NotApplicable
    );
}

#[test]
fn registry_valid_matches_direct_validator_for_many_tokens() {
    for entropy in CORPUS {
        let tok = valid_token(entropy);
        assert_eq!(classic().validate(&tok), ChecksumResult::Valid, "{tok}");
        assert_eq!(validate_checksum(&tok), ChecksumResult::Valid, "{tok}");
    }
}

#[test]
fn registry_invalid_matches_direct_validator_for_corrupted_tokens() {
    for entropy in CORPUS {
        // Corrupt the checksum by appending-style swap of first char.
        let cs = checksum_for(entropy);
        let mut chars: Vec<char> = cs.chars().collect();
        chars[0] = if chars[0] == 'A' { 'B' } else { 'A' };
        let bad: String = chars.into_iter().collect();
        let tok = format!("ghp_{}{}", entropy, bad);
        assert_eq!(classic().validate(&tok), ChecksumResult::Invalid, "{tok}");
        assert_eq!(validate_checksum(&tok), ChecksumResult::Invalid, "{tok}");
    }
}

// ── PROPTEST-STYLE LOOPS: derive every expectation from the oracle ──────────

// 30-char alphanumeric entropy bodies (offline-fixed so checksums are stable).
const CORPUS: &[&str] = &[
    "abcdefghijklmnopqrstuvwxyz1234",
    "000000000000000000000000000000",
    "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5",
    "AUa00Zt2x7mrKBkxh3BqJOlNJlwV9U",
    "fHVALGkjnUem1vubDvb9GSVAaa8Q3k",
    "XLlsgPAg4RKlVyo9HMT60vZcoh3FnV",
    "ZWJQlqLBH69ickt31aj9owIvkyuadd",
    "TCfyZ6lYaXTxnRGWhENdaOFuXN9A78",
    "JmxXQShJjfFk59vonkksjIfHSajaQF",
    "4l1M7Z2gqGWzeYW9DAlp64lbxvlzll",
    "KR0H5p9AGSAuhePDVmONKmViH5ovKs",
];

#[test]
fn proptest_constructed_tokens_are_valid() {
    for entropy in CORPUS {
        let tok = valid_token(entropy);
        assert_eq!(tok.len(), 40, "{tok}");
        assert_eq!(
            classic().validate(&tok),
            ChecksumResult::Valid,
            "expected Valid for {tok}"
        );
    }
}

#[test]
fn proptest_every_single_entropy_byte_flip_breaks_checksum() {
    // For each corpus entropy, flipping any one alnum char to a different alnum
    // char while keeping the original checksum must yield Invalid (the CRC of
    // the body changed, so the trailing 6 no longer match). We also assert the
    // checksum genuinely changed, ruling out an accidental collision masking a
    // false pass.
    for entropy in CORPUS {
        let original_cs = checksum_for(entropy);
        let body: Vec<char> = entropy.chars().collect();
        for i in 0..body.len() {
            let mut mutated = body.clone();
            // Map current char to a guaranteed-different alnum char.
            let repl = if mutated[i] == 'a' { 'b' } else { 'a' };
            mutated[i] = repl;
            let mutated_body: String = mutated.into_iter().collect();
            if checksum_for(&mutated_body) == original_cs {
                // Extremely unlikely CRC collision; skip to avoid a false fail.
                continue;
            }
            let tok = format!("ghp_{}{}", mutated_body, original_cs);
            assert_eq!(tok.len(), 40);
            assert_eq!(
                classic().validate(&tok),
                ChecksumResult::Invalid,
                "byte flip at {i} of {entropy} should invalidate"
            );
        }
    }
}

#[test]
fn proptest_appended_or_truncated_payload_is_not_applicable() {
    // Adding/removing a single char shifts payload length off 36 -> NotApplicable.
    for entropy in CORPUS {
        let valid = valid_token(entropy); // len 40, payload 36
        let too_long = format!("{valid}a"); // payload 37
        let too_short = &valid[..valid.len() - 1]; // payload 35
        assert_eq!(
            classic().validate(&too_long),
            ChecksumResult::NotApplicable,
            "{too_long}"
        );
        assert_eq!(
            classic().validate(too_short),
            ChecksumResult::NotApplicable,
            "{too_short}"
        );
    }
}

#[test]
fn proptest_idempotent_and_pure() {
    // Validation has no internal state: repeated calls agree.
    let tok = valid_token(E_ALPHA);
    let a = classic().validate(&tok);
    let b = classic().validate(&tok);
    let c = GithubClassicPatValidator.validate(&tok);
    assert_eq!(a, ChecksumResult::Valid);
    assert_eq!(a, b);
    assert_eq!(b, c);
}

// ── ChecksumResult algebra used by these tests ──────────────────────────────

#[test]
fn checksum_result_variants_are_distinct() {
    assert_ne!(ChecksumResult::Valid, ChecksumResult::Invalid);
    assert_ne!(ChecksumResult::Valid, ChecksumResult::NotApplicable);
    assert_ne!(ChecksumResult::Invalid, ChecksumResult::NotApplicable);
    assert_eq!(ChecksumResult::Valid, ChecksumResult::Valid);
}
