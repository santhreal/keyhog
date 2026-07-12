//! Boundary contract for the two canonical base64-byte predicates in
//! decode/base64.rs — `is_standard_base64_byte` (RFC 4648 standard alphabet:
//! alphanumeric + `+ / =`) and `is_base64_candidate_byte` (standard plus the
//! url-safe `-` and `_`). Four scanner call sites (three in
//! context/false_positive.rs, one in suppression/shape/canonical.rs) inlined
//! these byte sets by hand; they now delegate to the canonical predicates, so
//! these tests pin the exact accepted/rejected alphabet that the dedup relies
//! on. The distinguishing chars are `-` and `_`: rejected by the standard
//! predicate, accepted by the candidate predicate.

use keyhog_scanner::testing::{is_base64_candidate_byte, is_standard_base64_byte};

// ── is_standard_base64_byte: accepts alphanumeric + '+' '/' '=' ─────────────

#[test]
fn standard_accepts_uppercase_bounds() {
    assert!(is_standard_base64_byte(b'A'));
    assert!(is_standard_base64_byte(b'Z'));
}

#[test]
fn standard_accepts_lowercase_bounds() {
    assert!(is_standard_base64_byte(b'a'));
    assert!(is_standard_base64_byte(b'z'));
}

#[test]
fn standard_accepts_digit_bounds() {
    assert!(is_standard_base64_byte(b'0'));
    assert!(is_standard_base64_byte(b'9'));
}

#[test]
fn standard_accepts_plus() {
    assert!(is_standard_base64_byte(b'+'));
}

#[test]
fn standard_accepts_slash() {
    assert!(is_standard_base64_byte(b'/'));
}

#[test]
fn standard_accepts_padding_equals() {
    assert!(is_standard_base64_byte(b'='));
}

#[test]
fn standard_rejects_url_safe_dash() {
    assert!(!is_standard_base64_byte(b'-'));
}

#[test]
fn standard_rejects_url_safe_underscore() {
    assert!(!is_standard_base64_byte(b'_'));
}

#[test]
fn standard_rejects_space() {
    assert!(!is_standard_base64_byte(b' '));
}

#[test]
fn standard_rejects_punctuation() {
    assert!(!is_standard_base64_byte(b'!'));
    assert!(!is_standard_base64_byte(b'.'));
    assert!(!is_standard_base64_byte(b'@'));
    assert!(!is_standard_base64_byte(b'~'));
}

#[test]
fn standard_rejects_newline_and_control() {
    assert!(!is_standard_base64_byte(b'\n'));
    assert!(!is_standard_base64_byte(0x00));
}

#[test]
fn standard_rejects_high_byte() {
    assert!(!is_standard_base64_byte(0xFF));
}

// ── is_base64_candidate_byte: standard alphabet plus '-' and '_' ────────────

#[test]
fn candidate_accepts_alphanumeric_bounds() {
    assert!(is_base64_candidate_byte(b'A'));
    assert!(is_base64_candidate_byte(b'z'));
    assert!(is_base64_candidate_byte(b'0'));
    assert!(is_base64_candidate_byte(b'9'));
}

#[test]
fn candidate_accepts_standard_symbols() {
    assert!(is_base64_candidate_byte(b'+'));
    assert!(is_base64_candidate_byte(b'/'));
    assert!(is_base64_candidate_byte(b'='));
}

#[test]
fn candidate_accepts_url_safe_dash() {
    assert!(is_base64_candidate_byte(b'-'));
}

#[test]
fn candidate_accepts_url_safe_underscore() {
    assert!(is_base64_candidate_byte(b'_'));
}

#[test]
fn candidate_rejects_space() {
    assert!(!is_base64_candidate_byte(b' '));
}

#[test]
fn candidate_rejects_punctuation() {
    assert!(!is_base64_candidate_byte(b'!'));
    assert!(!is_base64_candidate_byte(b'.'));
    assert!(!is_base64_candidate_byte(b'@'));
    assert!(!is_base64_candidate_byte(b'~'));
}

#[test]
fn candidate_rejects_high_byte() {
    assert!(!is_base64_candidate_byte(0xFF));
}

// ── the distinguishing contract between the two predicates ──────────────────

#[test]
fn dash_and_underscore_separate_the_two_predicates() {
    for &byte in &[b'-', b'_'] {
        assert!(!is_standard_base64_byte(byte));
        assert!(is_base64_candidate_byte(byte));
    }
}

#[test]
fn candidate_is_a_strict_superset_of_standard() {
    // Every byte the standard predicate accepts, the candidate predicate also
    // accepts (the candidate set only adds chars, never removes).
    for byte in 0u8..=255 {
        if is_standard_base64_byte(byte) {
            assert!(
                is_base64_candidate_byte(byte),
                "candidate must accept standard byte {byte:#x}"
            );
        }
    }
}

#[test]
fn only_dash_and_underscore_differ() {
    // The two predicates agree on every byte except '-' and '_'.
    for byte in 0u8..=255 {
        let differ = is_standard_base64_byte(byte) != is_base64_candidate_byte(byte);
        assert_eq!(
            differ,
            byte == b'-' || byte == b'_',
            "predicates may differ only on '-'/'_', not {byte:#x}"
        );
    }
}

// ── autoroute decode-density consumer (keyhog-cli workload) dedup contract ───
// `orchestrator::dispatch::backend::workload::decode_density_bucket` inlined a
// byte-identical `is_encoded_alphabet_byte`; it now routes through this same
// `is_base64_candidate_byte` owner. These three pin the exact classification
// the encoded-run counter depends on so the two can never drift again.

#[test]
fn autoroute_counts_alphanumeric_run_bytes() {
    // Valid alnum: every ASCII letter/digit is an encoded-run byte.
    for byte in [b'A', b'M', b'Z', b'a', b'm', b'z', b'0', b'5', b'9'] {
        assert!(
            is_base64_candidate_byte(byte),
            "autoroute must count alnum byte {byte:#x} into an encoded run"
        );
    }
}

#[test]
fn autoroute_counts_plus_and_slash_run_bytes() {
    // '+' '/' chars: standard-base64 symbols that continue an encoded run.
    assert!(is_base64_candidate_byte(b'+'));
    assert!(is_base64_candidate_byte(b'/'));
}

#[test]
fn autoroute_breaks_run_on_invalid_byte() {
    // Invalid byte: a space is not alphabet, so it terminates an encoded run
    // (the branch that flushes `encoded_run` in `decode_density_bucket`).
    assert!(!is_base64_candidate_byte(b' '));
    assert!(!is_base64_candidate_byte(b','));
    assert!(!is_base64_candidate_byte(0x00));
}
