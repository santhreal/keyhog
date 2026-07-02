//! Regression: Caesar/ROT-N MULTI-SHIFT REGISTRY behaviour.
//!
//! Sibling file `regression_caesar_decoder.rs` locks the single-shift recovery
//! + shape gates. This file takes the DISTINCT angle of the shift *registry*:
//! the `matched_caesar_shifts` `[bool; 26]` selection table, the exact
//! rotated-prefix ⇔ forward-shift BIJECTION it encodes, index-0 never being a
//! shift, multi-shift unions, and how `decode_chunk` fans those selected shifts
//! into emitted sub-chunks (recovery, source-type tag, min-len boundary,
//! zero-emission when no shift is selected, recursion refusal on nested
//! `/caesar` source types).
//!
//! Every assertion pins a concrete value (exact bytes / exact bool / exact
//! `[bool; 26]` table / exact count), never a bare non-emptiness check.
//!
//! The `[bool; 26]` bijection assertions assume the rotated-prefix automaton
//! built successfully; it is built once from the compile-time constant
//! `KNOWN_PREFIXES`, so on any host it is the deterministic AC path (the
//! all-25 fallback is a Law-10 invariant-violation branch, not a host mode).

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::testing::decode_caesar;
use keyhog_scanner::testing::CaesarDecoder;

/// AWS-access-key-shaped plaintext credential (starts with the `AKIA` known
/// prefix; 20 chars ≥ `MIN_CAESAR_LEN`; carries digits and a long alnum run).
const PLANTED_AKIA: &str = "AKIA1234567890ABCDEF";
/// `PLANTED_AKIA` forward-shifted by 3 (the on-disk "encoded" form). Its
/// inverse-recovery shift is 26 − 3 = 23.
const AKIA_ENC_SHIFT3: &str = "DNLD1234567890DEFGHI";

/// A GitHub-PAT-shaped credential and its ROT13 (shift 13) form. ROT13 is its
/// own inverse, so shift 13 both encodes and recovers.
const GHP_ORIG: &str = "ghp_1234567890abcdefgh";
const GHP_ROT13: &str = "tuc_1234567890nopqrstu";

/// A Slack-bot-token-shaped credential forward-shifted by 5; recovery shift is
/// 26 − 5 = 21.
const XOXB_ENC_SHIFT5: &str = "ctcg-0123456789fghijk";

fn chunk(data: &str, source_type: &str, path: Option<&str>) -> Chunk {
    Chunk {
        data: data.into(),
        metadata: ChunkMetadata {
            source_type: source_type.to_string(),
            path: path.map(str::to_string),
            ..Default::default()
        },
    }
}

/// True iff some decoded output chunk's data equals `needle` exactly.
fn any_output_equals(out: &[Chunk], needle: &str) -> bool {
    out.iter().any(|oc| {
        let data: &str = &oc.data;
        data == needle
    })
}

/// The shift-selection table computed *independently* of the automaton, from
/// the forward-shift definition: shift `k` is selectable iff some KNOWN_PREFIX
/// appears in `caesar_shift(candidate, k)`. `matched_caesar_shifts` MUST equal
/// this for every candidate (the rotated-prefix ⇔ forward-shift bijection).
fn expected_shift_table(candidate: &str) -> [bool; 26] {
    let mut expected = [false; 26];
    for k in 1..=25u8 {
        let shifted = decode_caesar::caesar_shift(candidate, k);
        expected[k as usize] = decode_caesar::KNOWN_PREFIXES
            .iter()
            .any(|prefix| shifted.contains(prefix));
    }
    expected
}

// ---------------------------------------------------------------------------
// caesar_shift primitive: exact outputs, round-trip, non-alpha passthrough.
// ---------------------------------------------------------------------------

#[test]
fn caesar_shift_produces_exact_reference_strings() {
    // Forward shift 3 of the AWS credential: 20 letters rotate, 10 digits are
    // identity (position-wise).
    assert_eq!(
        decode_caesar::caesar_shift(PLANTED_AKIA, 3),
        AKIA_ENC_SHIFT3
    );
    // ROT13 of the GitHub PAT: `_` and the digits are fixed, letters rotate 13.
    assert_eq!(decode_caesar::caesar_shift(GHP_ORIG, 13), GHP_ROT13);
    // Forward shift 5 of the Slack token: `-` and digits fixed.
    assert_eq!(
        decode_caesar::caesar_shift("xoxb-0123456789abcdef", 5),
        XOXB_ENC_SHIFT5
    );
}

#[test]
fn rot13_roundtrips_a_known_secret_to_itself() {
    // ROT13 is an involution: encoding then re-applying shift 13 restores the
    // exact original credential byte-for-byte.
    let encoded = decode_caesar::caesar_shift(GHP_ORIG, 13);
    assert_eq!(encoded, GHP_ROT13);
    assert_eq!(decode_caesar::caesar_shift(&encoded, 13), GHP_ORIG);
}

#[test]
fn caesar_shift_leaves_non_alphabetic_bytes_unchanged() {
    // Digits, '-', '_', '.', and space are all shift-identity; a string with no
    // ASCII letters is returned verbatim under any shift.
    let non_alpha = "12-34_56.78 90";
    assert_eq!(decode_caesar::caesar_shift(non_alpha, 7), non_alpha);
    assert_eq!(decode_caesar::caesar_shift(non_alpha, 1), non_alpha);
    assert_eq!(decode_caesar::caesar_shift(non_alpha, 25), non_alpha);
}

#[test]
fn caesar_shift_inverse_recovers_original_for_every_shift() {
    // For k ∈ 1..=25, applying shift k then shift (26 − k) is the identity
    // (mod-26 composition), so any of the 25 non-trivial encodings is exactly
    // reversible. This is what makes the 25-shift registry lossless.
    let secret = "AbYz1234567890Xk";
    for k in 1..=25u8 {
        let encoded = decode_caesar::caesar_shift(secret, k);
        let recovered = decode_caesar::caesar_shift(&encoded, 26 - k);
        assert_eq!(
            recovered,
            secret,
            "shift {k} then {} must round-trip",
            26 - k
        );
    }
}

// ---------------------------------------------------------------------------
// matched_caesar_shifts: the [bool; 26] shift-selection registry.
// ---------------------------------------------------------------------------

#[test]
fn matched_shifts_index_zero_is_never_a_selectable_shift() {
    // The registry indexes k ∈ 1..=25; slot 0 (the trivial identity shift) is
    // never populated, whatever the candidate.
    assert!(!decode_caesar::matched_caesar_shifts(AKIA_ENC_SHIFT3)[0]);
    assert!(!decode_caesar::matched_caesar_shifts(GHP_ROT13)[0]);
    assert!(!decode_caesar::matched_caesar_shifts("zzzzzzzz12345678")[0]);
}

#[test]
fn matched_shifts_selects_the_exact_inverse_recovery_shift() {
    // AKIA encoded +3 → recovery shift 23 is flagged.
    assert!(decode_caesar::matched_caesar_shifts(AKIA_ENC_SHIFT3)[23]);
    // ghp_ ROT13 → recovery shift 13 is flagged.
    assert!(decode_caesar::matched_caesar_shifts(GHP_ROT13)[13]);
    // xoxb- encoded +5 → recovery shift 21 is flagged.
    assert!(decode_caesar::matched_caesar_shifts(XOXB_ENC_SHIFT5)[21]);
}

#[test]
fn matched_shifts_equals_forward_shift_bijection_on_akia() {
    // Flagship registry lock: the automaton-computed table is byte-identical to
    // the forward-shift reference table for the AKIA-encoded candidate. The
    // reference here flags exactly {23}; the automaton must agree everywhere.
    let table = decode_caesar::matched_caesar_shifts(AKIA_ENC_SHIFT3);
    let expected = expected_shift_table(AKIA_ENC_SHIFT3);
    assert_eq!(table, expected);
    // Pin the concrete content: shift 23 selected, all others clear.
    for k in 1..=25usize {
        assert_eq!(table[k], k == 23, "shift {k} selection mismatch");
    }
}

#[test]
fn matched_shifts_equals_forward_shift_bijection_on_rot13_ghp() {
    // The bijection holds even when a candidate legitimately selects MORE than
    // one shift (the ghp_ ROT13 form incidentally aligns a second prefix at
    // another shift). The registry must match the forward reference exactly,
    // not merely include the recovery shift.
    let table = decode_caesar::matched_caesar_shifts(GHP_ROT13);
    let expected = expected_shift_table(GHP_ROT13);
    assert_eq!(table, expected);
    // Shift 13 (the ROT13 recovery) is definitely among the selected set.
    assert!(table[13]);
    // At least two shifts are selected here — multi-shift, not single.
    let selected = table.iter().filter(|&&b| b).count();
    assert!(
        selected >= 2,
        "expected multi-shift selection, got {selected}"
    );
}

#[test]
fn matched_shifts_selects_nothing_for_a_prefix_free_candidate() {
    // An all-lowercase 'z' run plus digits: no rotation of any KNOWN_PREFIX can
    // appear (rotated prefixes carry uppercase / `_` / `-` / `.` / a leading
    // `0`, none present), so the whole 25-shift fan-out is provably dead work.
    let candidate = "zzzzzzzz12345678";
    let table = decode_caesar::matched_caesar_shifts(candidate);
    assert_eq!(table, expected_shift_table(candidate));
    assert_eq!(table.iter().filter(|&&b| b).count(), 0);
}

#[test]
fn matched_shifts_unions_multiple_distinct_shifts_in_one_candidate() {
    // A candidate carrying the rotated form of `AKIA` (→ recovery shift 23) AND
    // the rotated form of `ghp_` (→ recovery shift 13) selects BOTH shifts: the
    // registry is a union over prefixes, not first-match-wins.
    let candidate = "DNLD1234tuc_5678";
    let table = decode_caesar::matched_caesar_shifts(candidate);
    assert!(table[13], "ghp_ rotation must select shift 13");
    assert!(table[23], "AKIA rotation must select shift 23");
    assert_eq!(table, expected_shift_table(candidate));
}

// ---------------------------------------------------------------------------
// decode_chunk: fanning the selected shifts into emitted sub-chunks.
// ---------------------------------------------------------------------------

#[test]
fn decode_chunk_recovers_credential_via_registry_selected_shift() {
    // A file line carrying the +3-encoded AKIA credential. `decode_chunk` must
    // select shift 23 and emit the recovered plaintext as a `/caesar` chunk.
    let body = format!("token = \"{AKIA_ENC_SHIFT3}\"\n");
    let out = CaesarDecoder.decode_chunk(&chunk(&body, "src", Some("creds.env")));

    // The exact recovered credential is present.
    assert!(
        any_output_equals(&out, PLANTED_AKIA),
        "must recover {PLANTED_AKIA}: {out:#?}"
    );
    // Every emitted sub-chunk carries the parent source-type with `/caesar`
    // appended, and is itself credential-shaped (a real shift, not noise).
    for oc in &out {
        assert_eq!(oc.metadata.source_type, "src/caesar");
        let data: &str = &oc.data;
        assert!(
            decode_caesar::looks_credential_shaped(data),
            "emitted chunk must be credential-shaped: {data:?}"
        );
    }
}

#[test]
fn decode_chunk_emits_nothing_when_registry_selects_no_shift() {
    // The prefix-free candidate selects zero shifts, so the decoder emits no
    // sub-chunks at all (the whole fan-out is skipped).
    let body = "value = \"zzzzzzzz12345678\"\n";
    let out = CaesarDecoder.decode_chunk(&chunk(body, "src", None));
    assert_eq!(out.len(), 0, "no shift selected → no emission: {out:#?}");
}

#[test]
fn decode_chunk_enforces_min_caesar_len_boundary() {
    // 15-char encoded candidate: below MIN_CAESAR_LEN (16), so even though its
    // rotated form would select shift 23, it is skipped entirely.
    assert_eq!(decode_caesar::MIN_CAESAR_LEN, 16);
    let short_body = "k=\"DNLD1234567890D\"\n"; // 15-char token
    let short_out = CaesarDecoder.decode_chunk(&chunk(short_body, "src", None));
    assert_eq!(
        short_out.len(),
        0,
        "15-char candidate must be skipped: {short_out:#?}"
    );

    // 16-char encoded candidate: at the boundary, recovered to `AKIA1234567890AB`.
    let long_body = "k=\"DNLD1234567890DE\"\n"; // 16-char token
    let long_out = CaesarDecoder.decode_chunk(&chunk(long_body, "src", None));
    assert!(
        any_output_equals(&long_out, "AKIA1234567890AB"),
        "16-char candidate must recover AKIA1234567890AB: {long_out:#?}"
    );
}

#[test]
fn decode_chunk_refuses_recursion_on_nested_caesar_source_type() {
    // A source-type that already contains a `/caesar` segment anywhere (here a
    // base64→caesar chain) is our own prior output; re-shifting it would fold
    // the value back, so the decoder returns nothing regardless of content.
    let body = format!("token = \"{AKIA_ENC_SHIFT3}\"\n");
    let out = CaesarDecoder.decode_chunk(&chunk(&body, "raw/base64/caesar", Some("creds.env")));
    assert_eq!(
        out.len(),
        0,
        "nested /caesar source must not recurse: {out:#?}"
    );
}
