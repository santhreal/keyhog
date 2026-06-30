//! Exhaustive decode contract for the hand-rolled Z85 decoder
//! (`decode::z85_decode`).
//!
//! Z85 (ZeroMQ Base-85) maps an 85-symbol alphabet to the values `0..=84` and
//! packs every 5 symbols big-endian into one `u32` (4 output bytes). The decoder
//! is a hand-written `match` table plus a `u32` overflow guard — exactly the
//! shape where a single transcription slip (an off-by-one at a range join, a
//! wrong punctuation value, a missing overflow check) silently DECODES A SECRET
//! TO GARBAGE rather than erroring, so the planted credential is never matched
//! and recall is lost with no signal. `Z85Decoder` is a registered decode-through
//! decoder, so a Z85-wrapped secret in a scanned file is decoded by this path.
//!
//! Ground truth is the canonical ZeroMQ Z85 specification:
//!   * the reference vector `HelloWorld` decodes to the 8 bytes
//!     `86 4F D2 6F  B5 59 F7 5B`;
//!   * the largest legal 5-tuple is `u32::MAX`, encoded `%nSc0`;
//!   * `#####` (five value-84 symbols) exceeds `u32` and MUST be rejected, never
//!     wrapped or truncated.
//! Every alphabet class boundary is pinned to its exact value so the whole
//! `0..=84` table is locked, and each `Ok` vector is paired with a malformed
//! twin that must error.

use keyhog_scanner::decode::z85_decode;

fn dec(input: &str) -> Vec<u8> {
    z85_decode(input).unwrap_or_else(|()| panic!("z85_decode({input:?}) must succeed"))
}

/// Decode a single 5-symbol group whose first four symbols are `'0'` (value 0),
/// returning the trailing byte. With four leading zeros the group's numeric
/// value equals exactly `z85_val(symbol)` (all `< 85 < 256`), so the decoded
/// 4-byte group is `[0, 0, 0, z85_val(symbol)]` — a direct probe of one
/// alphabet-table entry.
fn symbol_value(symbol: char) -> u8 {
    let group = format!("0000{symbol}");
    let decoded = dec(&group);
    assert_eq!(decoded.len(), 4, "one 5-symbol group decodes to 4 bytes");
    assert_eq!(
        &decoded[..3],
        &[0, 0, 0],
        "four leading '0' symbols contribute zero"
    );
    decoded[3]
}

// ── canonical ZeroMQ specification vectors ──────────────────────────────────

#[test]
fn canonical_hello_world_reference_vector() {
    // The Z85 spec's own published test vector: "HelloWorld" ⇄ these 8 bytes.
    // Decoding it correctly exercises every alphabet class and the full
    // big-endian u32 packing in one shot.
    assert_eq!(
        dec("HelloWorld"),
        vec![0x86, 0x4F, 0xD2, 0x6F, 0xB5, 0x59, 0xF7, 0x5B]
    );
}

#[test]
fn max_u32_group_decodes_to_four_0xff() {
    // "%nSc0" is the Z85 encoding of u32::MAX — the largest legal 5-tuple.
    assert_eq!(dec("%nSc0"), vec![0xFF, 0xFF, 0xFF, 0xFF]);
}

#[test]
fn value_just_below_overflow_is_accepted() {
    // "%nSb#" encodes 0xFFFFFFFE (u32::MAX - 1): still legal, must decode.
    assert_eq!(dec("%nSb#"), vec![0xFF, 0xFF, 0xFF, 0xFE]);
}

#[test]
fn all_max_symbol_group_overflows_u32_and_is_rejected() {
    // "#####" = five value-84 symbols = 84·(85⁴+85³+85²+85+1) = 4_437_053_124,
    // which exceeds u32::MAX. The decoder must reject it, not wrap/truncate.
    assert!(z85_decode("#####").is_err());
}

#[test]
fn one_past_max_overflow_is_rejected() {
    // "%nSc1" = u32::MAX + 1 — the exact overflow boundary, one symbol past the
    // largest legal group "%nSc0".
    assert!(z85_decode("%nSc1").is_err());
}

// ── alphabet table: each class boundary maps to its exact value ─────────────

#[test]
fn digit_symbols_map_to_zero_through_nine() {
    assert_eq!(symbol_value('0'), 0);
    assert_eq!(symbol_value('1'), 1);
    assert_eq!(symbol_value('9'), 9);
}

#[test]
fn lowercase_symbols_map_to_ten_through_thirty_five() {
    assert_eq!(symbol_value('a'), 10);
    assert_eq!(symbol_value('f'), 15);
    // Boundary where the a–f and g–z arms join: 'f'→15 must be followed by 'g'→16.
    assert_eq!(symbol_value('g'), 16);
    assert_eq!(symbol_value('z'), 35);
}

#[test]
fn uppercase_symbols_map_to_thirty_six_through_sixty_one() {
    assert_eq!(symbol_value('A'), 36);
    assert_eq!(symbol_value('Z'), 61);
}

#[test]
fn punctuation_symbols_map_to_sixty_two_through_eighty_four() {
    let expected = [
        ('.', 62),
        ('-', 63),
        (':', 64),
        ('+', 65),
        ('=', 66),
        ('^', 67),
        ('!', 68),
        ('/', 69),
        ('*', 70),
        ('?', 71),
        ('&', 72),
        ('<', 73),
        ('>', 74),
        ('(', 75),
        (')', 76),
        ('[', 77),
        (']', 78),
        ('{', 79),
        ('}', 80),
        ('@', 81),
        ('%', 82),
        ('$', 83),
        ('#', 84),
    ];
    for (symbol, value) in expected {
        assert_eq!(symbol_value(symbol), value, "symbol {symbol:?}");
    }
}

#[test]
fn full_alphabet_table_is_complete_and_monotonic() {
    // The single strongest lock: every one of the 85 symbols, in canonical
    // order, maps to its 0-based index. Any future edit that drops, duplicates,
    // reorders, or mis-values a single entry fails here.
    const ALPHABET: &str =
        "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#";
    assert_eq!(ALPHABET.chars().count(), 85, "Z85 has exactly 85 symbols");
    for (expected_value, symbol) in ALPHABET.chars().enumerate() {
        assert_eq!(
            symbol_value(symbol),
            expected_value as u8,
            "alphabet index {expected_value} ({symbol:?})"
        );
    }
}

#[test]
fn alphabet_is_case_sensitive() {
    // Unlike hex, Z85 distinguishes case: 'a' (10) and 'A' (36) are different
    // symbols. A decoder that lowercased its input would collapse them.
    assert_eq!(symbol_value('a'), 10);
    assert_eq!(symbol_value('A'), 36);
    assert_ne!(symbol_value('a'), symbol_value('A'));
    assert_eq!(symbol_value('z'), 35);
    assert_eq!(symbol_value('Z'), 61);
    assert_ne!(symbol_value('z'), symbol_value('Z'));
}

// ── invalid symbols are rejected (no silent skip / substitution) ────────────

#[test]
fn underscore_is_not_a_z85_symbol() {
    // Underscore is a base64url symbol but NOT Z85. A decoder that confused the
    // two alphabets would wrongly accept it instead of erroring.
    assert!(z85_decode("0000_").is_err());
}

#[test]
fn space_is_an_invalid_symbol() {
    // z85_decode is strict: whitespace stripping is the span-extractor's job,
    // not the primitive's. A space is simply not in the alphabet.
    assert!(z85_decode("0000 ").is_err());
    assert!(z85_decode("00 00").is_err());
}

#[test]
fn assorted_non_alphabet_punctuation_is_rejected() {
    for bad in [",", ";", "`", "~", "|", "\\", "\"", "'"] {
        let group = format!("0000{bad}");
        assert!(
            z85_decode(&group).is_err(),
            "symbol {bad:?} is not in the Z85 alphabet and must be rejected"
        );
    }
}

#[test]
fn control_characters_are_rejected() {
    assert!(z85_decode("0000\n").is_err());
    assert!(z85_decode("0000\t").is_err());
    assert!(z85_decode("0000\0").is_err());
}

#[test]
fn non_ascii_byte_inside_a_full_group_is_rejected() {
    // "abcé" is 5 BYTES (a,b,c + é=0xC3 0xA9) — a complete chunk whose 4th byte
    // (0xC3) is not a Z85 symbol. The alphabet table must reject it.
    let input = "abcé";
    assert_eq!(input.len(), 5, "fixture must be exactly one 5-byte chunk");
    assert!(z85_decode(input).is_err());
}

// ── group-length structure ──────────────────────────────────────────────────

#[test]
fn empty_input_decodes_to_empty() {
    assert_eq!(dec(""), Vec::<u8>::new());
}

#[test]
fn length_not_multiple_of_five_is_rejected() {
    for len in [1usize, 2, 3, 4, 6, 7, 8, 9, 11, 14] {
        let input = "0".repeat(len);
        assert!(
            z85_decode(&input).is_err(),
            "length {len} is not a Z85 group boundary"
        );
    }
}

// ── multi-group composition ──────────────────────────────────────────────────

#[test]
fn two_groups_decode_to_eight_bytes_independently() {
    // "%nSc0" (→0xFFFFFFFF) followed by "00001" (→0x00000001).
    assert_eq!(
        dec("%nSc000001"),
        vec![0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01]
    );
}

#[test]
fn all_zero_two_groups_decode_to_eight_nulls() {
    assert_eq!(dec("0000000000"), vec![0u8; 8]);
}

#[test]
fn overflow_in_second_group_rejects_whole_input() {
    // First group is valid, the second overflows u32 → the entire decode fails
    // with no partial output, matching the recall-preserving contract (the
    // original encoded chunk stays scanned unchanged rather than yielding a
    // truncated, misleading decode).
    assert!(z85_decode("00001#####").is_err());
}

#[test]
fn invalid_symbol_in_later_group_rejects_whole_input() {
    // A bad symbol only in the SECOND group must still fail the whole input.
    assert!(z85_decode("00001000_0").is_err());
}

// ── realistic decode-through: a Z85-wrapped ASCII secret round-trips ─────────

#[test]
fn z85_wrapped_ascii_secret_decodes_to_plaintext() {
    // "Bz>@4hf.$U" is the Z85 encoding of the 8 ASCII bytes "tok_5xQ9"; this is
    // the exact shape the decode-through pipeline relies on to surface a secret
    // hidden inside a Z85 blob.
    assert_eq!(dec("Bz>@4hf.$U"), b"tok_5xQ9");
}

#[test]
fn z85_wrapped_aws_shaped_token_decodes_to_plaintext() {
    // "k$:^niA!vs" → "AKIA9Z7Q" (an AWS-access-key-shaped 8-byte prefix).
    assert_eq!(dec("k$:^niA!vs"), b"AKIA9Z7Q");
}
