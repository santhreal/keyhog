//! Forward-decode regression coverage for the Z85 decoder
//! (`keyhog_scanner::decode::z85_decode`).
//!
//! Distinct in angle from `regression_z85_reverse_decoders.rs` (which covers the
//! ZeroMQ `HelloWorld` reference plus the reversibility helpers): this file pins
//! EXACT decoded bytes for the full Z85 alphabet mapping, every character-class
//! boundary in the least-significant frame position, higher-position weighting,
//! fresh multi-frame vectors, the exact `u32::MAX` positive boundary and its
//! smallest-overflow negative twin, length-modulo refusal, and invalid-symbol
//! refusal (comma, whitespace, and the `\x60`/`\x7E` gaps around the alphabet).
//!
//! Every vector was computed against the canonical Z85 alphabet
//! `0123456789abcdef…ABCDEF….-:+=^!/*?&<>()[]{}@%$#` (indices 0..=84).

use keyhog_scanner::decode::z85_decode;

/// A single 5-char frame `0000X` weights only the last symbol (multiplier 1),
/// so `z85_decode("0000X") == [0,0,0, z85_val(X)]`. This pins every
/// character-CLASS boundary of the alphabet at once.
#[test]
fn least_significant_frame_pins_each_alphabet_class_boundary() {
    // digit class boundaries '0'(0) .. '9'(9)
    assert_eq!(z85_decode("00000"), Ok(vec![0u8, 0, 0, 0]));
    assert_eq!(z85_decode("00009"), Ok(vec![0u8, 0, 0, 9]));
    // lowercase a-f (10..=15)
    assert_eq!(z85_decode("0000a"), Ok(vec![0u8, 0, 0, 10]));
    assert_eq!(z85_decode("0000f"), Ok(vec![0u8, 0, 0, 15]));
    // lowercase g-z (16..=35)
    assert_eq!(z85_decode("0000g"), Ok(vec![0u8, 0, 0, 16]));
    assert_eq!(z85_decode("0000z"), Ok(vec![0u8, 0, 0, 35]));
    // uppercase A-Z (36..=61)
    assert_eq!(z85_decode("0000A"), Ok(vec![0u8, 0, 0, 36]));
    assert_eq!(z85_decode("0000Z"), Ok(vec![0u8, 0, 0, 61]));
    // symbol boundaries: '.'(62) .. '#'(84, last index)
    assert_eq!(z85_decode("0000."), Ok(vec![0u8, 0, 0, 62]));
    assert_eq!(z85_decode("0000#"), Ok(vec![0u8, 0, 0, 84]));
}

/// The `00001` frame is the smallest nonzero value: exactly `1`.
#[test]
fn smallest_nonzero_frame_decodes_to_one() {
    assert_eq!(z85_decode("00001"), Ok(vec![0u8, 0, 0, 1]));
}

/// Symbol `#` (value 84) in the 3rd position (weight 85) => 84*85 = 7140 =
/// 0x1BE4, i.e. bytes [0, 0, 0x1B, 0xE4].
#[test]
fn higher_position_applies_base85_weight() {
    assert_eq!(z85_decode("000#0"), Ok(vec![0u8, 0, 0x1B, 0xE4]));
}

/// A concrete full-range u32: 0x11223344 encodes to "5H620".
#[test]
fn exact_u32_vector_11223344() {
    assert_eq!(z85_decode("5H620"), Ok(vec![0x11u8, 0x22, 0x33, 0x44]));
}

/// Fresh two-frame vector (distinct from the sibling's "00000%nSc0"):
/// bytes CA FE BA BE DE AD F0 0D encode to "+kO#^?MunR".
#[test]
fn two_frame_contiguous_fresh_vector() {
    assert_eq!(
        z85_decode("+kO#^?MunR"),
        Ok(vec![0xCAu8, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xF0, 0x0D])
    );
}

/// A single frame that decodes to printable ASCII "AB!!" -> "k%=.r".
#[test]
fn single_frame_decodes_to_ascii_text() {
    assert_eq!(z85_decode("k%=.r"), Ok(b"AB!!".to_vec()));
}

/// All-zero two frames => eight zero bytes; also fixes output length = in/5*4.
#[test]
fn all_zero_two_frames_yield_eight_zero_bytes() {
    let out = z85_decode("0000000000").expect("valid all-zero frames");
    assert_eq!(out, vec![0u8; 8]);
    assert_eq!(out.len(), 8);
}

/// Positive boundary: "%nSc0" is exactly u32::MAX => four 0xFF bytes.
#[test]
fn max_u32_frame_decodes_to_four_ff_bytes() {
    assert_eq!(z85_decode("%nSc0"), Ok(vec![0xFFu8, 0xFF, 0xFF, 0xFF]));
}

/// Negative twin of the max: "%nSc1" is u32::MAX + 1 (0x1_0000_0000), which
/// overflows a u32 frame and must be refused.
#[test]
fn smallest_overflow_frame_is_err() {
    assert_eq!(z85_decode("%nSc1"), Err(()));
    // sanity: it is exactly one past the valid maximum.
    assert_eq!(z85_decode("%nSc0"), Ok(vec![0xFFu8, 0xFF, 0xFF, 0xFF]));
}

/// Length not a multiple of 5 is refused regardless of validity of the symbols.
#[test]
fn length_not_multiple_of_five_is_err() {
    assert_eq!(z85_decode("0"), Err(())); // len 1
    assert_eq!(z85_decode("000"), Err(())); // len 3
    assert_eq!(z85_decode("0000"), Err(())); // len 4
    assert_eq!(z85_decode("000000"), Err(())); // len 6
    assert_eq!(z85_decode("000000000"), Err(())); // len 9
}

/// Empty input is a valid multiple of 5 (zero frames) => empty output.
#[test]
fn empty_input_decodes_to_empty_vec() {
    assert_eq!(z85_decode(""), Ok(Vec::<u8>::new()));
}

/// Comma is not in the Z85 alphabet: a length-valid frame containing it fails.
#[test]
fn comma_symbol_is_refused() {
    assert_eq!(z85_decode("0000,"), Err(()));
}

/// Whitespace bytes are not Z85 symbols; a 5-byte frame carrying one is refused
/// (the decoder itself does no whitespace stripping, that happens only in the
/// span visitor before decode).
#[test]
fn whitespace_symbols_are_refused() {
    assert_eq!(z85_decode("0000 "), Err(())); // space 0x20
    assert_eq!(z85_decode("0000\t"), Err(())); // tab 0x09
    assert_eq!(z85_decode("0000\n"), Err(())); // newline 0x0A
}

/// The ASCII gaps immediately around the alphabet ranges must be refused:
/// '`' (0x60, between 'Z'/symbol block and 'a') and '~' (0x7E, above '#').
#[test]
fn ascii_gap_symbols_are_refused() {
    assert_eq!(z85_decode("0000`"), Err(())); // 0x60
    assert_eq!(z85_decode("0000~"), Err(())); // 0x7E
}

/// Decoded output length is deterministically input_len/5*4 for valid input.
#[test]
fn decoded_length_is_four_fifths_of_input() {
    // four frames (20 chars) => 16 bytes
    let out = z85_decode("00000000000000000000").expect("four valid frames");
    assert_eq!(out.len(), 16);
    assert_eq!(out, vec![0u8; 16]);
}
