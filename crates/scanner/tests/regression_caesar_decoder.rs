//! Regression: Caesar/ROT-N decoder recovery, shaping gates, and skip rules.
//!
//! Locks the behavioural contract of `crates/scanner/src/decode/caesar.rs`:
//!   * `caesar_shift` rotates ASCII letters only, mod 26, digits/punct fixed;
//!   * a Caesar-shifted known-prefix credential is recovered at the EXACT
//!     inverse shift and the rotated-prefix automaton selects that shift;
//!   * the shape gates (`candidate_shape_invariant` / `looks_credential_shaped`)
//!     enforce the `MIN_ALNUM_RUN` run, a digit, a letter, and a known prefix;
//!   * `CaesarDecoder::decode_chunk` recovers a planted rotation but SKIPS
//!     credential-URL lines, source-code paths, its own `/caesar` output, and
//!     candidates below `MIN_CAESAR_LEN`.
//!
//! Every assertion pins a concrete value (exact bytes / bools / counts), never
//! a mere non-emptiness check.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::testing::decode_caesar;
use keyhog_scanner::testing::CaesarDecoder;

/// The planted AWS-access-key-shaped credential (starts with the `AKIA` known
/// prefix, all-alphanumeric, contains digits, 20 chars ≥ `MIN_CAESAR_LEN`).
const PLANTED: &str = "AKIA1234567890ABCDEF";
/// `PLANTED` Caesar-shifted forward by 3 (the on-disk "encoded" form). Its
/// inverse recovery shift is therefore 26 - 3 = 23.
const ENCODED_SHIFT3: &str = "DNLD1234567890DEFGHI";

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

#[test]
fn caesar_shift_rotates_letters_preserves_digits_and_punct() {
    // Forward shift of the planted credential by 3: letters rotate, the 10
    // digits are identity.
    assert_eq!(decode_caesar::caesar_shift(PLANTED, 3), ENCODED_SHIFT3);
    // Mixed case + punctuation + digits: only the letters move.
    // a->b b->c, '-' '1' '2' '_' fixed, Y->Z, Z->A.
    assert_eq!(decode_caesar::caesar_shift("ab-12_YZ", 1), "bc-12_ZA");
}

#[test]
fn caesar_shift_wraps_and_is_identity_at_zero_and_full_alphabet() {
    // Wraparound at the top of each case: Z->A, z->a.
    assert_eq!(decode_caesar::caesar_shift("Zz", 1), "Aa");
    // Shift 0 and shift 26 are both the identity (mod 26).
    assert_eq!(decode_caesar::caesar_shift("AKIA1234", 0), "AKIA1234");
    assert_eq!(decode_caesar::caesar_shift("AKIA1234", 26), "AKIA1234");
}

#[test]
fn recovers_known_prefix_credential_at_exact_shift() {
    // The rotated-prefix automaton must select exactly shift 23 (the inverse of
    // the +3 encoding) because the encoded blob contains needle(AKIA, 23) =
    // caesar_shift("AKIA", 3) = "DNLD".
    let matched = decode_caesar::matched_caesar_shifts(ENCODED_SHIFT3);
    assert!(
        matched[23],
        "inverse shift 23 must be selected for {ENCODED_SHIFT3}"
    );
    // Slot 0 is never a Caesar shift (loop is 1..=25).
    assert!(!matched[0], "shift 0 must never be selected");

    // Applying the selected shift recovers the exact planted bytes.
    let recovered = decode_caesar::caesar_shift(ENCODED_SHIFT3, 23);
    assert_eq!(recovered, PLANTED);
    // And the recovered value passes the credential-shape gate.
    assert!(decode_caesar::looks_credential_shaped(&recovered));

    // A neighbouring wrong shift does NOT recover the credential.
    assert_ne!(decode_caesar::caesar_shift(ENCODED_SHIFT3, 24), PLANTED);
    assert_ne!(decode_caesar::caesar_shift(ENCODED_SHIFT3, 22), PLANTED);
}

#[test]
fn rot13_roundtrip_recovers_ghp_prefixed_credential() {
    // A GitHub PAT-shaped credential (`ghp_` prefix) ROT13'd on disk.
    let original = "ghp_abcdefgh12345678";
    let encoded = decode_caesar::caesar_shift(original, 13);
    assert_eq!(encoded, "tuc_nopqrstu12345678");

    // ROT13 is its own inverse; the automaton selects shift 13.
    let matched = decode_caesar::matched_caesar_shifts(&encoded);
    assert!(matched[13], "ROT13 inverse shift 13 must be selected");

    let recovered = decode_caesar::caesar_shift(&encoded, 13);
    assert_eq!(recovered, original);
    assert!(decode_caesar::looks_credential_shaped(&recovered));
}

#[test]
fn matched_shifts_empty_when_no_rotated_prefix_present() {
    // No rotation of any known prefix can appear in an all-lowercase run of
    // z's plus a lone digit (rotated prefixes carry uppercase, `_`, `-`, `.`,
    // or a leading `0`, none of which are present), so the entire 25-shift
    // fan-out is provably dead work.
    let matched = decode_caesar::matched_caesar_shifts("zzzzzzzzzzzzzzzz1");
    let selected = matched.iter().filter(|&&b| b).count();
    assert_eq!(selected, 0, "no shift should be selected: {matched:?}");
}

#[test]
fn candidate_shape_invariant_requires_a_digit() {
    // 16 letters, no digit -> the shift-invariant precondition fails, so the
    // whole 25x fan-out is skipped for this candidate.
    assert!(!decode_caesar::candidate_shape_invariant(
        "ABCDEFGHIJKLMNOP"
    ));
    // Add a digit and keep an 8+ alnum run -> it passes.
    assert!(decode_caesar::candidate_shape_invariant("abcdefgh1"));
}

#[test]
fn candidate_shape_invariant_requires_a_letter() {
    // Digit + an 8-char alnum run BUT no letter: a Caesar shift can do nothing,
    // so the invariant rejects it even though the digit/run half is satisfied.
    assert!(!decode_caesar::candidate_shape_invariant("12345678"));
}

#[test]
fn candidate_shape_invariant_requires_eight_char_alnum_run() {
    // Punctuation chops every alnum run below MIN_ALNUM_RUN (=8): max run here
    // is 2, so the invariant fails despite a letter and a digit being present.
    assert!(!decode_caesar::candidate_shape_invariant("ab-12-cd-34"));
    // Exactly an 8-char contiguous alnum run passes the boundary.
    assert!(decode_caesar::candidate_shape_invariant("abcdefg1"));
    // A 7-char run is one short and fails.
    assert!(!decode_caesar::candidate_shape_invariant("abcdef1-x"));
}

#[test]
fn min_alnum_run_gate_rejects_short_and_punctuated_candidates() {
    // `looks_credential_shaped` requires an 8+ contiguous ASCII-alphanumeric
    // run. A known prefix split by punctuation never reaches the run length.
    assert!(!decode_caesar::looks_credential_shaped("AKIA-12-34"));
    // Exactly 8 alnum chars (AKIA1234) hits the boundary and passes.
    assert!(decode_caesar::looks_credential_shaped("AKIA1234"));
    // 7 alnum chars is one below the floor and fails.
    assert!(!decode_caesar::looks_credential_shaped("AKIA123"));
}

#[test]
fn looks_credential_shaped_requires_known_provider_prefix() {
    // Digit + a 16-char alnum run but NO known provider prefix: an incidental
    // shift of a real secret must not be emitted as a finding.
    assert!(!decode_caesar::looks_credential_shaped("ph1ifsb2cdefghij"));
    // The same shape carrying the `AKIA` prefix is credential-shaped.
    assert!(decode_caesar::looks_credential_shaped("AKIA5678cdefghij"));
}

#[test]
fn decode_chunk_recovers_planted_caesar_credential() {
    let body = format!("api_token = \"{ENCODED_SHIFT3}\"\n");
    let out = CaesarDecoder.decode_chunk(&chunk(&body, "filesystem", Some("secrets.env")));

    // The exact planted credential is recovered as a decoded sub-chunk.
    assert!(
        any_output_equals(&out, PLANTED),
        "decoder must recover {PLANTED}: {out:#?}"
    );
    // Every emitted sub-chunk is tagged with the caesar decoder source-type.
    assert!(
        out.iter()
            .all(|oc| oc.metadata.source_type == "filesystem/caesar"),
        "all outputs must be tagged /caesar: {out:#?}"
    );
}

#[test]
fn decode_chunk_skips_line_with_embedded_credential_url() {
    // The SAME encoded token, but sitting inside a `scheme://user:pass@host`
    // credential URL. The whole line is a credential-URL span, so every
    // candidate on it is skipped and NOTHING is decoded — the plaintext URL is
    // already the credential and the 25-shift fan-out would only manufacture a
    // garbage finding that out-resolves the real connection string.
    let body = format!("db_url = \"postgres://admin:{ENCODED_SHIFT3}@db.example.com:5432/app\"\n");
    let out = CaesarDecoder.decode_chunk(&chunk(&body, "filesystem", Some("app.env")));

    assert_eq!(
        out.len(),
        0,
        "credential-URL line must be skipped: {out:#?}"
    );
    assert!(
        !any_output_equals(&out, PLANTED),
        "no recovery from a credential-URL line"
    );
}

#[test]
fn decode_chunk_skips_source_code_path() {
    // Identical recoverable token, but the chunk's path is program source
    // (`.py`). Caesar decoding of source is pure noise and is refused entirely.
    let body = format!("api_token = \"{ENCODED_SHIFT3}\"\n");
    let out = CaesarDecoder.decode_chunk(&chunk(&body, "filesystem", Some("app.py")));
    assert_eq!(out.len(), 0, "source-code path must be skipped: {out:#?}");
}

#[test]
fn decode_chunk_refuses_to_recurse_on_own_caesar_output() {
    // A chunk whose source_type already carries `/caesar` (i.e. it is a prior
    // decode output) must not be re-shifted — one of the 25 shifts would just
    // rotate it back to the original.
    let body = format!("api_token = \"{ENCODED_SHIFT3}\"\n");
    let out = CaesarDecoder.decode_chunk(&chunk(&body, "filesystem/caesar", Some("secrets.env")));
    assert_eq!(
        out.len(),
        0,
        "must not recurse on own /caesar output: {out:#?}"
    );
}

#[test]
fn decode_chunk_enforces_min_caesar_len() {
    // The MIN_CAESAR_LEN floor is 16 chars.
    assert_eq!(decode_caesar::MIN_CAESAR_LEN, 16);
    // A 10-char candidate is below the floor and is never shifted, so no
    // credential is manufactured even though its +3 rotation would begin AKIA.
    let out = CaesarDecoder.decode_chunk(&chunk("t = \"DNLD12ABCD\"\n", "filesystem", None));
    assert_eq!(
        out.len(),
        0,
        "sub-MIN_CAESAR_LEN candidate must be skipped: {out:#?}"
    );
}

#[test]
fn source_path_classification_matches_expected() {
    // Program source: extension-driven and filename-driven.
    assert!(decode_caesar::is_program_source_code_path(Some("main.rs")));
    assert!(decode_caesar::is_program_source_code_path(Some("Makefile")));
    // A doc file is NOT program source (entropy suppression must not inherit it).
    assert!(!decode_caesar::is_program_source_code_path(Some(
        "README.md"
    )));
    assert!(!decode_caesar::is_program_source_code_path(None));

    // The broader Caesar "source or text-noise" set: program source AND docs.
    assert!(decode_caesar::is_source_code_path(Some("app.py")));
    assert!(decode_caesar::is_source_code_path(Some("README.md")));
    assert!(decode_caesar::is_source_code_path(Some("notes.txt")));
    // A `.env` secrets file is neither, so Caesar decoding is allowed there.
    assert!(!decode_caesar::is_source_code_path(Some("secrets.env")));
    assert!(!decode_caesar::is_source_code_path(None));
}
