//! Regression: hex decoder decode-through (`crates/scanner/src/decode/hex.rs`).
//!
//! Pins the exact contract of the shipped hex decoder and its decode-through
//! wiring into the full scanner:
//!
//!   * `hex_decode` returns the EXACT decoded bytes for well-formed even-length
//!     hex (including underscore-separated firmware-style literals), and
//!     REJECTS odd-length / non-hex / odd-cleaned inputs with `Err(())`.
//!   * `find_hex_strings` extracts hex candidates at/above the caller's
//!     `min_length` floor and drops odd-length and non-hex look-alikes.
//!   * A hex-encoded AWS access key decodes THROUGH the pipeline and the SAME
//!     detector (`aws-access-key`) fires on the recovered plaintext bytes.
//!   * A hex-encoded *gzip* stream stays OPAQUE: the hex decoder has no inflate
//!     stage and the decoded bytes are binary (not valid UTF-8), so the
//!     credential compressed inside is never surfaced (documented gap, count 0).
//!
//! Every assertion pins a concrete value (exact bytes / exact string / exact
//! count / exact detector id), never a bare `is_empty()`/`is_ok()` shape check.

mod support;
use std::io::Write;
use support::paths::detector_dir;

use flate2::write::GzEncoder;
use flate2::Compression;
use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::decode::{find_hex_strings, hex_decode};
use keyhog_scanner::CompiledScanner;

/// Bare canonical AWS access key from `tests/contracts/aws-access-key.toml`
/// (fires with no surrounding anchor).
const AWS_KEY: &str = "AKIAQYLPMN5HFIQR7XYA";
/// Lowercase hex of `AWS_KEY.as_bytes()` (20 bytes -> 40 hex chars).
const AWS_KEY_HEX: &str = "414b494151594c504d4e35484649515237585941";

// ── scanner harness ──────────────────────────────────────────────────

fn full_scanner() -> CompiledScanner {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors from disk");
    CompiledScanner::compile(detectors).expect("compile full detector scanner")
}

fn make_chunk(text: &str) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "hex-decode-through".into(),
            path: Some("hex.txt".into()),
            ..Default::default()
        },
    }
}

/// Detector ids that fired on `credential` (exact string match against the
/// surfaced credential bytes), sorted + deduped for stable comparison.
fn detector_ids_for_credential(matches: &[RawMatch], credential: &str) -> Vec<String> {
    let mut ids: Vec<String> = matches
        .iter()
        .filter(|m| &*m.credential == credential)
        .map(|m| (*m.detector_id).to_string())
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

// ── hex_decode: positive exact-byte decoding ─────────────────────────

#[test]
fn hex_decode_valid_even_bytes_exact() {
    // "414243" -> 0x41 0x42 0x43 == b"ABC".
    let decoded = hex_decode("414243").expect("well-formed even hex decodes");
    assert_eq!(decoded, vec![0x41u8, 0x42, 0x43]);
    assert_eq!(decoded, b"ABC".to_vec());
}

#[test]
fn hex_decode_aws_key_roundtrip_exact() {
    // The lowercase hex of the AWS key decodes back to the exact key bytes.
    let decoded = hex_decode(AWS_KEY_HEX).expect("aws-key hex decodes");
    assert_eq!(decoded, AWS_KEY.as_bytes().to_vec());
    assert_eq!(String::from_utf8(decoded).unwrap(), AWS_KEY.to_string());
}

#[test]
fn hex_decode_uppercase_and_lowercase_agree() {
    // hex-simd accepts both cases; both must produce the identical bytes.
    let lower = hex_decode("4a4b").expect("lowercase hex decodes");
    let upper = hex_decode("4A4B").expect("uppercase hex decodes");
    assert_eq!(lower, vec![0x4au8, 0x4b]);
    assert_eq!(upper, vec![0x4au8, 0x4b]);
    assert_eq!(lower, upper);
    assert_eq!(String::from_utf8(lower).unwrap(), "JK".to_string());
}

#[test]
fn hex_decode_underscore_separated_decodes() {
    // Firmware/config `_`-grouped hex: underscores are stripped, then decoded.
    let decoded = hex_decode("41_42_43").expect("underscore-grouped hex decodes");
    assert_eq!(decoded, b"ABC".to_vec());
}

#[test]
fn hex_decode_empty_input_yields_empty_bytes() {
    // Length 0 is a multiple of 2 and has no underscore: hex-simd returns [].
    let decoded = hex_decode("").expect("empty hex is well-formed");
    assert_eq!(decoded, Vec::<u8>::new());
}

#[test]
fn hex_decode_single_byte_ff_boundary() {
    // Smallest well-formed even hex (one byte) and its odd-length twin.
    let decoded = hex_decode("ff").expect("two-char hex decodes to one byte");
    assert_eq!(decoded, vec![0xffu8]);
    // A single hex digit is odd length -> rejected.
    assert_eq!(hex_decode("f").unwrap_err(), ());
}

// ── hex_decode: negative twins ───────────────────────────────────────

#[test]
fn hex_decode_odd_length_rejected() {
    // 5 chars: not a multiple of 2 -> Err before hex-simd runs.
    assert_eq!(hex_decode("41424").unwrap_err(), ());
}

#[test]
fn hex_decode_nonhex_chars_rejected() {
    // Even length (4) but non-hex bytes: the char check inside hex-simd fails.
    assert_eq!(hex_decode("gg41").unwrap_err(), ());
    assert_eq!(hex_decode("zzzz").unwrap_err(), ());
}

#[test]
fn hex_decode_underscore_odd_cleaned_rejected() {
    // "41_4" -> stripped "414" is length 3 (odd) -> rejected.
    assert_eq!(hex_decode("41_4").unwrap_err(), ());
}

// ── find_hex_strings: extraction floor + rejection ───────────────────

#[test]
fn find_hex_strings_extracts_freestanding_run() {
    // A freestanding 40-char hex run is one candidate at min_length 16.
    let found = find_hex_strings(AWS_KEY_HEX, 16);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].value, AWS_KEY_HEX.to_string());
}

#[test]
fn find_hex_strings_min_length_boundary() {
    // Quoted 16-hex value: extracted as a candidate regardless of floor, then
    // is_hex_candidate applies the caller's min_length.
    let text = "key = \"0123456789abcdef\"";
    let at_floor = find_hex_strings(text, 16);
    assert_eq!(at_floor.len(), 1);
    assert_eq!(at_floor[0].value, "0123456789abcdef".to_string());
    // One above the 16-char length -> below floor -> dropped.
    let above_floor = find_hex_strings(text, 17);
    assert_eq!(above_floor.len(), 0);
}

#[test]
fn find_hex_strings_rejects_odd_and_nonhex() {
    // Odd length (15 hex chars) -> not a hex candidate.
    let odd = find_hex_strings("key = \"0123456789abcde\"", 8);
    assert_eq!(odd.len(), 0);
    // Even length (16) but a non-hex 'g' -> not a hex candidate.
    let nonhex = find_hex_strings("key = \"0123456789abcdeg\"", 8);
    assert_eq!(nonhex.len(), 0);
    // Control: the corrected 16-hex twin IS a candidate.
    let ok = find_hex_strings("key = \"0123456789abcdef\"", 8);
    assert_eq!(ok.len(), 1);
    assert_eq!(ok[0].value, "0123456789abcdef".to_string());
}

// ── decode-through: same detector fires on decoded bytes ─────────────

#[test]
fn hex_encoded_aws_key_decodes_through_same_detector() {
    let scanner = full_scanner();

    // Baseline: the plaintext key fires the aws-access-key detector.
    scanner.clear_fragment_cache();
    let plain = scanner.scan(&make_chunk(AWS_KEY));
    let plain_ids = detector_ids_for_credential(&plain, AWS_KEY);
    assert!(
        plain_ids.iter().any(|id| id == "aws-access-key"),
        "plaintext AWS key must fire aws-access-key; got {plain_ids:?}"
    );

    // Hex-encode ONLY the credential inside a realistic assignment. The hex
    // decoder must recover the exact key bytes and the SAME detector fires.
    let encoded_line = format!("aws_access_key_id = {AWS_KEY_HEX}\n");
    scanner.clear_fragment_cache();
    let decoded = scanner.scan(&make_chunk(&encoded_line));
    let decoded_ids = detector_ids_for_credential(&decoded, AWS_KEY);
    assert!(
        decoded.iter().any(|m| &*m.credential == AWS_KEY),
        "hex-encoded AWS key must be recovered verbatim via decode-through"
    );
    assert!(
        decoded_ids.iter().any(|id| id == "aws-access-key"),
        "decode-through must fire the SAME aws-access-key detector; got {decoded_ids:?}"
    );
}

// ── documented gap: hex decoder has no inflate stage ─────────────────

#[test]
fn hex_encoded_gzip_stays_opaque_no_inflate_stage() {
    // Compress the AWS key so its plaintext bytes never appear directly.
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(format!("{AWS_KEY} in gzip").as_bytes())
        .expect("gzip write");
    let gzip_bytes = encoder.finish().expect("gzip finish");

    // gzip magic header 0x1f 0x8b confirms we built a real gzip stream.
    assert_eq!(&gzip_bytes[..2], &[0x1fu8, 0x8b]);

    // hex-encode the gzip bytes, then round-trip through the hex decoder.
    let gzip_hex = hex::encode(&gzip_bytes);
    let decoded = hex_decode(&gzip_hex).expect("hex of gzip decodes to raw gzip bytes");
    // The hex decoder returns the RAW gzip bytes verbatim (no inflate stage).
    assert_eq!(decoded, gzip_bytes);
    assert_eq!(&decoded[..2], &[0x1fu8, 0x8b]);
    // The decoded bytes are binary, so the UTF-8 gate in `HexDecoder::decode_chunk`
    // drops them: the hex path cannot surface the compressed credential.
    assert!(
        String::from_utf8(decoded).is_err(),
        "raw gzip bytes must be non-UTF-8 so the hex decode_chunk gate drops them"
    );

    // End to end: scanning the hex-encoded gzip surfaces ZERO matches carrying
    // the compressed AWS key (the documented gap (hex has no inflate stage)).
    let scanner = full_scanner();
    scanner.clear_fragment_cache();
    let matches = scanner.scan(&make_chunk(&gzip_hex));
    let recovered = matches.iter().filter(|m| &*m.credential == AWS_KEY).count();
    assert_eq!(recovered, 0);
}
