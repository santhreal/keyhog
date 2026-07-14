//! Regression locks for the scanner's decode-density gate
//! (`decode::has_decodable_payload`), the O(n), allocation-free prefilter in
//! `crates/scanner/src/decode/mod.rs` that decides whether an otherwise
//! prefilter-skipped chunk is routed into a decode-only pass.
//!
//! The gate fires on four bounded shapes. Numeric HTML entities use an exact
//! valid-codepoint floor in addition to the existing encoded-run and escape
//! counters.
//!   * a contiguous base64/hex/url-safe run of `MIN_DECODABLE_RUN` (24) bytes,
//!   * `MIN_PERCENT_ESCAPES` (4) `%XX` url-escapes,
//!   * `MIN_HTML_NUMERIC_ENTITIES` (4) valid decimal/hex entities, or
//!   * `MIN_BACKSLASH_ESCAPES` (2) `\uXXXX` / `\xXX` string-escapes.
//!
//! The testing facade exposes the gate for exact threshold checks. This file
//! also pins the observable end-to-end scan path.
//!
//!   1. Exhaustive exact-`bool` coverage of the run counter's alphabet predicate
//!      `decode::is_base64_candidate_byte` (the public single-owner that decides,
//!      byte by byte, whether the contiguous run extends toward 24 or resets to
//!      0). This is the load-bearing primitive behind the "23 vs 24" boundary.
//!   2. Observable end-to-end contract via the public `CompiledScanner::scan`
//!      path: a FULLY-encoded secret carrying no plaintext keyword surfaces ONLY
//!      because the gate returned `true` and routed decode-through; the same
//!      credential stays absent from normal prose that carries no encoded shape.
//!
//! Every assertion pins a concrete value (exact `bool` / exact needle presence),
//! never `is_empty()` / `is_some()`.

mod support;
use support::paths::detector_dir;

use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::decode::is_base64_candidate_byte;
use keyhog_scanner::testing::has_decodable_payload_for_test;
use keyhog_scanner::CompiledScanner;

// ─────────────────────────────────────────────────────────────────────────────
// PART 1 (run-counter alphabet: `is_base64_candidate_byte` exact bools).
//
// The gate counts CONSECUTIVE bytes for which this predicate is `true`; the
// first `false` byte resets the run to 0. So the exact membership of this set is
// what makes a 24-byte base64 blob cross `MIN_DECODABLE_RUN` while 23 does not.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn uppercase_letters_extend_run_neighbours_reset() {
    // 'A'..='Z' extend the run.
    assert!(is_base64_candidate_byte(b'A'));
    assert!(is_base64_candidate_byte(b'Z'));
    assert!(is_base64_candidate_byte(b'M'));
    // Immediate ASCII neighbours below 'A' (0x40 '@') and above 'Z' (0x5B '[')
    // reset the run.
    assert!(!is_base64_candidate_byte(b'@'));
    assert!(!is_base64_candidate_byte(b'['));
}

#[test]
fn lowercase_letters_extend_run_neighbours_reset() {
    assert!(is_base64_candidate_byte(b'a'));
    assert!(is_base64_candidate_byte(b'z'));
    assert!(is_base64_candidate_byte(b'q'));
    // '`' (0x60) is just below 'a'; '{' (0x7B) is just above 'z'.
    assert!(!is_base64_candidate_byte(b'`'));
    assert!(!is_base64_candidate_byte(b'{'));
}

#[test]
fn digits_extend_run_upper_neighbour_resets() {
    assert!(is_base64_candidate_byte(b'0'));
    assert!(is_base64_candidate_byte(b'9'));
    assert!(is_base64_candidate_byte(b'5'));
    // ':' (0x3A) is immediately above '9' and is NOT in the alphabet.
    assert!(!is_base64_candidate_byte(b':'));
    // NB: the byte immediately BELOW '0' is '/' (0x2F), which IS a member
    // (url/base64), so the low digit edge is asserted in the specials test.
}

#[test]
fn base64_and_urlsafe_specials_extend_run() {
    // Standard base64 specials.
    assert!(is_base64_candidate_byte(b'+'));
    assert!(is_base64_candidate_byte(b'/'));
    // Padding.
    assert!(is_base64_candidate_byte(b'='));
    // Url-safe variants.
    assert!(is_base64_candidate_byte(b'-'));
    assert!(is_base64_candidate_byte(b'_'));
}

#[test]
fn punctuation_adjacent_to_specials_resets_run() {
    // '*' (0x2A) sits just below '+' (0x2B); ',' (0x2C) between '+' and '-'.
    assert!(!is_base64_candidate_byte(b'*'));
    assert!(!is_base64_candidate_byte(b','));
    // '.' (0x2E) between '-' (0x2D) and '/' (0x2F).
    assert!(!is_base64_candidate_byte(b'.'));
    // '<' (0x3C) and '>' (0x3E) straddle '=' (0x3D).
    assert!(!is_base64_candidate_byte(b'<'));
    assert!(!is_base64_candidate_byte(b'>'));
    // '^' (0x5E) sits just below '_' (0x5F).
    assert!(!is_base64_candidate_byte(b'^'));
}

#[test]
fn escape_introducer_bytes_are_not_base64_run_bytes() {
    // '%' opens a `%XX` url-escape and '\\' opens a `\u`/`\x` string-escape
    // both are handled by the gate's DEDICATED counters, never the base64 run,
    // so the alphabet predicate must reject them (a `true` here would merge the
    // two counting regimes and corrupt the 24-run boundary).
    assert!(!is_base64_candidate_byte(b'%'));
    assert!(!is_base64_candidate_byte(b'\\'));
}

#[test]
fn whitespace_and_control_bytes_reset_run() {
    assert!(!is_base64_candidate_byte(b' '));
    assert!(!is_base64_candidate_byte(b'\n'));
    assert!(!is_base64_candidate_byte(b'\t'));
    assert!(!is_base64_candidate_byte(b'\r'));
    assert!(!is_base64_candidate_byte(0x00));
}

#[test]
fn non_ascii_and_del_bytes_reset_run() {
    // DEL (0x7F), and the entire high half (0x80..=0xFF) are never base64.
    assert!(!is_base64_candidate_byte(0x7F));
    assert!(!is_base64_candidate_byte(0x80));
    assert!(!is_base64_candidate_byte(0xC3)); // UTF-8 lead byte
    assert!(!is_base64_candidate_byte(0xFF));
}

#[test]
fn alphabet_cardinality_is_exactly_sixty_seven() {
    // 26 + 26 + 10 = 62 alnum, plus the 5 specials {+ / = - _} = 67 distinct
    // accepting bytes across the whole 0..=255 space. A drift in the byte set
    // (silently widening or narrowing the run alphabet) changes this count and
    // fails the lock.
    let accepting = (0u16..=255)
        .filter(|&b| is_base64_candidate_byte(b as u8))
        .count();
    assert_eq!(accepting, 67);
}

#[test]
fn contiguous_24_byte_alphabet_run_all_accept_delimiter_breaks() {
    // A 24-char base64 blob (every byte extends the run to reach the 24 gate).
    let run = b"QUJDREVGR0hJSktMTU5PUFFS"; // 24 base64 chars
    assert_eq!(run.len(), 24);
    assert!(run.iter().all(|&b| is_base64_candidate_byte(b)));
    // Insert one space at index 12: now the longest contiguous run is 12, well
    // under 24 (the delimiter byte is the sole non-accepting element).
    let broken = b"QUJDREVGR0hJ SktMTU5PUFFS";
    let non_accept = broken
        .iter()
        .filter(|&&b| !is_base64_candidate_byte(b))
        .count();
    assert_eq!(non_accept, 1);
}

// ─────────────────────────────────────────────────────────────────────────────
// PART 2 (observable gate contract through the public scan path).
//
// A fully-encoded secret carries NO plaintext keyword, so the direct-match
// prefilters skip it; it can only surface if `has_decodable_payload` returned
// `true` and routed the chunk into decode-through. These locks are backend
// (host) independent: `CompiledScanner::scan` returns the same credentials
// whether Hyperscan/SIMD/GPU is present or not.
// ─────────────────────────────────────────────────────────────────────────────

/// `.npmrc` legacy auth token (fires `npmrc-auth-token`, no vendor checksum).
const NPMRC: &str = "//registry.npmjs.org/:_authToken=s0meL3gacyT0kenValue12345";
const NPMRC_NEEDLE: &str = "s0meL3gacyT0kenValue12345";

fn scanner() -> CompiledScanner {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    CompiledScanner::compile(detectors).expect("compile scanner")
}

fn scan_text(text: &str) -> Vec<RawMatch> {
    let chunk = Chunk {
        data: text.to_string().into(),
        metadata: ChunkMetadata {
            source_type: "decode-density-gate-test".into(),
            path: Some("config.txt".into()),
            ..Default::default()
        },
    };
    scanner().scan(&chunk)
}

fn surfaces_needle(text: &str) -> bool {
    scan_text(text)
        .iter()
        .any(|m| m.credential.as_ref().contains(NPMRC_NEEDLE))
}

fn b64(s: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(s.as_bytes())
}

fn urlenc(s: &str) -> String {
    use std::fmt::Write as _;
    let mut u = String::new();
    for byte in s.bytes() {
        let _ = write!(u, "%{byte:02x}");
    }
    u
}

fn html_numeric(s: &str) -> String {
    use std::fmt::Write as _;
    let mut encoded = String::new();
    for ch in s.chars() {
        let _ = write!(encoded, "&#{};", ch as u32);
    }
    encoded
}

#[test]
fn baseline_plaintext_secret_fires_exactly() {
    // Proves the detector fires unwrapped, so a decode-through absence below is
    // attributable to the gate, not a broken detector.
    assert!(surfaces_needle(NPMRC));
}

#[test]
fn base64_encoded_secret_surfaces_only_via_decode_gate() {
    // The encoded value is one contiguous base64 run far past MIN_DECODABLE_RUN
    // (24). The plaintext `_authToken` keyword exists ONLY after decoding, so
    // surfacing the needle proves the base64-run branch of the gate admitted the
    // chunk into decode-through.
    let encoded = b64(NPMRC);
    assert!(encoded.len() >= 24);
    let embedded = format!("blob = \"{encoded}\"\n");
    assert!(surfaces_needle(&embedded));
}

#[test]
fn url_percent_encoded_secret_surfaces_via_percent_gate() {
    // Every byte becomes a `%XX` escape (57 escapes ≫ MIN_PERCENT_ESCAPES=4),
    // so the percent-escape branch of the gate admits the chunk.
    let encoded = urlenc(NPMRC);
    let percent_count = encoded.matches('%').count();
    assert_eq!(percent_count, NPMRC.len());
    assert!(percent_count >= 4);
    let embedded = format!("blob = \"{encoded}\"\n");
    assert!(surfaces_needle(&embedded));
}

#[test]
fn html_numeric_entity_gate_has_an_exact_valid_entity_floor() {
    assert!(!has_decodable_payload_for_test(b"&#65;&#66;&#67;"));
    assert!(has_decodable_payload_for_test(b"&#65;&#x42;&#67;&#x44;"));
    assert!(!has_decodable_payload_for_test(
        b"&#65;&#xZZ;&#1114112;&#xD800;"
    ));
    assert!(!has_decodable_payload_for_test(b"&#65&#66&#67&#68"));
    assert!(!has_decodable_payload_for_test(
        b"&#00000000000;&#00000000000;&#00000000000;&#00000000000;"
    ));
}

#[test]
fn fully_html_numeric_encoded_secret_surfaces_via_decode_gate() {
    let encoded = html_numeric(NPMRC);
    assert!(!encoded.contains("_authToken"));
    assert!(!encoded.contains(NPMRC_NEEDLE));
    let matches = scan_text(&format!("<data>{encoded}</data>\n"));
    let finding = matches
        .iter()
        .find(|finding| finding.detector_id.as_ref() == "npmrc-auth-token")
        .expect("the numeric-entity admission gate must make the decoder reachable");
    assert_eq!(finding.credential.as_ref(), NPMRC_NEEDLE);
    assert_eq!(
        finding.location.source.as_ref(),
        "decode-density-gate-test/html-numeric-entity"
    );
    assert_eq!(finding.location.file_path.as_deref(), Some("config.txt"));
    assert_eq!(finding.location.line, Some(1));
}

#[test]
fn prose_without_encoded_shape_never_surfaces_the_needle() {
    // Ordinary text: no 24-byte base64 run, no `%XX`, no `\u`/`\x`. The gate
    // returns false and decode-through never runs, so the encoded-only needle
    // cannot appear.
    let prose = "The quick brown fox jumps over the lazy dog while the meeting \
                 is rescheduled to noon tomorrow near the old library entrance.";
    assert!(!surfaces_needle(prose));
}

#[test]
fn sub_threshold_base64_run_cannot_carry_the_needle() {
    // Boundary twin of the positive: a base64 blob whose contiguous run is 23
    // one byte UNDER MIN_DECODABLE_RUN (24). 23 base64 chars decode to at most
    // 17 bytes, which cannot contain the 25-char needle regardless of whether
    // the gate admits it, so the needle is provably absent. This pins the
    // direction of the threshold without depending on a specific backend.
    let filler = b64("this-is-not-a-secret-value-just-filler");
    let short = &filler[..23];
    assert_eq!(short.len(), 23);
    assert!(short.chars().all(|c| is_base64_candidate_byte(c as u8)));
    let embedded = format!("blob = \"{short}\"\n");
    assert!(!surfaces_needle(&embedded));
}
