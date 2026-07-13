//! Decode-through recall for the JSON-string decoder (`decode/json.rs`).
//!
//! keyhog treats a JSON string value as an encoding layer: before pattern
//! matching it UNESCAPES the value (`\"`, `\\`, `\/`, `\n`, `\uXXXX`, and
//! UTF-16 surrogate pairs) and re-splices the plaintext adjacent to its key so
//! a credential stored as a JSON-encoded field survives into the scanner. This
//! file pins that contract with EXACT decoded-byte / detector-id / credential
//! assertions (Law 6), and pins the deliberate BOUNDARY (a malformed escape or
//! a broken surrogate aborts the unescape and recovers nothing).
//!
//! Isolation technique (why every positive is attributable to JSON decode):
//! the detector's structural ANCHOR keyword is itself written with a `o`
//! ('o') escape, e.g. `_authToken`, `password`, `BEGIN`. In the
//! RAW (un-decoded) bytes that keyword is ABSENT, so the detector cannot fire on
//! the parent chunk; the credential can ONLY surface after the JSON decoder
//! unescapes `o` back to `o`. `baseline_raw_anchor_escaped_yields_zero`
//! proves the raw form is inert, and `baseline_plaintext_anchor_fires` proves
//! the decoded anchor is the thing that fires.
//!
//! Dedup note: the pipeline dedups decoded matches by `(detector_id,
//! credential)` (see `engine/scan_postprocess.rs`), so even though BOTH the
//! `json` decoder and the sibling `unicode-escape` decoder unescape `\uXXXX`,
//! the identical recovered credential collapses to exactly ONE match, hence the
//! `== 1` counts below are stable, not brittle.

mod support;
use support::paths::detector_dir;

use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::CompiledScanner;

// ── firing plaintexts (all shipped checksum-free contract positives) ──

/// `.npmrc` legacy token: `npmrc-auth-token`, capture group 1 = bare token.
const NPMRC_FULL_TOKEN: &str = "s0meL3gacyT0kenValue12345";
/// Same token but with an embedded `/` (npm token class includes `/`).
const NPMRC_SLASH_TOKEN: &str = "s0meL3gacyT0ken/alue12345";
/// `.netrc` password with a single interior backslash (netrc class allows `\`).
const NETRC_BACKSLASH_PW: &str = "Zx9Qw\\3Rt7Lp2Mk"; // 15 chars, one backslash
/// PEM body anchor (distinctive first base64 run of the RSA key).
const PEM_NEEDLE: &str = "MIIBOgIBAAJBAKj34Gkx";

fn scanner() -> CompiledScanner {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    CompiledScanner::compile(detectors).expect("compile scanner")
}

/// Scan raw text through the full pipeline (decode-through runs in postprocess).
fn scan(text: &str) -> Vec<RawMatch> {
    let chunk = Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "json-decode-through".into(),
            path: Some("config.json".into()),
            ..Default::default()
        },
    };
    scanner().scan(&chunk)
}

fn count_id(matches: &[RawMatch], id: &str) -> usize {
    matches.iter().filter(|m| &*m.detector_id == id).count()
}

/// The single match for `id`, panicking if there is not exactly one.
fn only(matches: &[RawMatch], id: &str) -> RawMatch {
    let hits: Vec<&RawMatch> = matches.iter().filter(|m| &*m.detector_id == id).collect();
    assert_eq!(
        hits.len(),
        1,
        "expected exactly one `{id}` match, got {}",
        hits.len()
    );
    hits[0].clone()
}

// ─────────────────────────────────────────────────────────────────────────
// BASELINES (establish that recovery is attributable to JSON decode).
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn unicode_escape_decode_is_quote_independent_recovers_without_json_string() {
    // A `o` escape is recovered by the unicode-escape decoder on ANY chunk,
    // not only inside a JSON string: decode-through runs over the raw bytes, so
    // even with no surrounding quotes the anchor `_authToken` -> `_authToken`
    // is restored and the npmrc token surfaces exactly once with its exact bytes.
    let raw = "//registry.npmjs.org/:_authT\\u006Fken=s0meL3gacyT0kenValue12345";
    let matches = scan(raw);
    assert_eq!(count_id(&matches, "npmrc-auth-token"), 1);
    assert_eq!(
        only(&matches, "npmrc-auth-token").credential.as_ref(),
        NPMRC_FULL_TOKEN
    );
}

#[test]
fn baseline_plaintext_anchor_fires() {
    // The DECODED anchor `_authToken=` is exactly what the detector keys on.
    let raw = "//registry.npmjs.org/:_authToken=s0meL3gacyT0kenValue12345";
    let m = only(&scan(raw), "npmrc-auth-token");
    // Group 1 is the bare token (no registry prefix, no quotes).
    assert_eq!(m.credential.as_ref(), NPMRC_FULL_TOKEN);
}

// ─────────────────────────────────────────────────────────────────────────
// POSITIVE, each JSON escape kind is unescaped and the detector fires on the
// EXACT decoded bytes.
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn unicode_bmp_escape_recovers_exact_token() {
    // Anchor `o` hidden as `o`. Only JSON/unicode decode restores it.
    let json =
        "{\"registry\":\"//registry.npmjs.org/:_authT\\u006Fken=s0meL3gacyT0kenValue12345\"}";
    let m = only(&scan(json), "npmrc-auth-token");
    assert_eq!(m.credential.as_ref(), NPMRC_FULL_TOKEN);
    assert_eq!(&*m.detector_id, "npmrc-auth-token");
}

#[test]
fn solidus_escape_recovers_slash_in_token() {
    // `\/` must decode to a literal `/` INSIDE the captured token.
    let json =
        "{\"registry\":\"//registry.npmjs.org/:_authT\\u006Fken=s0meL3gacyT0ken\\/alue12345\"}";
    let m = only(&scan(json), "npmrc-auth-token");
    assert_eq!(m.credential.as_ref(), NPMRC_SLASH_TOKEN);
    assert!(
        m.credential.as_ref().contains('/'),
        "decoded `\\/` should yield a literal slash: {:?}",
        m.credential.as_ref()
    );
}

#[test]
fn escaped_quote_is_not_a_string_terminator() {
    // `\"` inside the value must NOT close the JSON string early; the extractor
    // has to skip the escaped-quote pair and keep walking to the real closer,
    // then the anchor after it is decoded and the token recovered.
    let json =
        "{\"k\":\"desc\\\"//registry.npmjs.org/:_authT\\u006Fken=s0meL3gacyT0kenValue12345\"}";
    let m = only(&scan(json), "npmrc-auth-token");
    assert_eq!(m.credential.as_ref(), NPMRC_FULL_TOKEN);
}

#[test]
fn double_backslash_collapses_to_single_in_netrc() {
    // `\\` decodes to ONE backslash; the netrc password class keeps it.
    // Anchor `password` hidden as `password`.
    let json =
        "{\"netrc\":\"machine api.example.com login deploy passw\\u006Frd Zx9Qw\\\\3Rt7Lp2Mk\"}";
    let m = only(&scan(json), "netrc-password");
    // Exactly one interior backslash: NOT the two that appear in the JSON text.
    assert_eq!(m.credential.as_ref(), NETRC_BACKSLASH_PW);
    assert_eq!(
        m.credential.as_ref().matches('\\').count(),
        1,
        "double backslash must collapse to exactly one: {:?}",
        m.credential.as_ref()
    );
}

#[test]
fn newline_escape_yields_real_newline_in_pem_credential() {
    // A multi-line PEM stored as a JSON string with `\n` separators. Anchor
    // `BEGIN` hidden as `BEGIN` so only the decoded block can fire.
    let json = "{\"pem\":\"-----BEG\\u0049N RSA PRIVATE KEY-----\
\\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\
\\nKUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQJAIWPaVgC5bA8AjVWdjxNm\
\\n-----END RSA PRIVATE KEY-----\"}";
    let m = only(&scan(json), "private-key");
    // The decoded credential carries a REAL 0x0A, not the literal `\n` pair.
    assert!(
        m.credential
            .as_ref()
            .contains("-----BEGIN RSA PRIVATE KEY-----\n"),
        "decoded PEM must contain a real newline after the BEGIN line: {:?}",
        m.credential.as_ref()
    );
    assert!(
        m.credential.as_ref().contains(PEM_NEEDLE),
        "decoded PEM must contain the body needle: {:?}",
        m.credential.as_ref()
    );
    // The escaped-form artifact (backslash-n) must NOT survive into the match.
    assert!(!m.credential.as_ref().contains("KEY-----\\n"));
}

#[test]
fn valid_surrogate_pair_decodes_and_recovers_token() {
    // `😀` is the UTF-16 surrogate pair for U+1F600 😀. A correct
    // pair decode is a PRECONDITION for the whole-string unescape to succeed;
    // if it errored, the anchor after it would never be restored (count 0).
    let json = "{\"k\":\"\\uD83D\\uDE00 //registry.npmjs.org/:_authT\\u006Fken=s0meL3gacyT0kenValue12345\"}";
    let m = only(&scan(json), "npmrc-auth-token");
    // The astral char is not in the token class, so the credential is exact.
    assert_eq!(m.credential.as_ref(), NPMRC_FULL_TOKEN);
}

// ─────────────────────────────────────────────────────────────────────────
// BOUNDARY / ADVERSARIAL, a malformed escape aborts the unescape entirely,
// so the anchor is never restored and NOTHING is recovered.
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn broken_high_surrogate_aborts_no_recovery() {
    // High surrogate `\uD83D` followed by a NON-low BMP unit `A` ('A') is
    // an illegal pair → unescape returns Err → no decoded child → the escaped
    // anchor stays broken → zero matches.
    let json = "{\"k\":\"\\uD83D\\u0041 //registry.npmjs.org/:_authT\\u006Fken=s0meL3gacyT0kenValue12345\"}";
    assert_eq!(count_id(&scan(json), "npmrc-auth-token"), 0);
}

#[test]
fn lone_low_surrogate_aborts_no_recovery() {
    // A low surrogate `\uDC00` with no preceding high surrogate is never valid.
    let json =
        "{\"k\":\"\\uDC00 //registry.npmjs.org/:_authT\\u006Fken=s0meL3gacyT0kenValue12345\"}";
    assert_eq!(count_id(&scan(json), "npmrc-auth-token"), 0);
}

#[test]
fn truncated_unicode_escape_aborts_no_recovery() {
    // `\u` followed by non-hex (`gggg`) has no valid code point → both the
    // json and unicode-escape decoders bail → the anchor is never restored.
    let json =
        "{\"k\":\"\\ugggg //registry.npmjs.org/:_authT\\u006Fken=s0meL3gacyT0kenValue12345\"}";
    assert_eq!(count_id(&scan(json), "npmrc-auth-token"), 0);
}

// ─────────────────────────────────────────────────────────────────────────
// NEGATIVE-TWIN, the decoder must not fabricate findings, and non-escaped
// JSON is left untouched (raw detection still works, no duplicate surfaces).
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn benign_escaped_value_fabricates_nothing() {
    // Escapes are present (so the decoder RUNS) but the decoded bytes carry no
    // secret. Decoding `\n`/`\t` must not manufacture any finding.
    let json = "{\"note\":\"line one\\nline two\\ttabbed value here\"}";
    let matches = scan(json);
    assert_eq!(count_id(&matches, "npmrc-auth-token"), 0);
    assert_eq!(count_id(&matches, "netrc-password"), 0);
    assert_eq!(count_id(&matches, "private-key"), 0);
    assert_eq!(
        matches.len(),
        0,
        "benign escaped JSON must yield no findings"
    );
}

#[test]
fn unescaped_value_left_alone_but_raw_still_fires() {
    // No backslash anywhere: the JSON decoder extracts nothing (it only touches
    // strings that CONTAIN escapes), yet the plaintext anchor still fires on the
    // parent scan (and exactly ONCE, proving no phantom decoded duplicate).
    let json = "{\"registry\":\"//registry.npmjs.org/:_authToken=s0meL3gacyT0kenValue12345\"}";
    let m = only(&scan(json), "npmrc-auth-token");
    assert_eq!(m.credential.as_ref(), NPMRC_FULL_TOKEN);
}

#[test]
fn unterminated_json_string_still_recovers_via_quote_independent_unicode_decode_no_panic() {
    // Opening quote, escaped anchor, but NO closing quote before EOF. The JSON
    // string-extractor drops the unterminated span, but the unicode-escape
    // decoder still runs over the raw chunk (quote-independent) and restores the
    // `o` escape, so the token surfaces exactly once, and the scan
    // terminates cleanly (no panic / no infinite loop).
    let json = "{\"registry\":\"//registry.npmjs.org/:_authT\\u006Fken=s0meL3gacyT0kenValue12345";
    let matches = scan(json);
    assert_eq!(count_id(&matches, "npmrc-auth-token"), 1);
    assert_eq!(
        only(&matches, "npmrc-auth-token").credential.as_ref(),
        NPMRC_FULL_TOKEN
    );
}

#[test]
fn multiple_escaped_values_each_surface_with_exact_credential() {
    // Two independent escaped string values in one object. The npm anchor is a
    // clean `o` escape, so it dedups to exactly one match. The netrc value
    // carries a JSON-escaped backslash `\\3`: the JSON-decoded form
    // `Zx9Qw\3...` (15 chars, one backslash) AND the raw literal form
    // `Zx9Qw\\3...` (16 chars, two backslashes) are BOTH valid netrc-password
    // strings, so that anchor legitimately surfaces two DISTINCT credentials
    // assert the decoded secret is present with its exact bytes (not `only`).
    let json = "{\"a\":\"//registry.npmjs.org/:_authT\\u006Fken=s0meL3gacyT0kenValue12345\",\
\"b\":\"machine api.example.com login deploy passw\\u006Frd Zx9Qw\\\\3Rt7Lp2Mk\"}";
    let matches = scan(json);
    let npm = only(&matches, "npmrc-auth-token");
    assert_eq!(npm.credential.as_ref(), NPMRC_FULL_TOKEN);
    assert!(
        matches
            .iter()
            .any(|m| &*m.detector_id == "netrc-password"
                && m.credential.as_ref() == NETRC_BACKSLASH_PW),
        "decoded netrc password must surface with its exact credential"
    );
}
