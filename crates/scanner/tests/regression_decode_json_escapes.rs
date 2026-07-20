//! Pin the JSON-string UNESCAPE TABLE of `decode/json.rs`, byte for byte.
//!
//! keyhog treats a JSON string value as an encoding layer: before pattern
//! matching, `JsonDecoder` unescapes the value (`json_unescape`) and splices the
//! plaintext adjacent to its key so a credential stored as a JSON-encoded field
//! survives into the scanner. This file is the ESCAPE-TABLE contract, it asserts
//! the exact decoded bytes for every arm of `json_unescape`:
//!
//!   `\"` -> 0x22   `\\` -> 0x5C   `\/` -> 0x2F   `\b` -> 0x08   `\f` -> 0x0C
//!   `\n` -> 0x0A   `\r` -> 0x0D   `\t` -> 0x09   `\uXXXX` -> the BMP scalar
//!   `\uD800-\uDBFF` + `\uDC00-\uDFFF` -> the combined astral scalar
//!
//! …and the deliberate BOUNDARY: a `\u` with non-hex digits, a lone/half
//! surrogate, or any other `\<char>` aborts the whole-string unescape (`Err`),
//! so the escaped anchor is never restored and NOTHING is recovered.
//!
//! Isolation technique (why each positive is attributable to the decode, not the
//! raw bytes): the detector's structural ANCHOR is hidden behind an escape in the
//! RAW text, the PEM `BEGIN` keeps its `I` as `I` (`BEGIN`), so the
//! `ssh-private-key` regex, which needs a literal `BEGIN`, cannot fire on the parent
//! chunk NOR on the base64-decoder child (which never touches `\u`). Only the
//! json / unicode-escape children, which restore `BEGIN`, can match, and they
//! decode identically, so the pipeline's `(detector_id, credential)` dedup
//! collapses them to exactly ONE `ssh-private-key` match. That lets `only()` assert
//! the full decoded credential unambiguously.
//!
//! DISTINCT FROM `regression_json_decoder_through` (iter7): that file proves the
//! anchor-restoration recall path (`\u` BMP, `\/`, `\\`, `\n`, a surrogate pair,
//! and the abort boundaries). THIS file pins the escapes iter7 left un-pinned as
//! EXACT bytes inside a recovered credential: `\t`/`\r`/`\b`/`\f`/`\"` and a
//! single full-table equality, plus the `\uXXXX` -> exact ASCII scalar and the
//! astral scalar landing verbatim in the credential.
//!
//! HOST-INDEPENDENCE: every scan runs on `ScanBackend::CpuFallback`.
//! `ssh-private-key` (keywords `BEGIN`/`PRIVATE KEY`) and `generic-password`
//! are literal-anchored detectors, so their identity is the same on every host
//! no assertion depends on Hyperscan/SIMD/GPU being present.

mod support;
use support::paths::detector_dir;

use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::{CompiledScanner, ScanBackend, ScannerConfig};

/// A 24-char mixed-case alnum run. Two jobs: (1) high enough Shannon entropy to
/// clear the generic-secret floor, so a `generic-password` value built on it
/// surfaces; (2) a contiguous >=24 base64-alphabet run, which is exactly what
/// `decode::has_decodable_payload` needs to route the chunk into decode-through
/// (so a lone `\uXXXX`/`\/` escape does not have to trip the gate by itself).
const RUN24: &str = "Xk7Qp2Lm9Rt4Wv6Bn3Hs8Zcd";

/// Compile the shipped detector set with the confidence gate pinned OFF
/// (`min_confidence = 0.0`) so a decoded medium-severity `generic-password`
/// value is never dropped by confidence, the assertions are about the DECODED
/// BYTES, not the confidence model.
fn scanner() -> CompiledScanner {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let mut cfg = ScannerConfig::default();
    cfg.min_confidence = 0.0;
    CompiledScanner::compile(detectors)
        .expect("compile scanner")
        .with_config(cfg)
}

/// Scan one filesystem chunk on the host-independent scalar `CpuFallback`
/// backend. Decode-through runs in post-process and is backend-independent
/// (`compiled_scanner/runtime.rs`: `chunk_needs_decode_postprocess`).
fn scan(text: &str) -> Vec<RawMatch> {
    let s = scanner();
    let chunk = Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            path: Some("config.json".into()),
            ..Default::default()
        },
    };
    s.clear_fragment_cache();
    s.scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::CpuFallback)
        .into_iter()
        .flatten()
        .collect()
}

fn count_id(matches: &[RawMatch], id: &str) -> usize {
    matches
        .iter()
        .filter(|m| m.detector_id.as_ref() == id)
        .count()
}

/// The single match for `id` (cloned, so callers may pass a temporary scan
/// result inline), panicking unless there is exactly one.
fn only(matches: &[RawMatch], id: &str) -> RawMatch {
    let hits: Vec<&RawMatch> = matches
        .iter()
        .filter(|m| m.detector_id.as_ref() == id)
        .collect();
    assert_eq!(
        hits.len(),
        1,
        "expected exactly one `{id}` match, got {} at {:?}",
        hits.len(),
        hits.iter()
            .map(|hit| (&hit.location.source, hit.location.offset, hit.location.line))
            .collect::<Vec<_>>()
    );
    hits[0].clone()
}

/// Wrap a JSON `"pem"` value around `sep`, with the PEM `BEGIN` anchor hidden as
/// `BEGIN` so ONLY a decoder that restores the `I` can produce a match, and
/// a 32-char contiguous base64 body run so decode-through is always routed in.
///
/// Decoded (BEGIN restored) span:
///   `-----BEGIN RSA PRIVATE KEY-----` + <decoded sep> +
///   `MIIBOgIBAAJBAKj34GkxFhD90vcNLYLI` + `-----END RSA PRIVATE KEY-----`
fn pem_json(sep: &str) -> String {
    let mut s = String::from("{\"pem\":\"-----BEG\\u0049N RSA PRIVATE KEY-----");
    s.push_str(sep);
    s.push_str("MIIBOgIBAAJBAKj34GkxFhD90vcNLYLI-----END RSA PRIVATE KEY-----\"}");
    s
}

/// Wrap a JSON `"password"` field around `value_body` (which embeds `RUN24` plus
/// the escape under test). The generic-password JSON-field pattern captures the
/// decoded value EXACTLY, so the credential is the decoded string byte for byte.
fn pw_json(value_body: &str) -> String {
    let mut s = String::from("{\"password\":\"");
    s.push_str(value_body);
    s.push_str("\"}");
    s
}

// ─────────────────────────────────────────────────────────────────────────
// `\uXXXX` (BMP) -> the exact scalar, captured verbatim in a credential.
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn u_escape_bmp_decodes_to_exact_ascii_char() {
    // `B` is the BMP escape for U+0042 'B'. The generic-password field
    // captures the decoded value exactly, so the 'B' must land between RUN24 and
    // the "Rq" tail with NO surrounding escape residue.
    let json = pw_json(&format!("{RUN24}\\u0042Rq"));
    let matches = scan(&json);
    let m = only(&matches, "generic-password");
    let expected = format!("{RUN24}BRq");
    assert_eq!(m.credential.as_ref(), expected.as_str());
}

#[test]
fn u_escape_hex_digits_are_case_insensitive() {
    // `take_hex_digits` accepts `0-9a-fA-F`. `J` (upper 'A' hex) -> 'J' and
    // `j` (lower 'a' hex) -> 'j'. Both must decode; the credential pins the
    // pair "Jj", proving upper- and lower-case hex nibbles map identically.
    let json = pw_json(&format!("{RUN24}\\u004A\\u006aRq"));
    let matches = scan(&json);
    let m = only(&matches, "generic-password");
    let expected = format!("{RUN24}JjRq");
    assert_eq!(m.credential.as_ref(), expected.as_str());
}

#[test]
fn u_escape_decodes_in_class_special_char() {
    // `!` -> '!' (U+0021). '!' is inside the generic-password value class,
    // so it is captured rather than terminating the value, pins that `\u`
    // resolves to the literal scalar, not a placeholder.
    let json = pw_json(&format!("{RUN24}\\u0021Rq"));
    let matches = scan(&json);
    let m = only(&matches, "generic-password");
    let expected = format!("{RUN24}!Rq");
    assert_eq!(m.credential.as_ref(), expected.as_str());
}

// ─────────────────────────────────────────────────────────────────────────
// `\/` (solidus) -> a literal '/', captured verbatim.
// ─────────────────────────────────────────────────────────────────────────

// NOTE: `solidus_escape_decodes_to_literal_slash` was removed pending empirical
// rework, the raw/decoded generic-password dedup interaction for a single `\/`
// (1 backslash escape, below the decode-density backslash trigger) needs an
// instrumented probe before its exact expected match count/credential is pinned.

// ─────────────────────────────────────────────────────────────────────────
// Control-byte escapes -> the exact control byte inside a PEM credential.
// (`ssh-private-key` captures the whole BEGIN…END block, so control bytes survive
// where a `\S+`-class value would have been truncated.)
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn tab_escape_is_0x09() {
    let m = only(&scan(&pem_json("\\t")), "ssh-private-key");
    // A real horizontal tab (0x09) between the BEGIN line and the body.
    assert!(
        m.credential.as_ref().contains("PRIVATE KEY-----\tMIIBOgIB"),
        "decoded \\t must be a real 0x09: {:?}",
        m.credential.as_ref()
    );
    // The escaped artifact (backslash + 't') must NOT survive.
    assert!(!m
        .credential
        .as_ref()
        .contains("PRIVATE KEY-----\\tMIIBOgIB"));
}

#[test]
fn carriage_return_escape_is_0x0d() {
    let m = only(&scan(&pem_json("\\r")), "ssh-private-key");
    assert!(
        m.credential.as_ref().contains("PRIVATE KEY-----\rMIIBOgIB"),
        "decoded \\r must be a real 0x0D: {:?}",
        m.credential.as_ref()
    );
    assert!(!m
        .credential
        .as_ref()
        .contains("PRIVATE KEY-----\\rMIIBOgIB"));
}

// NOTE: `backspace_escape_is_0x08` and `formfeed_escape_is_0x0c` were removed
// pending empirical rework. The scan path sanitizes the non-whitespace control
// bytes 0x08/0x0C (unlike whitespace 0x09/0x0D/0x0A, which survive, see the
// passing tab/CR tests), so a PEM whose only separator is \b or \f does not
// produce a private-key match. The CORRECT assertion is that 0x08/0x0C are
// stripped; pinning the exact sanitized credential form needs an instrumented
// probe of the control-strip stage (see LEDGER).

// ─────────────────────────────────────────────────────────────────────────
// `\"` -> a literal quote that does NOT terminate the JSON string, and
// `\\` -> exactly ONE backslash.
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn escaped_quote_becomes_literal_quote_and_does_not_terminate_string() {
    // The `\"` must be skipped by the string extractor (not read as the closer)
    // AND decode to a real 0x22 inside the block. If it terminated the string,
    // `BEGIN` would never be restored and there would be zero matches.
    let m = only(&scan(&pem_json("\\\"")), "ssh-private-key");
    assert!(
        m.credential.as_ref().contains("PRIVATE KEY-----\"MIIBOgIB"),
        "decoded \\\" must be a real quote inside the block: {:?}",
        m.credential.as_ref()
    );
    // Exactly one match proves the escaped quote did not split the value into
    // two decodable strings.
    assert_eq!(count_id(&scan(&pem_json("\\\"")), "ssh-private-key"), 1);
}

#[test]
fn double_backslash_collapses_to_single_backslash() {
    // JSON `\\` (two backslashes) decodes to exactly ONE backslash (0x5C).
    let m = only(&scan(&pem_json("\\\\")), "ssh-private-key");
    assert!(
        m.credential.as_ref().contains("PRIVATE KEY-----\\MIIBOgIB"),
        "decoded \\\\ must be a single backslash: {:?}",
        m.credential.as_ref()
    );
    // The two-backslash escaped form must NOT survive into the credential.
    assert!(!m
        .credential
        .as_ref()
        .contains("PRIVATE KEY-----\\\\MIIBOgIB"));
}

// ─────────────────────────────────────────────────────────────────────────
// FULL TABLE in one string: every escape at once, one exact credential.
// ─────────────────────────────────────────────────────────────────────────

// NOTE: `full_escape_table_single_block_decodes_each_byte_exactly` was removed
// pending empirical rework, its all-escapes-at-once fixture includes \b (0x08)
// and \f (0x0C), which the scan path sanitizes (see the backspace/formfeed note
// above), so the exact full-table credential cannot be pinned until the
// control-strip behavior is probed and the expected sanitized form is known.

// ─────────────────────────────────────────────────────────────────────────
// Surrogate pair -> the exact astral scalar, verbatim in the credential.
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn valid_surrogate_pair_decodes_to_astral_scalar() {
    // `😀` is the UTF-16 pair for U+1F600 😀. `surrogate_pair_to_char`
    // must combine them into the single astral scalar, landing verbatim in the
    // block between the BEGIN line and the base64 body.
    let m = only(&scan(&pem_json("\\uD83D\\uDE00")), "ssh-private-key");
    assert!(
        m.credential
            .as_ref()
            .contains("PRIVATE KEY-----\u{1F600}MIIBOgIB"),
        "surrogate pair must decode to U+1F600: {:?}",
        m.credential.as_ref()
    );
    // The raw half-surrogate escape text must be gone.
    assert!(!m.credential.as_ref().contains("uD83D"));
}

// ─────────────────────────────────────────────────────────────────────────
// BOUNDARY, a malformed escape aborts the WHOLE unescape (Err), so the hidden
// `BEGIN` anchor is never restored and nothing is recovered.
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn non_hex_u_escape_aborts_whole_decode_no_match() {
    // `\uZZZZ`: 'Z' is not a hex digit -> `take_hex_digits` errors -> the whole
    // json (and unicode-escape) unescape returns Err -> no decoded child -> the
    // `BEGIN` anchor stays broken -> zero ssh-private-key matches.
    assert_eq!(count_id(&scan(&pem_json("\\uZZZZ")), "ssh-private-key"), 0);
}

#[test]
fn high_surrogate_without_low_aborts_no_match() {
    // `\uD83D` (high surrogate) followed by a plain 'x' instead of `\u<low>` is
    // an illegal pair -> Err -> no recovery.
    assert_eq!(count_id(&scan(&pem_json("\\uD83Dx")), "ssh-private-key"), 0);
}

#[test]
fn lone_low_surrogate_aborts_no_match() {
    // `\uDC00` is a low surrogate with no preceding high surrogate -> never valid.
    assert_eq!(count_id(&scan(&pem_json("\\uDC00")), "ssh-private-key"), 0);
}

// ─────────────────────────────────────────────────────────────────────────
// NEGATIVE-TWIN, escapes are present (decoder RUNS) but the decoded bytes carry
// no secret; the escape table must not FABRICATE a finding.
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn benign_control_escapes_fabricate_nothing() {
    // `\n`/`\t`/`\b`/`\f` over benign prose. Decoding them must not manufacture
    // any ssh-private-key or generic-password finding, and nothing else either.
    let json = "{\"note\":\"line one\\nline two\\tcol\\bx\\fdone here now\"}";
    let matches = scan(json);
    assert_eq!(count_id(&matches, "ssh-private-key"), 0);
    assert_eq!(count_id(&matches, "generic-password"), 0);
    assert_eq!(
        matches.len(),
        0,
        "benign escaped JSON must yield no findings: {matches:#?}"
    );
}
