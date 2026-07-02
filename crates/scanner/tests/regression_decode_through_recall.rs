//! Decode-through recall across container wrappers (base64 vs gzip vs zip).
//!
//! keyhog decodes *text* encodings (base64/hex/url/…) before pattern matching,
//! so a secret re-encoded as base64 must fire the SAME detector on the SAME
//! credential. This file pins that recovery with exact detector-id and exact
//! decoded-credential-byte assertions, and — separately — pins the DELIBERATE
//! boundary of decode-through: a secret **compressed** into a gzip or zip
//! container is opaque to the pipeline.
//!
//! Why gzip/zip are opaque (verified against the source, not assumed):
//!   * The pipeline registry (`decode::pipeline::registry::default_decoders`)
//!     has NO gzip/zip inflate decoder — only text codecs.
//!   * Every text decoder only emits a decoded sub-chunk when the decoded bytes
//!     are valid UTF-8 (`String::from_utf8` gate in `decode/base64.rs:22` and
//!     `decode/hex.rs:22`). A gzip stream (`1f 8b …`) and a zip local-file
//!     header carry non-UTF-8 bytes (gzip byte `0x8b`; the zip CRC-32/size
//!     fields carry bytes >= 0x80), so the decoded blob is dropped and never
//!     re-scanned.
//!
//! The gzip/zip fixtures below are REAL containers produced by Python's `gzip`
//! / `zipfile` (base64-of-the-container is embedded as a literal, since the
//! scanner crate has no compression dependency to build them at test time). The
//! `zip STORED` fixture literally contains the plaintext token yet is STILL not
//! recovered — the surprising, load-bearing lock in this file.
//!
//! Companion file `regression_decode_through_strict.rs` covers the base64 ×
//! hex × url matrix for the SAME contract positives; this file adds the
//! container dimension and exact-byte credential identity.

mod support;
use support::paths::detector_dir;

use base64::Engine;
use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::CompiledScanner;

// ── checksum-free firing plaintexts (shipped contract positives) ──

/// `.npmrc` legacy token — fires `npmrc-auth-token`, capture group 1 is the
/// bare token, so the recovered credential equals `NPMRC_NEEDLE` exactly.
const NPMRC: &str = "//registry.npmjs.org/:_authToken=s0meL3gacyT0kenValue12345";
const NPMRC_NEEDLE: &str = "s0meL3gacyT0kenValue12345";

/// `.netrc` triple — fires `netrc-password`, capture group 1 is the bare
/// password, so the recovered credential equals `NETRC_NEEDLE` exactly.
const NETRC: &str = "machine api.example.com login deploy password Zx9Qw3Rt7Lp2Mk";
const NETRC_NEEDLE: &str = "Zx9Qw3Rt7Lp2Mk";

/// PEM RSA private key — fires `private-key`, no vendor checksum.
const PEM: &str = "-----BEGIN RSA PRIVATE KEY-----\n\
    MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n\
    KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQJAIWPaVgC5bA8AjVWdjxNm\n\
    -----END RSA PRIVATE KEY-----";
const PEM_NEEDLE: &str = "MIIBOgIBAAJBAKj34Gkx";

// ── container fixtures: base64( <container>(NPMRC) ) ──
// Produced by CPython 3: `gzip.compress(NPMRC, 9)` / `zipfile.ZipFile(...)`.
// Verified: each decodes to non-UTF-8 bytes; the DEFLATE variants do not even
// contain the needle; the STORED variant contains it literally.

/// `base64(gzip(NPMRC))` — DEFLATE-compressed; needle absent from bytes.
const B64_GZIP_NPMRC: &str =
    "H4sIAMQARmoC/9PXL0pNzywuKarUyyvIzSrWyy9K17eKTywtyQjJz07Nsy02yE31MU5PTK4MMQDywxJzSlMNjYxNTAFX/JQuOgAAAA==";

/// `base64(zip_deflated(NPMRC))` — ZIP with a DEFLATE entry; needle absent.
const B64_ZIP_NPMRC: &str =
    "UEsDBBQAAAAIAEa54VxX/JQuOgAAADoAAAAKAAAAc2VjcmV0LnR4dNPXL0pNzywuKarUyyvIzSrWyy9K17eKTywtyQjJz07Nsy02yE31MU5PTK4MMQDywxJzSlMNjYxNTAFQSwECFAMUAAAACABGueFcV/yULjoAAAA6AAAACgAAAAAAAAAAAAAAgAEAAAAAc2VjcmV0LnR4dFBLBQYAAAAAAQABADgAAABiAAAAAAA=";

/// `base64(zip_stored(NPMRC))` — ZIP with an UNCOMPRESSED (STORED) entry. The
/// plaintext token is present verbatim in the decoded bytes, but a CRC-32 byte
/// (`0x94`) makes the blob invalid UTF-8, so the base64 decoder drops it.
const B64_ZIP_STORED_NPMRC: &str =
    "UEsDBBQAAAAAAEa54VxX/JQuOgAAADoAAAAKAAAAc2VjcmV0LnR4dC8vcmVnaXN0cnkubnBtanMub3JnLzpfYXV0aFRva2VuPXMwbWVMM2dhY3lUMGtlblZhbHVlMTIzNDVQSwECFAMUAAAAAABGueFcV/yULjoAAAA6AAAACgAAAAAAAAAAAAAAgAEAAAAAc2VjcmV0LnR4dFBLBQYAAAAAAQABADgAAABiAAAAAAA=";

/// `base64(gzip("the quick brown fox …"))` — benign, non-secret payload.
const B64_GZIP_BENIGN: &str =
    "H4sIAO0ARmoC/yvJSFUoLM1MzlZIKsovz1NIy69QyCrNLShWyC9LLVIoAUrnJFZVKqTkp4M5A60WAMsN9o2wAAAA";

/// `base64(zlib.compress(NPMRC, 9))` — zlib stream (`78 da`), DEFLATE-compressed.
/// Recovered through the same bounded inflate decode-through as gzip.
const B64_ZLIB_NPMRC: &str =
    "eNrT1y9KTc8sLimq1MsryM0q1ssvSte3ik8sLckIyc9OzbMtNshN9TFOT0yuDDEA8sMSc0pTDY2MTUwBd6oUsg==";

/// `base64(gzip-magic + 0xff garbage)` — a well-formed gzip header followed by a
/// corrupt DEFLATE body. The inflate must fail closed (no panic, no finding).
const B64_CORRUPT_GZIP: &str = "H4sIAP//////////////////////////";

fn scanner() -> CompiledScanner {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    CompiledScanner::compile(detectors).expect("compile scanner")
}

fn b64(s: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(s.as_bytes())
}
fn b64_urlsafe_nopad(s: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s.as_bytes())
}

/// Scan a raw plaintext directly (no wrapper) with a config-ish path.
fn scan_raw(text: &str, path: &str) -> Vec<RawMatch> {
    let chunk = Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "decode-through-recall".into(),
            path: Some(path.into()),
            ..Default::default()
        },
    };
    scanner().scan(&chunk)
}

/// Embed `encoded` in a config value and scan; return the surfaced matches.
fn scan_embedded(encoded: &str) -> Vec<RawMatch> {
    scan_raw(&format!("decoded_payload = \"{encoded}\"\n"), "config.txt")
}

fn count_detector(matches: &[RawMatch], id: &str) -> usize {
    matches
        .iter()
        .filter(|m| m.detector_id.as_ref() == id)
        .count()
}
fn count_with_needle(matches: &[RawMatch], needle: &str) -> usize {
    matches
        .iter()
        .filter(|m| m.credential.as_ref().contains(needle))
        .count()
}

// ─────────────────────────────────────────────────────────────────────────
// BASELINE: exact credential identity on the unwrapped positives. If these
// drift, every decode-through assertion below is measuring nothing.
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn baseline_npmrc_plaintext_captures_exact_token() {
    let matches = scan_raw(NPMRC, ".npmrc");
    let m = matches
        .iter()
        .find(|m| m.detector_id.as_ref() == "npmrc-auth-token")
        .expect("npmrc-auth-token fires on the raw .npmrc line");
    // group 1 of the detector regex is the bare token — exact bytes, no prefix.
    assert_eq!(m.credential.as_ref(), NPMRC_NEEDLE);
}

#[test]
fn baseline_netrc_plaintext_captures_exact_password() {
    let matches = scan_raw(NETRC, ".netrc");
    let m = matches
        .iter()
        .find(|m| m.detector_id.as_ref() == "netrc-password")
        .expect("netrc-password fires on the raw .netrc triple");
    assert_eq!(m.credential.as_ref(), NETRC_NEEDLE);
}

// ─────────────────────────────────────────────────────────────────────────
// BASE64 decode-through: the secret is RECOVERED, same detector, same bytes.
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn npmrc_recovered_through_base64_standard() {
    let matches = scan_embedded(&b64(NPMRC));
    let m = matches
        .iter()
        .find(|m| m.credential.as_ref().contains(NPMRC_NEEDLE))
        .expect("npmrc token recovered through base64");
    assert_eq!(m.detector_id.as_ref(), "npmrc-auth-token");
    // Decode-through re-splices the plaintext, so the bare token is captured
    // exactly — not the surrounding `//host/:` prefix or the config quotes.
    assert_eq!(m.credential.as_ref(), NPMRC_NEEDLE);
}

#[test]
fn netrc_recovered_through_base64_standard() {
    let matches = scan_embedded(&b64(NETRC));
    let m = matches
        .iter()
        .find(|m| m.credential.as_ref().contains(NETRC_NEEDLE))
        .expect("netrc password recovered through base64");
    assert_eq!(m.detector_id.as_ref(), "netrc-password");
}

#[test]
fn pem_recovered_through_base64() {
    let matches = scan_embedded(&b64(PEM));
    let m = matches
        .iter()
        .find(|m| m.credential.as_ref().contains(PEM_NEEDLE))
        .expect("PEM private key recovered through base64");
    assert_eq!(m.detector_id.as_ref(), "private-key");
}

#[test]
fn npmrc_recovered_through_base64_urlsafe_nopad() {
    let matches = scan_embedded(&b64_urlsafe_nopad(NPMRC));
    let m = matches
        .iter()
        .find(|m| m.detector_id.as_ref() == "npmrc-auth-token")
        .expect("npmrc token recovered through url-safe base64");
    assert_eq!(m.credential.as_ref(), NPMRC_NEEDLE);
}

#[test]
fn npmrc_recovered_through_double_base64() {
    // base64(base64(plaintext)) must still recover at decode depth 2.
    let matches = scan_embedded(&b64(&b64(NPMRC)));
    let m = matches
        .iter()
        .find(|m| m.credential.as_ref().contains(NPMRC_NEEDLE))
        .expect("npmrc token recovered through nested base64");
    assert_eq!(m.detector_id.as_ref(), "npmrc-auth-token");
}

// ─────────────────────────────────────────────────────────────────────────
// GZIP / ZLIB via base64: the secret is COMPRESSED then base64-encoded
// (`secret -> gzip -> base64` exfil). The base64 decoder now runs a bounded
// inflate (decode::inflate) BEFORE its from_utf8 gate, so the token IS
// recovered. ZIP and hex-wrapped containers remain gaps (see below): zip needs
// a central-directory parser, and the hex decoder has no inflate stage yet.
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn gzip_compressed_npmrc_recovered_through_base64() {
    let matches = scan_embedded(B64_GZIP_NPMRC);
    // decode-through: base64 decodes to a gzip stream (`1f 8b …`); the bounded
    // inflate stage recovers the UTF-8 npmrc line before the from_utf8 gate, so
    // the token is rescanned and found.
    assert_eq!(count_with_needle(&matches, NPMRC_NEEDLE), 1);
    assert_eq!(count_detector(&matches, "npmrc-auth-token"), 1);
}

#[test]
fn zlib_compressed_npmrc_recovered_through_base64() {
    // zlib stream (`78 da`) via base64 — same bounded inflate decode-through.
    let matches = scan_embedded(B64_ZLIB_NPMRC);
    let hit = matches
        .iter()
        .find(|m| m.detector_id.as_ref() == "npmrc-auth-token")
        .expect("zlib+base64 wrapper recovers the npmrc token");
    assert_eq!(hit.credential.as_ref(), NPMRC_NEEDLE);
    assert_eq!(count_detector(&matches, "npmrc-auth-token"), 1);
}

#[test]
fn corrupt_gzip_fails_closed_no_panic_no_finding() {
    // Valid gzip magic, corrupt DEFLATE body: the bounded inflate returns None
    // (fails closed) — no panic, and the un-inflatable bytes surface no token.
    let matches = scan_embedded(B64_CORRUPT_GZIP);
    assert_eq!(count_with_needle(&matches, NPMRC_NEEDLE), 0);
    assert_eq!(count_detector(&matches, "npmrc-auth-token"), 0);
}

#[test]
fn zip_deflate_npmrc_not_recovered_through_base64() {
    let matches = scan_embedded(B64_ZIP_NPMRC);
    assert_eq!(count_with_needle(&matches, NPMRC_NEEDLE), 0);
    assert_eq!(count_detector(&matches, "npmrc-auth-token"), 0);
}

#[test]
fn zip_stored_npmrc_not_recovered_despite_literal_token() {
    // The STORED (uncompressed) zip entry contains the token verbatim, but a
    // CRC-32 byte (0x94) makes the whole blob invalid UTF-8, so the base64
    // decoder drops it before any scan. Surprising, and the reason a naive
    // "just scan the decoded bytes" assumption is wrong here.
    let matches = scan_embedded(B64_ZIP_STORED_NPMRC);
    assert_eq!(count_with_needle(&matches, NPMRC_NEEDLE), 0);
    assert_eq!(count_detector(&matches, "npmrc-auth-token"), 0);
}

#[test]
fn hex_wrapped_gzip_also_not_recovered() {
    // Cross-wrapper: hex-encode the SAME gzip bytes. The hex decoder shares the
    // UTF-8 gate, so the container stays opaque under hex too.
    let gz = base64::engine::general_purpose::STANDARD
        .decode(B64_GZIP_NPMRC)
        .expect("gzip fixture decodes");
    let mut hex = String::with_capacity(gz.len() * 2);
    for b in &gz {
        use std::fmt::Write as _;
        let _ = write!(hex, "{b:02x}");
    }
    let matches = scan_embedded(&hex);
    assert_eq!(count_with_needle(&matches, NPMRC_NEEDLE), 0);
    assert_eq!(count_detector(&matches, "npmrc-auth-token"), 0);
}

#[test]
fn nested_base64_of_zip_still_opaque() {
    // Wrapping the container in a second base64 layer does not help: depth-2
    // decode yields the same non-UTF-8 zip bytes, which are dropped.
    let matches = scan_embedded(&b64(B64_ZIP_NPMRC));
    assert_eq!(count_with_needle(&matches, NPMRC_NEEDLE), 0);
    assert_eq!(count_detector(&matches, "npmrc-auth-token"), 0);
}

// ─────────────────────────────────────────────────────────────────────────
// CONTRAST + PRECISION: prove the 0-findings above are caused by the container
// specifically (not a dead scanner), and that benign blobs stay clean.
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn base64_and_gzip_wrappers_both_recover_the_secret() {
    // Same plaintext, two wrappers: base64 -> recovered token; gzip+base64 ->
    // recovered too (via the bounded inflate decode-through).
    let via_b64 = scan_embedded(&b64(NPMRC));
    let via_gzip = scan_embedded(B64_GZIP_NPMRC);
    let recovered = via_b64
        .iter()
        .find(|m| m.detector_id.as_ref() == "npmrc-auth-token")
        .expect("base64 wrapper recovers the npmrc token");
    assert_eq!(recovered.credential.as_ref(), NPMRC_NEEDLE);
    let via_gzip_hit = via_gzip
        .iter()
        .find(|m| m.detector_id.as_ref() == "npmrc-auth-token")
        .expect("gzip+base64 wrapper recovers the npmrc token");
    assert_eq!(via_gzip_hit.credential.as_ref(), NPMRC_NEEDLE);
}

#[test]
fn base64_of_benign_prose_yields_no_secret() {
    let benign = "the quick brown fox jumps over the lazy dog, nothing secret here at all today";
    let matches = scan_embedded(&b64(benign));
    assert_eq!(count_detector(&matches, "npmrc-auth-token"), 0);
    assert_eq!(count_detector(&matches, "netrc-password"), 0);
    assert_eq!(count_detector(&matches, "private-key"), 0);
}

#[test]
fn gzip_of_benign_blob_yields_no_secret() {
    let matches = scan_embedded(B64_GZIP_BENIGN);
    assert_eq!(count_detector(&matches, "npmrc-auth-token"), 0);
    assert_eq!(count_detector(&matches, "netrc-password"), 0);
    assert_eq!(count_detector(&matches, "private-key"), 0);
    assert_eq!(count_with_needle(&matches, NPMRC_NEEDLE), 0);
}
