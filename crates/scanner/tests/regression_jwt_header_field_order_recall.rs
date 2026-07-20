//! Regression (KH recall lane: CredData candidate-generation gap): the
//! `jwt-token` named detector must surface a structurally-valid JWT REGARDLESS
//! of which header field serializes first, not only when `alg` comes first.
//!
//! Root cause this locks against: the shipped `jwt-token` detector
//! (`detectors/jwt-token.toml`) anchored on the literal `eyJhbGci`: the exact
//! base64url of the 8 bytes `{"alg":`. That requires `alg` to be the FIRST
//! header field. A spec-valid JWT whose JSON header serializes `typ` / `jwk` /
//! `kid` first begins `eyJ0eXAi` (`{"typ":`) / `eyJqd2si` (`{"jwk":`) /
//! `eyJraWQ` (`{"kid":`) and the detector NEVER GENERATED A CANDIDATE for it.
//! On the full real CredData tree that header-order miss class is 52 labeled
//! positives (measured: the `jwt_non_alg_first` candidate in
//! `benchmarks/bench/creddata_miss_analysis.py` recovers +54 TP at 0.964
//! precision, +2 NEW FP (both themselves structurally-valid JWTs)).
//!
//! The fix is candidate-GENERATION only (this lane does not touch scoring /
//! suppression internals): the detector now anchors on the structural JWT
//! shape, an `eyJ`-headed base64url HEADER segment, `.`, an `eyJ`-headed
//! base64url PAYLOAD segment, `.`, a base64url SIGNATURE segment. `eyJ` is the
//! base64url of `{"`, the first two bytes of EVERY JWT header's JSON object, so
//! it triggers on any field order; both the header AND the payload starting
//! `eyJ` is itself a two-point structural anchor that keeps precision high. The
//! `eyJ` prefix is >= `MIN_LITERAL_PREFIX_CHARS` (3) so the detector keeps a
//! first-class Aho-Corasick / Hyperscan literal trigger (no fallback-only
//! regression).
//!
//! Precision is pinned by the negative arm: a header+payload pair WITHOUT a
//! third (signature) segment, the most common JWT look-alike (a 2-dot
//! property access or a truncated token) (must NOT fire `jwt-token`).

mod support;
use support::paths::detector_dir;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};

fn scanner() -> CompiledScanner {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    CompiledScanner::compile(detectors).expect("compile scanner")
}

/// Scan one line via the backend-independent CPU fallback (so the assertion is
/// not contingent on a Hyperscan/SIMD build) and return `(detector_id,
/// credential)` for every surfaced match. Clears the fragment cache first so
/// identical payloads across tests are never deduplicated cross-line.
fn matches_for(scanner: &CompiledScanner, line: &str) -> Vec<(String, String)> {
    let chunk = Chunk {
        data: line.into(),
        metadata: ChunkMetadata::default(),
    };
    scanner.clear_fragment_cache();
    scanner
        .scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::CpuFallback)
        .into_iter()
        .flatten()
        .map(|m| (m.detector_id.to_string(), m.credential.as_str().to_string()))
        .collect()
}

/// True iff `jwt-token` surfaced a credential that CONTAINS `value` (keyhog's
/// context-window extraction may over-capture trailing punctuation, so the
/// contract is "the JWT is inside the surfaced credential", matching the
/// per-detector contract runner's `any_credential_contains`).
fn jwt_caught(scanner: &CompiledScanner, line: &str, value: &str) -> bool {
    matches_for(scanner, line)
        .iter()
        .any(|(id, cred)| id == "jwt-token" && cred.contains(value))
}

/// True iff ANY match under `jwt-token` fired on this line (used by the
/// precision arm: the detector must not fire at all on a non-JWT shape).
fn jwt_fired(scanner: &CompiledScanner, line: &str) -> bool {
    matches_for(scanner, line)
        .iter()
        .any(|(id, _)| id == "jwt-token")
}

// ── Header-field-order RECALL ─────────────────────────────────────────
//
// Each token below is a real three-segment base64url JWT whose JSON header puts
// a NON-`alg` field first, so it begins with a prefix the old `eyJhbGci` anchor
// could never match. The payload is the canonical jwt.io `{"sub":"1234567890",
// "name":"John Doe","iat":1516239022}` and the signature is a fixed base64url
// blob, so the value is a structurally-coherent JWT (header decodes to a JSON
// object carrying `alg`).

const PAYLOAD: &str = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ";
const SIG: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

/// `{"typ":"JWT","alg":"HS256"}` → `eyJ0eXAi...` header (typ serialized first).
const TYP_FIRST_HEADER: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9";
/// `{"jwk":{"crv":"P-256","kty":"EC"},"alg":"ES256"}` → `eyJqd2si...` header.
/// This is the exact `eyJqd2si` prefix seen in CredData's miss set.
const JWK_FIRST_HEADER: &str = "eyJqd2siOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyJ9LCJhbGciOiJFUzI1NiJ9";
/// `{"kid":"abc123","alg":"RS256"}` → `eyJraWQ...` header (kid first, the
/// key-rotation serialization order).
const KID_FIRST_HEADER: &str = "eyJraWQiOiJhYmMxMjMiLCJhbGciOiJSUzI1NiJ9";

fn jwt(header: &str) -> String {
    format!("{header}.{PAYLOAD}.{SIG}")
}

#[test]
fn typ_first_header_jwt_is_surfaced() {
    let s = scanner();
    let tok = jwt(TYP_FIRST_HEADER);
    // Sanity: prefix really is non-alg-first, so the old anchor could not match.
    assert!(
        tok.starts_with("eyJ0eXAi") && !tok.starts_with("eyJhbGci"),
        "fixture must be typ-first (eyJ0eXAi), not alg-first"
    );
    assert!(
        jwt_caught(&s, &format!("token = \"{tok}\""), &tok),
        "typ-first JWT ({tok}) must surface under jwt-token after the structural-anchor broadening"
    );
}

#[test]
fn jwk_first_header_jwt_is_surfaced() {
    let s = scanner();
    let tok = jwt(JWK_FIRST_HEADER);
    assert!(
        tok.starts_with("eyJqd2si") && !tok.starts_with("eyJhbGci"),
        "fixture must be jwk-first (eyJqd2si), the exact CredData miss prefix"
    );
    assert!(
        jwt_caught(&s, &format!("jwt: {tok}"), &tok),
        "jwk-first JWT ({tok}) must surface under jwt-token"
    );
}

#[test]
fn kid_first_header_jwt_is_surfaced() {
    let s = scanner();
    let tok = jwt(KID_FIRST_HEADER);
    assert!(
        tok.starts_with("eyJraWQ") && !tok.starts_with("eyJhbGci"),
        "fixture must be kid-first (eyJraWQ)"
    );
    assert!(
        jwt_caught(&s, &format!("Authorization: Bearer {tok}"), &tok),
        "kid-first JWT ({tok}) must surface under jwt-token"
    );
}

#[test]
fn alg_first_header_jwt_still_surfaced() {
    // The broadening must not regress the original alg-first class: the
    // canonical jwt.io HS256 token (the most-cited JWT in industry docs).
    let s = scanner();
    let tok = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5OTk5OTk5OTk5IiwidGVuYW50Ijoia2V5aG9nLWUyZSIsImlhdCI6MTc0ODA3MjAwMH0.K3xqLnZWP4UlH9oZcQK7nBmJrEzVfYp2N1RsAtX5Y8w";
    assert!(
        jwt_caught(&s, tok, tok),
        "the canonical alg-first jwt.io token must still surface (no recall regression)"
    );
}

// ── Precision: the broadening must not over-fire on non-JWT shapes ────

#[test]
fn two_segment_no_signature_does_not_fire_jwt() {
    // Header + payload but NO third segment: only 2 dot-separated base64url
    // runs. This is the dominant JWT look-alike (a truncated token, or a
    // two-dot property access). The structural anchor requires THREE segments,
    // so jwt-token must not fire.
    let s = scanner();
    let two = format!("{TYP_FIRST_HEADER}.{PAYLOAD}");
    assert!(
        !jwt_fired(&s, &format!("value = \"{two}\"")),
        "a 2-segment (header.payload, no signature) base64url pair must NOT fire jwt-token"
    );
}

#[test]
fn bare_header_prefix_does_not_fire_jwt() {
    // Just the `eyJ`-headed first segment, no `.payload.signature`. The literal
    // trigger may match `eyJ`, but the full structural regex requires the two
    // following dot-separated segments, so jwt-token must not fire.
    let s = scanner();
    assert!(
        !jwt_fired(&s, &format!("header_only = \"{TYP_FIRST_HEADER}\"")),
        "a bare eyJ-headed segment with no payload/signature must NOT fire jwt-token"
    );
}

#[test]
fn prose_mentioning_the_prefix_does_not_fire_jwt() {
    // Prose that NAMES the prefix but contains no real three-segment JWT.
    let s = scanner();
    assert!(
        !jwt_fired(
            &s,
            "the eyJ prefix is base64url of the two bytes {\" per RFC 7519"
        ),
        "prose mentioning the eyJ prefix without a real JWT must NOT fire jwt-token"
    );
}

/// DR-330 CONSOLIDATION GUARD, the JWT header marker `eyJ` (base64url of `{"`,
/// the load-bearing anchor of the `jwt-token` detector pattern) is ALSO keyed off
/// by the entropy plausibility gate (`entropy/plausibility.rs`) and the
/// canonical-shape suppression check (`suppression/shape/canonical.rs`). Those
/// were three bare `"eyJ"` literals free to drift; they now share the single
/// owner `jwt::JWT_BASE64_HEADER_PREFIX` via `has_jwt_header_prefix`. This binds
/// that const to its authoritative detector so it can never diverge from the
/// pattern that surfaces a JWT. (Only the LITERAL is unified here, the full
/// looks_like_jwt shape unification, which would tighten the plausibility gate,
/// remains bench-gated per DR-330.)
#[test]
fn jwt_header_marker_is_backed_by_the_jwt_detector() {
    let marker = keyhog_scanner::testing::jwt_header_prefix();
    let path = std::path::Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../core/detectors/jwt-token.toml"
    ));
    let toml = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read jwt-token detector {}: {e}", path.display()));
    assert!(
        toml.contains(marker),
        "JWT header marker {marker:?} (jwt::JWT_BASE64_HEADER_PREFIX) is absent from its \
         authoritative jwt-token.toml pattern, the single-owner const drifted from the \
         detector that surfaces a JWT"
    );
}
