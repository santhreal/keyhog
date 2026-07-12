//! #128 JWT completeness — the SIGNING material, not just the token.
//!
//! The `jwt-token` detector already recovers a JWT regardless of header field
//! order (#66, locked in regression_jwt_header_field_order_recall.rs). The more
//! dangerous leak is the material that lets an attacker FORGE tokens:
//!   * the HS256 shared signing SECRET in config (`JWT_SECRET=…`, `jwt_signing_key`),
//!     which authenticates every token the service issues;
//!   * the RS256/ES256 signing PRIVATE KEY (a PEM), recovered by `private-key`.
//! A symmetric secret leak is worse than one token leaking: it is forge-anything.
//!
//! This lock pins that those signing secrets surface with the exact value (never
//! `!is_empty`), that the token itself surfaces across algorithms and contexts,
//! and that weak/placeholder signing secrets are correctly suppressed so the
//! recall does not come at the cost of flagging `JWT_SECRET=changeme`.

mod support;
use support::contracts::{make_chunk, scanner};

use base64::Engine;
use keyhog_core::Chunk;
use keyhog_scanner::CompiledScanner;
use std::sync::OnceLock;

fn shared() -> &'static CompiledScanner {
    static SCANNER: OnceLock<CompiledScanner> = OnceLock::new();
    SCANNER.get_or_init(scanner)
}

/// Deterministic high-entropy alphanumeric signing secret of length `n`. Mixed
/// case + digits, no dictionary word, no repeated run — so a miss is a real
/// recall gap, not a value the low-diversity / placeholder gates legitimately drop.
fn secret(n: usize, seed: usize) -> String {
    const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    (0..n)
        .map(|i| ALNUM[(i * 7 + seed * 13 + i * i) % ALNUM.len()] as char)
        .collect()
}

fn scan(path: &str, text: &str) -> Vec<(String, String)> {
    let s = shared();
    s.clear_fragment_cache();
    let chunk: Chunk = make_chunk(text, "filesystem", path);
    s.scan(&chunk)
        .into_iter()
        .map(|m| (m.detector_id.to_string(), m.credential.to_string()))
        .collect()
}

/// True iff some surfaced credential contains `needle`.
fn surfaces(path: &str, text: &str, needle: &str) -> bool {
    scan(path, text)
        .iter()
        .any(|(_, cred)| cred.contains(needle))
}

/// True iff some surfaced credential under `detector` contains `needle`.
fn surfaces_under(path: &str, text: &str, detector: &str, needle: &str) -> bool {
    scan(path, text)
        .iter()
        .any(|(id, cred)| id == detector && cred.contains(needle))
}

/// True iff NO surfaced credential contains `needle`.
fn nothing_surfaces(path: &str, text: &str, needle: &str) -> bool {
    !scan(path, text)
        .iter()
        .any(|(_, cred)| cred.contains(needle))
}

/// PEM private key proven to fire `private-key` unwrapped.
const PEM: &str = "-----BEGIN RSA PRIVATE KEY-----\n\
    MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n\
    KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQJAIWPaVgC5bA8AjVWdjxNm\n\
    -----END RSA PRIVATE KEY-----";
const PEM_NEEDLE: &str = "MIIBOgIBAAJBAKj34Gkx";

fn b64url(s: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s.as_bytes())
}

/// A realistic, non-specimen JWT payload. Deliberately NOT the RFC 7519 /
/// jwt.io demo claim (`"sub":"1234567890","name":"John Doe"`), which keyhog
/// correctly suppresses as `rfc7519_example_jwt` — see the dedicated precision
/// locks below.
const REAL_PAYLOAD: &str = r#"{"email":"ops@acme.io","sub":"auth0|65f3a9c1d2b4","scope":"read:billing","iat":1700000000,"exp":1700003600}"#;
/// High-entropy, non-specimen signature (NOT the demo `SflKxw…` signature).
const REAL_SIG: &str = "Kp7Vb2T9hYR3qZ8mNx4cLwF6aD1sG5jB0eU2iO7tArQ9xZ";

/// Build a realistic structural JWT for the given `alg`. The algorithm value is
/// irrelevant to the `eyJ`-anchored structural shape (that is the point of #66),
/// so HS256/RS256/ES256 all surface identically — none collides with the
/// suppressed RFC 7519 specimen because the payload + signature are realistic.
fn jwt(alg: &str) -> String {
    let header = format!(r#"{{"alg":"{alg}","typ":"JWT"}}"#);
    format!("{}.{}.{}", b64url(&header), b64url(REAL_PAYLOAD), REAL_SIG)
}

/// The verbatim RFC 7519 §3.1 / jwt.io demo token — a textbook example that
/// appears in millions of docs and tutorials and is NOT a real credential.
const RFC7519_SPECIMEN: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
    eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.\
    SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

// ── HS256 shared signing secret in config (the forge-anything leak) ───────────

#[test]
fn jwt_secret_env_assignment_surfaces() {
    let sec = secret(40, 1);
    assert!(
        surfaces("app.env", &format!("JWT_SECRET={sec}\n"), &sec),
        "a JWT_SECRET env assignment must surface its signing secret"
    );
}

#[test]
fn jwt_secret_lowercase_yaml_surfaces() {
    let sec = secret(40, 2);
    assert!(
        surfaces("config.yaml", &format!("jwt_secret: {sec}\n"), &sec),
        "a lowercase jwt_secret YAML value must surface"
    );
}

#[test]
fn jwt_secret_quoted_surfaces() {
    let sec = secret(40, 3);
    assert!(
        surfaces("app.env", &format!("JWT_SECRET=\"{sec}\"\n"), &sec),
        "a quoted JWT_SECRET value must surface"
    );
}

#[test]
fn jwt_signing_secret_surfaces() {
    let sec = secret(40, 4);
    assert!(
        surfaces("app.env", &format!("JWT_SIGNING_SECRET={sec}\n"), &sec),
        "a JWT_SIGNING_SECRET assignment must surface"
    );
}

#[test]
fn jwt_signing_key_surfaces() {
    let sec = secret(40, 5);
    assert!(
        surfaces("app.env", &format!("JWT_SIGNING_KEY={sec}\n"), &sec),
        "a JWT_SIGNING_KEY assignment must surface (ends in _key)"
    );
}

#[test]
fn auth_secret_surfaces() {
    let sec = secret(40, 6);
    assert!(
        surfaces("app.env", &format!("AUTH_SECRET={sec}\n"), &sec),
        "an AUTH_SECRET (NextAuth-style JWT secret) must surface"
    );
}

#[test]
fn token_secret_surfaces() {
    let sec = secret(40, 7);
    assert!(
        surfaces("app.env", &format!("TOKEN_SECRET={sec}\n"), &sec),
        "a TOKEN_SECRET assignment must surface"
    );
}

#[test]
fn jwt_secret_base64_value_surfaces() {
    // Signing secrets are often stored base64-encoded; a 44-char base64 body
    // (32 random bytes) under JWT_SECRET must surface.
    let sec = "aGVsbG9zZWNyZXR2YWx1ZWZvcmp3dHNpZ25pbmcxMjM0NTY3OA==";
    assert!(
        surfaces(
            "app.env",
            &format!("JWT_SECRET={sec}\n"),
            "aGVsbG9zZWNyZXR2YWx1ZWZvcmp3"
        ),
        "a base64-encoded JWT_SECRET value must surface"
    );
}

#[test]
fn supabase_jwt_secret_attributed_to_supabase_detector() {
    let sec = secret(40, 8);
    assert!(
        surfaces_under(
            "supabase.env",
            &format!("SUPABASE_JWT_SECRET={sec}\n"),
            "supabase-jwt-secret",
            &sec
        ),
        "a SUPABASE_JWT_SECRET must be attributed to the supabase-jwt-secret detector"
    );
}

// ── RS256 / ES256: the signing PRIVATE KEY surfaces (asymmetric pairing) ──────

#[test]
fn rs256_signing_private_key_surfaces() {
    let text = format!("# RS256 signing key for JWT issuance\nJWT_PRIVATE_KEY=\"{PEM}\"\n");
    assert!(
        surfaces_under("jwt.env", &text, "private-key", PEM_NEEDLE),
        "an RS256 JWT signing PEM private key must surface as private-key"
    );
}

#[test]
fn rs256_signing_key_pem_block_surfaces() {
    // The PEM as a standalone block (the common id_rsa-style storage).
    assert!(
        surfaces_under("jwtRS256.key", PEM, "private-key", PEM_NEEDLE),
        "a standalone RS256 signing PEM block must surface as private-key"
    );
}

// ── the token itself surfaces across algorithms + contexts ────────────────────

#[test]
fn hs256_alg_first_token_surfaces() {
    let t = jwt("HS256");
    assert!(
        surfaces_under("h.txt", &t, "jwt-token", &t),
        "an HS256 JWT must surface as jwt-token"
    );
}

#[test]
fn rs256_alg_token_surfaces() {
    let t = jwt("RS256");
    assert!(
        surfaces_under("r.txt", &t, "jwt-token", &t),
        "an RS256 JWT must surface as jwt-token"
    );
}

#[test]
fn es256_alg_token_surfaces() {
    let t = jwt("ES256");
    assert!(
        surfaces_under("e.txt", &t, "jwt-token", &t),
        "an ES256 JWT must surface as jwt-token"
    );
}

#[test]
fn jwt_in_authorization_bearer_header_surfaces() {
    let t = jwt("HS256");
    let text = format!("Authorization: Bearer {t}\n");
    assert!(
        surfaces_under("req.http", &text, "jwt-token", &t),
        "a Bearer-header JWT must surface"
    );
}

#[test]
fn jwt_in_json_id_token_field_surfaces() {
    let t = jwt("HS256");
    let text = format!("{{\"id_token\":\"{t}\"}}\n");
    assert!(
        surfaces_under("resp.json", &text, "jwt-token", &t),
        "a JSON id_token JWT must surface"
    );
}

// ── precision: weak / placeholder signing secrets are correctly suppressed ────

#[test]
fn weak_dictionary_jwt_secret_is_suppressed() {
    assert!(
        nothing_surfaces("app.env", "JWT_SECRET=secret\n", "JWT_SECRET=secret"),
        "the literal weak value `secret` must not surface as a credential"
    );
}

#[test]
fn placeholder_jwt_secret_is_suppressed() {
    let text = "JWT_SECRET=your-256-bit-secret\n";
    assert!(
        nothing_surfaces("app.env", text, "your-256-bit-secret"),
        "the documented placeholder `your-256-bit-secret` must be suppressed"
    );
}

#[test]
fn changeme_jwt_secret_is_suppressed() {
    assert!(
        nothing_surfaces("app.env", "JWT_SECRET=changeme\n", "changeme"),
        "the placeholder `changeme` must be suppressed"
    );
}

#[test]
fn short_jwt_secret_below_floor_is_suppressed() {
    assert!(
        nothing_surfaces("app.env", "JWT_SECRET=abc123\n", "abc123"),
        "a 6-char JWT secret is below the entropy/length floor and must be suppressed"
    );
}

#[test]
fn jwt_secret_prose_mention_without_value_surfaces_nothing() {
    let text = "Set the JWT_SECRET environment variable before starting the server.\n";
    assert!(
        nothing_surfaces("README.md", text, "JWT_SECRET environment"),
        "prose mentioning JWT_SECRET without a value must surface nothing"
    );
}

// ── precision: the RFC 7519 / jwt.io specimen token is NOT a real credential ──
// It is the most-copied JWT on earth (every tutorial). The structural shape
// matches it, so it is dropped post-match by the `rfc7519_example_jwt`
// suppression — keyed on the literal base64url of
// `{"alg":"HS256","typ":"JWT"}.{"sub":"1234567890`, which no production token
// carries. A realistic JWT (REAL_PAYLOAD) with the SAME shape still surfaces,
// proving the suppression is specimen-specific and does not cost JWT recall.

#[test]
fn rfc7519_specimen_token_is_suppressed() {
    assert!(
        nothing_surfaces("app.log", RFC7519_SPECIMEN, RFC7519_SPECIMEN),
        "the verbatim RFC 7519 / jwt.io specimen JWT must be suppressed, not flagged"
    );
}

#[test]
fn rfc7519_specimen_in_auth_token_assignment_is_suppressed() {
    // The dominant real FP shape: the specimen pasted into a log/property line
    // (`auth_token=<specimen>`). The `contains`-based marker check catches it.
    let text = format!("auth_token={RFC7519_SPECIMEN}\n");
    assert!(
        nothing_surfaces("server.log", &text, RFC7519_SPECIMEN),
        "the specimen inside an auth_token= assignment must still be suppressed"
    );
}

#[test]
fn realistic_jwt_with_specimen_shape_still_surfaces() {
    // Same structural shape + same HS256 header bytes as the specimen, but a
    // realistic payload/signature — must surface, proving the suppression is
    // specimen-keyed, not a blanket HS256-JWT drop (no recall cost).
    let t = jwt("HS256");
    assert!(
        surfaces_under("token.txt", &t, "jwt-token", &t),
        "a realistic HS256 JWT must surface even though the specimen is suppressed"
    );
}
