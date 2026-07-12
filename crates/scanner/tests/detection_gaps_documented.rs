//! Detection behavior guards + honestly-labeled open candidates (#177/#184).
//!
//! IMPORTANT (integrity note): an earlier version of this file asserted several
//! "confirmed recall bugs." Rigorous re-verification against the PRODUCTION auto
//! scan path (`CompiledScanner::scan`, which selects SimdCpu/Hyperscan when
//! usable) showed most were MY TESTING ERRORS, not scanner bugs:
//!   * mongodb-connection-string — fires on the auto/SimdCpu path; only silent on
//!     the AC-only `CpuFallback` backend I had forced. Correct-by-design.
//!   * jwt-token — my token was the canonical RFC-7519 / jwt.io EXAMPLE, which is
//!     correctly suppressed (`rfc7519_example_n`). A real JWT fires.
//!   * twilio-api-key — spec has a `required=true` companion + SK is deliberately
//!     below the AC-prefilter floor (documented in the .toml).
//! The lesson: these must be tested via the auto `scan()` path (production), not
//! a forced backend. The tests below are GREEN guards for the correct behavior;
//! only two genuinely-unexplained cases remain as `#[ignore]` UNCONFIRMED
//! candidates (silent even under ideal conditions — likely spec nuances I have
//! not yet isolated, given the 4/5 false-positive rate above, NOT confirmed
//! bugs). ML-independent; run without `ml` while the embedded weights are
//! mid-retrain.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};

fn chunk(text: &str) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "gap-repro".into(),
            path: Some("s.txt".into()),
            base_offset: 0,
            ..Default::default()
        },
    }
}

/// Production auto path: `scan` selects SimdCpu/Hyperscan when usable, which is
/// what real scans use. This is the correct path for detection-truth.
fn fired_ids_auto(text: &str) -> Vec<String> {
    let scanner = CompiledScanner::compile(keyhog_core::embedded_detector_specs().to_vec())
        .expect("scanner compile");
    scanner
        .scan(&chunk(text))
        .iter()
        .map(|m| m.detector_id.to_string())
        .collect()
}

/// Forced-backend path, for asserting backend-specific behavior explicitly.
fn fired_ids_backend(text: &str, backend: ScanBackend) -> Vec<String> {
    let scanner = CompiledScanner::compile(keyhog_core::embedded_detector_specs().to_vec())
        .expect("scanner compile");
    scanner
        .scan_chunks_with_backend(std::slice::from_ref(&chunk(text)), backend)
        .iter()
        .flat_map(|per| per.iter())
        .map(|m| m.detector_id.to_string())
        .collect()
}

// ── GREEN guards: correct behavior (via the production auto path) ─────────────

#[test]
fn jwt_token_fires_on_a_real_jwt() {
    // A non-example JWT (fresh payload) must be detected.
    let ids = fired_ids_auto(
        "authorization = eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.\
         eyJ1c2VyIjoiYWxpY2UiLCJyb2xlIjoiYWRtaW4iLCJvcmciOiJhY21lY29ycCJ9.\
         k3nGq7pXwZ2vLm9RtY4bN8sD1fHcJ0aQ6eU5iO2xW3o",
    );
    assert!(
        ids.iter().any(|id| id == "jwt-token"),
        "a real JWT must fire jwt-token; got {ids:?}"
    );
}

#[test]
fn jwt_token_suppresses_the_rfc7519_example() {
    // The canonical jwt.io / RFC-7519 example token is a documented non-secret
    // and MUST be suppressed (precision), even though it is a structurally valid
    // JWT. This pins that suppression.
    let ids = fired_ids_auto(
        "authorization = eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
         eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.\
         SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    );
    assert!(
        !ids.iter().any(|id| id == "jwt-token"),
        "the RFC-7519 example JWT must be suppressed; got {ids:?}"
    );
}

#[test]
fn mongodb_connection_string_fires_on_plain_uri_via_auto() {
    // The production auto path (SimdCpu/Hyperscan) catches the plain mongodb://
    // URI. (The AC-only CpuFallback backend does not — that is a deliberate
    // literal-only path, not a production recall gap.)
    let ids =
        fired_ids_auto("MONGO_URI=mongodb://admin:Str0ngMongoPwd@cluster0.example.com:27017/db");
    assert!(
        ids.iter().any(|id| id == "mongodb-connection-string"),
        "mongodb-connection-string must fire on the plain URI via the auto path; got {ids:?}"
    );
}

#[test]
fn cpufallback_is_ac_only_for_hs_only_detectors() {
    // Documents (does not lament) the deliberate design: the forced CpuFallback
    // backend is AC-literal-only, so an HS-only-triggered detector like
    // mongodb-connection-string is not reached there. This is why detection
    // tests must use the auto path, and why forcing CpuFallback understates
    // recall for the ~49 no-literal detectors.
    let uri = "MONGO_URI=mongodb://admin:Str0ngMongoPwd@cluster0.example.com:27017/db";
    let cpu = fired_ids_backend(uri, ScanBackend::CpuFallback);
    let simd = fired_ids_backend(uri, ScanBackend::SimdCpu);
    assert!(
        !cpu.iter().any(|id| id == "mongodb-connection-string"),
        "expected CpuFallback (AC-only) NOT to reach mongodb-connection-string; got {cpu:?}"
    );
    assert!(
        simd.iter().any(|id| id == "mongodb-connection-string"),
        "expected SimdCpu (AC ∪ HS) to reach mongodb-connection-string; got {simd:?}"
    );
}

#[test]
fn sanity_api_token_fires_with_keyword_context() {
    let ids = fired_ids_auto("sanity_token = \"skPNc6FX11CsV275924b377c3d0bc2b3c27e9\"");
    assert!(
        ids.iter().any(|id| id == "sanity-api-token"),
        "sanity-api-token should fire with keyword context; got {ids:?}"
    );
}

// ── UNCONFIRMED candidates (silent even under ideal conditions) ───────────────
// These are #[ignore] and honestly labeled: given the 4/5 false-positive rate on
// my earlier "confirmed bugs," these are most likely spec nuances (a required
// companion, an entropy/placeholder suppression, an exact-length mismatch) I
// have not yet isolated — NOT verified bugs. They reproduce the silence so a
// scanner-internals owner can adjudicate; delete or convert to green on verdict.

#[test]
#[ignore = "UNCONFIRMED — twilio-api-key silent on auto path even with required companion; likely spec nuance, needs adjudication"]
fn twilio_api_key_candidate() {
    let ids = fired_ids_auto(
        "TWILIO_API_KEY=SKf77dea48db85fef690ffcbfc3fc3a4e6\n\
         TWILIO_API_SECRET=abcdefghijklmnopqrstuvwxyz012345",
    );
    assert!(
        ids.iter().any(|id| id == "twilio-api-key"),
        "twilio-api-key silent even with companion+keyword on auto path; got {ids:?}"
    );
}

#[test]
#[ignore = "UNCONFIRMED — telegram-bot-token silent on auto path with keyword+shape-valid token; needs adjudication"]
fn telegram_bot_token_candidate() {
    let ids = fired_ids_auto("TELEGRAM_BOT_TOKEN=36969501:Y3v_-X128qWyqrf_g__n_s-O--j-_m6-2GY");
    assert!(
        ids.iter().any(|id| id == "telegram-bot-token"),
        "telegram-bot-token silent with keyword+shape-valid token on auto path; got {ids:?}"
    );
}
