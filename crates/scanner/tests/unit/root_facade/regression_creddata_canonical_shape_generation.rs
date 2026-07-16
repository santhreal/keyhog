//! Regression for model-authoritative canonical key-material generation. A
//! strong key-material anchor may release narrowly accepted hex key shapes for
//! MoE arbitration. UUIDs remain identifiers in the generic entropy bridge;
//! provider-specific UUID credentials belong in detector TOMLs.
//!
//! Tests split into (a) GENERATION-gate truth on the pure
//! `candidate_is_plausible` predicate (the cheapest, most direct pin of the lift
//! switch) and (b) END-TO-END proof that the shipped CPU-fallback scan path
//! surfaces the value with the production default config (ML + entropy +
//! `entropy_ml_authoritative` all on), gated to a `min_confidence = 0.0` floor
//! so the assertion pins candidate GENERATION, not the MoE's score magnitude
//! (which is lane-4 scoring, deliberately out of scope here).

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::testing::entropy_scanner::{
    candidate_is_plausible, credential_keyword_context, credential_keyword_context_with_lift,
    is_canonical_non_secret_shape,
};
use keyhog_scanner::{CompiledScanner, ScanBackend, ScannerConfig};

// Real-world canonical-shape secrets, none matching any named service detector
// (no vendor prefix), so a hit proves the GENERIC entropy generation lift fired.
const UUID_SECRET: &str = "636765a9-1f92-4b40-ab0b-85ebd1e2c23d";
const HEX64_SECRET: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
const HEX32_SECRET: &str = "3f8a9c2e1b7d4f6a8c0e2d4f6a8b0c1e";
const SHA1_DIGEST: &str = "356a192b7913b04c54574d18c28d46e6395428ab";

/// The SAME Shannon-entropy metric the scanner computes for a candidate, so the
/// generation-gate unit tests below feed `candidate_is_plausible` the exact
/// value the production path would.
fn entropy(value: &str) -> f64 {
    keyhog_scanner::entropy::shannon_entropy(value.as_bytes())
}

// ── (a) GENERATION-gate truth: the lift switch on `candidate_is_plausible` ──

#[test]
fn strict_gate_drops_canonical_shapes_under_anchor() {
    // The non-lift (model-absent) credential context MUST keep the strict gate:
    // a UUID / 64-hex / SHA-1 value is a hash/UUID shape and never generates a
    // candidate. A 32-hex api_key is deliberately detector-owned key material,
    // even without model arbitration.
    let ctx = credential_keyword_context("api_key");
    for shape in [UUID_SECRET, HEX64_SECRET, SHA1_DIGEST] {
        assert!(
            is_canonical_non_secret_shape(shape),
            "{shape:?} must be a canonical non-secret shape (test fixture invariant)"
        );
        assert!(
            !candidate_is_plausible(shape, entropy(shape), &ctx, &[]),
            "strict credential context must DROP canonical shape {shape:?} at the \
             generation source (no model in scope → no lift)"
        );
    }
}

#[test]
fn lift_generates_only_key_material_candidates_under_anchor() {
    // The model-authoritative (lifted) credential context MUST GENERATE the
    // candidate so the MoE can arbitrate it. UUIDs are deliberately excluded:
    // generic assignment keywords cannot distinguish them from identifiers.
    let broad_ctx = credential_keyword_context_with_lift("api_key", true);
    assert!(!candidate_is_plausible(
        UUID_SECRET,
        entropy(UUID_SECRET),
        &broad_ctx,
        &[]
    ));
    assert!(candidate_is_plausible(
        HEX32_SECRET,
        entropy(HEX32_SECRET),
        &broad_ctx,
        &[]
    ));
    let crypto_ctx = credential_keyword_context_with_lift("encryption_key", true);
    assert!(
        candidate_is_plausible(HEX64_SECRET, entropy(HEX64_SECRET), &crypto_ctx, &[]),
        "hex64 must generate only under explicit crypto-key material anchors"
    );
}

#[test]
fn lift_never_generates_sha1_hex40_under_anchor() {
    let ctx = credential_keyword_context_with_lift("api_key", true);
    let sha1_hex40 = "356a192b7913b04c54574d18c28d46e6395428ab";
    assert_eq!(sha1_hex40.len(), 40);
    assert!(is_canonical_non_secret_shape(sha1_hex40));
    assert!(
        !candidate_is_plausible(sha1_hex40, entropy(sha1_hex40), &ctx, &[]),
        "sha1/git-sha hex40 must stay suppressed even under the model-authoritative lift"
    );
}

#[test]
fn lift_still_drops_short_and_placeholder_values() {
    // The lift releases ONLY the canonical-shape gate; the length floor and the
    // entropy-threshold floor still apply, so a too-short or a zero-entropy
    // value never generates even under the lift. Negative twin to the lift test.
    let ctx = credential_keyword_context_with_lift("api_key", true);
    // 7-char value: below MIN_PASSWORD_LEN (8), dropped regardless of lift.
    assert!(
        !candidate_is_plausible("abc1234", entropy("abc1234"), &ctx, &[]),
        "value below the password-length floor must stay dropped under the lift"
    );
    // All-identical low-entropy value: below the credential-context entropy
    // threshold, dropped regardless of lift.
    let flat = "aaaaaaaaaaaaaaaa";
    assert!(
        !candidate_is_plausible(flat, entropy(flat), &ctx, &[]),
        "value below the entropy threshold must stay dropped under the lift"
    );
}

// ── (b) END-TO-END: the shipped CPU-fallback path surfaces the candidate ────

fn scanner_with_floor(min_confidence: f64) -> CompiledScanner {
    // Default config has ml_enabled, entropy_enabled, and
    // entropy_ml_authoritative all true, the production state that engages the
    // lift. Lower only the min-confidence floor so the assertion pins candidate
    // GENERATION (the value reaches the output), not the MoE's score magnitude.
    let mut config = ScannerConfig::default();
    config.min_confidence = min_confidence;
    config.sanitise();
    assert!(
        config.entropy_ml_authoritative && config.ml_enabled && config.entropy_enabled,
        "fixture invariant: default config must be model-authoritative for the lift"
    );
    CompiledScanner::compile(Vec::new())
        .expect("compile scanner")
        .with_config(config)
}

fn scanner_without_lift(min_confidence: f64) -> CompiledScanner {
    let mut config = ScannerConfig::default();
    config.min_confidence = min_confidence;
    // Turn OFF model authority: the lift must NOT engage, so the canonical
    // shapes stay suppressed exactly as on the legacy path.
    config.entropy_ml_authoritative = false;
    config.sanitise();
    CompiledScanner::compile(Vec::new())
        .expect("compile scanner")
        .with_config(config)
}

fn credentials_for(scanner: &CompiledScanner, line: &str) -> Vec<String> {
    let chunk = Chunk {
        data: line.into(),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            path: Some("config/app.env".into()),
            ..ChunkMetadata::default()
        },
    };
    scanner.clear_fragment_cache();
    scanner
        .scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::CpuFallback)
        .into_iter()
        .flatten()
        .map(|m| m.credential.to_string())
        .collect()
}

fn caught(scanner: &CompiledScanner, line: &str, value: &str) -> bool {
    credentials_for(scanner, line).iter().any(|c| c == value)
}

#[test]
fn e2e_uuid_under_generic_keyword_stays_suppressed() {
    // A generic assignment cannot distinguish a UUID credential from a resource
    // identifier. Provider-specific UUID formats belong to detector TOMLs.
    let s = scanner_with_floor(0.0);
    for keyword in ["api_key", "client_secret"] {
        assert!(
            !caught(&s, &format!("{keyword} = \"{UUID_SECRET}\""), UUID_SECRET),
            "UUID under generic `{keyword}=` must stay suppressed"
        );
    }
}

#[test]
fn e2e_hex64_aes_key_under_strong_keyword_is_generated_and_surfaced() {
    // 64-hex (AES-256 key) under a strong cryptographic-key keyword, the
    // CredData `hex64` miss class, previously dropped as a sha256 digest at the
    // generation source.
    let s = scanner_with_floor(0.0);
    assert!(
        caught(
            &s,
            &format!("encryption_key = \"{HEX64_SECRET}\""),
            HEX64_SECRET
        ),
        "64-hex AES-256 key under `encryption_key=` must be GENERATED + surfaced \
         via the model-authoritative entropy lift"
    );
}

#[test]
fn e2e_sha1_hex40_under_broad_secret_keywords_stays_suppressed() {
    let s = scanner_with_floor(0.0);
    let sha1_hex40 = "356a192b7913b04c54574d18c28d46e6395428ab";
    for line in [
        format!("api_key = \"{sha1_hex40}\""),
        format!("secret = \"{sha1_hex40}\""),
        format!("secret_key = \"{sha1_hex40}\""),
    ] {
        assert!(
            !caught(&s, &line, sha1_hex40),
            "sha1/git-sha hex40 must stay suppressed for broad entropy anchors: {line}"
        );
    }
}

#[test]
fn e2e_hex64_under_broad_secret_keyword_stays_suppressed() {
    let s = scanner_with_floor(0.0);
    assert!(
        !caught(&s, &format!("secret = \"{HEX64_SECRET}\""), HEX64_SECRET),
        "sha256-length hex64 under broad `secret=` must stay suppressed; explicit \
         crypto-key anchors own the AES-256 key-material exception"
    );
}

#[test]
fn e2e_placeholder_uuid_stays_suppressed_even_under_lift() {
    // Negative twin: the lift releases the SHAPE gate but keeps every CONTENT
    // gate. An all-zero placeholder UUID is content-suppressed (run-of-identical
    // bytes) and must NEVER surface, even at a zero floor under the lift.
    let s = scanner_with_floor(0.0);
    let zero_uuid = "00000000-0000-0000-0000-000000000000";
    assert!(
        !caught(&s, &format!("api_key = \"{zero_uuid}\""), zero_uuid),
        "all-zero placeholder UUID must stay content-suppressed"
    );
    // EXAMPLE-bearing canonical hex placeholder must also stay dropped: the
    // empty-input MD5 hash is a documentation/integrity placeholder, never a
    // secret, and the content (example) gate fires even with the shape arm lifted.
    let empty_md5 = "d41d8cd98f00b204e9800998ecf8427e";
    assert!(
        !caught(&s, &format!("secret = \"{empty_md5}\""), empty_md5),
        "empty-input MD5 placeholder hash must stay content-suppressed under the lift"
    );
}

#[test]
fn e2e_lift_is_gated_off_when_model_not_authoritative() {
    // With `entropy_ml_authoritative = false`, the hex-key lift must not engage.
    // UUIDs stay suppressed with or without model authority.
    let s = scanner_without_lift(0.0);
    assert!(
        !caught(&s, &format!("api_key = \"{UUID_SECRET}\""), UUID_SECRET),
        "UUID under `api_key=` must stay suppressed"
    );
    assert!(
        !caught(
            &s,
            &format!("encryption_key = \"{HEX64_SECRET}\""),
            HEX64_SECRET
        ),
        "64-hex key under `encryption_key=` must STAY suppressed when the MoE is \
         not authoritative (lift gated off)"
    );
}

#[test]
fn e2e_keyword_free_canonical_shape_never_lifts() {
    // The lift is anchor-gated: a canonical shape with NO credential keyword on
    // its line has no positive evidence, so it must NEVER generate, even with the
    // model authoritative and a zero floor. Pins the keyword-free strict gate.
    let s = scanner_with_floor(0.0);
    // A bare UUID on a line with no credential keyword (a plain value line).
    let line = format!("resource_id = \"{UUID_SECRET}\"");
    assert!(
        !caught(&s, &line, UUID_SECRET),
        "UUID under a non-credential keyword (`resource_id`) must stay suppressed"
    );
}
