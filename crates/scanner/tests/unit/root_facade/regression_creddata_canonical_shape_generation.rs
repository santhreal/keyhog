//! Regression for detector-owned canonical key-material generation. An owning
//! detector may admit exact hex key shapes; UUIDs and undeclared digest shapes
//! remain suppressed. Tests cover direct generation and end-to-end CPU scans.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::testing::entropy_scanner::{
    candidate_is_plausible, candidate_plausibility_rejection_reason, credential_keyword_context,
    is_canonical_non_secret_shape,
};
use keyhog_scanner::{CompiledScanner, ScanBackend, ScannerConfig};

// Real-world canonical-shape secrets, none matching any named service detector
// (no vendor prefix), so a hit proves the generic detector policy fired.
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

// ── (a) GENERATION-gate truth on `candidate_is_plausible` ──

#[test]
fn strict_gate_drops_canonical_shapes_under_anchor() {
    // A UUID, undeclared 64-hex value, and SHA-1 remain canonical non-secrets.
    let ctx = credential_keyword_context("api_key");
    for shape in [UUID_SECRET, HEX64_SECRET, SHA1_DIGEST] {
        assert!(
            is_canonical_non_secret_shape(shape),
            "{shape:?} must be a canonical non-secret shape (test fixture invariant)"
        );
        assert!(
            !candidate_is_plausible(shape, entropy(shape), &ctx, &[]),
            "credential context must drop undeclared canonical shape {shape:?}"
        );
    }
}

#[test]
fn detector_policy_generates_only_declared_key_material_under_anchor() {
    // Canonical key material is admitted only by the owning detector TOML.
    // UUIDs remain excluded because the generic assignment policy does not
    // declare them.
    let broad_ctx = credential_keyword_context("api_key");
    assert!(!candidate_is_plausible(
        UUID_SECRET,
        entropy(UUID_SECRET),
        &broad_ctx,
        &[]
    ));
    assert!(
        candidate_is_plausible(HEX32_SECRET, entropy(HEX32_SECRET), &broad_ctx, &[]),
        "detector-owned 32-hex rejection: {:?}",
        candidate_plausibility_rejection_reason(
            HEX32_SECRET,
            entropy(HEX32_SECRET),
            &broad_ctx,
            &[]
        )
    );
    let crypto_ctx = credential_keyword_context("encryption_key");
    assert!(
        candidate_is_plausible(HEX64_SECRET, entropy(HEX64_SECRET), &crypto_ctx, &[]),
        "hex64 must generate only under explicit crypto-key material anchors"
    );
}

#[test]
fn detector_policy_never_generates_sha1_hex40_under_anchor() {
    let ctx = credential_keyword_context("api_key");
    let sha1_hex40 = "356a192b7913b04c54574d18c28d46e6395428ab";
    assert_eq!(sha1_hex40.len(), 40);
    assert!(is_canonical_non_secret_shape(sha1_hex40));
    assert!(
        !candidate_is_plausible(sha1_hex40, entropy(sha1_hex40), &ctx, &[]),
        "sha1/git-sha hex40 must stay outside the detector-owned canonical policy"
    );
}

#[test]
fn detector_policy_still_drops_short_and_placeholder_values() {
    // Canonical-shape policy does not bypass length or entropy floors.
    let ctx = credential_keyword_context("api_key");
    // 7-char value: below the detector-owned minimum.
    assert!(
        !candidate_is_plausible("abc1234", entropy("abc1234"), &ctx, &[]),
        "value below the password-length floor must stay dropped"
    );
    // All-identical low-entropy value: below the credential-context entropy
    // threshold.
    let flat = "aaaaaaaaaaaaaaaa";
    assert!(
        !candidate_is_plausible(flat, entropy(flat), &ctx, &[]),
        "value below the entropy threshold must stay dropped"
    );
}

// ── (b) END-TO-END: the shipped CPU-fallback path surfaces the candidate ────

fn scanner() -> &'static CompiledScanner {
    static SCANNER: std::sync::LazyLock<CompiledScanner> = std::sync::LazyLock::new(|| {
        let mut config = ScannerConfig::default();
        config.min_confidence = 0.0;
        config.sanitise();
        CompiledScanner::compile(
            keyhog_core::load_embedded_detectors_or_fail().expect("load embedded detectors"),
        )
        .expect("compile scanner")
        .with_config(config)
    });
    &SCANNER
}

fn scanner_without_ml_authority() -> &'static CompiledScanner {
    static SCANNER: std::sync::LazyLock<CompiledScanner> = std::sync::LazyLock::new(|| {
        let mut config = ScannerConfig::default();
        config.min_confidence = 0.0;
        config.entropy_ml_authoritative = false;
        config.sanitise();
        CompiledScanner::compile(
            keyhog_core::load_embedded_detectors_or_fail().expect("load embedded detectors"),
        )
        .expect("compile scanner")
        .with_config(config)
    });
    &SCANNER
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
    let s = scanner();
    for keyword in ["api_key", "client_secret"] {
        assert!(
            !caught(s, &format!("{keyword} = \"{UUID_SECRET}\""), UUID_SECRET),
            "UUID under generic `{keyword}=` must stay suppressed"
        );
    }
}

#[test]
fn e2e_hex64_aes_key_under_strong_keyword_is_generated_and_surfaced() {
    // 64-hex (AES-256 key) under a strong cryptographic-key keyword, the
    // CredData `hex64` miss class, previously dropped as a sha256 digest at the
    // generation source.
    let s = scanner();
    assert!(
        caught(
            s,
            &format!("encryption_key = \"{HEX64_SECRET}\""),
            HEX64_SECRET
        ),
        "64-hex AES-256 key under `encryption_key=` must be generated by the owning detector policy"
    );
}

#[test]
fn e2e_sha1_hex40_under_broad_secret_keywords_stays_suppressed() {
    let s = scanner();
    let sha1_hex40 = "356a192b7913b04c54574d18c28d46e6395428ab";
    for line in [
        format!("api_key = \"{sha1_hex40}\""),
        format!("secret = \"{sha1_hex40}\""),
        format!("secret_key = \"{sha1_hex40}\""),
    ] {
        assert!(
            !caught(s, &line, sha1_hex40),
            "sha1/git-sha hex40 must stay suppressed for broad entropy anchors: {line}"
        );
    }
}

#[test]
fn e2e_hex64_under_broad_secret_keyword_stays_suppressed() {
    let s = scanner();
    assert!(
        !caught(s, &format!("secret = \"{HEX64_SECRET}\""), HEX64_SECRET),
        "sha256-length hex64 under broad `secret=` must stay suppressed; explicit \
         crypto-key anchors own the AES-256 key-material exception"
    );
}

#[test]
fn e2e_placeholder_uuid_stays_suppressed() {
    let s = scanner();
    let zero_uuid = "00000000-0000-0000-0000-000000000000";
    assert!(
        !caught(s, &format!("api_key = \"{zero_uuid}\""), zero_uuid),
        "all-zero placeholder UUID must stay content-suppressed"
    );
    // EXAMPLE-bearing canonical hex placeholder must also stay dropped: the
    // empty-input MD5 hash is a documentation/integrity placeholder, never a
    // secret.
    let empty_md5 = "d41d8cd98f00b204e9800998ecf8427e";
    assert!(
        !caught(s, &format!("secret = \"{empty_md5}\""), empty_md5),
        "empty-input MD5 placeholder hash must stay content-suppressed"
    );
}

#[test]
fn e2e_detector_owned_hex_policy_does_not_depend_on_ml_authority() {
    let s = scanner_without_ml_authority();
    assert!(
        !caught(s, &format!("api_key = \"{UUID_SECRET}\""), UUID_SECRET),
        "UUID under `api_key=` must stay suppressed"
    );
    assert!(
        caught(
            s,
            &format!("encryption_key = \"{HEX64_SECRET}\""),
            HEX64_SECRET
        ),
        "64-hex key under `encryption_key=` must remain detector-owned when ML authority is disabled"
    );
}

#[test]
fn e2e_keyword_free_canonical_shape_stays_suppressed() {
    let s = scanner();
    // A bare UUID on a line with no credential keyword (a plain value line).
    let line = format!("resource_id = \"{UUID_SECRET}\"");
    assert!(
        !caught(s, &line, UUID_SECRET),
        "UUID under a non-credential keyword (`resource_id`) must stay suppressed"
    );
}
