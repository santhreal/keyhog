//! Regression: a service-anchored detector whose regex REQUIRED its
//! service-specific keyword (`ALCHEMY_API_KEY=`, `CROWDIN_API_TOKEN=`,
//! `DATADOG_API_KEY:`) and captured a canonical-length pure-hex value must
//! surface that value — the keyword anchor disambiguates the MD5/SHA collision.
//!
//! These detectors are classified `weak_anchor` (their pure-hex capture is
//! shape-indistinguishable from a digest), so `bypass_shape_gates` is false and
//! the `bare_hex_digest` arm of the suppression cascade dropped the value BEFORE
//! confidence ran — defeating the detectors' own `min_confidence = 0.2`, which
//! explicitly declares the keyword anchor authoritative. The fix wires the
//! existing KH-L-0110 `allow_canonical_hex_key` escape hatch (CredData-validated:
//! hex48+kw 1033 POS / 0 NEG; hex32+kw 0.976) into the named-detector path,
//! keyed on the detector's service anchor instead of a captured keyword.
//!
//! FP-safe by construction: only the `bare_hex_digest` / `algorithmic_placeholder`
//! arms are exempted — every decoy gate (repetitive runs, fake sequences,
//! prefixed-hash labels, UUID, dashed serials) still runs, and only for
//! `is_service_anchored_detector` ids whose regex required the keyword. The
//! negative twins below pin that the lift rides on the service-anchored match,
//! not the bare hex shape, and that an obvious placeholder hex stays suppressed.

mod support;
use support::paths::detector_dir;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::testing::is_canonical_service_hex_key;
use keyhog_scanner::{CompiledScanner, ScanBackend};
use std::sync::OnceLock;

fn scanner() -> &'static CompiledScanner {
    static SCANNER: OnceLock<CompiledScanner> = OnceLock::new();
    SCANNER.get_or_init(|| {
        let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
        CompiledScanner::compile(detectors).expect("compile scanner")
    })
}

fn matches_for(body: &str) -> Vec<(String, String)> {
    let chunk = Chunk {
        data: body.into(),
        metadata: ChunkMetadata {
            source_type: "canonical-hex-key-regression".into(),
            path: Some("notes/hex-key-probe.txt".into()),
            ..Default::default()
        },
    };
    scanner().clear_fragment_cache();
    scanner()
        .scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::CpuFallback)
        .into_iter()
        .flatten()
        .map(|m| (m.detector_id.to_string(), m.credential.to_string()))
        .collect()
}

fn surfaced(matches: &[(String, String)], detector_id: &str, credential_substr: &str) -> bool {
    matches
        .iter()
        .any(|(id, found)| id == detector_id && found.contains(credential_substr))
}

fn detector_fired(matches: &[(String, String)], detector_id: &str) -> bool {
    matches.iter().any(|(id, _)| id == detector_id)
}

#[test]
fn is_canonical_service_hex_key_accepts_only_canonical_hex_lengths() {
    // Canonical service-key lengths: accepted.
    assert!(is_canonical_service_hex_key(
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d"
    )); // 32 (MD5)
    assert!(is_canonical_service_hex_key(
        "3b70df2c347b7e02b642198793dc0b8a9827bb4c"
    )); // 40 (SHA1)
    assert!(is_canonical_service_hex_key(&"a".repeat(48))); // 48
    assert!(is_canonical_service_hex_key(&"0123456789abcdef".repeat(4))); // 64 (SHA256)

    // Non-canonical lengths the gate also catches (56/72/128 SHA-2 digests)
    // stay OUT — no service detector requests them as a key body.
    assert!(!is_canonical_service_hex_key(&"a".repeat(56)));
    assert!(!is_canonical_service_hex_key(&"a".repeat(72)));
    assert!(!is_canonical_service_hex_key(&"a".repeat(128)));
    // Off-length: rejected.
    assert!(!is_canonical_service_hex_key(&"a".repeat(31)));
    assert!(!is_canonical_service_hex_key(&"a".repeat(33)));
    // Non-hex / mixed-case: rejected (real digests are single-case).
    assert!(!is_canonical_service_hex_key(
        "g123456789abcdef0123456789abcdef"
    ));
    assert!(!is_canonical_service_hex_key(
        "7B3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d"
    ));
}

#[test]
fn keyword_anchored_pure_hex_key_surfaces() {
    // alchemy-api-key: `ALCHEMY_API_KEY=` keyword + 32-hex. weak_anchor, so
    // bypass_shape_gates is false; the bare_hex_digest arm used to drop it.
    let matches = matches_for("ALCHEMY_API_KEY=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d");
    assert!(
        surfaced(
            &matches,
            "alchemy-api-key",
            "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d"
        ),
        "ALCHEMY_API_KEY=<32hex> must surface; matches={matches:?}"
    );

    // crowdin-api-token: 40-hex under the CROWDIN keyword — the longer SHA1
    // length must also surface under the service anchor.
    let matches = matches_for("CROWDIN_API_TOKEN = 3b70df2c347b7e02b642198793dc0b8a9827bb4c");
    assert!(
        surfaced(
            &matches,
            "crowdin-api-token",
            "3b70df2c347b7e02b642198793dc0b8a9827bb4c"
        ),
        "CROWDIN_API_TOKEN=<40hex> must surface; matches={matches:?}"
    );
}

#[test]
fn bare_hex_without_service_keyword_does_not_claim_the_named_detector() {
    // The exemption rides on the service-anchored regex match, not the hex
    // shape: a bare 32-hex with no ALCHEMY keyword does not match the detector
    // regex, so the named detector must not fire.
    let matches = matches_for("git_commit = 7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d");
    assert!(
        !detector_fired(&matches, "alchemy-api-key"),
        "bare 32-hex without the ALCHEMY anchor must not fire alchemy-api-key; matches={matches:?}"
    );
}

#[test]
fn placeholder_hex_under_service_keyword_stays_suppressed() {
    // The exemption relaxes ONLY the bare-hex-digest arm; the repetition decoy
    // gate still runs. An all-zero 32-hex placeholder under the keyword must NOT
    // surface — it is an obvious decoy, not a real key.
    let matches = matches_for("ALCHEMY_API_KEY=00000000000000000000000000000000");
    assert!(
        !surfaced(
            &matches,
            "alchemy-api-key",
            "00000000000000000000000000000000"
        ),
        "all-zero placeholder hex must stay suppressed even under the keyword; matches={matches:?}"
    );
}
