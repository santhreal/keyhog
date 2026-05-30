//! Regression gate for task #64 - PEM private-key recall on the
//! production CLI path.
//!
//! The contract-runner-level test passes on raw `scanner.scan(&chunk)`,
//! but the K8s differential bench showed the production CLI path was
//! still missing private-key findings even when scanner found them
//! (the orchestrator's `min_confidence < 0.3` filter was dropping
//! them at confidence 0.053). The four fixes in #64 (detector rename,
//! multi-line regex, `-----BEGIN` confidence floor, PEM body-entropy
//! bypass) MUST keep both layers passing.
//!
//! This test verifies the SCANNER layer reports confidence ≥ 0.5 for
//! a PEM-framed credential - a guard against any future change that
//! re-lowers the confidence floor below the CLI's default
//! min_confidence filter.

mod support;
use support::paths::detector_dir;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;
const PEM_YAML: &str = r#"api_key: my-real-app-key
tls_private_key: |
  -----BEGIN RSA PRIVATE KEY-----
  MIIEowIBAAKCAQEA3UzRe60Sgbw7Szrwkw4I97rbfs7+bvtt8ZAs9uO+Qz502eyS
  toqQrh3psgmPPDOlcmgZCKgFb75dy2Ykvh7t4HfvHpW3RqwsULLotTK1HAIPDqAT
  Pve1M6CgtxzBSBRKasyo1SSq+T21dxfF1yAUHk
  -----END RSA PRIVATE KEY-----
"#;

fn scan() -> Vec<keyhog_core::RawMatch> {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");
    let chunk = Chunk {
        data: PEM_YAML.into(),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            path: Some("config.yaml".into()),
            ..Default::default()
        },
    };
    scanner.scan(&chunk)
}

#[test]
fn private_key_detector_fires_on_yaml_embedded_pem() {
    let matches = scan();
    let hit = matches
        .iter()
        .find(|m| m.detector_id.as_ref() == "private-key");
    assert!(
        hit.is_some(),
        "TASK #64: `private-key` detector MUST fire on the YAML-embedded \
         RSA PEM block. Scanner saw: {:?}",
        matches
            .iter()
            .map(|m| m.detector_id.as_ref())
            .collect::<Vec<_>>(),
    );
}

#[test]
fn private_key_capture_includes_pem_body() {
    let matches = scan();
    let hit = matches
        .iter()
        .find(|m| m.detector_id.as_ref() == "private-key")
        .expect("private-key must fire");
    // Body-unique substring NOT present in the BEGIN/END headers.
    let body_marker = "toqQrh3psgmPPDOlcmgZCKgFb75dy2Ykvh7t4HfvHpW3RqwsULLotTK1HAIPDqAT";
    assert!(
        hit.credential.as_ref().contains(body_marker),
        "TASK #64: `private-key` capture must include the PEM body, not just \
         the BEGIN/END header. Captured: {:?}",
        &hit.credential.as_ref()[..hit.credential.len().min(120)],
    );
}

#[test]
fn private_key_confidence_above_cli_floor() {
    // The CLI's default `min_confidence` is 0.3 (see crates/cli/src/orchestrator.rs).
    // Any detector with a real-world recall target MUST score above
    // that floor at the scanner layer, or the CLI silently drops it.
    // Asserting 0.5 here gives 67% headroom over the CLI cutoff so a
    // future tuning change can move the cutoff to 0.4 without
    // regressing.
    let matches = scan();
    let hit = matches
        .iter()
        .find(|m| m.detector_id.as_ref() == "private-key")
        .expect("private-key must fire");
    let conf = hit.confidence.unwrap_or(0.0);
    assert!(
        conf >= 0.5,
        "TASK #64: `private-key` confidence must be >= 0.5 to clear the \
         CLI's 0.3 min_confidence floor with headroom. Saw {conf:.3}. \
         If this regresses, the `-----BEGIN` entry in \
         crates/scanner/src/confidence/prefixes.rs has likely been removed, \
         OR the pipeline's PEM body-entropy bypass in \
         crates/scanner/src/pipeline.rs no longer triggers."
    );
}
