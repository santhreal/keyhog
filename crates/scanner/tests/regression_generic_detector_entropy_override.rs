//! The generic assignment bridge must pass the raw scan entropy threshold to
//! the shared detector-aware policy owner. A detector can calibrate
//! `entropy_high` below the compiled global default, so pre-resolving against
//! that global default would silently ignore stricter operator settings in the
//! gap between the detector and global thresholds.

use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::testing::entropy_fast::shannon_entropy_simd;
use keyhog_scanner::{CompiledScanner, ScanBackend, ScannerConfig};

const CREDENTIAL: &str = "kD7pQ2vN8xC4mR6tK7pQ";
const DETECTOR_ENTROPY_HIGH: f64 = 4.0;

fn scanner(entropy_threshold: f64) -> CompiledScanner {
    let mut detectors =
        keyhog_core::load_embedded_detectors_or_fail().expect("load embedded detectors");
    detectors.retain(|detector| detector.id == "generic-secret");
    detectors
        .iter_mut()
        .find(|detector| detector.id == "generic-secret")
        .expect("generic-secret detector exists")
        .entropy_high = Some(DETECTOR_ENTROPY_HIGH);

    let mut config = ScannerConfig::default();
    config.entropy_threshold = entropy_threshold;
    config.generic_keyword_low_entropy = false;
    config.min_confidence = 0.0;

    CompiledScanner::compile(detectors)
        .expect("compile detectors")
        .with_config(config)
}

fn matches_at(entropy_threshold: f64) -> Vec<RawMatch> {
    let chunk = Chunk {
        data: format!("app_secret={CREDENTIAL}\n").into(),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            path: Some("/repo/service.env".into()),
            ..Default::default()
        },
    };
    scanner(entropy_threshold)
        .scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::CpuFallback)
        .into_iter()
        .flatten()
        .collect()
}

fn generic_secret_surfaces(entropy_threshold: f64) -> bool {
    matches_at(entropy_threshold).iter().any(|finding| {
        finding.detector_id.as_ref() == "generic-secret"
            && finding.credential.as_ref() == CREDENTIAL
    })
}

#[test]
fn detector_local_entropy_high_controls_operator_override_boundary() {
    let entropy = shannon_entropy_simd(CREDENTIAL.as_bytes());
    assert!(
        entropy > DETECTOR_ENTROPY_HIGH && entropy < 4.1,
        "fixture entropy {entropy} must sit strictly inside the (4.0, 4.1) boundary"
    );

    assert!(
        generic_secret_surfaces(3.9),
        "3.9 is below detector entropy_high and must preserve its calibrated floor"
    );
    assert!(
        generic_secret_surfaces(4.0),
        "4.0 equals detector entropy_high and must preserve its calibrated floor"
    );
    assert!(
        !generic_secret_surfaces(4.1),
        "4.1 is stricter than detector entropy_high and must suppress a 4.02-bit credential"
    );
}
