//! LR1-A8 replacement gate: `lib.rs` VerificationEngine with no detectors.

use keyhog_verifier::{VerificationEngine, VerifyConfig};

#[test]
fn verification_engine_new_with_empty_detectors() {
    let engine = VerificationEngine::new(&[], VerifyConfig::default());
    assert!(
        engine.is_ok(),
        "empty detector list must construct engine: {:?}",
        engine.err()
    );
}
