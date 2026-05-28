//! R5-REV-SCAN reverse decode must surface `stripe-secret-key`.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;
use std::path::PathBuf;

#[test]
fn reverse_stripe_sk_reversed_in_env() {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    let scanner = CompiledScanner::compile(keyhog_core::load_detectors(&d).expect("detectors"))
        .expect("compile");
    let secret = "sk_live_51AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCd";
    let reversed: String = secret.chars().rev().collect();
    let chunk = Chunk {
        data: format!("STRIPE_SECRET={reversed}").into(),
        metadata: ChunkMetadata {
            source_type: "adversarial".into(),
            path: Some("reversed-stripe.env".into()),
            ..Default::default()
        },
    };
    let matches = scanner.scan(&chunk);
    assert!(
        matches.iter().any(|m| {
            m.detector_id.as_ref() == "stripe-secret-key" && m.credential.as_ref() == secret
        }),
        "reverse-encoded stripe-secret-key must surface; matches={:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref()))
            .collect::<Vec<_>>()
    );
}
