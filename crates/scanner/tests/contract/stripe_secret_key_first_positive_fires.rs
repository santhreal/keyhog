//! Contract: stripe-secret-key env-var positive fires under its detector id.

use crate::support::paths::detector_dir;
use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;

const DETECTOR_ID: &str = "stripe-secret-key";
const TEXT: &str = "STRIPE_SECRET_KEY=sk_live_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcD";
const CREDENTIAL: &str = concat!("sk_li", "ve_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcD");

#[test]
fn stripe_secret_key_first_positive_fires() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");
    let chunk = Chunk {
        data: TEXT.into(),
        metadata: ChunkMetadata {
            source_type: "contract".into(),
            path: Some("stripe.env".into()),
            ..Default::default()
        },
    };

    scanner.clear_fragment_cache();
    let matches = scanner.scan(&chunk);
    assert!(
        matches.iter().any(|m| {
            m.detector_id.as_ref() == DETECTOR_ID && m.credential.as_ref().contains(CREDENTIAL)
        }),
        "{DETECTOR_ID} must surface {CREDENTIAL:?}; saw {:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref()))
            .collect::<Vec<_>>()
    );
}
