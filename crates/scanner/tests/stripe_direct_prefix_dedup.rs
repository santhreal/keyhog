mod support;
use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;
use support::paths::detector_dir;

fn scanner() -> CompiledScanner {
    let mut detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors");
    detectors.retain(|detector| detector.id == "stripe-secret-key");
    assert_eq!(
        detectors.len(),
        1,
        "test must load exactly the shipped Stripe secret-key detector"
    );
    CompiledScanner::compile(detectors).expect("compile Stripe scanner")
}

#[test]
fn stripe_hot_and_confirmed_paths_share_nonzero_base_offset() {
    let secret = concat!("sk_li", "ve_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcD");
    let text = format!("STRIPE_SECRET_KEY={secret}\n");
    let local_offset = text.find(secret).expect("secret present");
    let base_offset = 4096usize;
    let base_line = 23usize;
    let matches = scanner()
        .scan(&Chunk {
            data: text.into(),
            metadata: ChunkMetadata {
                source_type: "stripe-direct-prefix-dedup".into(),
                path: Some("windowed-stripe.env".into()),
                base_offset,
                base_line,
                ..Default::default()
            },
        })
        .expect("scanner call should succeed");

    let stripe: Vec<_> = matches
        .iter()
        .filter(|m| m.detector_id.as_ref() == "stripe-secret-key")
        .collect();
    assert_eq!(
        stripe.len(),
        1,
        "Stripe hot-prefix and confirmed regex lanes must not emit duplicate same-start findings; matches={:?}",
        matches
            .iter()
            .map(|m| (
                m.detector_id.as_ref(),
                m.credential.as_ref(),
                m.location.offset,
                m.location.line
            ))
            .collect::<Vec<_>>()
    );
    assert_eq!(stripe[0].location.offset, base_offset + local_offset);
    assert_eq!(stripe[0].location.line, Some(base_line + 1));
}
