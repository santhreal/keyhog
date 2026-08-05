use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::testing::{
    confidence::{compute_confidence, ConfidenceSignals},
    decode_chunk,
    entropy_fast::shannon_entropy_simd,
    ml_score, AlphabetMask, AlphabetScreen,
};

#[test]
fn hidden_testing_facade_exposes_only_the_standalone_probe_contract() {
    let mask = AlphabetMask::from_bytes(b"abc");
    assert!(mask.intersects(&AlphabetMask::from_text("xcy")));

    let screen = AlphabetScreen::new(&["sk_live".to_string()]);
    assert!(screen.screen(b"prefix sk_live_suffix"));

    let confidence = compute_confidence(&ConfidenceSignals {
        has_literal_prefix: true,
        has_context_anchor: true,
        entropy: 5.0,
        keyword_nearby: true,
        sensitive_file: false,
        match_length: 32,
        has_companion: false,
    });
    assert!((0.0..=1.0).contains(&confidence));
    assert!(shannon_entropy_simd(b"abcdabcdabcdabcd") > 0.0);

    let score = ml_score(
        "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890",
        "API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz1234567890",
    );
    assert!((0.0..=1.0).contains(&score));

    let chunk = Chunk {
        data: "plain text without encoded payload".to_string().into(),
        metadata: ChunkMetadata {
            source_type: "contract".into(),
            ..Default::default()
        },
    };
    assert_eq!(decode_chunk(&chunk, 1, false, None, None).len(), 0);
}

