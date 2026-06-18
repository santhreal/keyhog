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

#[test]
fn scanner_testing_facade_is_file_owned_not_inline_root_sprawl() {
    let lib = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"))
        .expect("scanner lib.rs is readable");
    let facade = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/testing.rs"))
        .expect("scanner testing.rs is readable");
    for forbidden in [
        "\n    pub mod checksum",
        "\n    pub mod compiler_prefix",
        "\n    pub mod entropy_scanner",
        "\n    pub mod segment_attribution",
        "\n    pub mod unicode_hardening",
    ] {
        assert!(
            !lib.contains(forbidden),
            "scanner testing facade must not expose bulk internal module `{forbidden}`"
        );
    }
    assert!(
        lib.contains("#[doc(hidden)]\npub mod testing;"),
        "scanner crate root must delegate the doc-hidden facade to src/testing.rs"
    );
    assert!(
        !lib.contains("pub mod testing {"),
        "scanner crate root must not inline the testing facade body"
    );
    assert!(
        facade.contains("Doc-hidden scanner test facade") && facade.contains("pub fn decode_chunk"),
        "src/testing.rs owns the standalone probe contract"
    );
}
