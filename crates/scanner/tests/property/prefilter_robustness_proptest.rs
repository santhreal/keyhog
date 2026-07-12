use keyhog_scanner::testing::BigramBloom;
use keyhog_scanner::testing::{
    assert_alphabet_prefilter_backend_parity, AlphabetMask, AlphabetScreen,
};
use proptest::prelude::*;

proptest! {
    // Testing Contract: 10k+ cases. Single test; per case = prefilter primitive
    // ops (AlphabetMask/BigramBloom/AlphabetScreen) + 2 SIMD-vs-scalar parity
    // passes over <=4KB — no full scan, so 10k stays cheap.
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    #[test]
    fn test_prefilter_soundness_and_parity(
        chunk_bytes in prop::collection::vec(any::<u8>(), 0..4096),
        literal in any::<String>(),
        high_entropy_bytes in prop::collection::vec(any::<u8>(), 0..1024),
    ) {
        let literal_bytes = literal.as_bytes();

        // 1. Construct a chunk that explicitly contains the literal to verify soundness.
        let mut chunk_with_literal = Vec::new();
        if chunk_bytes.len() > 2 {
            let split_idx = chunk_bytes.len() / 2;
            chunk_with_literal.extend_from_slice(&chunk_bytes[..split_idx]);
            chunk_with_literal.extend_from_slice(literal_bytes);
            chunk_with_literal.extend_from_slice(&chunk_bytes[split_idx..]);
        } else {
            chunk_with_literal.extend_from_slice(literal_bytes);
            chunk_with_literal.extend_from_slice(&chunk_bytes);
        }

        // Verify AlphabetMask soundness (if chunk has literal, the mask of the chunk must intersect the literal mask)
        if !literal_bytes.is_empty() && !chunk_with_literal.is_empty() {
            let chunk_mask = AlphabetMask::from_bytes(&chunk_with_literal);
            let lit_mask = AlphabetMask::from_text(&literal);
            assert!(
                chunk_mask.intersects(&lit_mask),
                "AlphabetMask soundness failed: literal {:?} is in chunk {:?}",
                literal,
                chunk_with_literal
            );
        }

        // Verify BigramBloom soundness
        if !literal_bytes.is_empty() {
            let bloom = BigramBloom::from_literal_prefixes(&[literal.clone()]);
            // Soundness is guaranteed if:
            // - literal.len() >= 2
            // - literal.len() == 1 and it's not strictly at the last index of a chunk of size >= 2
            let is_sound = if literal_bytes.len() >= 2 {
                true
            } else {
                chunk_with_literal.len() < 2 || chunk_with_literal[..chunk_with_literal.len() - 1].contains(&literal_bytes[0])
            };

            if is_sound {
                assert!(
                    bloom.maybe_overlaps(&chunk_with_literal),
                    "BigramBloom soundness failed: literal {:?} is in chunk {:?}",
                    literal,
                    chunk_with_literal
                );
            }
        }

        // Verify AlphabetScreen soundness
        if !literal_bytes.is_empty() && !chunk_with_literal.is_empty() {
            let screen = AlphabetScreen::new(&[literal.clone()]);
            assert!(
                screen.screen(&chunk_with_literal),
                "AlphabetScreen soundness failed: literal {:?} is in chunk {:?}",
                literal,
                chunk_with_literal
            );
        }

        // 2. Parity validation between Scalar and SIMD.
        let literals = vec![literal.clone(), "test".to_string(), "SECRET".to_string()];
        assert_alphabet_prefilter_backend_parity(&literals, &chunk_bytes);

        // 3. Strictly high entropy or non-ASCII / high-entropy validation
        if !high_entropy_bytes.is_empty() {
            assert_alphabet_prefilter_backend_parity(&literals, &high_entropy_bytes);
        }
    }
}
