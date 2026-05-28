use keyhog_scanner::alphabet_filter::{AlphabetMask, AlphabetScreen};
use keyhog_scanner::bigram_bloom::BigramBloom;
use proptest::prelude::*;

trait AlphabetScreenExt {
    fn screen_scalar_fallback(&self, data: &[u8]) -> bool;
}

impl AlphabetScreenExt for AlphabetScreen {
    fn screen_scalar_fallback(&self, data: &[u8]) -> bool {
        if data.is_empty() {
            return false;
        }
        self.target_mask
            .intersects(&AlphabetMask::from_bytes_scalar(data))
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

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

        // 2. Parity validation between Scalar and SIMD
        // Check AlphabetMask parity:
        let mask_scalar = AlphabetMask::from_bytes_scalar(&chunk_bytes);
        let mask_auto = AlphabetMask::from_bytes(&chunk_bytes);
        assert_eq!(mask_scalar, mask_auto, "AlphabetMask auto vs scalar parity failed");

        #[cfg(target_arch = "x86_64")]
        {
            if is_x86_feature_detected!("avx2") {
                // SAFETY: We just checked AVX2 detection.
                let mask_avx2 = unsafe { AlphabetMask::from_bytes_avx2(&chunk_bytes) };
                assert_eq!(mask_scalar, mask_avx2, "AVX2 AlphabetMask parity failed");
            }
            if is_x86_feature_detected!("sse2") {
                // SAFETY: We just checked SSE2 detection.
                let mask_sse2 = unsafe { AlphabetMask::from_bytes_sse2(&chunk_bytes) };
                assert_eq!(mask_scalar, mask_sse2, "SSE2 AlphabetMask parity failed");
            }
        }

        #[cfg(target_arch = "aarch64")]
        {
            // NEON is always supported on aarch64.
            // SAFETY: Neon code path.
            let mask_neon = unsafe { AlphabetMask::from_bytes_neon(&chunk_bytes) };
            assert_eq!(mask_scalar, mask_neon, "NEON AlphabetMask parity failed");
        }

        // Check AlphabetScreen parity:
        let literals = vec![literal.clone(), "test".to_string(), "SECRET".to_string()];
        let screen = AlphabetScreen::new(&literals);

        let screen_result_auto = screen.screen(&chunk_bytes);
        let screen_result_scalar = screen.screen_scalar_fallback(&chunk_bytes);
        assert_eq!(
            screen_result_auto,
            screen_result_scalar,
            "AlphabetScreen auto vs scalar parity failed"
        );

        #[cfg(target_arch = "x86_64")]
        {
            if is_x86_feature_detected!("avx2") {
                // SAFETY: We just checked AVX2 detection.
                let screen_result_avx2 = unsafe { screen.screen_avx2(&chunk_bytes) };
                assert_eq!(
                    screen_result_scalar,
                    screen_result_avx2,
                    "AVX2 AlphabetScreen parity failed"
                );
            }
        }

        // 3. Strictly high entropy or non-ASCII / high-entropy validation
        if !high_entropy_bytes.is_empty() {
            let mask_he_scalar = AlphabetMask::from_bytes_scalar(&high_entropy_bytes);
            let mask_he_auto = AlphabetMask::from_bytes(&high_entropy_bytes);
            assert_eq!(mask_he_scalar, mask_he_auto);

            #[cfg(target_arch = "x86_64")]
            {
                if is_x86_feature_detected!("avx2") {
                    // SAFETY: We checked AVX2.
                    let mask_he_avx2 = unsafe { AlphabetMask::from_bytes_avx2(&high_entropy_bytes) };
                    assert_eq!(mask_he_scalar, mask_he_avx2);
                }
            }
        }
    }
}
