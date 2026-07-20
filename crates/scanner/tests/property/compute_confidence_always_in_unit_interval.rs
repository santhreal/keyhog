//! compute_confidence never escapes [0, 1] for arbitrary signal tuples.

use keyhog_scanner::testing::confidence::{compute_confidence, ConfidenceSignals};
use proptest::prelude::*;

#[test]
fn compute_confidence_always_in_unit_interval() {
    proptest!(|(
        has_prefix in any::<bool>(),
        has_anchor in any::<bool>(),
        entropy in 0.0f64..9.0,
        keyword in any::<bool>(),
        sensitive in any::<bool>(),
        len in 0usize..512,
        companion in any::<bool>(),
    )| {
        let signals = ConfidenceSignals {
            has_literal_prefix: has_prefix,
            has_context_anchor: has_anchor,
            entropy,
            keyword_nearby: keyword,
            sensitive_file: sensitive,
            match_length: len,
            has_companion: companion,
        };
        let score = compute_confidence(&signals);
        prop_assert!(score >= 0.0 && score <= 1.0, "score out of range: {score}");
        prop_assert!(!score.is_nan());
    });
}
