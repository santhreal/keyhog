//! `ml_features` must not fork scanner entropy thresholds.

#[test]
fn ml_features_imports_canonical_entropy_thresholds() {
    let source = include_str!("../../../src/ml_scorer/ml_features.rs");
    assert!(
        source.contains(
            "use crate::entropy::{shannon_entropy, HIGH_ENTROPY_THRESHOLD, VERY_HIGH_ENTROPY_THRESHOLD};"
        ),
        "ml_features must import high/very-high entropy thresholds from entropy/mod.rs"
    );
    for forbidden in [
        "const LOW_ENTROPY_THRESHOLD",
        "const HIGH_ENTROPY_THRESHOLD",
        "const VERY_HIGH_ENTROPY_THRESHOLD",
    ] {
        assert!(
            !source.contains(forbidden),
            "ml_features must not redeclare scanner entropy threshold name `{forbidden}`"
        );
    }
    assert!(
        source.contains("const ML_LOW_ENTROPY_FEATURE_THRESHOLD: f64 = 3.5;"),
        "the model-specific low entropy feature bucket must be explicitly named as ML-specific"
    );
}
