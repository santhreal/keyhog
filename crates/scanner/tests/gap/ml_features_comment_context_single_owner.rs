//! Gap test: the ML feature vector's two comment-context signals share one owner.
//!
//! `compute_features_with_config` emits a 43-float vector (`model_arch::INPUT_DIM`,
//! the single owner of the count). Two of those floats
//! encode "is this match inside a comment": feature 19 (in the context-feature
//! block) and feature 38 (`COMMENT_CONTEXT_FEATURE_INDEX`). Both derive from the
//! SAME `COMMENT_PREFIXES`/`context.trim().starts_with(..)` check, hoisted into a
//! single `context_starts_with_comment_prefix` owner so they can never drift to
//! different comment definitions, the model was trained on them as identical
//! signals, so a divergence would silently corrupt scoring. Pin that they move
//! together (both 1.0 in a comment, both 0.0 outside) alongside the exact prefix
//! and length binary features computed from the same call.
//!
//! Feature extraction is multiline-independent but lives under the `ml` feature.
#![cfg(feature = "ml")]

use keyhog_scanner::ml_scorer::compute_features_with_config;

// Indices into the feature vector (mirrors ml_features.rs layout).
const F_LEN_GE_20: usize = 1;
const F_LEN_GE_40: usize = 2;
const F_PREFIX_SK: usize = 14;
const F_PREFIX_AKIA: usize = 15;
const F_CONTEXT_COMMENT: usize = 19;
const F_EXTRA_COMMENT: usize = 38;

#[test]
fn comment_context_sets_both_comment_features_to_one() {
    // 20-char AWS access-key id (starts with AKIA) inside a `#` comment line.
    let text = "AKIAIOSFODNN7EXAMPLE";
    assert_eq!(
        text.len(),
        20,
        "fixture must hit the len>=20 boundary exactly"
    );
    let context = "# AKIAIOSFODNN7EXAMPLE";

    let f = compute_features_with_config(text, context, &[], &[], &[], &[]);

    // Prefix features: AKIA yes, sk- no.
    assert_eq!(f[F_PREFIX_AKIA], 1.0);
    assert_eq!(f[F_PREFIX_SK], 0.0);
    // Length features: len==20 hits the >=20 floor, stays under >=40.
    assert_eq!(f[F_LEN_GE_20], 1.0);
    assert_eq!(f[F_LEN_GE_40], 0.0);
    // Both comment-context signals fire, and they are equal (single owner).
    assert_eq!(f[F_CONTEXT_COMMENT], 1.0);
    assert_eq!(f[F_EXTRA_COMMENT], 1.0);
    assert_eq!(f[F_CONTEXT_COMMENT], f[F_EXTRA_COMMENT]);
}

#[test]
fn non_comment_context_clears_both_comment_features() {
    // `sk-`-prefixed token in an ordinary assignment line (no comment marker).
    let text = "sk-abc123";
    let context = "openai_key = sk-abc123";

    let f = compute_features_with_config(text, context, &[], &[], &[], &[]);

    // Prefix features: sk- yes, AKIA no.
    assert_eq!(f[F_PREFIX_SK], 1.0);
    assert_eq!(f[F_PREFIX_AKIA], 0.0);
    // Neither comment signal fires, and they stay equal (single owner).
    assert_eq!(f[F_CONTEXT_COMMENT], 0.0);
    assert_eq!(f[F_EXTRA_COMMENT], 0.0);
    assert_eq!(f[F_CONTEXT_COMMENT], f[F_EXTRA_COMMENT]);
}
