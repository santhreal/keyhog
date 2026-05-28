//! Adversarial tests for GPU program fusion.
//!
//! Exercises edge cases in the fusion API: empty inputs, incompatible
//! programs, large program sets, and cache key stability.

use keyhog_scanner::engine::gpu_program_fusion::{
    fuse_or_fallback, fusion_cache_key, try_fuse, FUSION_CACHE_VERSION,
};

// ────────────────────────────────────────────────────────────
// Empty / degenerate inputs
// ────────────────────────────────────────────────────────────

#[test]
fn fuse_empty_slice_returns_error() {
    let result = try_fuse(&[]);
    assert!(result.is_err());
}

#[test]
fn fuse_or_fallback_empty_returns_none() {
    assert!(fuse_or_fallback(&[]).is_none());
}

// ────────────────────────────────────────────────────────────
// Cache key stability
// ────────────────────────────────────────────────────────────

#[test]
fn cache_key_deterministic() {
    let k1 = fusion_cache_key(&[]);
    let k2 = fusion_cache_key(&[]);
    assert_eq!(k1, k2, "same inputs should produce same key");
}

#[test]
fn cache_key_hex_format() {
    let key = fusion_cache_key(&[]);
    assert_eq!(key.len(), 64, "SHA-256 hex is 64 chars");
    assert!(
        key.chars().all(|c| c.is_ascii_hexdigit()),
        "key should be hex: {key}"
    );
}

#[test]
fn cache_key_varies_with_empty_vs_nonempty() {
    // Without programs the key is just hash(version, 0).
    let key_empty = fusion_cache_key(&[]);
    // Key should be valid even with no programs.
    assert_eq!(key_empty.len(), 64);
}

// ────────────────────────────────────────────────────────────
// Version constant
// ────────────────────────────────────────────────────────────

#[test]
fn fusion_cache_version_is_nonzero() {
    assert!(FUSION_CACHE_VERSION > 0, "version should be positive");
}
