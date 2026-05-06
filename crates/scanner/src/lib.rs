//! KeyHog Scanner: A high-performance, multi-layered secret detection engine.
//!
//! This crate implements the core scanning logic, combining SIMD pre-filtering,
//! Aho-Corasick literal matching, regex fallback, and ML-based confidence scoring.

#![deny(unsafe_op_in_unsafe_fn)]
#![allow(clippy::too_many_arguments)]

// ── Public API ──────────────────────────────────────────────────────
/// Service-specific credential checksum validation (GitHub, npm, Slack, etc.).
pub mod checksum;
/// Detector compilation into high-performance matching structures.
pub mod compiler;
/// Heuristic and ML-based confidence scoring for candidate matches.
pub mod confidence;
/// Code context analysis (comments, assignments, test files).
pub mod context;
/// Decode-through pipeline for nested encodings (base64, hex, URL, etc.).
pub mod decode;
/// Core scan execution engine.
pub mod engine;
/// Shannon entropy analysis for secret detection.
pub mod entropy;
/// Specialized error types for the scanner.
pub mod error;
/// GPU-accelerated matching via wgpu.
pub mod gpu;
/// Hardware capability detection and backend selection.
pub mod hw_probe;
/// Machine learning inference for secret scoring.
pub mod ml_scorer;
/// Multiline secret reassembly logic.
pub mod multiline;
/// Match resolution and deduplication.
pub mod resolution;
/// Shared types for the scanner engine.
pub mod types;

// Internal modules.
/// SIMD-accelerated alphabet pre-filtering.
pub mod alphabet_filter;
/// Bigram bloom filter for fast chunk gating.
pub mod bigram_bloom;
/// AVX-512 optimized entropy calculation.
pub(crate) mod entropy_avx512;
/// Fast scalar entropy calculation.
pub mod entropy_fast;
/// JWT structural validation and anomaly detection.
pub mod jwt;
// `fragment_cache` lives under `multiline/` (its only call sites are there);
// re-exported at the crate root so existing `keyhog_scanner::fragment_cache`
// paths and the Tier-C audit cleanup don't churn the public API.
pub use multiline::fragment_cache;
pub(crate) mod homoglyph;
/// Internal scan pipeline orchestration.
pub mod pipeline;
/// Prefix trie for efficient keyword propagation.
pub mod prefix_trie;
pub(crate) mod probabilistic_gate;
pub(crate) mod structured;
/// Unicode normalization and homoglyph defense.
pub mod unicode_hardening;

pub(crate) fn sha256_hash(s: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(feature = "simd")]
pub(crate) mod simd;
#[cfg(feature = "simdsieve")]
mod simdsieve_prefilter;

pub use engine::CompiledScanner;
pub use error::{Result, ScanError};
pub use hw_probe::{probe_hardware, select_backend, HardwareCaps, ScanBackend};
pub use types::ScannerConfig;

use std::borrow::Cow;

/// Normalize scannable text by removing evasion characters and handling homoglyphs.
pub fn normalize_chunk_data(data: &str) -> Cow<'_, str> {
    if data.is_ascii() {
        return Cow::Borrowed(data);
    }
    let mut normalized = String::with_capacity(data.len());
    let mut changed = false;
    for ch in data.chars() {
        if !unicode_hardening::is_evasion_char(ch) {
            normalized.push(ch);
        } else {
            changed = true;
        }
    }
    if changed {
        Cow::Owned(normalized)
    } else {
        Cow::Borrowed(data)
    }
}

/// Pre-process a chunk of text for scanning.
pub fn normalize_scannable_chunk<'a>(
    chunk: &'a keyhog_core::Chunk,
    owned: &'a mut Option<keyhog_core::Chunk>,
) -> &'a keyhog_core::Chunk {
    pipeline::normalize_scannable_chunk(chunk, owned)
}

/// Compute line offsets for a block of text.
pub fn compute_line_offsets(text: &str) -> Vec<usize> {
    pipeline::compute_line_offsets(text)
}

/// Map a byte offset to a line number using pre-computed offsets.
pub fn match_line_number(
    preprocessed: &types::ScannerPreprocessedText,
    line_offsets: &[usize],
    offset: usize,
) -> usize {
    pipeline::match_line_number(preprocessed, line_offsets, offset)
}

/// measure shannon entropy of a byte slice.
pub fn match_entropy(data: &[u8]) -> f64 {
    pipeline::match_entropy(data)
}

/// Find the largest char boundary <= index.
pub fn floor_char_boundary(text: &str, index: usize) -> usize {
    engine::floor_char_boundary(text, index)
}

/// Check if a match is within a hex-encoded context.
pub fn is_within_hex_context(data: &str, match_start: usize, match_end: usize) -> bool {
    pipeline::is_within_hex_context(data, match_start, match_end)
}

/// Check if a credential should be suppressed because it is a known example.
pub fn should_suppress_known_example_credential(
    credential: &str,
    path: Option<&str>,
    context: context::CodeContext,
) -> bool {
    pipeline::should_suppress_known_example_credential(credential, path, context)
}

/// Search for a companion pattern near a primary match.
pub fn find_companion(
    preprocessed: &types::ScannerPreprocessedText,
    primary_line: usize,
    companion: &types::CompiledCompanion,
) -> Option<String> {
    pipeline::find_companion(preprocessed, primary_line, companion)
}
