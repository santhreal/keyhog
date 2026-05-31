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
/// Decode-structure analysis: classify what a candidate base64/hex-decodes to
/// (binary asset magic bytes, protobuf wire) so decode-through feeds scoring.
pub mod decode_structure;
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
/// Scanner configuration and state.
pub mod scanner_config;
/// Static-string interner backed by vyre's CHD perfect hash.
/// Used by `CompiledScanner` to pre-intern detector metadata strings
/// so the per-scan `ScanState` interner is hit only by dynamic
/// strings (file paths, commit SHAs).
pub mod static_intern;
/// Shared types for the scanner engine.
pub mod types;

// Internal modules.
/// SIMD-accelerated alphabet pre-filtering.
pub mod alphabet_filter;
/// ASCII case-insensitive byte-search primitives shared by every hot path
/// that needs to skim text without lowering the haystack first.
pub(crate) mod ascii_ci;
/// Bigram bloom filter for fast chunk gating.
pub mod bigram_bloom;
/// AVX-512 optimized entropy calculation.
pub(crate) mod entropy_avx512;
/// Fast scalar entropy calculation.
pub mod entropy_fast;
#[cfg(target_arch = "aarch64")]
pub(crate) mod entropy_fast_neon;
#[cfg(target_arch = "x86_64")]
pub(crate) mod entropy_fast_x86;
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
pub(crate) mod suppression;
/// Per-scan telemetry: always-on counters + opt-in `--dogfood` events.
pub mod telemetry;
/// Shared FNV-1a hash + content-keyed memoization primitives. Single home for
/// the seed every per-scan cache keys on, plus the bounded thread-local cache
/// helper they all share, so a hash change can never re-key only some caches.
pub(crate) mod util_hash;
/// Unicode normalization and homoglyph defense.
pub mod unicode_hardening;

/// SHA-256 of a credential as the raw 32 inline bytes - matching
/// `Finding::credential_hash: [u8; 32]`. Hex encoding is deferred to the
/// serde/reporter boundary (`keyhog_core::hex_encode`), keeping the pre-dedup
/// hot path zero-heap. All `credential_hash:` assignment sites forward this
/// value straight into the `[u8; 32]` field, so the byte form is required.
pub(crate) fn sha256_hash(s: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    hasher.finalize().into()
}

#[cfg(feature = "simd")]
pub(crate) mod simd;
#[cfg(feature = "simdsieve")]
mod simdsieve_prefilter;

pub(crate) mod shared_regexes;

pub use engine::CompiledScanner;
pub use engine::GpuPhase1Output;
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

pub mod testing {
    pub use crate::compiler::{rewrite_alternation_prefix, split_leading_inline_flag};
    pub use crate::confidence::penalties::finalize_confidence;
    /// Full feature extractor (with detector-config keyword lists) exposed for
    /// the ML training-pipeline parity harness (`ml/parity_check.py`), which
    /// must compute byte-identical features to the serve path.
    pub use crate::ml_scorer::compute_features_with_config;
    pub use crate::engine::boundary::scan_chunk_boundaries;
    pub use crate::engine::gpu_postprocess::{
        attribute_matches_to_chunks, fold_overlapping_same_pid_inplace,
    };
    pub use crate::engine::gpu_regex_dfa::extract_literal_core;
    pub use crate::entropy::keywords::looks_like_program_identifier;
    pub use crate::probabilistic_gate::ProbabilisticGate;
    pub use crate::static_intern::seed_source_type_count;

    pub mod ascii_ci {
        pub use crate::ascii_ci::{ci_find, contains_path_segment, contains_path_segment_two};
    }

    pub mod shape {
        pub use crate::suppression::shape::{
            looks_like_credential_colliding_punctuation,
            looks_like_punctuation_decorated_identifier, looks_like_syntactic_punctuation_marker,
        };
    }

    pub mod compiler_prefix {
        pub use crate::compiler::compiler_prefix::{
            extract_literal_prefixes, strip_leading_boundary_guard, strip_leading_inline_flags,
        };
    }

    pub use crate::decode::caesar::{
        caesar_shift, is_source_code_path, looks_credential_shaped, CaesarDecoder,
    };
    pub use crate::decode::hex::find_hex_strings;
    pub use crate::decode::reverse::{looks_reversible, reverse_str, ReverseDecoder};
    pub use crate::decode::util::take_hex_digits;
    pub use crate::gpu::{env_no_gpu, is_ci_environment};

    /// Shannon entropy of `chunk` in bits/byte.
    ///
    /// # Safety
    ///
    /// On `x86_64` this dispatches straight to the AVX-512 kernel, which
    /// requires the running CPU to support `avx512f`/`avx512bw`. The caller
    /// must confirm those features first (e.g. via `is_x86_feature_detected!`);
    /// calling it on a CPU without them is undefined behavior.
    ///
    /// On every other target (aarch64/macOS, wasm, …) the AVX-512 kernel does
    /// not exist, so this routes to the portable feature-detecting dispatcher
    /// (`entropy_fast::shannon_entropy_simd`), which is itself safe and always
    /// correct. The `unsafe` marker is kept for one cross-platform signature.
    /// Without this arch split the non-x86 build failed to compile
    /// (`E0425: cannot find calculate_shannon_entropy`), breaking the portable
    /// / macOS-arm64 build.
    pub unsafe fn calculate_shannon_entropy(chunk: &[u8]) -> f64 {
        #[cfg(target_arch = "x86_64")]
        {
            unsafe { crate::entropy_avx512::calculate_shannon_entropy(chunk) }
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            crate::entropy_fast::shannon_entropy_simd(chunk)
        }
    }

    #[cfg(feature = "simd")]
    pub use crate::simd::backend::HsScanner;

    #[cfg(feature = "simdsieve")]
    pub use crate::simdsieve_prefilter::{
        HOT_PATTERNS, HOT_PATTERN_DETECTOR_IDS, HOT_PATTERN_DISPLAY_NAMES, HOT_PATTERN_NAMES,
    };

    pub use crate::structured::parsers::{
        parse_docker_compose, parse_env, parse_hcl, parse_jupyter, parse_k8s_secret, parse_tfstate,
    };
}
