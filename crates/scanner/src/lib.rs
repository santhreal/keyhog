//! KeyHog Scanner: A high-performance, multi-layered secret detection engine.
//!
//! This crate implements the core scanning logic, combining SIMD pre-filtering,
//! Aho-Corasick literal matching, regex fallback, and ML-based confidence scoring.
//!
//! # Module map (by pipeline stage)
//!
//! The modules below are declared in dependency order, but they READ in pipeline
//! order — the same bytes→finding flow as [`docs/ARCHITECTURE.md`] and the
//! method-level map in [`engine`] (`engine::mod` "# The one flow"). To find a
//! responsibility, locate its stage:
//!
//! - **Config / shared types** — [`scanner_config`], [`types`], [`hw_probe`]
//!   (hardware routing), [`error`].
//! - **Phase 1 · prefilter** (cheap "could a detector fire here?") —
//!   [`alphabet_filter`], [`bigram_bloom`], [`prefix_trie`], `ascii_ci`,
//!   `simd` / `simdsieve_prefilter` (feature-gated), `prefilter_degrade`
//!   (loud Law-10 fallback).
//! - **Compile** (detectors → matchers) — [`compiler`], `shared_regexes`,
//!   [`static_intern`].
//! - **Scan engine** (phase 1 triggers + phase 2 extraction; CPU or GPU) —
//!   [`engine`] (start at its header doc), [`pipeline`], [`gpu`].
//! - **Decode-through** (nested base64/hex/url/unicode, recursive) —
//!   [`decode`], [`decode_structure`].
//! - **Entropy** — [`entropy`] is now the single home for all of it: the
//!   keyword/scanner detection logic plus the fast Shannon-entropy primitive
//!   `entropy::fast` (+ `entropy::avx512` / `entropy::fast_x86` /
//!   `entropy::fast_neon` SIMD impls, arch-gated).
//! - **Confidence / ML** — [`ml_scorer`] (serves the embedded `weights.bin`;
//!   trained out-of-band by the repo's `ml/`), [`confidence`],
//!   `probabilistic_gate`.
//! - **Context, fragment reassembly, multiline, suppression, resolution** —
//!   [`context`], `fragment_cache`, [`multiline`], `suppression`,
//!   [`resolution`], `structured`.
//! - **Specialized validators** — [`checksum`], [`jwt`], [`aws`],
//!   `homoglyph`, [`unicode_hardening`].
//! - **Cross-cutting** — `platform_compat`, `placeholder_words`,
//!   `process_exit`, [`telemetry`], `util_hash`.
//!
//! Most single-file modules are one responsibility each; the multi-file engine
//! is the exception and carries its own internal map in `engine::mod`.

#![deny(unsafe_op_in_unsafe_fn)]
#![allow(clippy::too_many_arguments)]

#[cfg(test)]
extern crate self as keyhog_scanner;

#[cfg(test)]
#[path = "../tests/adversarial/mod.rs"]
mod adversarial;
#[cfg(test)]
#[path = "../tests/gap/mod.rs"]
mod gap;
#[cfg(test)]
#[path = "../tests/gate/mod.rs"]
mod gate;
#[cfg(test)]
#[path = "../tests/property/mod.rs"]
mod property;
#[cfg(test)]
#[path = "../tests/unit/mod.rs"]
mod unit;

// ── Public API ──────────────────────────────────────────────────────
pub(crate) mod api;
/// Offline AWS account-ID recovery from an access-key ID (no network/verify).
pub mod aws;
/// Service-specific credential checksum validation (GitHub, npm, Slack, etc.).
pub mod checksum;
/// Detector compilation into high-performance matching structures.
pub(crate) mod compiler;
/// Heuristic and ML-based confidence scoring for candidate matches.
pub(crate) mod confidence;
/// Code context analysis (comments, assignments, test files).
pub mod context;
pub(crate) mod deadline;
/// Decode-through pipeline for nested encodings (base64, hex, URL, etc.).
pub mod decode;
/// Decode-structure analysis: classify what a candidate base64/hex-decodes to
/// (binary asset magic bytes, protobuf wire) so decode-through feeds scoring.
pub(crate) mod decode_structure;
/// Canonical detector-id strings and scanner-side detector-family predicates.
pub(crate) mod detector_ids;
/// Core scan execution engine.
pub(crate) mod engine;
/// Shannon entropy analysis for secret detection.
pub mod entropy;
/// Specialized error types for the scanner.
pub(crate) mod error;
/// Cross-chunk fragment reassembly cache.
pub(crate) mod fragment_cache;
/// Named-detector ownership for assignment-key fallback suppression.
pub(crate) mod generic_keyword_owner;
/// GPU-accelerated matching via wgpu.
pub mod gpu;
/// Hardware capability detection and backend selection.
pub mod hw_probe;
/// Machine learning inference for secret scoring.
pub mod ml_scorer;
/// Multiline secret reassembly logic.
pub(crate) mod multiline;
pub(crate) mod placeholder_words;
pub(crate) mod platform_compat;
pub(crate) mod process_exit;
/// Match resolution and deduplication.
pub mod resolution;
/// Scanner configuration and state.
pub(crate) mod scanner_config;
/// Static-string interner backed by vyre's CHD perfect hash.
/// Used by `CompiledScanner` to pre-intern detector metadata strings
/// so the per-scan `ScanState` interner is hit only by dynamic
/// strings (file paths, commit SHAs).
pub(crate) mod static_intern;
/// Shared types for the scanner engine.
pub(crate) mod types;

// Internal modules.
/// SIMD-accelerated alphabet pre-filtering.
pub(crate) mod alphabet_filter;
pub(crate) mod anchored_regex;
/// ASCII case-insensitive byte-search primitives shared by every hot path
/// that needs to skim text without lowering the haystack first.
pub(crate) mod ascii_ci;
/// Bigram bloom filter for fast chunk gating.
pub(crate) mod bigram_bloom;
// The fast Shannon-entropy primitives (scalar dispatcher + AVX-512 / AVX2-SSE2 /
// NEON SIMD impls) now live UNDER `entropy/` (entropy::fast / ::avx512 /
// ::fast_x86 / ::fast_neon) — one home for all entropy code. See `entropy/mod.rs`.
pub(crate) mod homoglyph;
/// JWT structural validation and anomaly detection.
pub mod jwt;
/// Internal scan pipeline orchestration.
pub(crate) mod pipeline;
/// Prefix trie for efficient keyword propagation.
pub(crate) mod prefix_trie;
pub(crate) mod probabilistic_gate;
pub(crate) mod structured;
pub(crate) mod suppression;
/// Per-scan telemetry: always-on counters + opt-in `--dogfood` events.
pub mod telemetry;
pub(crate) mod tuning;
/// Unicode normalization and homoglyph defense.
pub(crate) mod unicode_hardening;
/// Shared FNV-1a hash + content-keyed memoization primitives. Single home for
/// the seed every per-scan cache keys on, plus the bounded thread-local cache
/// helper they all share, so a hash change can never re-key only some caches.
pub(crate) mod util_hash;

/// Loud, recall-preserving degradation for static prefilter automata (Law 10).
pub(crate) mod prefilter_degrade;

pub(crate) use engine::floor_char_boundary;
/// SHA-256 of a credential as the raw 32 inline bytes, matching
/// `Finding::credential_hash: [u8; 32]`. Re-exported from the single canonical
/// implementation in `keyhog_core` so the scanner, core dedup, and telemetry
/// all hash credentials identically (no second copy to drift). Hex encoding is
/// a separate step at the serde/reporter boundary (`keyhog_core::hex_encode`),
/// keeping the pre-dedup hot path zero-heap.
pub(crate) use keyhog_core::sha256_hash;
pub(crate) use pipeline::compute_line_offsets;

#[cfg(feature = "simd")]
pub(crate) mod simd;
#[cfg(feature = "simdsieve")]
mod simdsieve_prefilter;

pub(crate) mod shared_regexes;

pub use api::*;

#[cfg(test)]
use std::borrow::Cow;

/// Configure the Hyperscan compiled-database cache directory for this process.
///
/// Call before compiling a scanner. `None` restores the platform default
/// (`dirs::cache_dir()/keyhog`, with a per-user temp fallback). The SIMD backend
/// still validates the final directory: explicit paths must live under the
/// user's home or the per-uid keyhog temp cache root, must be user-owned, and
/// must not be symlinks.
#[cfg(feature = "simd")]
pub fn set_hyperscan_cache_dir(path: Option<std::path::PathBuf>) {
    simd::backend::set_configured_cache_dir(path);
}

/// Validate an explicit Hyperscan cache directory without compiling a scanner.
#[cfg(feature = "simd")]
pub fn validate_hyperscan_cache_dir(path: &std::path::Path) -> std::result::Result<(), String> {
    simd::backend::validate_configured_cache_dir(path)
}

/// Normalize scannable text by removing evasion characters and handling homoglyphs.
#[cfg(test)]
pub(crate) fn normalize_chunk_data(data: &str) -> Cow<'_, str> {
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

#[doc(hidden)]
pub mod testing;
