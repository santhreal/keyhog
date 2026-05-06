//! Core types shared across all KeyHog crates.
//!
//! Defines the [`Source`] trait for pluggable input backends, [`DetectorSpec`]
//! for TOML-based pattern definitions, [`RawMatch`] and [`VerifiedFinding`] for
//! scanner output, [`DedupedMatch`] for grouped findings, and [`Reporter`] for
//! structured result formatting.

/// Credential/path allowlist parsing and matching.
pub mod allowlist;
/// ANSI-colored CLI startup banner with detector counts.
pub mod banner;
/// Configuration system for KeyHog scanning options.
pub mod config;
/// Secure credential storage and redaction.
pub mod credential;
mod dedup;
/// Shared standard Base64 decode (wire / K8s), bounded for DoS safety.
pub mod encoding;
mod finding;
/// Security hardening: memory zeroization and process isolation helpers.
pub mod hardening;
/// Structured reporting (JSON, SARIF, Text).
pub mod report;
/// Safe absolute-path resolution for external binaries.
pub mod safe_bin;
mod source;
mod spec;
use std::borrow::Cow;

/// Global registry for sources and verifiers.
pub mod registry;

pub use allowlist::*;
pub use config::*;
pub use credential::{Credential, SensitiveString};
pub use dedup::*;
pub use finding::*;
pub use report::*;
pub use source::*;
/// Auto-fix suggestion logic for SARIF output.
pub mod auto_fix;
/// Bayesian confidence calibration for detectors.
pub mod calibration;
/// Incremental scan state via BLAKE3 Merkle index.
pub mod merkle_index;
pub use spec::*;

// Embedded detectors compiled into the binary at build time.
// These are used when no external detectors directory is found.
mod embedded {
    include!(concat!(env!("OUT_DIR"), "/embedded_detectors.rs"));
}

/// Load detectors from embedded data (compiled into the binary).
/// Returns detector TOML strings that can be parsed by the spec loader.
pub fn embedded_detector_tomls() -> &'static [(&'static str, &'static str)] {
    embedded::EMBEDDED_DETECTORS
}

/// Number of embedded detector specs (authoritative for banners and tests).
#[inline]
pub fn embedded_detector_count() -> usize {
    embedded_detector_tomls().len()
}

/// Redact a sensitive credential string for safe display.
pub fn redact(s: &str) -> Cow<'static, str> {
    // ASCII fast path: byte indexing is valid (no UTF-8 boundary risk),
    // skips the O(n) `chars().count()` walk plus two intermediate `String`
    // allocations from `take(4).collect()` / `skip(n).collect()`. Most
    // credentials are pure ASCII (provider keys, hashes, base64 tokens).
    if s.is_ascii() {
        if s.len() <= 8 {
            return Cow::Borrowed("****");
        }
        let mut out = String::with_capacity(s.len().min(11));
        out.push_str(&s[..4]);
        out.push_str("...");
        out.push_str(&s[s.len() - 4..]);
        return Cow::Owned(out);
    }
    // UTF-8 path: char-count for grapheme correctness.
    let char_count = s.chars().count();
    if char_count <= 8 {
        return Cow::Borrowed("****");
    }
    let first_four: String = s.chars().take(4).collect();
    let last_four: String = s.chars().skip(char_count.saturating_sub(4)).collect();
    Cow::Owned(format!("{first_four}...{last_four}"))
}
