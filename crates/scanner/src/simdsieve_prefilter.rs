//! SIMD-accelerated prefilter for the top N most common secret patterns.
//!
//! `simdsieve` provides 50+ GB/s scanning for up to 8 patterns using AVX-512/AVX2.
//! This module integrates it as Layer 1 of the scanning pipeline:
//! hot patterns are checked first, and if found, we can often skip AC/Regex.

use simdsieve::SimdSieve;

/// Common high-value secret prefixes that trigger Layer 1 SIMD.
pub const HOT_PATTERNS: &[&[u8]] = &[
    b"ghp_",
    b"sk-proj-",
    b"AKIA",
    b"ASIA",
    b"SG.",
    b"xoxb-",
    b"xoxp-",
    b"sq0csp-",
];

pub const HOT_PATTERN_NAMES: &[&str] = &[
    "github_pat",
    "openai_key",
    "aws_key",
    "aws_session_key",
    "sendgrid_key",
    "slack_bot_token",
    "slack_user_token",
    "square_secret",
];

/// A SIMD pre-filter that checks chunks for common secret prefixes.
pub struct SimdPrefilter;

impl SimdPrefilter {
    /// Create a new pre-filter.
    pub fn new() -> Self {
        Self
    }

    /// Fast screen: returns true if the chunk likely contains any hot pattern.
    /// Returns (should_scan, confidence).
    pub fn quick_screen(&self, data: &[u8]) -> (bool, f64) {
        if data.is_empty() {
            return (false, 0.0);
        }

        // SimdSieve is a streaming iterator that performs the scan.
        // We just check if there's at least one match.
        if let Ok(mut sieve) = SimdSieve::new(data, HOT_PATTERNS) {
            if sieve.next().is_some() {
                return (true, 0.95);
            }
        }

        (false, 0.0)
    }
}

impl Default for SimdPrefilter {
    fn default() -> Self {
        Self::new()
    }
}
