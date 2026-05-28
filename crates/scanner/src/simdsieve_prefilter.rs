//! SIMD-accelerated prefilter for the top N most common secret patterns.
//!
//! `simdsieve` provides 50+ GB/s scanning for up to 8 patterns using AVX-512/AVX2.
//! This module integrates it as Layer 1 of the scanning pipeline:
//! hot patterns are checked first, and if found, we can often skip AC/Regex.

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

/// Pre-formatted `hot-<name>` detector ID per hot pattern. The hot-path
/// scanner used to `format!("hot-{}", HOT_PATTERN_NAMES[idx])` once per
/// match; that allocated a fresh `String` per hit. With 8 hot patterns
/// fixed at compile time, hand-rolling the prefix at static-build time
/// kills the per-match allocation. Index-parallel with HOT_PATTERN_NAMES.
pub const HOT_PATTERN_DETECTOR_IDS: &[&str] = &[
    "hot-github_pat",
    "hot-openai_key",
    "hot-aws_key",
    "hot-aws_session_key",
    "hot-sendgrid_key",
    "hot-slack_bot_token",
    "hot-slack_user_token",
    "hot-square_secret",
];

/// Pre-formatted `Hot Pattern: <name>` display name per hot pattern.
/// Same rationale as HOT_PATTERN_DETECTOR_IDS - kills the per-match
/// `format!()` allocation that the perf kimi audit called out.
pub const HOT_PATTERN_DISPLAY_NAMES: &[&str] = &[
    "Hot Pattern: github_pat",
    "Hot Pattern: openai_key",
    "Hot Pattern: aws_key",
    "Hot Pattern: aws_session_key",
    "Hot Pattern: sendgrid_key",
    "Hot Pattern: slack_bot_token",
    "Hot Pattern: slack_user_token",
    "Hot Pattern: square_secret",
];

#[cfg(test)]
mod parallel_array_tests {
    use super::*;

    #[test]
    fn detector_id_array_matches_names() {
        assert_eq!(HOT_PATTERN_NAMES.len(), HOT_PATTERN_DETECTOR_IDS.len());
        for (name, id) in HOT_PATTERN_NAMES.iter().zip(HOT_PATTERN_DETECTOR_IDS) {
            assert_eq!(format!("hot-{name}"), *id);
        }
    }

    #[test]
    fn display_name_array_matches_names() {
        assert_eq!(HOT_PATTERN_NAMES.len(), HOT_PATTERN_DISPLAY_NAMES.len());
        for (name, display) in HOT_PATTERN_NAMES.iter().zip(HOT_PATTERN_DISPLAY_NAMES) {
            assert_eq!(format!("Hot Pattern: {name}"), *display);
        }
    }
}

