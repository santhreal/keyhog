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

/// `service` field per hot pattern - the CANONICAL service of the detector
/// this fast-path stands in for, NOT an internal `*_key` label. The hot path
/// is a perf optimization, not a distinct detector: a leaked `AKIA…` is an
/// `aws-access-key` finding however the engine found it. Before 2026-05-29
/// these were `aws_key`/`github_pat`/… so the SAME secret surfaced as
/// `hot-aws_key`/service `aws_key` on Linux (Hyperscan path) but
/// `aws-access-key`/service `aws` on macOS/Windows (portable, no hot path) -
/// a cross-platform id divergence. Emitting canonical identity here makes all
/// platforms agree and matches what `keyhog explain` already resolves hot ids
/// to. Index-parallel with HOT_PATTERNS / the two arrays below.
pub const HOT_PATTERN_NAMES: &[&str] = &[
    "github", "openai", "aws", "aws", "sendgrid", "slack", "slack", "square",
];

/// Canonical `detector_id` per hot pattern - the id of the named detector the
/// fast-path represents, so scan output (JSON/SARIF/text/baselines) is
/// identical regardless of which engine path made the find. `sq0csp-` keeps
/// `hot-square_secret`: no standalone square-secret detector exists yet, so it
/// is genuinely fast-path-only (`keyhog explain` documents this). Static (not
/// `format!`-per-match) to keep the per-hit allocation the perf audit removed.
///
/// `ASIA` maps to `aws-access-key`, NOT `aws-session-token`: an `ASIA…` string
/// is a temporary STS *access key ID* (the same shape as `AKIA…` - the
/// `aws-access-key` detector regex is literally `(?-i)(AKIA|ASIA)[0-9A-Z]{16}`
/// and the verifier lists `ASIA` in `AWS_VALID_ACCESS_KEY_PREFIXES`). The
/// *session token* is the separate long base64 blob the `aws-session-token`
/// detector matches via the `AWS_SESSION_TOKEN=`/`X-Amz-Security-Token=`
/// anchors - none of which begin with `ASIA`. The old `ASIA→aws-session-token`
/// mapping mis-attributed every `ASIA` key ID and (once the hot path gained
/// precise-regex validation) would have rejected them outright, since the
/// session-token regex can never match an `ASIA…` literal.
pub const HOT_PATTERN_DETECTOR_IDS: &[&str] = &[
    "github-classic-pat",
    "openai-api-key",
    "aws-access-key",
    "aws-access-key",
    "sendgrid-api-key",
    "slack-bot-token",
    "slack-user-token",
    "hot-square_secret",
];

/// Canonical human-readable detector name per hot pattern (matches the `name`
/// field of the corresponding `detectors/*.toml`). Square has no canonical
/// detector, so it carries a plain "Square Secret" label.
pub const HOT_PATTERN_DISPLAY_NAMES: &[&str] = &[
    "GitHub Classic PAT",
    "OpenAI API Key",
    "AWS Access Key",
    "AWS Access Key",
    "SendGrid API Key",
    "Slack Bot Token",
    "Slack User Token",
    "Square Secret",
];

/// Build a precise-regex validator for each hot-pattern slot, index-parallel
/// with [`HOT_PATTERNS`].
///
/// The hot path is a literal-prefix prefilter: a 50+ GB/s SIMD sieve finds
/// `ghp_`/`xoxp-`/`AKIA`/… and historically emitted a `Critical` finding
/// gated ONLY by a per-prefix length floor (`PER_PATTERN_MIN_LEN` in
/// `engine/hot_patterns.rs`). A length floor is a crude proxy for the
/// detector's real regex and admits wrong-character-class tokens the precise
/// pattern rejects:
///   - `ghp_THIS_HAS_UNDERSCORES_IN_IT_NOT_A_TOKEN0` (43 ≥ 40 floor, but `_`
///     is not in `[A-Za-z0-9]` and the body is 39 chars, not 36), and
///   - `xoxp-123-456-789-abc` (20 ≥ 16 floor, but the segments are far short
///     of the 10-13-digit Slack shape)
/// both cleared the floor and surfaced as `Critical` false positives that the
/// AC+regex path correctly rejected. Validating each candidate against the
/// detector's own regex (anchored at the candidate start) restores parity: the
/// fast path emits exactly what the precise path would, just sooner.
///
/// A slot is `None` only when its `HOT_PATTERN_DETECTOR_IDS` entry names no
/// loaded detector (`hot-square_secret`, genuinely fast-path-only); that slot
/// keeps the length-floor as its sole gate.
#[allow(dead_code)] // used by the simdsieve hot path; harmless if that path is cfg-stripped
pub fn build_hot_pattern_validators(
    detectors: &[keyhog_core::DetectorSpec],
) -> Vec<Option<regex::Regex>> {
    HOT_PATTERN_DETECTOR_IDS
        .iter()
        .map(|&id| {
            let detector = detectors.iter().find(|d| d.id == id)?;
            let alts: Vec<String> = detector
                .patterns
                .iter()
                .map(|p| format!("(?:{})", p.regex))
                .collect();
            if alts.is_empty() {
                return None;
            }
            // Anchor at the candidate start. The candidate always begins with
            // the hot literal and every hot detector's regex begins with that
            // same literal, so `^` is the correct anchor. The build flags
            // mirror `compiler_compile::shared_regex_compile` exactly (the
            // engine's own regex build) so validation semantics match the
            // AC+regex path byte-for-byte: `case_insensitive(true)` as the
            // default with inline `(?-i)` (AWS `AKIA`/`ASIA`) scoping within
            // its own alternative, plus the same size and DFA limits.
            let combined = format!("^(?:{})", alts.join("|"));
            regex::RegexBuilder::new(&combined)
                .case_insensitive(true)
                .size_limit(crate::types::REGEX_SIZE_LIMIT_BYTES)
                .dfa_size_limit(crate::types::regex_dfa_limit())
                .crlf(true)
                .build()
                .ok()
        })
        .collect()
}
