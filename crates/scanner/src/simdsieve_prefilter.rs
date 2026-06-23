//! SIMD-accelerated prefilter for the top N most common secret patterns.
//!
//! `simdsieve` checks keyhog's hot prefixes in a single AVX-512/AVX2/NEON
//! pass. (The crate's 50+ GB/s headline is its single-byte-prefix peak;
//! multi-byte prefixes like these run lower — throughput scales down with
//! prefix length — but still far faster than running AC/regex on every byte.)
//! This module integrates it as Layer 1 of the scanning pipeline:
//! hot patterns are checked first, and if found, we can often skip AC/Regex.

macro_rules! define_hot_pattern_tables {
    ($(($prefix:expr, $min_len:expr, $service:expr, $detector_id:expr, $display_name:expr $(,)?)),+ $(,)?) => {
        /// Common high-value secret prefixes that trigger Layer 1 SIMD.
        pub(crate) const HOT_PATTERNS: &[&[u8]] = &[$($prefix),+];

        /// Per-pattern minimum credential length, in bytes.
        ///
        /// Each floor matches the shortest valid token for the same slot in
        /// [`HOT_PATTERNS`]. This lives beside the prefix/identity tables so a
        /// new hot pattern cannot silently inherit a permissive default in the
        /// engine fast path.
        pub(crate) const HOT_PATTERN_MIN_LENGTHS: &[usize] = &[$($min_len),+];

        /// `service` field per hot pattern - the CANONICAL service of the detector
        /// this fast-path stands in for, NOT an internal `*_key` label. The hot path
        /// is a perf optimization, not a distinct detector: a leaked `AKIA…` is an
        /// `aws-access-key` finding however the engine found it. Before 2026-05-29
        /// these were `aws_key`/`github_pat`/… so the SAME secret surfaced as
        /// `hot-aws_key`/service `aws_key` on Linux (Hyperscan path) but
        /// `aws-access-key`/service `aws` on macOS/Windows (portable, no hot path) -
        /// a cross-platform id divergence. Emitting canonical identity here makes all
        /// platforms agree and matches what `keyhog explain` already resolves hot ids
        /// to.
        pub(crate) const HOT_PATTERN_NAMES: &[&str] = &[$($service),+];

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
        pub(crate) const HOT_PATTERN_DETECTOR_IDS: &[&str] = &[$($detector_id),+];

        /// Canonical human-readable detector name per hot pattern (matches the `name`
        /// field of the corresponding `detectors/*.toml`). Square has no canonical
        /// detector, so it carries a plain "Square Secret" label.
        pub(crate) const HOT_PATTERN_DISPLAY_NAMES: &[&str] = &[$($display_name),+];

        const _: [(); HOT_PATTERNS.len()] = [(); HOT_PATTERN_MIN_LENGTHS.len()];
        const _: [(); HOT_PATTERNS.len()] = [(); HOT_PATTERN_NAMES.len()];
        const _: [(); HOT_PATTERNS.len()] = [(); HOT_PATTERN_DETECTOR_IDS.len()];
        const _: [(); HOT_PATTERNS.len()] = [(); HOT_PATTERN_DISPLAY_NAMES.len()];
    };
}

define_hot_pattern_tables![
    (
        b"ghp_",
        40,
        "github",
        crate::detector_ids::GITHUB_CLASSIC_PAT,
        "GitHub Classic PAT",
    ),
    (
        b"sk-proj-",
        20,
        "openai",
        crate::detector_ids::OPENAI_API_KEY,
        "OpenAI API Key",
    ),
    (
        b"AKIA",
        20,
        "aws",
        crate::detector_ids::AWS_ACCESS_KEY,
        "AWS Access Key",
    ),
    (
        b"ASIA",
        20,
        "aws",
        crate::detector_ids::AWS_ACCESS_KEY,
        "AWS Access Key",
    ),
    (
        b"SG.",
        26,
        "sendgrid",
        crate::detector_ids::SENDGRID_API_KEY,
        "SendGrid API Key",
    ),
    (
        b"xoxb-",
        16,
        "slack",
        crate::detector_ids::SLACK_BOT_TOKEN,
        "Slack Bot Token",
    ),
    (
        b"xoxp-",
        16,
        "slack",
        crate::detector_ids::SLACK_USER_TOKEN,
        "Slack User Token",
    ),
    (
        b"sq0csp-",
        16,
        "square",
        crate::detector_ids::HOT_SQUARE_SECRET,
        "Square Secret",
    ),
    (
        b"sk_live_",
        32,
        "stripe",
        crate::detector_ids::STRIPE_SECRET_KEY,
        "Stripe Secret Key",
    ),
    (
        b"sk_test_",
        32,
        "stripe",
        crate::detector_ids::STRIPE_SECRET_KEY,
        "Stripe Secret Key",
    ),
    (
        b"rk_live_",
        32,
        "stripe",
        crate::detector_ids::STRIPE_SECRET_KEY,
        "Stripe Secret Key",
    ),
    (
        b"rk_test_",
        32,
        "stripe",
        crate::detector_ids::STRIPE_SECRET_KEY,
        "Stripe Secret Key",
    ),
];

/// Build a precise-regex validator for each hot-pattern slot, index-parallel
/// with [`HOT_PATTERNS`].
///
/// The hot path is a literal-prefix prefilter: a single-pass SIMD sieve finds
/// `ghp_`/`xoxp-`/`AKIA`/… and historically emitted a `Critical` finding
/// gated ONLY by a per-prefix length floor. A length floor is a crude proxy for the
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
///
/// This module (`mod simdsieve_prefilter`) and the sole caller in
/// `engine::compile` are both gated on `feature = "simdsieve"`, so whenever
/// this function is compiled its caller is too: no `#[allow(dead_code)]` is
/// needed.
pub(crate) fn build_hot_pattern_validators(
    detectors: &[keyhog_core::DetectorSpec],
) -> crate::error::Result<Vec<Option<regex::Regex>>> {
    HOT_PATTERN_DETECTOR_IDS
        .iter()
        .map(|&id| -> crate::error::Result<Option<regex::Regex>> {
            // A slot with no loaded detector is the ONE legitimate `None`
            // (`hot-square_secret`, genuinely fast-path-only): keep the
            // length-floor as its sole gate. This is a documented design choice,
            // not a failure.
            let Some(detector) = detectors.iter().find(|d| d.id == id) else {
                return Ok(None);
            };
            let alts: Vec<String> = detector
                .patterns
                .iter()
                .map(|p| format!("(?:{})", p.regex))
                .collect();
            if alts.is_empty() {
                return Ok(None);
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
            // Law 10: FAIL CLOSED on a build error, never `.ok()` it away. The
            // old `.ok()` turned a build failure into a silent `None`, which the
            // consumer (`engine/hot_patterns.rs`) demotes to the weak
            // length-floor gate — an invisible precision loss on the hot path.
            // The individual detector patterns are already validated on the
            // primary compile path; the only NEW failure here is the combined
            // alternation exceeding the size/DFA limit. If that happens the build
            // is corrupt: abort scanner compile with a precise error rather than
            // run a degraded fast path.
            let re = regex::RegexBuilder::new(&combined)
                .case_insensitive(true)
                .size_limit(crate::types::REGEX_SIZE_LIMIT_BYTES)
                .dfa_size_limit(crate::types::regex_dfa_limit())
                .crlf(true)
                .build()
                .map_err(|source| crate::error::ScanError::RegexCompile {
                    detector_id: id.to_string(),
                    index: 0,
                    source,
                })?;
            Ok(Some(re))
        })
        .collect()
}
