/// Fast check for secret-related keywords in file content.
/// Used to gate the multiline fallback - only files that mention
/// secret/key/token/password are worth reassembling.
///
/// Used by coalesced SIMD and GPU phase2 no-hit routing to avoid full phase-2
/// scans on chunks that cannot plausibly contain split or prefix-known secrets.
///
/// Single-pass Aho-Corasick over all distinctive prefixes - replaces the
/// previous loop of N independent `memmem` scans (each O(n)) which traversed
/// the chunk N times. With the AC automaton the scan is O(n) total, with
/// one memory walk and shared cache lines.
//
// `any(simd, gpu)`: invoked only from `should_scan_no_hit_chunk`, the
// no-phase-1-trigger admission gate on the coalesced (`simd`) /
// region-presence (`gpu`) phase-2 tail. The no-`simd`-no-`gpu` AC+phase-2 path scans every
// chunk whole and never routes through that gate, so this filter has no caller
// there — gated to match (Law 11).
#[cfg(any(feature = "simd", feature = "gpu"))]
pub(super) fn has_secret_keyword_fast(data: &[u8]) -> bool {
    use aho_corasick::AhoCorasick;
    use std::sync::LazyLock;
    // Hold an `Option` instead of `.expect()`-unwrapping at LazyLock-init
    // time: a panic in a static initializer poisons the LazyLock for the
    // rest of the process and kills every subsequent prefilter call across
    // all threads. On the (build-invariant-violating) `None` path the
    // consumer returns `true` — scan the chunk unconditionally, so recall is
    // preserved — but Law 10 forbids doing that SILENTLY, so the init closure
    // warns loudly exactly once via `prefilter_degrade`.
    static AC: LazyLock<Option<AhoCorasick>> = LazyLock::new(|| {
        // Distinctive enough to be real secrets AND commonly split across
        // lines in source code. The previous 5-entry list missed every
        // GitHub variant after `ghp_` (ghs_, gho_, ghu_, ghr_), every
        // Stripe live key family except `sk_live_`, every modern OpenAI
        // org/proj key past `sk-proj-`, plus the high-volume HF/Anthropic/
        // GCP service-key prefixes that show up split across lines in
        // copy-pasted .env files. Avoid short prefixes (AKIA, eyJ) that
        // appear in fixtures.
        match AhoCorasick::new([
            // OpenAI
            "sk-proj-",
            "sk-svcacct-",
            "sk-admin-",
            // Stripe
            "sk_live_",
            "sk_test_",
            "rk_live_",
            "pk_live_",
            // GitHub (all installation variants)
            "ghp_",
            "ghs_",
            "gho_",
            "ghu_",
            "ghr_",
            "github_pat_",
            // Slack
            "xoxb-",
            "xoxp-",
            "xoxa-",
            "xoxr-",
            "xoxs-",
            "xapp-",
            // Anthropic
            "sk-ant-",
            // HuggingFace
            "hf_",
            // GCP service account email shard (rarely splits, but cheap)
            ".iam.gserviceaccount.com",
            // GitLab
            "glpat-",
            // npm
            "npm_",
            // Heroku UUID-style key family
            "HRKU-",
        ]) {
            Ok(ac) => Some(ac),
            Err(e) => {
                crate::prefilter_degrade::warn_prefilter_disabled(
                    "multiline secret-keyword gate (has_secret_keyword_fast)",
                    &e,
                );
                None
            }
        }
    });
    // Fail-closed (Law 10): `None` → scan the chunk unconditionally rather than
    // skip it. The warning above already surfaced the degradation once.
    AC.as_ref().is_none_or(|ac| ac.find(data).is_some())
}

/// Check for generic `secret=`, `password:`, `token=` etc. keywords.
/// Broader than `has_secret_keyword_fast` (which is for multiline only).
///
/// Same single-pass AC strategy as `has_secret_keyword_fast`, but with the
/// case-insensitive variants folded into one automaton - `aho-corasick`'s
/// `ascii_case_insensitive` builder option matches both `secret` and
/// `SECRET` from a single literal at scan-time, halving the pattern count.
///
//
// `any(simd, gpu)`: like `has_secret_keyword_fast`, this is consumed only by
// `should_scan_no_hit_chunk` on the coalesced/region-presence phase-2 tail;
// gated to match its caller so no-`simd`-no-`gpu` builds stay warning-clean (Law 11).
#[cfg(any(feature = "simd", feature = "gpu"))]
pub(super) fn has_generic_assignment_keyword(data: &[u8]) -> bool {
    use aho_corasick::AhoCorasick;
    use std::sync::LazyLock;
    // See `has_secret_keyword_fast` for the rationale; same fail-closed
    // (`true` on init failure) so the prefilter never causes an FN by
    // dropping a chunk, and the same loud one-shot warning (Law 10) so the
    // degradation is never silent.
    static AC: LazyLock<Option<AhoCorasick>> = LazyLock::new(|| {
        match AhoCorasick::builder().ascii_case_insensitive(true).build(
            crate::assignment_keywords::assignment_keywords()
                .iter()
                .map(String::as_str),
        ) {
            Ok(ac) => Some(ac),
            Err(e) => {
                crate::prefilter_degrade::warn_prefilter_disabled(
                    "generic-assignment keyword gate (has_generic_assignment_keyword)",
                    &e,
                );
                None
            }
        }
    });
    AC.as_ref().is_none_or(|ac| ac.find(data).is_some())
}

/// Single-pass scan for a contiguous run of credential-value bytes (including
/// common token separators and symbolic password punctuation).
/// of length >= `MIN_ENTROPY_RUN`. The keyword-gated fallback drop in
/// `scan_coalesced` (no-HS-hit branch) historically required the chunk
/// to contain a generic-assignment / secret keyword before routing
/// through `scan_inner` — chunks of pure entropy with NO keyword anchor
/// (the `generic-high-entropy-string` corpus shape) silently bailed,
/// pinning that category's recall at 0.36 on the SecretBench mirror.
///
/// `MIN_ENTROPY_RUN` is set to 32 chars so the gate stays cheap and
/// rarely trips on natural code: function/class names cap around 24
/// chars, UUIDs are 36 chars *with dashes* (longest base62 run = 12),
/// and the longest English word is 28 chars. Real secrets at this
/// threshold are credentials (32-char hex APIs, 40-char base62 tokens,
/// symbolic passwords, 64-char SHA hex, base64 blobs). Hash/UUID-shaped FPs
/// are still suppressed downstream by the bare/prefixed hash gates and
/// `is_uuid_v4_shape`, so trip-firing the gate does NOT add FPs - it just
/// admits the chunk to the entropy fallback for inspection.
//
// `any(simd, gpu)`: both callers live behind these features — the
// `should_scan_no_hit_chunk` admission gate (`any(simd, gpu)`) and the entropy
// fallback's cheap precheck (`#[cfg(simd)]` in `phase2_entropy.rs`). Their
// union is `any(simd, gpu)`; the no-`simd`-no-`gpu` path has neither, so gating
// here keeps that profile warning-clean (Law 11).
#[cfg(any(feature = "simd", feature = "gpu"))]
pub(super) fn has_high_entropy_run_fast(data: &[u8]) -> bool {
    has_high_entropy_run_at_least(data, DEFAULT_ENTROPY_RUN_BYTES)
}

#[cfg(any(feature = "simd", feature = "gpu"))]
pub(super) const DEFAULT_ENTROPY_RUN_BYTES: usize = 32;

#[cfg(any(feature = "simd", feature = "gpu"))]
pub(super) fn has_high_entropy_run_at_least(data: &[u8], min_run: usize) -> bool {
    let min_run = min_run.max(1);
    let mut run = 0usize;
    for &b in data {
        if is_entropy_candidate_byte(b) {
            run += 1;
            if run >= min_run {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

#[cfg(any(feature = "simd", feature = "gpu"))]
fn is_entropy_candidate_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'-' | b'_'
                | b'+'
                | b'/'
                | b'='
                | b'.'
                | b':'
                | b'!'
                | b'@'
                | b'#'
                | b'$'
                | b'%'
                | b'^'
                | b'&'
                | b'*'
        )
}

pub(super) fn looks_like_variable_name(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.is_empty() || bytes.len() > 64 {
        return false;
    }
    // Pure ASCII check - byte ops are ~4x faster than .chars().all()
    // because they skip UTF-8 decode and char boundary tracking.
    bytes
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Variable-name fallback for grouped detectors: when the configured capture
/// `group` looks like a variable name rather than a secret, scan the other
/// capture groups for the first value-shaped sibling (itself NOT variable-name
/// shaped, length >= 8) and return its `(start, end)` byte range; otherwise
/// return `current` unchanged.
///
/// Shared by `extract_grouped_matches` (whole-chunk walk) and `extract_anchored`
/// (phase-2 anchored verification) so this detection-load-bearing heuristic has
/// exactly one definition instead of two copies that could drift apart. Offsets
/// are relative to `text`, which each caller supplies as its own search base —
/// the full preprocessed text for the whole-chunk walk, or the anchored `slice`
/// for the phase-2 path — so the returned range re-slices correctly on either.
pub(crate) fn resolve_value_shaped_group(
    locs: &regex::CaptureLocations,
    text: &str,
    group: usize,
    groups_total: usize,
    current: (usize, usize),
) -> (usize, usize) {
    if !looks_like_variable_name(&text[current.0..current.1]) || groups_total <= 2 {
        return current;
    }
    for g in 1..groups_total {
        if g == group {
            continue;
        }
        if let Some((s, e)) = locs.get(g) {
            let candidate = &text[s..e];
            if !looks_like_variable_name(candidate) && candidate.len() >= 8 {
                return (s, e);
            }
        }
    }
    current
}

pub(crate) fn extend_known_prefix_credential<'a>(
    data: &'a str,
    credential: &'a str,
    match_end: usize,
) -> (&'a str, usize) {
    let original = credential;
    let original_end = match_end;
    let (credential, match_end) = if crate::confidence::known_prefix_confidence_floor(credential)
        .is_some()
    {
        let bytes = data.as_bytes();
        let mut end = match_end;
        while end < bytes.len() && is_provider_token_byte(bytes[end]) {
            end += 1;
        }

        if end == match_end || !data.is_char_boundary(end) {
            (credential, match_end)
        } else {
            // Slice from the CREDENTIAL's own start, not `match_start`. For a
            // grouped detector `KEYWORD[=:\s"']+(VALUE)` the whole regex span
            // starts at the keyword, not the secret. `credential` is a subslice
            // of `data` (extract.rs builds it as `&search_text[range]`, and
            // `data == search_text` here), so its byte offset within `data` is
            // the pointer delta. Fall back to the unextended credential if that
            // invariant ever fails to hold (defensive; never on the real path).
            let cred_start = (credential.as_ptr() as usize).wrapping_sub(data.as_ptr() as usize);
            if cred_start <= match_end && end <= bytes.len() && data.is_char_boundary(cred_start) {
                (&data[cred_start..end], end)
            } else {
                (credential, match_end)
            }
        }
    } else {
        (credential, match_end)
    };

    let (credential, match_end) = extend_base64_padding(data, credential, match_end);

    // A boundary extension must never DOWNGRADE an already-valid checksum. A
    // known-prefix token whose canonical form passes its checksum is complete;
    // grabbing a trailing byte that merely abuts it — a base64 `=` that is
    // really a separator (`pypi-…MNH` followed by `="…"`), or a provider-token
    // byte from adjacent content — corrupts the token so it fails the checksum
    // and is dropped, losing a real secret. Only the extension is reverted (the
    // canonical token still surfaces); the unicode swap-invariance gate
    // exercises exactly this (homoglyphed companion context whose trailing `=`
    // was being appended to a valid pypi token). Cheap: the length guard keeps
    // the checksum-validity comparison off the hot path until an extension
    // actually changed the credential. The comparison itself lives in the
    // checksum module (`extension_downgrades_checksum`) so this engine emission
    // path asks a named checksum question instead of owning raw checksum
    // primitives (the `engine_match_policy_checksum_owner` gate).
    if credential.len() != original.len()
        && crate::checksum::extension_downgrades_checksum(original, credential)
    {
        return (original, original_end);
    }

    (credential, match_end)
}

/// Swallow up to two trailing `=` when the captured body is base64-shaped.
/// Regexes often end with `=?` or `{20,}=?` and drop the second padding
/// char on values like `YWJj…vcA==` - `splitio-api-key` and friends.
fn extend_base64_padding<'a>(
    data: &'a str,
    credential: &'a str,
    match_end: usize,
) -> (&'a str, usize) {
    if !credential
        .bytes()
        .all(crate::decode::is_base64_candidate_byte)
    {
        return (credential, match_end);
    }
    let bytes = data.as_bytes();
    let mut end = match_end;
    let mut pad = 0u8;
    while end < bytes.len() && bytes[end] == b'=' && pad < 2 {
        end += 1;
        pad += 1;
    }
    if pad > 0 && data.is_char_boundary(end) {
        // Slice from the credential's own start (subslice of `data`) so base64
        // padding recovery on a grouped detector never prepends the keyword to
        // the credential.
        let cred_start = (credential.as_ptr() as usize).wrapping_sub(data.as_ptr() as usize);
        if cred_start <= match_end && data.is_char_boundary(cred_start) {
            (&data[cred_start..end], end)
        } else {
            (credential, match_end)
        }
    } else {
        (credential, match_end)
    }
}

fn is_provider_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')
}

/// Compute the two per-pattern-constant confidence signals (`keyword_nearby`,
/// `sensitive_file`). Extracted so `extract_grouped_matches`,
/// `extract_plain_matches`, and the shared-anchor path share one lazy
/// `OnceCell` init closure body (Rust can't `impl FnOnce<>` to share inline).
/// Lives here (not `scan.rs`) to keep that file under the standard 500-LOC cap.
pub(super) fn compute_pattern_signals(
    entry: &crate::types::CompiledPattern,
    detector: &keyhog_core::DetectorSpec,
    chunk: &keyhog_core::Chunk,
    preprocessed: &crate::types::ScannerPreprocessedText<'_>,
) -> (bool, bool) {
    let kw = entry.match_proves_keyword_nearby || {
        // `text_differs` is invariant across keywords, so compute it ONCE rather
        // than re-comparing the whole preprocessed buffer against `chunk.data`
        // inside the `any` loop. On the passthrough common path the two buffers
        // are the same bytes (a `Cow::Borrowed`), so the slice `!=` is an O(len)
        // memcmp — doing it per keyword made the keyword-nearby probe
        // O(keywords × len) for nothing.
        let text_differs = preprocessed.text.as_bytes() != chunk.data.as_bytes();
        detector.keywords.iter().any(|keyword| {
            let needle = keyword.as_str();
            chunk.data.contains(needle) || (text_differs && preprocessed.text.contains(needle))
        })
    };
    let sf = chunk
        .metadata
        .path
        .as_deref()
        .map(crate::confidence::is_sensitive_path)
        .unwrap_or(false); // LAW10: empty/absent => documented numeric/sentinel default, recall-safe
    (kw, sf)
}

// Behavioral lock for the two recall-critical no-hit prefilters
// (`has_secret_keyword_fast`, `has_generic_assignment_keyword`). They gate which
// no-phase-1-trigger chunks are still routed into phase-2 reassembly/extraction,
// so a silent drop from either list is a direct false-negative. These pin the
// exact triggering contract — every curated vendor prefix, the deliberately-
// EXCLUDED short prefixes, the case-sensitivity CONTRAST between the two gates,
// and the fail-open (never-drop) boundaries — white-box because both fns are
// `pub(super)` and cfg-gated behind `any(simd, gpu)` (see the allowlist entry in
// `tests/gap/no_inline_tests_in_src.rs`).
#[cfg(all(test, any(feature = "simd", feature = "gpu")))]
mod tests {
    use super::{has_generic_assignment_keyword, has_secret_keyword_fast};

    /// The EXACT set of distinctive vendor prefixes `has_secret_keyword_fast`
    /// treats as split-across-lines secret anchors. This is the contract: the fn
    /// must fire for every one of these, so if a future edit drops one the
    /// `every_curated_prefix_triggers` test fails loudly. Ordered by vendor to
    /// mirror the source list.
    const CURATED_PREFIXES: &[&str] = &[
        // OpenAI
        "sk-proj-",
        "sk-svcacct-",
        "sk-admin-",
        // Stripe
        "sk_live_",
        "sk_test_",
        "rk_live_",
        "pk_live_",
        // GitHub (all installation variants)
        "ghp_",
        "ghs_",
        "gho_",
        "ghu_",
        "ghr_",
        "github_pat_",
        // Slack
        "xoxb-",
        "xoxp-",
        "xoxa-",
        "xoxr-",
        "xoxs-",
        "xapp-",
        // Anthropic
        "sk-ant-",
        // HuggingFace
        "hf_",
        // GCP service-account email shard
        ".iam.gserviceaccount.com",
        // GitLab
        "glpat-",
        // npm
        "npm_",
        // Heroku
        "HRKU-",
    ];

    #[test]
    fn curated_prefix_list_has_exactly_twenty_five_entries() {
        // Fast tripwire on the size of the recall-critical list. If the source
        // list grows/shrinks, update this AND `every_curated_prefix_triggers`
        // together so the count and the behavior stay in lockstep.
        assert_eq!(CURATED_PREFIXES.len(), 25);
    }

    #[test]
    fn every_curated_prefix_triggers() {
        for prefix in CURATED_PREFIXES {
            let line = format!("api_key = {prefix}A1b2C3d4E5f6");
            assert!(
                has_secret_keyword_fast(line.as_bytes()),
                "curated prefix {prefix:?} must route the chunk to phase-2 reassembly"
            );
        }
    }

    #[test]
    fn openai_prefixes_trigger() {
        assert!(has_secret_keyword_fast(b"key=sk-proj-abcdef"));
        assert!(has_secret_keyword_fast(b"key=sk-svcacct-abcdef"));
        assert!(has_secret_keyword_fast(b"key=sk-admin-abcdef"));
    }

    #[test]
    fn stripe_prefixes_trigger() {
        assert!(has_secret_keyword_fast(b"k=sk_live_abcdef"));
        assert!(has_secret_keyword_fast(b"k=sk_test_abcdef"));
        assert!(has_secret_keyword_fast(b"k=rk_live_abcdef"));
        assert!(has_secret_keyword_fast(b"k=pk_live_abcdef"));
    }

    #[test]
    fn github_all_installation_variants_trigger() {
        for token in ["ghp_", "ghs_", "gho_", "ghu_", "ghr_", "github_pat_"] {
            let line = format!("gh={token}0123456789");
            assert!(
                has_secret_keyword_fast(line.as_bytes()),
                "GitHub variant {token:?} must trigger"
            );
        }
    }

    #[test]
    fn slack_prefixes_trigger() {
        for token in ["xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-", "xapp-"] {
            let line = format!("slack={token}0123456789");
            assert!(
                has_secret_keyword_fast(line.as_bytes()),
                "Slack prefix {token:?} must trigger"
            );
        }
    }

    #[test]
    fn anthropic_prefix_triggers() {
        assert!(has_secret_keyword_fast(b"key=sk-ant-api03-abcdef"));
    }

    #[test]
    fn huggingface_prefix_triggers() {
        assert!(has_secret_keyword_fast(b"HF_TOKEN=hf_abcdefghij"));
    }

    #[test]
    fn gitlab_and_npm_prefixes_trigger() {
        assert!(has_secret_keyword_fast(b"token=glpat-abcdefghij"));
        assert!(has_secret_keyword_fast(b"//registry:_authToken=npm_abcdef"));
    }

    #[test]
    fn heroku_prefix_triggers() {
        assert!(has_secret_keyword_fast(b"key=HRKU-9f8e7d6c5b4a"));
    }

    #[test]
    fn gcp_service_account_shard_triggers() {
        assert!(has_secret_keyword_fast(
            b"client_email: svc@proj.iam.gserviceaccount.com"
        ));
    }

    #[test]
    fn match_is_case_sensitive_unlike_the_generic_gate() {
        // `has_secret_keyword_fast` uses a case-SENSITIVE automaton (the prefixes
        // are exact vendor casings), so an uppercased OpenAI prefix must NOT
        // trigger. This is the deliberate contrast with the case-folding generic
        // gate asserted in `generic_gate_is_case_insensitive`.
        assert!(
            !has_secret_keyword_fast(b"KEY=SK-PROJ-ABCDEF"),
            "uppercased vendor prefix must not match the case-sensitive fast gate"
        );
    }

    #[test]
    fn heroku_prefix_is_case_sensitive() {
        // `HRKU-` is stored uppercase; the lowercase spelling is not a real Heroku
        // key prefix and must not trigger (guards against a case-fold regression
        // silently widening this gate).
        assert!(has_secret_keyword_fast(b"key=HRKU-abcdef"));
        assert!(!has_secret_keyword_fast(b"key=hrku-abcdef"));
    }

    #[test]
    fn deliberately_excluded_short_prefixes_do_not_trigger() {
        // AKIA (AWS access-key id) and eyJ (base64 `{"` JWT header) are SHORT and
        // appear constantly in fixtures/docs, so they are intentionally excluded
        // from this multiline gate. Pin that exclusion — re-adding them would flood
        // the phase-2 tail with fixture noise.
        assert!(
            !has_secret_keyword_fast(b"AKIAIOSFODNN7EXAMPLE"),
            "AKIA is deliberately excluded from the multiline fast gate"
        );
        assert!(
            !has_secret_keyword_fast(b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"),
            "eyJ JWT header is deliberately excluded from the multiline fast gate"
        );
    }

    #[test]
    fn prefix_anywhere_in_chunk_triggers() {
        // The gate is a substring scan, not line-anchored: a prefix buried in the
        // middle of a chunk still routes it to phase-2.
        assert!(has_secret_keyword_fast(
            b"noise noise ghp_abcdef trailing noise"
        ));
    }

    #[test]
    fn prefix_at_chunk_end_triggers() {
        assert!(has_secret_keyword_fast(b"the value is glpat-"));
    }

    #[test]
    fn empty_input_does_not_trigger() {
        assert!(!has_secret_keyword_fast(b""));
    }

    #[test]
    fn plain_prose_without_any_prefix_does_not_trigger() {
        assert!(!has_secret_keyword_fast(
            b"the quick brown fox jumps over the lazy dog"
        ));
    }

    #[test]
    fn truncated_prefixes_do_not_trigger() {
        // `ghp` without the `_`, and `sk-proj` without the trailing `-`, are not
        // the full curated prefixes — the gate must require the exact token so it
        // stays specific.
        assert!(!has_secret_keyword_fast(b"ghp is a common abbreviation"));
        assert!(!has_secret_keyword_fast(b"my sk-proj folder"));
    }

    #[test]
    fn generic_gate_is_case_insensitive() {
        // Contrast with the vendor-prefix gate: `has_generic_assignment_keyword`
        // folds case, so an all-caps assignment keyword still triggers.
        assert!(has_generic_assignment_keyword(b"PASSWORD=hunter2"));
        assert!(has_generic_assignment_keyword(b"Api_Key: xyz"));
    }

    #[test]
    fn the_two_gates_cover_different_shapes() {
        // Separation of concerns: a bare `password=` line has NO vendor prefix, so
        // only the generic gate admits it; a bare `ghp_` token has no assignment
        // keyword, so only the fast gate admits it. Pin that neither gate silently
        // subsumes the other's job.
        assert!(!has_secret_keyword_fast(b"password: hunter2"));
        assert!(has_generic_assignment_keyword(b"password: hunter2"));
        assert!(has_secret_keyword_fast(b"ghp_0123456789abcdef"));
        assert!(!has_generic_assignment_keyword(b"ghp_0123456789abcdef"));
    }

    #[test]
    fn generic_gate_rejects_a_non_credential_line() {
        assert!(!has_generic_assignment_keyword(
            b"the quick brown fox jumps over the lazy dog"
        ));
    }
}
