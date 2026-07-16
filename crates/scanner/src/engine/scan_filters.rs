/// Fast check for secret-related keywords in file content.
/// Used to gate the multiline fallback - only files that mention
/// secret/key/token/password are worth reassembling.
///
/// Used by every backend's phase-2 no-hit routing to avoid full phase-2 scans
/// on chunks that cannot plausibly contain split or prefix-known secrets.
///
/// Single-pass Aho-Corasick over all distinctive prefixes - replaces the
/// previous loop of N independent `memmem` scans (each O(n)) which traversed
/// the chunk N times. With the AC automaton the scan is O(n) total, with
/// one memory walk and shared cache lines.
//
// Every backend uses this from the shared no-trigger admission gate.
pub(super) fn has_secret_keyword_fast(data: &[u8]) -> bool {
    use aho_corasick::AhoCorasick;
    use std::sync::LazyLock;
    // Hold an `Option` instead of `.expect()`-unwrapping at LazyLock-init
    // time: a panic in a static initializer poisons the LazyLock for the
    // rest of the process and kills every subsequent prefilter call across
    // all threads. On the (build-invariant-violating) `None` path the
    // consumer returns `true`: scan the chunk unconditionally, so recall is
    // preserved, but Law 10 forbids doing that SILENTLY, so the init closure
    // warns loudly exactly once via `prefilter_degrade`.
    static AC: LazyLock<Option<AhoCorasick>> = LazyLock::new(|| {
        // The distinctive vendor prefixes (case-sensitive, exact casing) live in
        // Tier-B `rules/multiline_secret_prefixes.toml`: that file documents WHY
        // each is included and why short fixture-prone prefixes (AKIA, eyJ) are
        // deliberately excluded. `AhoCorasick::new` is case-sensitive by default,
        // which the prefix casing depends on (see the module doc in
        // `crate::secret_prefixes`).
        match AhoCorasick::new(
            crate::secret_prefixes::multiline_secret_prefixes()
                .iter()
                .map(String::as_str),
        ) {
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
// Consumed by the backend-neutral `should_scan_no_hit_chunk` contract.
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
/// of length >= `DEFAULT_ENTROPY_RUN_BYTES`. The keyword-gated fallback drop in
/// `scan_coalesced` (no-HS-hit branch) historically required the chunk
/// to contain a generic-assignment / secret keyword before routing
/// through `scan_inner`: chunks of pure entropy with NO keyword anchor
/// (the `generic-high-entropy-string` corpus shape) silently bailed,
/// pinning that category's recall at 0.36 on the SecretBench mirror.
///
/// `DEFAULT_ENTROPY_RUN_BYTES` is set to 32 chars so the gate stays cheap and
/// rarely trips on natural code: function/class names cap around 24
/// chars, UUIDs are 36 chars *with dashes* (longest base62 run = 12),
/// and the longest English word is 28 chars. Real secrets at this
/// threshold are credentials (32-char hex APIs, 40-char base62 tokens,
/// symbolic passwords, 64-char SHA hex, base64 blobs). Hash/UUID-shaped FPs
/// are still suppressed downstream by the bare/prefixed hash gates and
/// `is_uuid_v4_shape`, so trip-firing the gate does NOT add FPs - it just
/// admits the chunk to the entropy fallback for inspection.
//
// Used by the no-trigger admission gate and the entropy fallback's cheap
// precheck.
#[cfg(any(feature = "entropy", test))]
pub(super) fn has_high_entropy_run_fast(data: &[u8]) -> bool {
    has_high_entropy_run_at_least(data, DEFAULT_ENTROPY_RUN_BYTES)
}

#[cfg(any(feature = "entropy", test))]
pub(super) const DEFAULT_ENTROPY_RUN_BYTES: usize = 32;

#[cfg(any(feature = "entropy", test))]
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

#[cfg(any(feature = "entropy", test))]
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
/// are relative to `text`, which each caller supplies as its own search base
/// the full preprocessed text for the whole-chunk walk, or the anchored `slice`
/// for the phase-2 path (so the returned range re-slices correctly on either).
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
    validate: impl Fn(&str, bool) -> crate::checksum::ChecksumConfidenceDecision,
) -> (&'a str, usize, crate::checksum::ChecksumConfidenceDecision) {
    let original = credential;
    let original_end = match_end;
    let original_validation = validate(original, true);
    let (credential, match_end) = if original_validation.claims_family()
        || crate::confidence::known_prefix_confidence_floor(credential).is_some()
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
    // grabbing a trailing byte that merely abuts it, a base64 `=` that is
    // really a separator (`pypi-…MNH` followed by `="…"`), or a provider-token
    // byte from adjacent content, corrupts the token so it fails the checksum
    // and is dropped, losing a real secret. Only the extension is reverted (the
    // canonical token still surfaces); the unicode swap-invariance gate
    // exercises exactly this (homoglyphed companion context whose trailing `=`
    // was being appended to a valid pypi token). Cheap: the length guard keeps
    // the checksum-validity comparison off the hot path until an extension
    // actually changed the credential. The comparison itself lives in the
    // Both decisions come from the active detector's already-compiled validator
    // set. Return the surviving decision with the slice so suppression and final
    // confidence never repeat validation.
    if credential.len() != original.len() {
        let extended_validation = validate(credential, false);
        if original_validation.is_proven_valid() && !extended_validation.is_proven_valid() {
            return (original, original_end, original_validation);
        }
        return (credential, match_end, extended_validation);
    }

    (credential, match_end, original_validation)
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
    // ONE owner for the `_ - .` token-separator set:
    // `crate::engine::phase2_generic::keywords::is_assignment_compact_separator`.
    byte.is_ascii_alphanumeric()
        || crate::engine::phase2_generic::keywords::is_assignment_compact_separator(byte)
}

/// Compute the two per-pattern-constant confidence signals (`keyword_nearby`,
/// `sensitive_file`). Extracted so `extract_grouped_matches`,
/// `extract_plain_matches`, and the shared-anchor path share one lazy
/// `OnceCell` init closure body (Rust can't `impl FnOnce<>` to share inline).
/// Lives here (not `scan.rs`) to keep that file under the standard 500-LOC cap.
pub(super) fn compute_pattern_signals(
    entry: &crate::types::CompiledPattern,
    execution_policy: &crate::detector_execution_policy::CompiledDetectorExecutionPolicy,
    chunk: &keyhog_core::Chunk,
    preprocessed: &crate::types::ScannerPreprocessedText<'_>,
) -> (bool, bool) {
    let kw = entry.match_proves_keyword_nearby
        || execution_policy.keyword_nearby(chunk.data.as_bytes(), preprocessed.text.as_bytes());
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
// exact triggering contract, every curated vendor prefix, the deliberately-
// EXCLUDED short prefixes, the case-sensitivity CONTRAST between the two gates,
// and the fail-open (never-drop) boundaries, white-box because both functions
// are `pub(super)`.
#[cfg(test)]
#[path = "../../tests/unit/engine_scan_filters.rs"]
mod tests;
