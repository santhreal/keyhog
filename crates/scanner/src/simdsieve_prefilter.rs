//! SIMD-accelerated prefilter for the top N most common secret patterns.
//!
//! `simdsieve` checks keyhog's hot prefixes in a single AVX-512/AVX2/NEON
//! pass. (The crate's 50+ GB/s headline is its single-byte-prefix peak;
//! multi-byte prefixes like these run lower, throughput scales down with
//! prefix length, but still far faster than running AC/regex on every byte.)
//! This module integrates it as Layer 1 of the scanning pipeline:
//! hot patterns are checked first, and if found, we can often skip AC/Regex.

#[inline]
pub(crate) fn hot_pattern_index_at(
    slots: &[HotPatternSlot],
    text_bytes: &[u8],
    offset: usize,
) -> Option<usize> {
    let rest = text_bytes.get(offset..)?;
    slots
        .iter()
        .enumerate()
        .find_map(|(idx, slot)| rest.starts_with(&slot.prefix).then_some(idx))
}

/// Everything the SIMD hot fast-path needs to turn a literal-prefix sieve hit
/// at slot `i` into a precise finding, kept in ONE row so a slot's validator and
/// its `ac_map` delegate are physically inseparable, they can never be indexed
/// apart and so can never drift. Slot order follows loaded detector specs and
/// their `simdsieve_prefixes`; built once by
/// `compiled_scanner::compile_helpers::build_hot_pattern_slots`.
///
/// Before unification these were two separate `Vec`s on `CompiledScanner`
/// (`hot_pattern_validators` and `hot_ac_map_index_by_index`) read by the SAME
/// `pattern_idx` at scan time. Nothing structurally bound slot `i`'s validator
/// to slot `i`'s `ac_map` entry, only construction discipline and a runtime
/// length-equality guard. A future edit that filtered one vec but not the other
/// would have silently applied slot `i`'s validator to slot `j`'s detector: a
/// wrong-detector emission, invisible. One row per slot makes that
/// unrepresentable.
#[derive(Debug)]
pub(crate) struct HotPatternSlot {
    pub(crate) prefix: Box<[u8]>,
    /// Precise-regex validator (anchored at the candidate start) every
    /// literal-prefix candidate for this slot must satisfy before emission
    /// restores AC+regex parity so the fast path can't surface a token the
    /// detector's own regex rejects (the length floor alone let
    /// `ghp_…_…`/`xoxp-123-456-789-abc` through).
    pub(crate) validator: regex::Regex,
    /// Canonical confirmed-pattern `ac_map` entry this slot accelerates.
    /// The SIMD hit is only an accelerator for `ac_map[i]` and delegates
    /// surviving candidates through `process_match`.
    pub(crate) ac_map_index: usize,
}

/// Build the precise-regex validator for a detector-owned hot-pattern slot.
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
/// Slots exist only for prefixes declared by loaded detectors. A detector that
/// is not loaded therefore cannot create a hot-path finding.
///
/// This module (`mod simdsieve_prefilter`) and the sole caller in
/// `compiled_scanner::compile` are both gated on `feature = "simdsieve"`, so whenever
/// this function is compiled its caller is too: no `#[allow(dead_code)]` is
/// needed.
pub(crate) fn build_hot_pattern_validator(
    detector: &keyhog_core::DetectorSpec,
) -> crate::error::Result<regex::Regex> {
    let alts: Vec<String> = detector
        .patterns
        .iter()
        .map(|p| format!("(?:{})", p.regex))
        .collect();
    if alts.is_empty() {
        return Err(crate::error::ScanError::Config(format!(
            "detector {} declares simdsieve prefixes but has no regex patterns",
            detector.id
        )));
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
    // length-floor gate (an invisible precision loss on the hot path).
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
            detector_id: detector.id.clone(),
            index: 0,
            source,
        })?;
    Ok(re)
}

/// Build validators for ALL detectors that declare simdsieve prefixes,
/// returning one `Option<Regex>` per detector (in the same order as the
/// input slice). Detectors without simdsieve prefixes get `None`.
#[cfg(feature = "simdsieve")]
pub(crate) fn build_hot_pattern_validators(
    detectors: &[keyhog_core::DetectorSpec],
) -> crate::error::Result<Vec<Option<regex::Regex>>> {
    detectors
        .iter()
        .map(|detector| {
            if detector.simdsieve_prefixes.is_empty() {
                Ok(None)
            } else {
                build_hot_pattern_validator(detector).map(Some)
            }
        })
        .collect()
}

/// Static hot-pattern data: (prefix bytes, detector id) pairs, one per
/// simdsieve prefix across all embedded detectors. Computed once from
/// `keyhog_core::embedded_detector_specs()` and leaked to satisfy the
/// `&'static` contract used by test helpers.
#[cfg(feature = "simdsieve")]
static HOT_PATTERN_DATA: std::sync::OnceLock<(&'static [&'static [u8]], &'static [&'static str])> =
    std::sync::OnceLock::new();

#[cfg(feature = "simdsieve")]
fn compute_hot_pattern_data() -> (&'static [&'static [u8]], &'static [&'static str]) {
    let detectors = keyhog_core::embedded_detector_specs();
    let mut prefixes: Vec<&'static [u8]> = Vec::new();
    let mut detector_ids: Vec<&'static str> = Vec::new();
    for detector in detectors {
        for prefix in &detector.simdsieve_prefixes {
            // Leak the prefix string to get a 'static slice. This runs once
            // per process and the total volume is tiny (< 16 prefixes).
            let static_prefix: &'static [u8] =
                Box::leak(prefix.clone().into_bytes().into_boxed_slice());
            prefixes.push(static_prefix);
            detector_ids.push(detector.id.as_str());
        }
    }
    // Leak the Vecs into 'static slices. One-time cost, tiny volume.
    let static_prefixes: &'static [&'static [u8]] = Box::leak(prefixes.into_boxed_slice());
    let static_ids: &'static [&'static str] = Box::leak(detector_ids.into_boxed_slice());
    (static_prefixes, static_ids)
}

/// The canonical hot-pattern prefix bytes, one entry per simdsieve prefix
/// across all embedded detectors. Order follows `embedded_detector_specs()`.
#[cfg(feature = "simdsieve")]
pub(crate) static HOT_PATTERNS: std::sync::LazyLock<&'static [&'static [u8]]> =
    std::sync::LazyLock::new(|| HOT_PATTERN_DATA.get_or_init(compute_hot_pattern_data).0);

/// The canonical hot-pattern detector IDs, one per simdsieve prefix (parallel
/// to [`HOT_PATTERNS`]). Each prefix is paired with the detector that owns it.
#[cfg(feature = "simdsieve")]
pub(crate) static HOT_PATTERN_DETECTOR_IDS: std::sync::LazyLock<&'static [&'static str]> =
    std::sync::LazyLock::new(|| HOT_PATTERN_DATA.get_or_init(compute_hot_pattern_data).1);
