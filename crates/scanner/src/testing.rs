// Doc-hidden scanner test facade. Kept out of lib.rs so the crate root
// remains a module map and public API surface, not a test-probe dumping ground.

#[cfg(test)]
use keyhog_core::Chunk;

#[cfg(test)]
pub(crate) use crate::engine::scan_chunk_boundaries;
#[cfg(test)]
pub(crate) const REGEX_SIZE_LIMIT_BYTES: usize = crate::types::REGEX_SIZE_LIMIT_BYTES;

pub fn pattern_regex_strs(scanner: &crate::CompiledScanner) -> Vec<&str> {
    scanner.pattern_regex_strs()
}

#[cfg(feature = "simd")]
pub fn scan_coalesced_phase2_with_admission_for_test(
    scanner: &crate::CompiledScanner,
    chunks: &[keyhog_core::Chunk],
    triggers: Vec<Option<Vec<u64>>>,
    phase2_admission: Option<&[bool]>,
) -> Vec<Vec<keyhog_core::RawMatch>> {
    scanner.scan_coalesced_phase2_with_admission(
        chunks,
        triggers,
        phase2_admission,
        None,
        None,
        None,
        None,
    )
}

#[cfg(feature = "simd")]
pub fn scan_windowed_with_triggered_for_test(
    scanner: &crate::CompiledScanner,
    chunk: &keyhog_core::Chunk,
    triggered_patterns: &[u64],
) -> Vec<keyhog_core::RawMatch> {
    scanner.scan_windowed_with_triggered(chunk, triggered_patterns, None, None, None, None, None)
}

#[cfg(test)]
pub(crate) fn scan_with_deadline(
    scanner: &crate::CompiledScanner,
    chunk: &Chunk,
    deadline: Option<std::time::Instant>,
) -> Vec<keyhog_core::RawMatch> {
    scanner.scan_with_deadline(chunk, deadline)
}

#[cfg(test)]
pub(crate) mod jwt {
    pub(crate) use crate::jwt::{JwtAnalysis, JwtAnomaly};

    pub(crate) fn analyze(s: &str) -> Option<JwtAnalysis> {
        crate::jwt::analyze(s)
    }

    pub(crate) fn anomalies_to_metadata(
        analysis: &JwtAnalysis,
    ) -> Option<std::collections::BTreeMap<String, String>> {
        crate::jwt::anomalies_to_metadata(analysis)
    }

    pub(crate) fn looks_like_jwt(s: &str) -> bool {
        crate::jwt::looks_like_jwt(s)
    }
}

pub mod confidence {
    #[derive(Debug, Clone, Copy)]
    pub struct ConfidenceSignals {
        pub has_literal_prefix: bool,
        pub has_context_anchor: bool,
        pub entropy: f64,
        pub keyword_nearby: bool,
        pub sensitive_file: bool,
        pub match_length: usize,
        pub has_companion: bool,
    }

    impl From<&ConfidenceSignals> for crate::confidence::ConfidenceSignals {
        fn from(signals: &ConfidenceSignals) -> Self {
            Self {
                has_literal_prefix: signals.has_literal_prefix,
                has_context_anchor: signals.has_context_anchor,
                entropy: signals.entropy,
                keyword_nearby: signals.keyword_nearby,
                sensitive_file: signals.sensitive_file,
                match_length: signals.match_length,
                has_companion: signals.has_companion,
            }
        }
    }

    pub fn compute_confidence(signals: &ConfidenceSignals) -> f64 {
        crate::confidence::compute_confidence(&signals.into())
    }

    #[cfg(test)]
    pub(crate) fn finalize_confidence(score: f64) -> f64 {
        crate::confidence::penalties::finalize_confidence(score)
    }

    #[cfg(test)]
    pub(crate) fn contains_placeholder_word(credential: &str) -> bool {
        crate::confidence::penalties::contains_placeholder_word(credential)
    }

    #[cfg(test)]
    pub(crate) fn placeholder_words() -> Vec<String> {
        crate::placeholder_words::words()
            .iter()
            .map(|word| word.lower().to_string())
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn parse_placeholder_words_for_test(raw: &str) -> Result<Vec<String>, String> {
        crate::placeholder_words::parse_placeholder_words(raw).map(|words| {
            words
                .into_iter()
                .map(|word| word.lower().to_string())
                .collect()
        })
    }

    #[cfg(test)]
    pub(crate) fn char_diversity(credential: &str) -> f64 {
        crate::confidence::penalties::char_diversity(credential)
    }

    #[cfg(test)]
    pub(crate) fn max_repeat_run(credential: &str) -> f64 {
        crate::confidence::penalties::max_repeat_run(credential)
    }

    #[cfg(test)]
    pub(crate) fn apply_post_ml_penalties(score: f64, credential: &str, is_named: bool) -> f64 {
        crate::confidence::penalties::apply_post_ml_penalties(score, credential, is_named)
    }

    #[cfg(test)]
    pub(crate) fn apply_calibration_multiplier(score: f64, detector_id: &str) -> f64 {
        crate::confidence::penalties::apply_calibration_multiplier(score, detector_id, None)
    }

    #[cfg(test)]
    pub(crate) fn apply_calibration_multiplier_with_store(
        score: f64,
        detector_id: &str,
        calibration: &keyhog_core::Calibration,
    ) -> f64 {
        crate::confidence::penalties::apply_calibration_multiplier(
            score,
            detector_id,
            Some(calibration),
        )
    }

    #[cfg(test)]
    pub(crate) fn apply_path_confidence_penalties(
        score: f64,
        path: Option<&str>,
        penalize: bool,
    ) -> f64 {
        crate::confidence::penalties::apply_path_confidence_penalties(score, path, penalize)
    }
}

pub mod entropy_fast {
    pub fn shannon_entropy_simd(data: &[u8]) -> f64 {
        crate::entropy::fast::shannon_entropy_simd(data)
    }

    #[cfg(test)]
    pub(crate) fn shannon_entropy_scalar(data: &[u8]) -> f64 {
        crate::entropy::fast::shannon_entropy_scalar(data)
    }

    #[cfg(test)]
    pub(crate) fn has_high_entropy_fast(data: &[u8], threshold: f64) -> bool {
        crate::entropy::fast::has_high_entropy_fast(data, threshold)
    }
}

#[cfg(test)]
pub(crate) mod context {
    pub fn documentation_line_flags(lines: &[&str]) -> Vec<bool> {
        crate::context::documentation_line_flags(lines)
    }

    pub(crate) fn is_false_positive_match_context(
        text: &str,
        match_start: usize,
        file_path: Option<&str>,
    ) -> bool {
        crate::context::is_false_positive_match_context(text, match_start, file_path)
    }

    pub(crate) fn is_false_positive_context(
        lines: &[&str],
        line_idx: usize,
        file_path: Option<&str>,
    ) -> bool {
        crate::context::is_false_positive_context(lines, line_idx, file_path)
    }

    pub(crate) fn parse_disclaimer_phrases_for_test(raw: &str) -> Result<Vec<String>, String> {
        crate::context::parse_disclaimer_phrases(raw)
    }

    pub(crate) fn is_known_example_credential(credential: &str) -> bool {
        crate::context::is_known_example_credential(credential)
    }

    pub(crate) fn is_sequential_placeholder(credential: &str) -> bool {
        crate::context::is_sequential_placeholder(credential)
    }
}

#[cfg(test)]
pub(crate) mod fragment_cache {
    use std::sync::Arc;

    use zeroize::Zeroizing;

    #[derive(Clone)]
    pub(crate) struct SecretFragment {
        pub(crate) prefix: String,
        pub(crate) var_name: String,
        pub(crate) value: Zeroizing<String>,
        pub(crate) line: usize,
        pub(crate) path: Option<Arc<str>>,
    }

    impl std::fmt::Debug for SecretFragment {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("SecretFragment")
                .field("prefix", &self.prefix)
                .field("var_name", &self.var_name)
                .field(
                    "value",
                    &format_args!("<redacted {} bytes>", self.value.len()),
                )
                .field("line", &self.line)
                .field("path", &self.path)
                .finish()
        }
    }

    pub(crate) struct ReassembledCandidate {
        pub(crate) value: Zeroizing<String>,
        pub(crate) path: Option<Arc<str>>,
        pub(crate) line: usize,
    }

    impl std::fmt::Debug for ReassembledCandidate {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ReassembledCandidate")
                .field(
                    "value",
                    &format_args!("<redacted {} bytes>", self.value.len()),
                )
                .field("path", &self.path)
                .field("line", &self.line)
                .finish()
        }
    }

    pub(crate) struct FragmentCache(crate::fragment_cache::FragmentCache);

    impl FragmentCache {
        pub(crate) fn new(capacity: usize) -> Self {
            Self(crate::fragment_cache::FragmentCache::new(capacity))
        }

        #[cfg(test)]
        pub(super) fn inner(&self) -> &crate::fragment_cache::FragmentCache {
            &self.0
        }

        pub(crate) fn record_and_reassemble(
            &self,
            fragment: SecretFragment,
        ) -> Vec<Zeroizing<String>> {
            self.0.record_and_reassemble(inner_fragment(fragment))
        }

        pub(crate) fn record_and_reassemble_stamped(
            &self,
            fragment: SecretFragment,
        ) -> Vec<ReassembledCandidate> {
            self.0
                .record_and_reassemble_stamped(inner_fragment(fragment))
                .into_iter()
                .map(|candidate| ReassembledCandidate {
                    value: candidate.value,
                    path: candidate.path,
                    line: candidate.line,
                })
                .collect()
        }

        pub(crate) fn clear(&self) {
            self.0.clear();
        }
    }

    fn inner_fragment(fragment: SecretFragment) -> crate::fragment_cache::SecretFragment {
        crate::fragment_cache::SecretFragment {
            prefix: fragment.prefix,
            var_name: fragment.var_name,
            value: fragment.value,
            line: fragment.line,
            path: fragment.path,
        }
    }

    pub(crate) fn shard_index_drift_probe(prefix: &str, scope: &str) -> (usize, usize) {
        crate::fragment_cache::shard_index_drift_probe(prefix, scope)
    }
}

#[cfg(test)]
pub(crate) mod multiline {
    pub(crate) use crate::multiline::{LineMapping, MultilineConfig, PreprocessedText};

    pub(crate) fn preprocess_multiline<'a>(
        text: impl Into<std::borrow::Cow<'a, str>>,
        config: &MultilineConfig,
        fragment_cache: &super::fragment_cache::FragmentCache,
    ) -> PreprocessedText<'a> {
        crate::multiline::preprocess_multiline(text, config, fragment_cache.inner())
    }
}

#[cfg(all(test, feature = "gpu"))]
pub(crate) use crate::compiler::{build_gpu_literals, build_gpu_position_literals};
#[cfg(all(test, feature = "gpu"))]
pub(crate) fn gpu_matcher_cache_dir_from_base(
    base: Option<std::path::PathBuf>,
) -> Result<std::path::PathBuf, String> {
    crate::engine::gpu_matcher_cache_dir_from_base(base).map_err(|error| error.to_string())
}
#[cfg(test)]
pub(crate) use crate::compiler::{
    build_ac_pattern_set, build_prefix_propagation, build_same_prefix_patterns,
    extract_inner_literals, extract_literal_prefix, extract_literal_prefixes, is_escaped_literal,
    rewrite_alternation_prefix, split_leading_inline_flag,
};
pub use crate::engine::{
    floor_char_boundary, line_number_for_offset, next_window_offset, record_window_match,
    window_chunk, window_end_offset, window_ranges,
};
pub fn code_lines_from_offsets_for_test<'a>(text: &'a str, line_offsets: &[usize]) -> Vec<&'a str> {
    crate::engine::code_lines_from_offsets(text, line_offsets)
}
#[cfg(test)]
pub(crate) use crate::normalize_chunk_data;
pub use crate::pipeline::compute_line_offsets;
#[cfg(test)]
pub(crate) use crate::pipeline::{
    detector_weak_anchor, is_within_hex_context, local_context_window, match_entropy,
    normalize_scannable_chunk, should_suppress_known_example_credential,
    should_suppress_known_example_credential_with_source, should_suppress_named_detector_finding,
};
#[cfg(test)]
pub(crate) use crate::pipeline::{find_companion, line_window_offsets, match_line_number};
#[cfg(test)]
pub(crate) use crate::prefix_trie::build_propagation_table;

#[cfg(test)]
pub(crate) fn scan_state_drain(
    matches: Vec<keyhog_core::RawMatch>,
    limit: usize,
) -> Vec<keyhog_core::RawMatch> {
    let mut state = crate::scanner_config::ScanState::default();
    for m in matches {
        state.push_match(m, limit);
    }
    state.into_matches()
}

#[cfg(test)]
pub(crate) fn scan_state_drain_with_static_intern(
    matches: Vec<keyhog_core::RawMatch>,
    limit: usize,
) -> Vec<keyhog_core::RawMatch> {
    let interner = std::sync::Arc::new(crate::static_intern::StaticInterner::default());
    let mut state = crate::scanner_config::ScanState::with_static_intern(interner);
    for m in matches {
        state.push_match(m, limit);
    }
    state.into_matches()
}

#[derive(Clone)]
#[cfg(test)]
pub(crate) struct LazyRegexProbe(crate::types::LazyRegex);

#[cfg(test)]
impl LazyRegexProbe {
    pub(crate) fn detector(src: impl Into<std::sync::Arc<str>>) -> Self {
        Self(crate::types::LazyRegex::detector(src))
    }

    pub(crate) fn plain(src: impl Into<std::sync::Arc<str>>) -> Self {
        Self(crate::types::LazyRegex::plain(src))
    }

    pub(crate) fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub(crate) fn get(&self) -> &regex::Regex {
        self.0.get()
    }

    pub(crate) fn has_literal_prefix(&self) -> bool {
        self.0.has_literal_prefix()
    }
}

#[cfg(test)]
pub(crate) fn phase2_keyword_ac_summary(regex: &str, keywords: Vec<String>) -> (bool, usize) {
    let pattern = crate::types::CompiledPattern {
        detector_index: 0,
        regex: crate::types::LazyRegex::detector(regex),
        group: None,
        client_safe: false,
        match_proves_keyword_nearby: false,
        homoglyph_variant: false,
    };
    let phase2_patterns = vec![(pattern, keywords)];
    let (ac, mapping, _keywords) = crate::compiler::build_phase2_keyword_ac(&phase2_patterns);
    (ac.is_some(), mapping.len())
}

#[cfg(test)]
pub(crate) fn compile_state_ac_literals(
    detectors: &[keyhog_core::DetectorSpec],
) -> crate::error::Result<Vec<String>> {
    crate::compiler::build_compile_state(detectors).map(|state| state.ac_literals)
}

#[cfg(test)]
pub(crate) fn compile_state_is_ok(detectors: &[keyhog_core::DetectorSpec]) -> bool {
    crate::compiler::build_compile_state(detectors).is_ok()
}

#[cfg(test)]
pub(crate) fn compile_state_error(
    detectors: &[keyhog_core::DetectorSpec],
) -> Option<crate::ScanError> {
    crate::compiler::build_compile_state(detectors).err()
}

#[cfg(test)]
pub(crate) fn phase2_anchor_stats(
    scanner: &crate::engine::CompiledScanner,
) -> (usize, usize, usize) {
    scanner.phase2_anchor_stats()
}

#[cfg(test)]
pub(crate) fn phase2_pattern_diagnostics(
    scanner: &crate::engine::CompiledScanner,
) -> Vec<(String, Vec<String>)> {
    scanner.phase2_pattern_diagnostics()
}

#[cfg(test)]
pub(crate) fn phase2_required_prefix_literals(src: &str) -> Option<Vec<String>> {
    crate::engine::phase2_required_prefix_literals_for_test(src)
}

#[cfg(test)]
pub(crate) fn phase2_gate_prefix_literals(src: &str) -> Option<Vec<Vec<u8>>> {
    crate::engine::phase2::gate_prefix_literals(src)
}

#[cfg(test)]
pub(crate) fn set_test_backend_override(mode: Option<crate::hw_probe::ScanBackend>) {
    crate::hw_probe::select::set_test_backend_override(mode);
}

#[cfg(test)]
pub(crate) fn clear_test_backend_override() {
    crate::hw_probe::select::clear_test_backend_override();
}

#[cfg(test)]
pub(crate) mod thresholds {
    pub(crate) const GPU_MIN_BYTES: u64 = crate::hw_probe::thresholds::GPU_MIN_BYTES;
    pub(crate) const GPU_MIN_BYTES_MID_TIER: u64 =
        crate::hw_probe::thresholds::GPU_MIN_BYTES_MID_TIER;
    pub(crate) const GPU_MIN_BYTES_HIGH_TIER: u64 =
        crate::hw_probe::thresholds::GPU_MIN_BYTES_HIGH_TIER;
    pub(crate) const GPU_PATTERN_BREAKEVEN: usize =
        crate::hw_probe::thresholds::GPU_PATTERN_BREAKEVEN;
    pub(crate) const GPU_PATTERN_BREAKEVEN_HIGH_TIER: usize =
        crate::hw_probe::thresholds::GPU_PATTERN_BREAKEVEN_HIGH_TIER;
    pub(crate) const GPU_BYTES_BREAKEVEN_SOLO: u64 =
        crate::hw_probe::thresholds::GPU_BYTES_BREAKEVEN_SOLO;
    pub(crate) const GPU_BYTES_BREAKEVEN_SOLO_HIGH_TIER: u64 =
        crate::hw_probe::thresholds::GPU_BYTES_BREAKEVEN_SOLO_HIGH_TIER;
}

#[cfg(test)]
pub(crate) fn set_phase2_hs(scanner: &crate::engine::CompiledScanner, mode: Option<bool>) {
    scanner.tuning().set_phase2_hs(mode);
}

#[cfg(test)]
pub(crate) fn set_hs_prefilter_max_len(
    scanner: &crate::engine::CompiledScanner,
    threshold: Option<usize>,
) {
    scanner.tuning().set_hs_prefilter_max_len(threshold);
}

#[cfg(test)]
pub(crate) fn set_phase2_anchor_mode(scanner: &crate::engine::CompiledScanner, mode: Option<bool>) {
    scanner.tuning().set_phase2_anchor_mode(mode);
}

#[cfg(test)]
pub(crate) fn set_phase2_homoglyph_gate(
    scanner: &crate::engine::CompiledScanner,
    mode: Option<bool>,
) {
    scanner.tuning().set_phase2_homoglyph_gate(mode);
}

#[cfg(test)]
pub(crate) fn set_homoglyph_ascii_skip(
    scanner: &crate::engine::CompiledScanner,
    mode: Option<bool>,
) {
    scanner.tuning().set_homoglyph_ascii_skip(mode);
}

#[cfg(test)]
pub(crate) fn set_phase2_reverse(scanner: &crate::engine::CompiledScanner, mode: Option<bool>) {
    scanner.tuning().set_phase2_reverse(mode);
}

#[cfg(test)]
pub(crate) fn set_prefilter_truncate(scanner: &crate::engine::CompiledScanner, mode: Option<bool>) {
    scanner.tuning().set_prefilter_truncate(mode);
}

#[cfg(test)]
pub(crate) fn set_phase2_prefix_gate(scanner: &crate::engine::CompiledScanner, mode: Option<bool>) {
    scanner.tuning().set_phase2_prefix_gate(mode);
}

#[cfg(test)]
pub(crate) fn set_decode_focus(scanner: &crate::engine::CompiledScanner, mode: Option<bool>) {
    scanner.tuning().set_decode_focus(mode);
}

#[cfg(test)]
pub(crate) fn set_confirmed_suffix_gate(
    scanner: &crate::engine::CompiledScanner,
    mode: Option<bool>,
) {
    scanner.tuning().set_confirmed_suffix_gate(mode);
}

#[cfg(test)]
pub(crate) fn disable_confirmed_anchor(scanner: &mut crate::engine::CompiledScanner) {
    scanner.disable_confirmed_anchor_for_test();
}

#[cfg(test)]
pub(crate) fn confirmed_anchor_eligible_count(scanner: &crate::engine::CompiledScanner) -> usize {
    scanner.confirmed_anchor_eligible_count_for_test()
}

#[cfg(test)]
pub(crate) fn confirmed_anchor_kind(
    scanner: &crate::engine::CompiledScanner,
) -> Option<aho_corasick::AhoCorasickKind> {
    scanner.confirmed_anchor_kind_for_test()
}

#[cfg(test)]
pub(crate) fn set_no_candidate_gate(scanner: &crate::engine::CompiledScanner, mode: Option<bool>) {
    scanner.tuning().set_no_candidate_gate(mode);
}

/// SWE-101 perf probe: directly time `mark_matches` on a no-candidate text,
/// bypassing the phase-1 HS scan so only the gate path is measured.
/// Returns mean ns/call over `n_calls` warm iterations.
#[cfg(test)]
pub(crate) fn mark_matches_gate_ns_per_call(
    scanner: &crate::engine::CompiledScanner,
    text: &str,
    n_calls: u32,
) -> f64 {
    scanner.mark_matches_gate_ns_per_call(text, n_calls)
}

/// Prefilter `{N,}`→`{N}` truncation, exposed for the sound-superset unit
/// tests migrated out of `src/engine/phase2.rs` (no-inline-tests gate).
#[cfg(test)]
pub(crate) fn truncate_for_prefilter(src: &str) -> Option<String> {
    crate::engine::phase2_truncate::truncate_for_prefilter(src)
}
#[cfg(test)]
pub(crate) fn looks_like_program_identifier(value: &str) -> bool {
    crate::entropy::keywords::looks_like_program_identifier(value)
}

/// Internal entropy shape-classification predicates, exposed for the
/// canonical-shape unit tests migrated out of `src/entropy/scanner.rs`
/// (KH-GAP-004). `credential_keyword_context` builds the production
/// credential anchor so tests need not know the private tuning constants.
#[cfg(test)]
pub(crate) mod entropy_scanner {
    pub(crate) struct KeywordContext {
        inner: crate::entropy::keywords::KeywordContext,
        pub(crate) threshold: f64,
    }

    impl KeywordContext {
        fn from_inner(inner: crate::entropy::keywords::KeywordContext) -> Self {
            Self {
                threshold: inner.threshold,
                inner,
            }
        }
    }

    pub(crate) fn credential_keyword_context(keyword: &str) -> KeywordContext {
        KeywordContext::from_inner(crate::entropy::scanner::credential_keyword_context(keyword))
    }

    pub(crate) fn credential_keyword_context_with_lift(
        keyword: &str,
        allow_canonical_lift: bool,
    ) -> KeywordContext {
        KeywordContext::from_inner(
            crate::entropy::scanner::credential_keyword_context_with_lift(
                keyword,
                allow_canonical_lift,
            ),
        )
    }

    pub(crate) fn candidate_is_plausible(
        candidate: &str,
        entropy: f64,
        context: &KeywordContext,
        placeholder_keywords: &[String],
    ) -> bool {
        crate::entropy::scanner::candidate_is_plausible(
            candidate,
            entropy,
            &context.inner,
            placeholder_keywords,
        )
    }

    pub(crate) fn is_canonical_non_secret_shape(value: &str) -> bool {
        crate::entropy::scanner::is_canonical_non_secret_shape(value)
    }
}

/// Internal prose/decoy/strict-secret predicates, exposed for the unit
/// tests migrated out of `src/entropy/keywords.rs` (KH-GAP-004).
#[cfg(test)]
pub(crate) mod entropy_keywords {
    pub(crate) fn looks_like_english_prose(value: &str) -> bool {
        crate::entropy::keywords::looks_like_english_prose(value)
    }

    pub(crate) fn entropy_value_looks_like_prose(value: &str) -> bool {
        crate::entropy::keywords::entropy_value_looks_like_prose(value)
    }

    pub(crate) fn passes_strict_secret_checks(value: &str, is_credential_context: bool) -> bool {
        crate::entropy::keywords::passes_strict_secret_checks(value, is_credential_context)
    }

    pub(crate) fn is_dash_segmented_alnum_decoy(value: &str) -> bool {
        crate::entropy::keywords::is_dash_segmented_alnum_decoy(value)
    }

    pub(crate) fn is_candidate_plausible(value: &str, placeholder_keywords: &[String]) -> bool {
        crate::entropy::keywords::is_candidate_plausible(value, placeholder_keywords)
    }

    pub fn is_secret_plausible(value: &str, placeholder_keywords: &[String]) -> bool {
        crate::entropy::keywords::is_secret_plausible(value, placeholder_keywords)
    }

    pub(crate) fn is_candidate_plausible_with_context(
        value: &str,
        placeholder_keywords: &[String],
        is_credential_context: bool,
    ) -> bool {
        crate::entropy::keywords::is_candidate_plausible_with_context(
            value,
            placeholder_keywords,
            is_credential_context,
        )
    }

    pub(crate) fn is_secret_plausible_with_context(
        value: &str,
        placeholder_keywords: &[String],
        is_credential_context: bool,
    ) -> bool {
        crate::entropy::keywords::is_secret_plausible_with_context(
            value,
            placeholder_keywords,
            is_credential_context,
        )
    }
}

#[cfg(test)]
pub(crate) mod checksum {
    pub(crate) use crate::checksum::{
        checksum_adjusted_confidence, validate_checksum, ChecksumResult, CHECKSUM_VALID_FLOOR,
    };

    pub(crate) fn standard_crc32(data: &[u8]) -> u32 {
        crate::checksum::standard_crc32(data)
    }

    pub(crate) fn base62_encode_u32(value: u32, width: usize) -> String {
        crate::checksum::base62_encode_u32(value, width)
    }

    pub(crate) fn crc32_base62_suffix(data: &[u8], width: usize) -> String {
        crate::checksum::crc32_base62_suffix(data, width)
    }

    pub(crate) fn github_classic_pat_with_checksum(body30: &str) -> String {
        assert_eq!(body30.len(), 30, "github classic body must be 30 chars");
        format!(
            "ghp_{}{}",
            body30,
            crc32_base62_suffix(body30.as_bytes(), 6)
        )
    }

    pub(crate) fn npm_token_with_checksum(body30: &str) -> String {
        assert_eq!(body30.len(), 30, "npm body must be 30 chars");
        format!(
            "npm_{}{}",
            body30,
            crc32_base62_suffix(body30.as_bytes(), 6)
        )
    }

    pub(crate) fn github_fine_grained_pat_with_checksum(
        left22: &str,
        right_body53: &str,
    ) -> String {
        assert_eq!(left22.len(), 22, "github fine-grained left segment");
        assert_eq!(
            right_body53.len(),
            53,
            "github fine-grained right body before checksum"
        );
        format!(
            "github_pat_{left22}_{}{}",
            right_body53,
            crc32_base62_suffix(right_body53.as_bytes(), 6)
        )
    }

    pub(crate) trait ChecksumValidator {
        fn validator_id(&self) -> &str;
        fn validate(&self, credential: &str) -> ChecksumResult;
    }

    macro_rules! checksum_validator_wrapper {
        ($name:ident, $inner:path, $validator_id:literal) => {
            pub(crate) struct $name;

            impl ChecksumValidator for $name {
                fn validator_id(&self) -> &str {
                    $validator_id
                }

                fn validate(&self, credential: &str) -> ChecksumResult {
                    let inner = $inner;
                    crate::checksum::ChecksumValidator::validate(&inner, credential)
                }
            }

            impl $name {
                pub(crate) fn validator_id(&self) -> &str {
                    <Self as ChecksumValidator>::validator_id(self)
                }

                pub(crate) fn validate(&self, credential: &str) -> ChecksumResult {
                    <Self as ChecksumValidator>::validate(self, credential)
                }
            }
        };
    }

    checksum_validator_wrapper!(
        GithubClassicPatValidator,
        crate::checksum::github::GithubClassicPatValidator,
        "github-classic-pat"
    );
    checksum_validator_wrapper!(
        GithubFineGrainedPatValidator,
        crate::checksum::github::GithubFineGrainedPatValidator,
        "github-fine-grained-pat"
    );
    checksum_validator_wrapper!(
        GitlabTokenValidator,
        crate::checksum::gitlab::GitlabTokenValidator,
        "gitlab-token"
    );
    checksum_validator_wrapper!(
        NpmTokenValidator,
        crate::checksum::npm::NpmTokenValidator,
        "npm-access-token"
    );
    checksum_validator_wrapper!(
        PypiTokenValidator,
        crate::checksum::npm::PypiTokenValidator,
        "pypi-api-token"
    );
    checksum_validator_wrapper!(
        SlackTokenValidator,
        crate::checksum::slack::SlackTokenValidator,
        "slack-token"
    );
    checksum_validator_wrapper!(
        StripeTokenValidator,
        crate::checksum::stripe::StripeTokenValidator,
        "stripe-api-key"
    );
}

#[cfg(test)]
pub(crate) const NUM_FEATURES: usize = crate::ml_scorer::NUM_FEATURES;

#[cfg(test)]
pub(crate) fn compute_features_public(text: &str, context: &str) -> [f32; NUM_FEATURES] {
    crate::ml_scorer::compute_features_public(text, context)
}

/// Full feature extractor (with detector-config keyword lists) exposed for
/// the ML training-pipeline parity harness (`ml/parity_check.py`), which
/// must compute byte-identical features to the serve path.
#[cfg(test)]
pub(crate) fn compute_features_with_config(
    text: &str,
    context: &str,
    known_prefixes: &[String],
    secret_keywords: &[String],
    test_keywords: &[String],
    placeholder_keywords: &[String],
) -> [f32; NUM_FEATURES] {
    crate::ml_scorer::compute_features_with_config(
        text,
        context,
        known_prefixes,
        secret_keywords,
        test_keywords,
        placeholder_keywords,
    )
}

#[cfg(test)]
pub(crate) struct ProbabilisticGate;

#[cfg(test)]
impl ProbabilisticGate {
    pub(crate) fn looks_promising(s: &str) -> bool {
        crate::probabilistic_gate::ProbabilisticGate::looks_promising(s)
    }
}
#[derive(Default)]
#[cfg(test)]
pub(crate) struct StaticInterner(crate::static_intern::StaticInterner);

#[cfg(test)]
impl StaticInterner {
    pub(crate) fn from_detector_strings<I, S>(detector_strings: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self(crate::static_intern::StaticInterner::from_detector_strings(
            detector_strings,
        ))
    }

    pub(crate) fn lookup(&self, s: &str) -> Option<std::sync::Arc<str>> {
        self.0.lookup(s)
    }

    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }
}

#[cfg(test)]
pub(crate) fn seed_source_type_count() -> usize {
    crate::static_intern::seed_source_type_count()
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AlphabetMask(crate::alphabet_filter::AlphabetMask);

impl AlphabetMask {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(crate::alphabet_filter::AlphabetMask::from_bytes(bytes))
    }

    fn from_bytes_scalar(bytes: &[u8]) -> Self {
        Self(crate::alphabet_filter::AlphabetMask::from_bytes_scalar(
            bytes,
        ))
    }

    #[cfg(target_arch = "aarch64")]
    pub unsafe fn from_bytes_neon(bytes: &[u8]) -> Self {
        Self(unsafe { crate::alphabet_filter::AlphabetMask::from_bytes_neon(bytes) })
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    pub unsafe fn from_bytes_avx2(bytes: &[u8]) -> Self {
        Self(unsafe { crate::alphabet_filter::AlphabetMask::from_bytes_avx2(bytes) })
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "sse2")]
    pub unsafe fn from_bytes_sse2(bytes: &[u8]) -> Self {
        Self(unsafe { crate::alphabet_filter::AlphabetMask::from_bytes_sse2(bytes) })
    }

    pub fn from_text(s: &str) -> Self {
        Self(crate::alphabet_filter::AlphabetMask::from_text(s))
    }

    pub fn intersects(&self, other: &Self) -> bool {
        self.0.intersects(&other.0)
    }

    pub fn union(&mut self, other: &Self) {
        self.0.union(&other.0);
    }
}

#[derive(Clone, Debug, Default)]
pub struct AlphabetScreen(crate::alphabet_filter::AlphabetScreen);

impl AlphabetScreen {
    pub fn new(targets: &[String]) -> Self {
        Self(crate::alphabet_filter::AlphabetScreen::new(targets))
    }

    pub fn screen(&self, data: &[u8]) -> bool {
        self.0.screen(data)
    }

    fn screen_scalar_fallback(&self, data: &[u8]) -> bool {
        if data.is_empty() {
            return false;
        }
        self.0
            .target_mask
            .intersects(&crate::alphabet_filter::AlphabetMask::from_bytes_scalar(
                data,
            ))
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    pub unsafe fn screen_avx2(&self, data: &[u8]) -> bool {
        unsafe { self.0.screen_avx2(data) }
    }
}

pub fn assert_alphabet_prefilter_backend_parity(targets: &[String], data: &[u8]) -> bool {
    let mask_scalar = AlphabetMask::from_bytes_scalar(data);
    let mask_auto = AlphabetMask::from_bytes(data);
    assert_eq!(
        mask_scalar, mask_auto,
        "AlphabetMask auto vs scalar parity failed"
    );

    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2") {
            let mask_avx2 = unsafe { AlphabetMask::from_bytes_avx2(data) };
            assert_eq!(mask_scalar, mask_avx2, "AVX2 AlphabetMask parity failed");
        }
        if is_x86_feature_detected!("sse2") {
            let mask_sse2 = unsafe { AlphabetMask::from_bytes_sse2(data) };
            assert_eq!(mask_scalar, mask_sse2, "SSE2 AlphabetMask parity failed");
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        let mask_neon = unsafe { AlphabetMask::from_bytes_neon(data) };
        assert_eq!(mask_scalar, mask_neon, "NEON AlphabetMask parity failed");
    }

    let screen = AlphabetScreen::new(targets);
    let screen_auto = screen.screen(data);
    let screen_scalar = screen.screen_scalar_fallback(data);
    assert_eq!(
        screen_auto, screen_scalar,
        "AlphabetScreen auto vs scalar parity failed"
    );

    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2") {
            let screen_avx2 = unsafe { screen.screen_avx2(data) };
            assert_eq!(
                screen_scalar, screen_avx2,
                "AVX2 AlphabetScreen parity failed"
            );
        }
    }

    screen_auto
}

pub fn decode_chunk(
    chunk: &keyhog_core::Chunk,
    max_depth: usize,
    validate: bool,
    deadline: Option<std::time::Instant>,
    screen: Option<&AlphabetScreen>,
) -> Vec<keyhog_core::Chunk> {
    crate::decode::decode_chunk(chunk, max_depth, validate, deadline, screen.map(|s| &s.0))
}

pub fn ml_score(text: &str, context: &str) -> f64 {
    crate::ml_scorer::score(text, context)
}

#[cfg(test)]
pub(crate) mod unicode_hardening {
    use std::borrow::Cow;

    #[derive(Debug, Clone, Copy, PartialEq)]
    pub(crate) enum EvasionKind {
        CyrillicHomoglyph,
        GreekHomoglyph,
        Fullwidth,
        ZeroWidth,
        RTLOverride,
        Decomposed,
        Suspicious,
    }

    impl EvasionKind {
        pub(crate) fn description(&self) -> &'static str {
            match self {
                Self::CyrillicHomoglyph => "Cyrillic lookalike character",
                Self::GreekHomoglyph => "Greek lookalike character",
                Self::Fullwidth => "Fullwidth ASCII variant",
                Self::ZeroWidth => "Zero-width character",
                Self::RTLOverride => "Right-to-left override",
                Self::Decomposed => "Decomposed Unicode form",
                Self::Suspicious => "Suspicious Unicode usage",
            }
        }
    }

    #[derive(Debug, Clone, PartialEq)]
    pub(crate) struct EvasionMatch {
        pub(crate) position: usize,
        pub(crate) kind: EvasionKind,
        pub(crate) char: char,
        pub(crate) replacement: Option<char>,
    }

    fn kind(kind: crate::unicode_hardening::EvasionKind) -> EvasionKind {
        match kind {
            crate::unicode_hardening::EvasionKind::CyrillicHomoglyph => {
                EvasionKind::CyrillicHomoglyph
            }
            crate::unicode_hardening::EvasionKind::GreekHomoglyph => EvasionKind::GreekHomoglyph,
            crate::unicode_hardening::EvasionKind::Fullwidth => EvasionKind::Fullwidth,
            crate::unicode_hardening::EvasionKind::ZeroWidth => EvasionKind::ZeroWidth,
            crate::unicode_hardening::EvasionKind::RTLOverride => EvasionKind::RTLOverride,
            crate::unicode_hardening::EvasionKind::Decomposed => EvasionKind::Decomposed,
            crate::unicode_hardening::EvasionKind::Suspicious => EvasionKind::Suspicious,
        }
    }

    pub(crate) fn detect_unicode_attacks(text: &str) -> Vec<EvasionMatch> {
        crate::unicode_hardening::detect_unicode_attacks(text)
            .into_iter()
            .map(|m| EvasionMatch {
                position: m.position,
                kind: kind(m.kind),
                char: m.char,
                replacement: m.replacement,
            })
            .collect()
    }

    pub(crate) fn normalize_homoglyphs(text: &str) -> Cow<'_, str> {
        crate::unicode_hardening::normalize_homoglyphs(text)
    }

    pub(crate) fn full_normalize(text: &str) -> String {
        crate::unicode_hardening::full_normalize(text)
    }

    pub(crate) fn strip_interior_evasion_controls(text: &str) -> Cow<'_, str> {
        crate::unicode_hardening::strip_interior_evasion_controls(text)
    }

    pub(crate) fn parse_evasion_anchors_for_test(raw: &str) -> Result<Vec<String>, String> {
        crate::unicode_hardening::parse_evasion_anchors(raw)
    }

    pub(crate) fn contains_evasion(text: &str) -> bool {
        crate::unicode_hardening::contains_evasion(text)
    }

    pub(crate) fn is_evasion_char(ch: char) -> bool {
        crate::unicode_hardening::is_evasion_char(ch)
    }
}

#[derive(Clone)]
pub struct BigramBloom(crate::bigram_bloom::BigramBloom);

impl BigramBloom {
    #[cfg(test)]
    pub(crate) fn empty() -> Self {
        Self(crate::bigram_bloom::BigramBloom::empty())
    }

    #[cfg(test)]
    pub(crate) fn insert_all(&mut self, bytes: &[u8]) {
        self.0.insert_all(bytes);
    }

    pub fn from_literal_prefixes(literals: &[String]) -> Self {
        Self(crate::bigram_bloom::BigramBloom::from_literal_prefixes(
            literals,
        ))
    }

    pub fn maybe_overlaps(&self, chunk: &[u8]) -> bool {
        self.0.maybe_overlaps(chunk)
    }

    #[cfg(test)]
    pub(crate) fn popcount(&self) -> u32 {
        self.0.popcount()
    }

    #[cfg(test)]
    pub(crate) fn is_saturated(&self) -> bool {
        self.0.is_saturated()
    }

    #[cfg(test)]
    pub(crate) fn scalar_overlaps_reference(&self, chunk: &[u8]) -> bool {
        self.0.scalar_overlaps_reference(chunk)
    }

    #[cfg(test)]
    pub(crate) fn saturated_for_test() -> Self {
        Self(crate::bigram_bloom::BigramBloom::saturated_for_test())
    }
}

#[cfg(test)]
pub(crate) fn looks_like_standard_base64_blob(credential: &str) -> bool {
    crate::suppression::shape_gates::looks_like_standard_base64_blob(credential)
}

#[cfg(all(test, feature = "entropy"))]
pub(crate) mod phase2_entropy_helpers {
    pub(crate) fn keyword_is_credential_anchor(keyword: &str) -> bool {
        crate::engine::phase2_entropy::helpers::keyword_is_credential_anchor(keyword)
    }

    pub(crate) fn entropy_path_looks_like_random_base64_blob(value: &str) -> bool {
        crate::engine::phase2_entropy::helpers::entropy_path_looks_like_random_base64_blob(value)
    }
}

#[cfg(test)]
pub(crate) fn hash_fast(data: &[u8]) -> u64 {
    crate::util_hash::hash_fast(data)
}

#[cfg(test)]
pub(crate) fn memoize_by_hash<T: Copy>(
    cache: &'static std::thread::LocalKey<std::cell::RefCell<std::collections::HashMap<u64, T>>>,
    key: u64,
    max_entries: usize,
    compute: impl FnOnce() -> T,
) -> T {
    crate::util_hash::memoize_by_hash(cache, key, max_entries, compute)
}

#[cfg(test)]
pub(crate) mod ascii_ci {
    pub(crate) fn extend_ascii_lowercase_from(dst: &mut Vec<u8>, src: &[u8]) {
        crate::ascii_ci::extend_ascii_lowercase_from(dst, src)
    }

    pub(crate) fn has_ascii_uppercase(src: &[u8]) -> bool {
        crate::ascii_ci::has_ascii_uppercase(src)
    }

    pub(crate) fn ci_find(haystack: &[u8], needle_lower: &[u8]) -> bool {
        crate::ascii_ci::ci_find(haystack, needle_lower)
    }

    pub(crate) fn contains_path_segment(path: &str, segment: &str) -> bool {
        crate::ascii_ci::contains_path_segment(path, segment)
    }

    pub(crate) fn contains_path_segment_two(path: &str, a: &str, b: &str) -> bool {
        crate::ascii_ci::contains_path_segment_two(path, a, b)
    }
}

#[cfg(test)]
pub(crate) mod shape {
    pub(crate) fn looks_like_credential_colliding_punctuation(credential: &str) -> bool {
        crate::suppression::shape::looks_like_credential_colliding_punctuation(credential)
    }

    pub fn looks_like_punctuation_decorated_identifier(credential: &str) -> bool {
        crate::suppression::shape::looks_like_punctuation_decorated_identifier(credential)
    }

    pub(crate) fn looks_like_syntactic_punctuation_marker(credential: &str) -> bool {
        crate::suppression::shape::looks_like_syntactic_punctuation_marker(credential)
    }

    pub(crate) fn looks_like_train_case_prose_identifier(credential: &str) -> bool {
        crate::suppression::shape::looks_like_train_case_prose_identifier(credential)
    }
}

#[cfg(test)]
pub(crate) mod compiler_prefix {
    pub(crate) fn extract_literal_prefixes(pattern: &str) -> Vec<String> {
        crate::compiler::compiler_prefix::extract_literal_prefixes(pattern)
    }

    pub(crate) fn strip_leading_boundary_guard(pattern: &str) -> Option<&str> {
        crate::compiler::compiler_prefix::strip_leading_boundary_guard(pattern)
    }

    pub(crate) fn strip_leading_inline_flags(pattern: &str) -> &str {
        crate::compiler::compiler_prefix::strip_leading_inline_flags(pattern)
    }
}

#[cfg(test)]
pub(crate) fn match_proves_keyword_nearby(regex: &str, keywords: &[String]) -> bool {
    crate::compiler::match_proves_keyword_nearby(regex, keywords)
}

/// Caesar shift-selection internals, exposed for the 100k differential
/// shift-selection parity test migrated out of `src/decode/caesar.rs`
/// (no-inline-tests gate). The `matched_caesar_shifts` optimization must emit
/// the exact same decoded-variant set as the all-25-shifts reference.
#[cfg(test)]
pub(crate) mod decode_caesar {
    pub(crate) use crate::confidence::KNOWN_PREFIXES;

    pub(crate) const MIN_CAESAR_LEN: usize = crate::decode::caesar::MIN_CAESAR_LEN;

    pub(crate) fn caesar_shift(input: &str, shift: u8) -> String {
        crate::decode::caesar::caesar_shift(input, shift)
    }

    pub(crate) fn candidate_shape_invariant(value: &str) -> bool {
        crate::decode::caesar::candidate_shape_invariant(value)
    }

    pub(crate) fn looks_credential_shaped(value: &str) -> bool {
        crate::decode::caesar::looks_credential_shaped(value)
    }

    pub(crate) fn matched_caesar_shifts(candidate: &str) -> [bool; 26] {
        crate::decode::caesar::matched_caesar_shifts(candidate)
    }

    pub(crate) fn is_source_code_path(path: Option<&str>) -> bool {
        crate::decode::caesar::is_source_code_path(path)
    }
}

#[cfg(test)]
pub(crate) mod decode_structure {
    #[derive(Debug, Clone, Default, PartialEq)]
    pub(crate) struct DecodeStructure {
        pub(crate) decodable: bool,
        pub(crate) decoded_len: usize,
        pub(crate) printable_ratio: f32,
        pub(crate) magic: Option<&'static str>,
        pub(crate) protobuf_wire: bool,
    }

    impl DecodeStructure {
        pub(crate) fn is_binary_payload(&self) -> bool {
            self.magic.is_some() || (self.protobuf_wire && self.decoded_len >= 8)
        }
    }

    fn expose(inner: crate::decode_structure::DecodeStructure) -> DecodeStructure {
        DecodeStructure {
            decodable: inner.decodable,
            decoded_len: inner.decoded_len,
            printable_ratio: inner.printable_ratio,
            magic: inner.magic,
            protobuf_wire: inner.protobuf_wire,
        }
    }

    pub(crate) fn analyze(candidate: &str) -> DecodeStructure {
        expose(crate::decode_structure::analyze(candidate))
    }

    pub(crate) fn decoded_contains_placeholder(candidate: &str) -> bool {
        crate::decode_structure::decoded_contains_placeholder(candidate)
    }

    pub fn decoded_is_base64_blob(candidate: &str) -> bool {
        crate::decode_structure::decoded_is_base64_blob(candidate)
    }

    pub(crate) fn decodes_to_printable_text(candidate: &str) -> bool {
        crate::decode_structure::decodes_to_printable_text(candidate)
    }

    pub(crate) fn is_encoded_binary(candidate: &str) -> bool {
        crate::decode_structure::is_encoded_binary(candidate)
    }

    pub(crate) fn looks_like_uniform_base64_blob(value: &str) -> bool {
        crate::decode_structure::looks_like_uniform_base64_blob(value)
    }
}

#[cfg(test)]
pub(crate) mod segment_attribution {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub(crate) struct Segment {
        pub(crate) id: u32,
        pub(crate) start: u32,
        pub(crate) len: u32,
    }

    impl Segment {
        pub(crate) const fn new(id: u32, start: u32, len: u32) -> Self {
            Self { id, start, len }
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub(crate) struct GlobalMatch {
        pub(crate) pattern_id: u32,
        pub(crate) start: u32,
        pub(crate) end: u32,
    }

    impl GlobalMatch {
        pub(crate) const fn new(pattern_id: u32, start: u32, end: u32) -> Self {
            Self {
                pattern_id,
                start,
                end,
            }
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub(crate) struct AttributedMatch {
        pub(crate) segment_id: u32,
        pub(crate) pattern_id: u32,
        pub(crate) local_start: u32,
        pub(crate) local_end: u32,
    }

    impl AttributedMatch {
        pub(crate) const fn new(
            segment_id: u32,
            pattern_id: u32,
            local_start: u32,
            local_end: u32,
        ) -> Self {
            Self {
                segment_id,
                pattern_id,
                local_start,
                local_end,
            }
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum SegmentAttributionError {
        SegmentEndOverflow {
            segment_index: usize,
            start: u32,
            len: u32,
        },
        SegmentsNotSorted {
            segment_index: usize,
            previous_start: u32,
            start: u32,
        },
        SegmentsOverlap {
            previous_index: usize,
            segment_index: usize,
            previous_end: u32,
            start: u32,
        },
        InvalidMatchRange {
            match_index: usize,
            start: u32,
            end: u32,
        },
    }

    fn inner_segment(segment: Segment) -> crate::engine::segment_attribution::Segment {
        crate::engine::segment_attribution::Segment::new(segment.id, segment.start, segment.len)
    }

    fn inner_match(item: GlobalMatch) -> crate::engine::segment_attribution::GlobalMatch {
        crate::engine::segment_attribution::GlobalMatch::new(item.pattern_id, item.start, item.end)
    }

    fn expose_match(item: crate::engine::segment_attribution::AttributedMatch) -> AttributedMatch {
        AttributedMatch::new(
            item.segment_id,
            item.pattern_id,
            item.local_start,
            item.local_end,
        )
    }

    fn expose_error(
        error: crate::engine::segment_attribution::SegmentAttributionError,
    ) -> SegmentAttributionError {
        use crate::engine::segment_attribution::SegmentAttributionError as Inner;
        match error {
            Inner::SegmentEndOverflow {
                segment_index,
                start,
                len,
            } => SegmentAttributionError::SegmentEndOverflow {
                segment_index,
                start,
                len,
            },
            Inner::SegmentsNotSorted {
                segment_index,
                previous_start,
                start,
            } => SegmentAttributionError::SegmentsNotSorted {
                segment_index,
                previous_start,
                start,
            },
            Inner::SegmentsOverlap {
                previous_index,
                segment_index,
                previous_end,
                start,
            } => SegmentAttributionError::SegmentsOverlap {
                previous_index,
                segment_index,
                previous_end,
                start,
            },
            Inner::InvalidMatchRange {
                match_index,
                start,
                end,
            } => SegmentAttributionError::InvalidMatchRange {
                match_index,
                start,
                end,
            },
        }
    }

    pub(crate) fn map_offsets_to_segments(
        segments: &[Segment],
        matches: &[GlobalMatch],
    ) -> Result<Vec<AttributedMatch>, SegmentAttributionError> {
        let inner_segments: Vec<_> = segments.iter().copied().map(inner_segment).collect();
        let inner_matches: Vec<_> = matches.iter().copied().map(inner_match).collect();
        crate::engine::segment_attribution::map_offsets_to_segments(&inner_segments, &inner_matches)
            .map(|items| items.into_iter().map(expose_match).collect())
            .map_err(expose_error)
    }
}

#[cfg(test)]
pub(crate) struct CaesarDecoder;

#[cfg(test)]
impl CaesarDecoder {
    pub(crate) fn decode_chunk(&self, chunk: &keyhog_core::Chunk) -> Vec<keyhog_core::Chunk> {
        use crate::decode::Decoder;
        let inner = crate::decode::caesar::CaesarDecoder;
        inner.decode_chunk(chunk)
    }
}

#[cfg(test)]
pub(crate) fn caesar_shift(input: &str, shift: u8) -> String {
    crate::decode::caesar::caesar_shift(input, shift)
}

#[cfg(test)]
pub(crate) fn is_source_code_path(path: Option<&str>) -> bool {
    crate::decode::caesar::is_source_code_path(path)
}

#[cfg(test)]
pub(crate) fn looks_credential_shaped(value: &str) -> bool {
    crate::decode::caesar::looks_credential_shaped(value)
}
#[cfg(test)]
pub(crate) fn find_hex_strings(text: &str, min_length: usize) -> Vec<crate::decode::EncodedString> {
    crate::decode::find_hex_strings(text, min_length)
}

#[cfg(test)]
pub(crate) fn take_hex_digits<I>(
    chars: &mut std::iter::Peekable<I>,
    count: usize,
) -> Result<u32, ()>
where
    I: Iterator<Item = char>,
{
    crate::decode::take_hex_digits(chars, count)
}

#[cfg(test)]
pub(crate) fn looks_reversible(candidate: &str) -> bool {
    crate::decode::reverse::looks_reversible(candidate)
}

#[cfg(test)]
pub(crate) fn reverse_str(s: &str) -> String {
    crate::decode::reverse::reverse_str(s)
}

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
/// (`entropy::fast::shannon_entropy_simd`), which is itself safe and always
/// correct. The `unsafe` marker is kept for one cross-platform signature.
/// Without this arch split the non-x86 build failed to compile
/// (`E0425: cannot find calculate_shannon_entropy`), breaking the portable
/// / macOS-arm64 build.
#[cfg(test)]
pub(crate) unsafe fn calculate_shannon_entropy(chunk: &[u8]) -> f64 {
    #[cfg(target_arch = "x86_64")]
    {
        unsafe { crate::entropy::avx512::calculate_shannon_entropy(chunk) }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        crate::entropy::fast::shannon_entropy_simd(chunk)
    }
}

#[cfg(all(test, feature = "simd"))]
pub(crate) struct HsScanner;

#[cfg(all(test, feature = "simd"))]
impl HsScanner {
    pub(crate) fn compile(
        patterns: &[(usize, usize, &str, bool)],
    ) -> Result<(Self, Vec<usize>), String> {
        crate::simd::backend::HsScanner::compile(patterns)
            .map(|(_scanner, unsupported)| (Self, unsupported))
    }
}

#[cfg(all(test, feature = "simd"))]
pub(crate) fn cache_dir_under_allowed_root(
    path: &std::path::Path,
    home: &std::path::Path,
    temp_root: &std::path::Path,
    uid: u32,
) -> bool {
    crate::simd::backend::cache_dir_under_allowed_root(path, home, temp_root, uid)
}

#[cfg(all(test, feature = "simd"))]
pub(crate) fn set_hyperscan_cache_dir(path: Option<std::path::PathBuf>) {
    crate::set_hyperscan_cache_dir(path);
}

#[cfg(all(test, feature = "simdsieve"))]
pub(crate) const HOT_PATTERNS: &[&[u8]] = crate::simdsieve_prefilter::HOT_PATTERNS;
#[cfg(all(test, feature = "simdsieve"))]
pub(crate) const HOT_PATTERN_DETECTOR_IDS: &[&str] =
    crate::simdsieve_prefilter::HOT_PATTERN_DETECTOR_IDS;
#[cfg(all(test, feature = "simdsieve"))]
pub(crate) const HOT_PATTERN_DISPLAY_NAMES: &[&str] =
    crate::simdsieve_prefilter::HOT_PATTERN_DISPLAY_NAMES;
#[cfg(all(test, feature = "simdsieve"))]
pub(crate) const HOT_PATTERN_NAMES: &[&str] = crate::simdsieve_prefilter::HOT_PATTERN_NAMES;

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(test)]
pub(crate) struct StructuredPair {
    pub(crate) context: String,
    pub(crate) value: String,
    pub(crate) line: usize,
}

#[cfg(test)]
fn structured_pair(pair: crate::structured::ExtractedPair) -> StructuredPair {
    StructuredPair {
        context: pair.context,
        value: pair.value,
        line: pair.line,
    }
}

#[cfg(test)]
fn structured_pairs(pairs: Vec<crate::structured::ExtractedPair>) -> Vec<StructuredPair> {
    pairs.into_iter().map(structured_pair).collect()
}

#[cfg(test)]
pub(crate) fn parse_docker_compose(text: &str) -> Vec<StructuredPair> {
    structured_pairs(crate::structured::parsers::parse_docker_compose(text))
}

#[cfg(test)]
pub(crate) fn parse_env(text: &str) -> Vec<StructuredPair> {
    structured_pairs(crate::structured::parsers::parse_env(text))
}

#[cfg(test)]
pub(crate) fn parse_hcl(text: &str) -> Vec<StructuredPair> {
    structured_pairs(crate::structured::parsers::parse_hcl(text))
}

#[cfg(test)]
pub(crate) fn parse_jupyter(text: &str) -> Vec<StructuredPair> {
    structured_pairs(crate::structured::parsers::parse_jupyter(text))
}

#[cfg(test)]
pub(crate) fn parse_k8s_secret(text: &str) -> Vec<StructuredPair> {
    structured_pairs(crate::structured::parsers::parse_k8s_secret(text))
}

#[cfg(test)]
pub(crate) fn parse_tfstate(text: &str) -> Vec<StructuredPair> {
    structured_pairs(crate::structured::parsers::parse_tfstate(text))
}
