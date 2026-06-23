// Doc-hidden scanner test facade. Kept out of lib.rs so the crate root
// remains a module map and public API surface, not a test-probe dumping ground.

#[cfg(test)]
use keyhog_core::Chunk;
#[cfg(test)]
use std::sync::{Mutex, MutexGuard, OnceLock};

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
pub(crate) fn telemetry_serial_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) // LAW10: testing-only mutex poisoning recovery; no runtime effect on shipped scanner behavior
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
        crate::confidence::penalties::apply_post_ml_penalties_with_encoded_text_lift(
            score, credential, is_named, false,
        )
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

    #[cfg(test)]
    pub(crate) fn apply_known_prefix_floor(score: f64, credential: &str) -> f64 {
        crate::confidence::policy::apply_known_prefix_floor(score, credential)
    }

    #[cfg(test)]
    pub(crate) fn pre_ml_heuristic_confidence(
        raw_confidence: f64,
        code_context: crate::context::CodeContext,
        penalize_test_paths: bool,
    ) -> f64 {
        crate::confidence::policy::pre_ml_heuristic_confidence(
            raw_confidence,
            code_context,
            penalize_test_paths,
        )
    }

    #[cfg(test)]
    pub(crate) fn match_heuristic_confidence(
        signals: &crate::confidence::ConfidenceSignals,
        code_context: crate::context::CodeContext,
        penalize_test_paths: bool,
    ) -> f64 {
        crate::confidence::policy::match_heuristic_confidence(
            crate::confidence::policy::MatchHeuristicConfidencePolicy {
                has_literal_prefix: signals.has_literal_prefix,
                has_context_anchor: signals.has_context_anchor,
                entropy: signals.entropy,
                keyword_nearby: signals.keyword_nearby,
                sensitive_file: signals.sensitive_file,
                match_length: signals.match_length,
                has_companion: signals.has_companion,
                code_context,
                penalize_test_paths,
            },
        )
    }

    #[cfg(all(test, feature = "ml"))]
    pub(crate) fn ml_pending_confidence(
        heuristic_confidence: f64,
        model_confidence: f64,
        ml_weight: f64,
        model_authoritative: bool,
        code_context: crate::context::CodeContext,
        scan_comments: bool,
        penalize_test_paths: bool,
    ) -> f64 {
        crate::confidence::policy::ml_pending_confidence(
            crate::confidence::policy::MlConfidencePolicy {
                heuristic_confidence,
                model_confidence,
                ml_weight,
                model_authoritative,
                code_context,
                scan_comments,
                penalize_test_paths,
            },
        )
    }

    #[cfg(all(test, feature = "ml"))]
    pub(crate) fn probabilistic_promise_confidence_override(
        credential: &str,
        is_named_detector: bool,
    ) -> Option<f64> {
        crate::confidence::policy::probabilistic_promise_confidence_override(
            credential,
            is_named_detector,
        )
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

    pub(crate) fn parse_test_path_rules_for_test(
        raw: &str,
    ) -> Result<(Vec<String>, Vec<String>, Vec<String>), String> {
        let rules = crate::context::parse_test_path_rules(raw)?;
        Ok((
            rules.filename_prefixes,
            rules.filename_suffixes,
            rules.path_components,
        ))
    }

    pub(crate) fn is_known_example_credential(credential: &str) -> bool {
        crate::context::is_known_example_credential(credential)
    }

    pub(crate) fn is_sequential_placeholder(credential: &str) -> bool {
        crate::context::is_sequential_placeholder(credential)
    }
}

pub mod fragment_cache {
    use std::sync::Arc;

    use zeroize::Zeroizing;

    #[derive(Clone)]
    pub struct SecretFragment {
        pub prefix: String,
        pub var_name: String,
        pub value: Zeroizing<String>,
        pub line: usize,
        pub path: Option<Arc<str>>,
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

    pub struct ReassembledCandidate {
        pub value: Zeroizing<String>,
        pub path: Option<Arc<str>>,
        pub line: usize,
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

    pub struct FragmentCache(crate::fragment_cache::FragmentCache);

    impl FragmentCache {
        pub fn new(capacity: usize) -> Self {
            Self(crate::fragment_cache::FragmentCache::new(capacity))
        }

        pub(super) fn inner(&self) -> &crate::fragment_cache::FragmentCache {
            &self.0
        }

        pub fn record_and_reassemble(&self, fragment: SecretFragment) -> Vec<Zeroizing<String>> {
            self.0.record_and_reassemble(inner_fragment(fragment))
        }

        #[cfg(feature = "simd")]
        pub fn record_and_reassemble_stamped(
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

        pub fn clear(&self) {
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

    pub fn shard_index_drift_probe(prefix: &str, scope: &str) -> (usize, usize) {
        crate::fragment_cache::shard_index_drift_probe(prefix, scope)
    }
}

#[cfg(feature = "multiline")]
pub mod multiline {
    pub use crate::multiline::MultilineConfig;

    #[derive(Debug, Clone)]
    pub struct LineMapping {
        pub start_offset: usize,
        pub end_offset: usize,
        pub line_number: usize,
        pub original_start_offset: usize,
    }

    #[derive(Debug, Clone)]
    pub struct PreprocessedText<'a> {
        pub text: std::borrow::Cow<'a, str>,
        pub original_end: usize,
        pub mappings: Vec<LineMapping>,
    }

    impl<'a> PreprocessedText<'a> {
        pub fn passthrough(text: impl Into<std::borrow::Cow<'a, str>>) -> Self {
            public_preprocessed(crate::multiline::PreprocessedText::passthrough(text))
        }

        pub fn line_for_offset(&self, offset: usize) -> Option<usize> {
            let idx = self.mappings.partition_point(|m| m.start_offset <= offset);
            if idx == 0 {
                return None;
            }
            let mapping = &self.mappings[idx - 1];
            if offset < mapping.end_offset {
                Some(mapping.line_number)
            } else {
                None
            }
        }
    }

    pub fn preprocess_multiline<'a>(
        text: impl Into<std::borrow::Cow<'a, str>>,
        config: &MultilineConfig,
        fragment_cache: &super::fragment_cache::FragmentCache,
    ) -> PreprocessedText<'a> {
        public_preprocessed(crate::multiline::preprocess_multiline(
            text,
            config,
            fragment_cache.inner(),
        ))
    }

    fn public_preprocessed<'a>(
        preprocessed: crate::multiline::PreprocessedText<'a>,
    ) -> PreprocessedText<'a> {
        PreprocessedText {
            text: preprocessed.text,
            original_end: preprocessed.original_end,
            mappings: preprocessed
                .mappings
                .into_iter()
                .map(|mapping| LineMapping {
                    start_offset: mapping.start_offset,
                    end_offset: mapping.end_offset,
                    line_number: mapping.line_number,
                    original_start_offset: mapping.original_start_offset,
                })
                .collect(),
        }
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
pub use crate::pipeline::compute_line_offsets;
pub fn normalize_chunk_data(data: &str) -> std::borrow::Cow<'_, str> {
    crate::normalize_chunk_data(data)
}
pub fn normalize_scannable_chunk<'a>(
    chunk: &'a keyhog_core::Chunk,
    owned: &'a mut Option<keyhog_core::Chunk>,
) -> &'a keyhog_core::Chunk {
    crate::pipeline::normalize_scannable_chunk(chunk, owned)
}
pub fn is_within_hex_context(data: &str, match_start: usize, match_end: usize) -> bool {
    crate::pipeline::is_within_hex_context(data, match_start, match_end)
}
pub fn local_context_window(text: &str, line: usize, radius: usize) -> &str {
    crate::pipeline::local_context_window(text, line, radius)
}
pub fn match_entropy(data: &[u8]) -> f64 {
    crate::pipeline::match_entropy(data)
}
#[cfg(all(feature = "multiline", test))]
pub(crate) use crate::pipeline::{find_companion, line_window_offsets, match_line_number};
#[cfg(all(feature = "multiline", test))]
pub(crate) use crate::types::{CompiledCompanion, ScannerPreprocessedText};

#[cfg(all(feature = "multiline", not(test)))]
pub use multiline::PreprocessedText as ScannerPreprocessedText;
#[cfg(all(feature = "multiline", not(test)))]
pub struct CompiledCompanion {
    pub name: String,
    pub regex: regex::Regex,
    pub capture_group: Option<usize>,
    pub within_lines: usize,
    pub required: bool,
}
#[cfg(all(feature = "multiline", not(test)))]
fn inner_preprocessed<'a>(
    preprocessed: &ScannerPreprocessedText<'a>,
) -> crate::types::ScannerPreprocessedText<'a> {
    crate::types::ScannerPreprocessedText {
        text: preprocessed.text.clone(),
        original_end: preprocessed.original_end,
        mappings: preprocessed
            .mappings
            .iter()
            .map(|mapping| crate::multiline::LineMapping {
                start_offset: mapping.start_offset,
                end_offset: mapping.end_offset,
                line_number: mapping.line_number,
                original_start_offset: mapping.original_start_offset,
            })
            .collect(),
    }
}
#[cfg(all(feature = "multiline", not(test)))]
fn inner_companion(companion: &CompiledCompanion) -> crate::types::CompiledCompanion {
    crate::types::CompiledCompanion {
        name: companion.name.clone(),
        regex: companion.regex.clone(),
        capture_group: companion.capture_group,
        within_lines: companion.within_lines,
        required: companion.required,
    }
}
#[cfg(all(feature = "multiline", not(test)))]
pub fn match_line_number(
    preprocessed: &ScannerPreprocessedText<'_>,
    line_offsets: &[usize],
    offset: usize,
) -> usize {
    let inner = inner_preprocessed(preprocessed);
    crate::pipeline::match_line_number(&inner, line_offsets, offset)
}
#[cfg(all(feature = "multiline", not(test)))]
pub fn line_window_offsets(
    preprocessed: &ScannerPreprocessedText<'_>,
    start_line: usize,
    end_line: usize,
) -> Option<(usize, usize)> {
    let inner = inner_preprocessed(preprocessed);
    crate::pipeline::line_window_offsets(&inner, start_line, end_line)
}
#[cfg(all(feature = "multiline", not(test)))]
pub fn find_companion(
    preprocessed: &ScannerPreprocessedText<'_>,
    primary_line: usize,
    companion: &CompiledCompanion,
) -> Option<String> {
    let inner_preprocessed = inner_preprocessed(preprocessed);
    let inner_companion = inner_companion(companion);
    crate::pipeline::find_companion(&inner_preprocessed, primary_line, &inner_companion)
}
#[cfg(test)]
pub(crate) use crate::prefix_trie::build_propagation_table;
#[cfg(test)]
pub(crate) use crate::suppression::detector_weak_anchor;

#[cfg(any(feature = "simdsieve", test))]
pub fn known_example_suppressed(
    credential: &str,
    path: Option<&str>,
    context: crate::context::CodeContext,
) -> bool {
    let stage = crate::suppression::api::suppress_known_example_credential_stage(
        credential,
        crate::suppression::api::KnownExampleSuppressionCtx::new(path, context, None),
    );
    if let Some(stage) = stage {
        let ctx = crate::adjudicate::MatchCtx::for_stage(stage);
        crate::adjudicate::record_suppression(path, credential, &ctx).is_some()
    } else {
        false
    }
}

#[cfg(any(feature = "simdsieve", test))]
pub fn known_example_suppressed_with_source(
    credential: &str,
    path: Option<&str>,
    context: crate::context::CodeContext,
    source_type: Option<&str>,
) -> bool {
    let stage = crate::suppression::api::suppress_known_example_credential_stage(
        credential,
        crate::suppression::api::KnownExampleSuppressionCtx::new(path, context, source_type),
    );
    if let Some(stage) = stage {
        let ctx = crate::adjudicate::MatchCtx::for_stage(stage);
        crate::adjudicate::record_suppression(path, credential, &ctx).is_some()
    } else {
        false
    }
}

pub fn named_detector_suppressed(
    credential: &str,
    path: Option<&str>,
    context: crate::context::CodeContext,
    source_type: Option<&str>,
    detector_id: &str,
) -> bool {
    crate::suppression::api::suppress_named_detector_finding(
        credential,
        crate::suppression::api::NamedDetectorSuppressionCtx::with_weak_anchor(
            path,
            context,
            source_type,
            detector_id,
            false,
        ),
    )
}

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
pub(crate) fn phase2_truncated_set_failure_matches_full_set(
    srcs: &[&str],
    trunc_srcs: &[String],
    case_insensitive: bool,
    text: &str,
) -> Result<Vec<usize>, regex::Error> {
    crate::engine::phase2::Phase2AlwaysActivePrefilter::compile_truncated_or_full_set(
        srcs,
        trunc_srcs,
        case_insensitive,
    )
    .map(|set| set.matches(text).iter().collect())
}
#[cfg(test)]
pub(crate) fn looks_like_program_identifier(value: &str) -> bool {
    crate::suppression::shape::looks_like_program_identifier(value)
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

    pub(crate) fn candidate_plausibility_rejection_reason(
        candidate: &str,
        entropy: f64,
        context: &KeywordContext,
        placeholder_keywords: &[String],
    ) -> Option<&'static str> {
        crate::entropy::scanner::candidate_plausibility_rejection_stage(
            candidate,
            entropy,
            &context.inner,
            placeholder_keywords,
        )
        .map(|stage| stage.as_str())
    }

    pub(crate) fn is_canonical_non_secret_shape(value: &str) -> bool {
        crate::entropy::scanner::is_canonical_non_secret_shape(value)
    }
}

/// Entropy plausibility and shape predicates exposed for unit tests migrated
/// out of their original inline homes (KH-GAP-004).
#[cfg(test)]
pub(crate) mod entropy_keywords {
    pub(crate) use crate::entropy::plausibility::PlausibilityContext;

    pub(crate) fn looks_like_english_prose(value: &str) -> bool {
        crate::suppression::shape::looks_like_english_prose(value)
    }

    pub(crate) fn entropy_value_looks_like_prose(value: &str) -> bool {
        crate::suppression::shape::looks_like_english_prose(value)
    }

    pub(crate) fn passes_secret_strength_checks(value: &str, is_credential_context: bool) -> bool {
        crate::entropy::plausibility::passes_secret_strength_checks(
            value,
            PlausibilityContext::new(is_credential_context, false),
        )
    }

    pub(crate) fn is_dash_segmented_alnum_decoy(value: &str) -> bool {
        crate::suppression::shape::is_dash_segmented_alnum_decoy(value)
    }

    pub(crate) fn is_candidate_plausible(value: &str, placeholder_keywords: &[String]) -> bool {
        crate::entropy::plausibility::is_candidate_plausible(
            value,
            placeholder_keywords,
            PlausibilityContext::default(),
        )
    }

    pub fn is_secret_plausible(value: &str, placeholder_keywords: &[String]) -> bool {
        crate::entropy::plausibility::is_secret_plausible(
            value,
            placeholder_keywords,
            PlausibilityContext::default(),
        )
    }

    pub(crate) fn is_candidate_plausible_in_context(
        value: &str,
        placeholder_keywords: &[String],
        context: PlausibilityContext,
    ) -> bool {
        crate::entropy::plausibility::is_candidate_plausible(value, placeholder_keywords, context)
    }

    pub(crate) fn is_secret_plausible_in_context(
        value: &str,
        placeholder_keywords: &[String],
        context: PlausibilityContext,
    ) -> bool {
        crate::entropy::plausibility::is_secret_plausible(value, placeholder_keywords, context)
    }
}

pub mod checksum {
    pub use crate::checksum::{
        checksum_adjusted_confidence, validate_checksum, ChecksumResult, CHECKSUM_VALID_FLOOR,
    };

    pub fn standard_crc32(data: &[u8]) -> u32 {
        crate::checksum::standard_crc32(data)
    }

    pub fn base62_encode_u32(value: u32, width: usize) -> String {
        crate::checksum::base62_encode_u32(value, width)
    }

    pub fn crc32_base62_suffix(data: &[u8], width: usize) -> String {
        crate::checksum::crc32_base62_suffix(data, width)
    }

    pub fn github_classic_pat_with_checksum(body30: &str) -> String {
        assert_eq!(body30.len(), 30, "github classic body must be 30 chars");
        format!(
            "ghp_{}{}",
            body30,
            crc32_base62_suffix(body30.as_bytes(), 6)
        )
    }

    pub fn npm_token_with_checksum(body30: &str) -> String {
        assert_eq!(body30.len(), 30, "npm body must be 30 chars");
        format!(
            "npm_{}{}",
            body30,
            crc32_base62_suffix(body30.as_bytes(), 6)
        )
    }

    pub fn github_fine_grained_pat_with_checksum(left22: &str, right_body53: &str) -> String {
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

    pub trait ChecksumValidator {
        fn validator_id(&self) -> &str;
        fn validate(&self, credential: &str) -> ChecksumResult;
    }

    macro_rules! checksum_validator_wrapper {
        ($name:ident, $inner:path, $validator_id:expr) => {
            pub struct $name;

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
                pub fn validator_id(&self) -> &str {
                    <Self as ChecksumValidator>::validator_id(self)
                }

                pub fn validate(&self, credential: &str) -> ChecksumResult {
                    <Self as ChecksumValidator>::validate(self, credential)
                }
            }
        };
    }

    checksum_validator_wrapper!(
        GithubClassicPatValidator,
        crate::checksum::github::GithubClassicPatValidator,
        crate::detector_ids::GITHUB_CLASSIC_PAT
    );
    checksum_validator_wrapper!(
        GithubFineGrainedPatValidator,
        crate::checksum::github::GithubFineGrainedPatValidator,
        crate::detector_ids::GITHUB_FINE_GRAINED_PAT
    );
    checksum_validator_wrapper!(
        GitlabTokenValidator,
        crate::checksum::gitlab::GitlabTokenValidator,
        crate::detector_ids::GITLAB_TOKEN
    );
    checksum_validator_wrapper!(
        NpmTokenValidator,
        crate::checksum::npm::NpmTokenValidator,
        crate::detector_ids::NPM_ACCESS_TOKEN
    );
    checksum_validator_wrapper!(
        PypiTokenValidator,
        crate::checksum::npm::PypiTokenValidator,
        crate::detector_ids::PYPI_API_TOKEN
    );
    checksum_validator_wrapper!(
        SlackTokenValidator,
        crate::checksum::slack::SlackTokenValidator,
        crate::detector_ids::SLACK_TOKEN
    );
    checksum_validator_wrapper!(
        StripeTokenValidator,
        crate::checksum::stripe::StripeTokenValidator,
        crate::detector_ids::STRIPE_API_KEY
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

#[cfg(test)]
pub(crate) fn register_thread_decoder(
    decoder: Box<dyn crate::decode::Decoder>,
) -> crate::decode::ScopedDecoderRegistration {
    crate::decode::register_thread_decoder(decoder)
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
    crate::suppression::shape::looks_like_standard_base64_blob(credential)
}

#[cfg(all(test, feature = "entropy"))]
pub(crate) mod phase2_entropy_helpers {
    pub(crate) fn keyword_is_credential_anchor(keyword: &str) -> bool {
        crate::engine::phase2_entropy::helpers::keyword_is_credential_anchor(keyword)
    }

    pub(crate) fn looks_like_entropy_random_base64_blob_decoy(value: &str) -> bool {
        crate::suppression::shape::looks_like_entropy_random_base64_blob_decoy(value)
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

    pub(crate) fn ci_find_nonempty(haystack: &[u8], needle: &[u8]) -> bool {
        crate::ascii_ci::ci_find_nonempty(haystack, needle)
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

    pub(crate) fn looks_like_filename_reference(credential: &str) -> bool {
        crate::suppression::shape::looks_like_filename_reference(credential)
    }

    pub(crate) fn looks_like_kebab_config_identifier(credential: &str) -> bool {
        crate::suppression::shape::looks_like_kebab_config_identifier(credential)
    }

    pub(crate) fn looks_like_generic_random_base64_blob_decoy(
        credential: &str,
        entropy: f64,
    ) -> bool {
        crate::suppression::shape::looks_like_generic_random_base64_blob_decoy(credential, entropy)
    }

    pub(crate) fn generic_base64_candidate_is_ambiguous(credential: &str, entropy: f64) -> bool {
        crate::suppression::shape::generic_base64_candidate_is_ambiguous(credential, entropy)
    }

    pub(crate) fn public_noncredential_shape_full(credential: &str) -> Option<&'static str> {
        crate::suppression::shape::public_noncredential_shape(
            credential,
            crate::suppression::shape::PublicShapeScope::Full,
        )
    }

    pub(crate) fn public_noncredential_shape_weak_anchor(credential: &str) -> Option<&'static str> {
        crate::suppression::shape::public_noncredential_shape(
            credential,
            crate::suppression::shape::PublicShapeScope::WeakAnchor,
        )
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

    #[cfg(any(feature = "entropy", test))]
    pub(crate) fn decoded_contains_nul_byte(candidate: &str) -> bool {
        crate::decode_structure::decoded_contains_nul_byte(candidate)
    }

    pub fn decoded_is_base64_blob(candidate: &str) -> bool {
        crate::decode_structure::decoded_is_base64_blob(candidate)
    }

    pub fn decoded_is_hex_key_material(candidate: &str) -> bool {
        crate::decode_structure::decoded_is_hex_key_material(candidate)
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

pub mod segment_attribution {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct Segment {
        pub id: u32,
        pub start: u32,
        pub len: u32,
    }

    impl Segment {
        pub const fn new(id: u32, start: u32, len: u32) -> Self {
            Self { id, start, len }
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct GlobalMatch {
        pub pattern_id: u32,
        pub start: u32,
        pub end: u32,
    }

    impl GlobalMatch {
        pub const fn new(pattern_id: u32, start: u32, end: u32) -> Self {
            Self {
                pattern_id,
                start,
                end,
            }
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct AttributedMatch {
        pub segment_id: u32,
        pub pattern_id: u32,
        pub local_start: u32,
        pub local_end: u32,
    }

    impl AttributedMatch {
        pub const fn new(
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
    pub enum SegmentAttributionError {
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

    pub fn map_offsets_to_segments(
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

pub fn is_source_code_path(path: Option<&str>) -> bool {
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

pub fn take_hex_digits<I>(chars: &mut std::iter::Peekable<I>, count: usize) -> Result<u32, ()>
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
