//! `CompiledScanner` match-scoring methods.
//!
//! Confidence policy lives in `crate::confidence::policy`; this module keeps
//! only the scanner methods that need `CompiledScanner` state or chunk context.

use super::*;
use crate::confidence::policy::{
    apply_known_prefix_floor, match_heuristic_confidence, MatchHeuristicConfidencePolicy,
};
use crate::context;
use std::collections::HashMap;

#[cfg(feature = "ml")]
use crate::confidence::policy::probabilistic_promise_confidence_override;

impl CompiledScanner {
    pub(crate) fn match_companions(
        &self,
        entry: &CompiledPattern,
        preprocessed: &ScannerPreprocessedText<'_>,
        line: usize,
    ) -> Option<HashMap<String, String>> {
        // Most detectors declare no companions. Return the empty map without
        // sizing a bucket array (`HashMap::new()` is allocation-free until the
        // first insert) and without entering the search loop. Only detectors
        // that actually have companions pay for the map.
        let Some(detector_companions) = self.companions.get(entry.detector_index) else {
            return Some(HashMap::new());
        };
        if detector_companions.is_empty() {
            return Some(HashMap::new());
        }
        let mut results = HashMap::with_capacity(detector_companions.len());
        for companion in detector_companions {
            if let Some(val) = find_companion(preprocessed, line, companion) {
                results.insert(companion.name.clone(), val);
            } else if companion.required {
                return None;
            }
        }
        Some(results)
    }

    pub(crate) fn match_confidence<'a>(
        &self,
        entry: &CompiledPattern,
        chunk: &Chunk,
        credential: &'a str,
        data: &'a str,
        line: usize,
        entropy: f64,
        has_companion: bool,
        // The context is computed once in `process_match` (where the
        // suppression checks already need it) and threaded through -
        // halves the per-match context-inference work.
        context: context::CodeContext,
        // `keyword_nearby` and `sensitive_file` are constant across
        // every match of a single (chunk, pattern) pair: keyword_nearby
        // depends only on the detector + chunk text, sensitive_file
        // only on the chunk's path. Hoisted to `extract_matches`'s
        // pre-loop preamble so the inner per-match path doesn't keep
        // re-running an O(K) substring scan over the whole chunk +
        // an Aho-Corasick scan over the path.
        keyword_nearby: bool,
        sensitive_file: bool,
        // True when the firing detector is service-anchored (not generic-* /
        // entropy-* / private-key). Such a detector's regex is itself the
        // positive evidence, so the generic probabilistic-promise gate must
        // not bury it - see the rationale in `process_match`.
        is_named_detector: bool,
        scan_state: &mut ScanState,
    ) -> Option<MlScoreResult<'a>> {
        // Checksum validation is handled in process_match (early reject for Invalid,
        // confidence floor for Valid). No need to re-validate here.
        let heuristic_conf = match_heuristic_confidence(MatchHeuristicConfidencePolicy {
            // Per-PATTERN constant, memoized on the `LazyRegex` (see
            // `LazyRegex::has_literal_prefix`): the prior inline
            // `extract_literal_prefix(entry.regex.as_str()).is_some()`
            // re-ran the allocating prefix parser on every surviving
            // candidate. Identical value, computed at most once.
            has_literal_prefix: entry.regex.has_literal_prefix(),
            has_context_anchor: entry.group.is_some(),
            entropy,
            keyword_nearby,
            sensitive_file,
            match_length: credential.len(),
            has_companion,
            code_context: context,
            penalize_test_paths: self.config.penalize_test_paths,
        });
        let score_result = self.calculate_final_score(
            heuristic_conf,
            context,
            credential,
            data,
            line,
            chunk,
            is_named_detector,
            scan_state,
        )?;

        match score_result {
            MlScoreResult::Final(confidence) => {
                let final_score = apply_known_prefix_floor(confidence, credential);
                Some(MlScoreResult::Final(final_score))
            }
            #[cfg(feature = "ml")]
            MlScoreResult::Pending { .. } => Some(score_result),
            #[cfg(not(feature = "ml"))]
            MlScoreResult::_Lifetime(_) => {
                unreachable!("_Lifetime is a never-constructed placeholder variant")
            }
        }
    }

    fn calculate_final_score<'a>(
        &self,
        heuristic_conf: f64,
        context: context::CodeContext,
        credential: &'a str,
        data: &'a str,
        line: usize,
        chunk: &Chunk,
        is_named_detector: bool,
        _scan_state: &mut ScanState,
    ) -> Option<MlScoreResult<'a>> {
        #[cfg(not(feature = "ml"))]
        {
            let _ = (context, credential, data, line, chunk, is_named_detector); // LAW10: unused-binding marker (signature/borrowck/cfg/compile-time assert); no runtime effect, not a fallback
            Some(MlScoreResult::Final(heuristic_conf))
        }

        #[cfg(feature = "ml")]
        {
            if !self.config.ml_enabled {
                return Some(MlScoreResult::Final(heuristic_conf));
            }

            if let Some(confidence) =
                probabilistic_promise_confidence_override(credential, is_named_detector)
            {
                return Some(MlScoreResult::Final(confidence));
            }

            let text_context = local_context_window(data, line, ML_CONTEXT_RADIUS_LINES);
            let ml_context = match chunk.metadata.path.as_deref() {
                Some(path) => format!("file:{path}\n{text_context}"),
                // `local_context_window` returns `&str`; the Some arm is an
                // owned `String`, and `ml_context` feeds `Cow::Owned` below,
                // so both arms must be `String`.
                None => text_context.to_string(),
            };

            Some(MlScoreResult::Pending {
                heuristic_conf,
                code_context: context,
                credential: std::borrow::Cow::Borrowed(credential),
                ml_context: std::borrow::Cow::Owned(ml_context),
            })
        }
    }
}
