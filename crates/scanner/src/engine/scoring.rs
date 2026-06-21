//! `CompiledScanner` match-scoring / confidence methods.
//!
//! Extracted from the phase-2 scanner tail to
//! separate the fallback-*scanning* path from the match-*scoring* path. These
//! are satellite `impl CompiledScanner` methods: the struct lives in `mod.rs`,
//! and the same `use super::*` glob the phase-2 modules rely on brings every
//! referenced symbol (`CompiledPattern`, `MlScoreResult`, `find_companion`,
//! `extract_literal_prefix`, `local_context_window`, `ML_CONTEXT_RADIUS_LINES`)
//! into scope here unchanged. Pure move — no behaviour change.

use super::*;
use crate::context;
use std::collections::HashMap;

pub(super) type CredentialChecksumPolicy = crate::checksum::ChecksumConfidenceDecision;

#[inline]
pub(super) fn checksum_policy_for(credential: &str) -> CredentialChecksumPolicy {
    crate::checksum::ChecksumConfidenceDecision::for_credential(credential)
}

#[inline]
pub(super) fn apply_checksum_confidence(confidence: f64, credential: &str) -> Option<f64> {
    checksum_policy_for(credential).adjusted_confidence(confidence)
}

#[cfg(feature = "simdsieve")]
pub(super) fn hot_pattern_confidence(credential: &str) -> Option<f64> {
    const BASE_CONFIDENCE: f64 = 0.7;
    let base_confidence = match crate::confidence::known_prefix_confidence_floor(credential) {
        Some(confidence) => confidence,
        None => BASE_CONFIDENCE,
    };
    apply_checksum_confidence(base_confidence, credential)
}

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
        let raw_conf =
            crate::confidence::compute_confidence(&crate::confidence::ConfidenceSignals {
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
            });

        // Checksum validation is handled in process_match (early reject for Invalid,
        // confidence floor for Valid). No need to re-validate here.
        // The fixture opt-out must also bypass this pre-ML context multiplier;
        // otherwise the lower score is baked into `heuristic_conf`.
        let context_multiplier = match context {
            crate::context::CodeContext::TestCode | crate::context::CodeContext::Documentation
                if !self.config.penalize_test_paths =>
            {
                1.0
            }
            _ => context.confidence_multiplier(),
        };
        let heuristic_conf = raw_conf * context_multiplier;
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
                let final_score = if let Some(floor) =
                    crate::confidence::known_prefix_confidence_floor(credential)
                {
                    confidence.max(floor)
                } else {
                    confidence
                };

                // Keep comment hard-suppression separate from the fixture
                // opt-out; comments stay controlled by `--scan-comments`.
                let hard_suppressed = context.should_hard_suppress(final_score)
                    && (self.config.penalize_test_paths
                        || matches!(context, crate::context::CodeContext::Comment));
                if hard_suppressed {
                    None
                } else {
                    Some(MlScoreResult::Final(final_score))
                }
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

            // The probabilistic-promise gate fast-rejects low-diversity /
            // UUID / structured strings to 0.1 (below the 0.3 report floor).
            // That is correct for generic-* / entropy-* detectors - their
            // only evidence is shape - but a NAMED service-anchored detector
            // proved via its own regex that these bytes are the credential
            // (Heroku / Braze / Codecov / Consul / Linode UUID & hex keys).
            // generic-no-prefix-not-promising matches were already dropped
            // upstream in `process_match`, so the only hits reaching here with
            // `!looks_promising` are named detectors or known-prefix generics.
            if !crate::probabilistic_gate::ProbabilisticGate::looks_promising(credential) {
                // A named detector bypasses the 0.1 slam ONLY for genuinely
                // structured secrets (UUID / hex / random tokens). A weak-prefix
                // detector (e.g. stackblitz `sb_[A-Za-z0-9_-]{20,}`) can still
                // match a CODE IDENTIFIER like `sb_get_string_descriptor` or
                // `SB_ENDPOINT_ADDRESS_MASK` - those are never secrets, so they
                // stay slammed even for named detectors. A UUID/hex credential
                // is never identifier-shaped (digit-only segments, no `_`/`-`
                // word structure), so the recall win for the 90+ real
                // structured-key detectors is preserved.
                // KH-L-0416 (EVALUATED, intentionally NOT discriminator-gated):
                // this block runs ONLY in the `!looks_promising` branch — i.e. on
                // LOW-DIVERSITY / structured values — and `token_randomness` is
                // unreliable there: a repetitive run (`aaaaaaaaaaaaaaaa` −9.34,
                // `qqqqwwww` −12.0) has improbable ENGLISH bigrams so it scores as
                // "random", which would WRONGLY un-slam low-diversity junk for
                // named detectors. The randomness discriminator is sound only
                // where an upstream entropy/diversity floor runs first (the
                // generic bridge); here `looks_promising` has already done the
                // opposite filtering. A/B confirmed no-op on both corpora; left as
                // the plain shape check by documented decision.
                let identifier_shaped =
                    crate::suppression::shape::looks_like_word_separated_identifier(credential)
                        || crate::suppression::shape::looks_like_pure_identifier(credential);
                if !is_named_detector || identifier_shaped {
                    return Some(MlScoreResult::Final(0.1));
                }
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
