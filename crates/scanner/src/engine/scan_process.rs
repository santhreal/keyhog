use super::*;
use crate::context;
#[cfg(feature = "simd")]
use std::cell::RefCell;
use std::collections::HashMap;

use super::scan_filters::*;

impl CompiledScanner {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn process_match(
        &self,
        entry: &CompiledPattern,
        detector: &DetectorSpec,
        data: &str,
        preprocessed: &ScannerPreprocessedText,
        line_offsets: &[usize],
        code_lines: &[&str],
        documentation_lines: &[bool],
        chunk: &Chunk,
        scan_state: &mut ScanState,
        credential: &str,
        match_start: usize,
        match_end: usize,
        base_line: usize,
        base_offset: usize,
        keyword_nearby: bool,
        sensitive_file: bool,
    ) {
        let (credential, match_end) =
            extend_known_prefix_credential(data, credential, match_start, match_end);
        let line = match_line_number(preprocessed, line_offsets, match_start);
        if is_within_hex_context(data, match_start, match_end) {
            return;
        }
        // Probabilistic gate: fast rejection of obvious non-secrets (UUIDs, low-diversity
        // strings) BEFORE the expensive false-positive context check and ML scoring.
        // Only applied to generic detectors — specific detectors with known prefixes
        // already have high confidence from the prefix match.
        if detector.id.starts_with("generic-")
            && crate::confidence::known_prefix_confidence_floor(credential).is_none()
            && !crate::probabilistic_gate::ProbabilisticGate::looks_promising(credential)
        {
            return;
        }
        if context::is_false_positive_context(
            code_lines,
            line.saturating_sub(PREVIOUS_LINE_DISTANCE),
            chunk.metadata.path.as_deref(),
        ) || context::is_false_positive_match_context(
            data,
            match_start,
            chunk.metadata.path.as_deref(),
        ) {
            return;
        }

        let inferred_context = context::infer_context_with_documentation(
            code_lines,
            line.saturating_sub(PREVIOUS_LINE_DISTANCE),
            chunk.metadata.path.as_deref(),
            documentation_lines,
        );
        if crate::pipeline::should_suppress_named_detector_finding(
            credential,
            chunk.metadata.path.as_deref(),
            inferred_context,
            Some(chunk.metadata.source_type.as_str()),
            detector.id.as_ref(),
        ) {
            return;
        }

        // `match_companions` returns `None` when a `required = true`
        // companion isn't found within the search radius — that is a
        // hard skip signal, not "no companions found." The previous
        // `.unwrap_or_default()` swallowed it and let the match fire
        // anyway, silently nullifying the `required` field on every
        // detector that uses it (notably `twilio-auth-token`).
        let companions = if self.companions.is_empty() {
            HashMap::new()
        } else {
            match self.match_companions(entry, preprocessed, line) {
                Some(c) => c,
                None => return,
            }
        };
        let entropy = match_entropy(credential.as_bytes());

        if detector.id.starts_with("generic-") && detector.id != "generic-private-key" {
            // Per-detector entropy floor. Structured tokens (UUIDs, short API keys)
            // have lower entropy than random strings. A blanket 3.5 floor misses them.
            let entropy_floor = generic_entropy_floor(detector.id.as_str(), credential.len());
            if entropy < entropy_floor {
                return;
            }
            let camel_transitions = credential
                .as_bytes()
                .windows(2)
                .filter(|w| w[0].is_ascii_lowercase() && w[1].is_ascii_uppercase())
                .count();
            if camel_transitions >= 2 && !credential.chars().any(|ch| ch.is_ascii_digit()) {
                return;
            }
        }

        // Checksum validation: tokens with embedded checksums (GitHub, npm, Slack,
        // Stripe, GitLab, PyPI) can be verified without network requests.
        // Valid checksum → floor confidence at 0.9 (confirmed real token format).
        // Invalid checksum → cap confidence at 0.1 (confirmed false positive).
        let checksum_result = crate::checksum::validate_checksum(credential);
        if checksum_result == crate::checksum::ChecksumResult::Invalid {
            // A validator recognized this token family and the embedded checksum
            // failed — drop for every detector path (generic, entropy, and named).
            return;
        }

        let Some(score_result) = self.match_confidence(
            entry,
            chunk,
            credential,
            data,
            line,
            entropy,
            !companions.is_empty(),
            inferred_context,
            keyword_nearby,
            sensitive_file,
            scan_state,
        ) else {
            return;
        };

        match score_result {
            MlScoreResult::Final(mut confidence) => {
                // Boost confidence for checksum-validated tokens
                if checksum_result == crate::checksum::ChecksumResult::Valid {
                    confidence = confidence.max(0.9);
                }
                let raw_match = build_raw_match(
                    detector,
                    chunk,
                    credential,
                    companions,
                    match_start + base_offset,
                    line + base_line,
                    entropy,
                    confidence,
                    scan_state,
                );
                scan_state.push_match(raw_match, self.config.max_matches_per_chunk);
            }
            #[cfg(feature = "ml")]
            MlScoreResult::Pending {
                heuristic_conf,
                code_context,
                credential: pending_credential,
                ml_context,
            } => {
                let raw_match = build_raw_match(
                    detector,
                    chunk,
                    credential,
                    companions,
                    match_start + base_offset,
                    line + base_line,
                    entropy,
                    heuristic_conf,
                    scan_state,
                );
                scan_state.ml_pending.push(crate::types::MlPendingMatch {
                    raw_match,
                    heuristic_conf,
                    code_context,
                    credential: pending_credential,
                    ml_context,
                });
            }
        }
    }
}
