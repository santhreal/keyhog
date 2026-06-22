//! `process_match`: the per-match post-processing chain.
//!
//! Runs the suppression chain, companion-required gate, entropy + camel-shape
//! filters for generic detectors, checksum validation, and finally ML /
//! heuristic scoring. Outputs either a `Final` finding into `scan_state.matches`
//! or queues an `MlPendingMatch` for the post-scan ML batch.

use super::scan_filters::*;
use super::CompiledScanner;
use crate::context;
use crate::pipeline::*;
use crate::types::*;
use keyhog_core::{Chunk, DetectorSpec};
use std::collections::HashMap;

impl CompiledScanner {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn process_match(
        &self,
        entry: &CompiledPattern,
        detector: &DetectorSpec,
        data: &str,
        preprocessed: &ScannerPreprocessedText<'_>,
        line_offsets: &[usize],
        code_lines: &[&str],
        documentation_lines: &[bool],
        chunk: &Chunk,
        scan_state: &mut ScanState,
        credential: &str,
        credential_start: usize,
        credential_end: usize,
        base_line: usize,
        base_offset: usize,
        keyword_nearby: bool,
        sensitive_file: bool,
    ) {
        let (credential, match_end) =
            extend_known_prefix_credential(data, credential, credential_end);
        if detector.id.as_str() == crate::detector_ids::AWS_ACCESS_KEY && credential.len() != 20 {
            return;
        }
        if detector.id.as_str() == crate::detector_ids::ANTHROPIC_API_KEY {
            const LEGACY_PREFIX: &str = "sk-ant-api03-";
            if let Some(body) = credential.strip_prefix(LEGACY_PREFIX) {
                if !(80..=120).contains(&body.len()) {
                    return;
                }
            }
        }
        let line = match_line_number(preprocessed, line_offsets, credential_start);
        if is_within_hex_context(data, credential_start, match_end) {
            crate::telemetry::record_shape_suppression(
                chunk.metadata.path.as_deref(),
                credential,
                "within_hex_context",
            );
            return;
        }
        // Digest-fragment guard: a fixed-length hex credential (e.g. a {32}-hex
        // API-key body) whose contiguous hex run is EXTENDED by adjacent hex
        // digits to digest length (>=40) is a slice of a SHA-1 (40) / SHA-256
        // (64) / git-commit hash, not a standalone key. `is_within_hex_context`
        // only fires when hex surrounds the match on BOTH sides; a detector
        // that matches the leading 32 hex of a 64-hex digest has hex only
        // AFTER, so it slipped through (etherscan/iterable firing on a sha256
        // substring). Real 32-hex keys (Twilio auth token, Datadog, Algolia,
        // Azure subscription) are delimiter-bounded (before==after==0) and are
        // never suppressed here, so recall is preserved.
        if is_hex_digest_fragment(data, credential_start, match_end, credential) {
            crate::telemetry::record_shape_suppression(
                chunk.metadata.path.as_deref(),
                credential,
                "hex_digest_fragment",
            );
            return;
        }
        // Probabilistic gate: fast rejection of obvious non-secrets (UUIDs, low-diversity
        // strings) BEFORE the expensive false-positive context check and ML scoring.
        // Only applied to generic detectors. Specific detectors with known prefixes
        // already have high confidence from the prefix match.
        if crate::detector_ids::is_generic_detector(detector.id.as_ref())
            && crate::confidence::known_prefix_confidence_floor(credential).is_none()
            && !crate::probabilistic_gate::ProbabilisticGate::looks_promising(credential)
        {
            crate::telemetry::record_shape_suppression(
                chunk.metadata.path.as_deref(),
                credential,
                "probabilistic_gate_not_promising",
            );
            return;
        }
        if context::is_false_positive_context(
            code_lines,
            line.saturating_sub(PREVIOUS_LINE_DISTANCE),
            chunk.metadata.path.as_deref(),
        ) || context::is_false_positive_match_context(
            data,
            credential_start,
            chunk.metadata.path.as_deref(),
        ) {
            crate::telemetry::record_shape_suppression(
                chunk.metadata.path.as_deref(),
                credential,
                "false_positive_context",
            );
            return;
        }

        let inferred_context = context::infer_context_with_documentation(
            code_lines,
            line.saturating_sub(PREVIOUS_LINE_DISTANCE),
            chunk.metadata.path.as_deref(),
            documentation_lines,
        );
        // Per-detector constant, resolved once at scanner construction
        // (`detector_weak_anchor_by_index`) instead of re-running
        // `detector_weak_anchor`'s regex-string scan for every surviving
        // candidate. `.get(...).copied().unwrap_or_else(...)` falls back to the
        // live computation only if the index is somehow out of range (it never
        // is — the vec is index-parallel with `detectors` — but the fallback
        // keeps this byte-identical to the prior inline call rather than
        // panicking on a malformed index, matching the resilience the extract
        // path already applies to `detector_index`).
        let weak_anchor = self
            .detector_weak_anchor_by_index
            .get(entry.detector_index)
            .copied()
            .unwrap_or_else(|| crate::suppression::detector_weak_anchor(detector)); // LAW10: bounds-checked lookup; out-of-range => documented default (total fn), recall-safe
        let named_suppression_ctx =
            crate::suppression::NamedDetectorSuppressionCtx::with_weak_anchor(
                chunk.metadata.path.as_deref(),
                inferred_context,
                Some(chunk.metadata.source_type.as_str()),
                detector.id.as_ref(),
                weak_anchor,
            );
        let candidate = crate::adjudicate::CandidateMatch::new(credential);
        let match_ctx = crate::adjudicate::MatchCtx::for_named_detector(named_suppression_ctx);
        match crate::adjudicate::adjudicate_match(candidate, &match_ctx) {
            crate::adjudicate::Verdict::Suppressed(stage_id) => {
                // KH-L-0412 (Law-10): named-detector context/example suppression
                // was the last silent `return` on this path. Trace it through the
                // adjudicator so a dropped match is visible to `--dogfood` with
                // the deciding stage name.
                crate::telemetry::record_shape_suppression(
                    chunk.metadata.path.as_deref(),
                    credential,
                    stage_id.as_str(),
                );
                return;
            }
            crate::adjudicate::Verdict::Reported => {}
        }

        // `match_companions` returns `None` when a `required = true`
        // companion isn't found within the search radius. That is a
        // hard skip signal, not "no companions found." The previous
        // `.unwrap_or_default()` swallowed it and let the match fire
        // anyway, silently nullifying the `required` field on every
        // detector that uses it (notably `twilio-auth-token`).
        let companions = if self.companions.is_empty() {
            HashMap::new()
        } else {
            match self.match_companions(entry, preprocessed, line) {
                Some(c) => c,
                None => {
                    crate::telemetry::record_shape_suppression(
                        chunk.metadata.path.as_deref(),
                        credential,
                        "missing_required_companion",
                    );
                    return;
                }
            }
        };
        let entropy = match_entropy(credential.as_bytes());

        let is_generic = crate::detector_ids::is_generic_detector(detector.id.as_ref())
            && detector.id.as_str() != crate::detector_ids::GENERIC_PRIVATE_KEY;
        let is_weakly_anchored = weak_anchor;
        if is_generic || is_weakly_anchored {
            // Per-detector entropy floor. Structured tokens (UUIDs, short API keys)
            // have lower entropy than random strings. A blanket 3.5 floor misses them.
            let floor_id = if is_weakly_anchored {
                crate::detector_ids::GENERIC_API_KEY
            } else {
                detector.id.as_str()
            };
            let entropy_floor =
                generic_entropy_floor(self.config.entropy_threshold, floor_id, credential.len());
            if entropy < entropy_floor {
                crate::telemetry::record_shape_suppression(
                    chunk.metadata.path.as_deref(),
                    credential,
                    "entropy_below_floor",
                );
                return;
            }
            // camelCase-without-digits is the false-positive shape (Java/Go
            // identifiers like `getUserName`); real tokens almost always carry
            // a digit. The cheap digit scan (ASCII bytes, no UTF-8 decode via
            // `chars()`) runs first so any credential containing a digit skips
            // the O(n) camel-transition window walk entirely. Only no-digit
            // credentials pay for the count, and `take(2)` stops it as soon as
            // the >=2 threshold is reached. Behavior is identical to the prior
            // `transitions >= 2 && !has_digit` gate.
            if !credential.bytes().any(|b| b.is_ascii_digit()) {
                let camel_transitions = credential
                    .as_bytes()
                    .windows(2)
                    .filter(|w| w[0].is_ascii_lowercase() && w[1].is_ascii_uppercase())
                    .take(2)
                    .count();
                if camel_transitions >= 2 {
                    crate::telemetry::record_shape_suppression(
                        chunk.metadata.path.as_deref(),
                        credential,
                        "camel_case_no_digit",
                    );
                    return;
                }
            }
        }

        // Checksum validation: tokens with embedded checksums (GitHub, npm, Slack,
        // Stripe, GitLab, PyPI) can be verified without network requests. The
        // engine match-policy owner makes the drop/floor rule shared with hot,
        // generic, entropy, and ML emitters.
        let checksum_policy = super::scoring::checksum_policy_for(credential);
        if checksum_policy.is_invalid() {
            // Checksum failed: NOT a real token. Skip expensive ML scoring.
            crate::telemetry::record_shape_suppression(
                chunk.metadata.path.as_deref(),
                credential,
                "checksum_invalid",
            );
            return;
        }

        // A named, service-anchored detector (anything that is not a
        // generic-* / entropy-* / private-key fallback) carries positive
        // evidence in its own regex: its match IS the credential. The
        // probabilistic "looks_promising" gate in `calculate_final_score`
        // is built to reject low-diversity / UUID / structured strings for
        // the GENERIC entropy path - applied to a named detector it slams
        // legitimate UUID/hex API keys (Heroku, Braze, Codecov, Consul,
        // Linode, Databricks, +100 others) to 0.1, below the 0.3 report
        // floor, silently deleting real secrets. Mirror the same anchor=
        // positive-evidence rule the shape-gate bypass already uses so the
        // gate stays load-bearing for generic-* but never buries a named hit.
        let is_named_detector =
            crate::confidence::is_service_anchored_detector(&detector.id) && !weak_anchor;
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
            is_named_detector,
            scan_state,
        ) else {
            crate::telemetry::record_shape_suppression(
                chunk.metadata.path.as_deref(),
                credential,
                "scoring_rejected",
            );
            return;
        };

        match score_result {
            super::MlScoreResult::Final(mut confidence) => {
                let Some(adjusted_confidence) = super::scoring::finalize_report_confidence(
                    confidence,
                    super::scoring::ReportConfidencePolicy {
                        credential,
                        detector_id: detector.id.as_ref(),
                        file_path: chunk.metadata.path.as_deref(),
                        is_named_detector,
                        penalize_test_paths: self.config.penalize_test_paths,
                        allow_encoded_text_lift: false,
                        calibration: self.config.calibration.as_deref(),
                    },
                ) else {
                    return;
                };
                confidence = adjusted_confidence;
                let source_offset =
                    preprocessed.source_offset_for_match(&chunk.data, credential_start, credential);
                let raw_match = build_raw_match(
                    detector,
                    self.interned_detector_metadata(entry.detector_index),
                    chunk,
                    credential,
                    companions,
                    source_offset + base_offset,
                    line + base_line,
                    entropy,
                    confidence,
                    scan_state,
                    entry.client_safe,
                );
                scan_state.push_match(raw_match, self.config.max_matches_per_chunk);
                crate::telemetry::record_match_found();
            }
            #[cfg(feature = "ml")]
            super::MlScoreResult::Pending {
                heuristic_conf,
                code_context,
                credential: pending_credential,
                ml_context,
            } => {
                let source_offset =
                    preprocessed.source_offset_for_match(&chunk.data, credential_start, credential);
                let raw_match = build_raw_match(
                    detector,
                    self.interned_detector_metadata(entry.detector_index),
                    chunk,
                    credential,
                    companions,
                    source_offset + base_offset,
                    line + base_line,
                    entropy,
                    heuristic_conf,
                    scan_state,
                    entry.client_safe,
                );
                scan_state.ml_pending.push(crate::types::MlPendingMatch {
                    raw_match,
                    heuristic_conf,
                    code_context,
                    credential: pending_credential.into_owned(),
                    ml_context: ml_context.into_owned(),
                    // Detector/generic matches: the firing regex is positive
                    // evidence, so the heuristic stays a confidence FLOOR (the
                    // model can only raise). Not model-authoritative.
                    model_authoritative: false,
                });
                crate::telemetry::record_match_found();
            }
            #[cfg(not(feature = "ml"))]
            super::MlScoreResult::_Lifetime(_) => {
                unreachable!("_Lifetime is a never-constructed placeholder variant")
            }
        }
    }
}

/// True when `credential` (a pure-hex token at `data[start..end]`) is a slice
/// of a longer contiguous hex run reaching digest length (>=40 chars: SHA-1,
/// git commit SHA, or SHA-256). Such a match is a fragment of a hash, never a
/// standalone key. A genuine fixed-length hex API key is delimiter-bounded
/// (the byte before and after is `"`/`=`/whitespace/EOL, not another hex
/// digit), so `before == 0 && after == 0` and this returns false - recall on
/// real 32/40/64-hex keys is preserved.
pub(super) fn is_hex_digest_fragment(
    data: &str,
    start: usize,
    end: usize,
    credential: &str,
) -> bool {
    if credential.len() < 16 || !credential.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }
    let bytes = data.as_bytes();
    if start > end || end > bytes.len() {
        return false;
    }
    let before = bytes[..start]
        .iter()
        .rev()
        .take_while(|b| b.is_ascii_hexdigit())
        .count();
    let after = bytes[end..]
        .iter()
        .take_while(|b| b.is_ascii_hexdigit())
        .count();
    if before == 0 && after == 0 {
        return false;
    }
    before + credential.len() + after >= 40
}
