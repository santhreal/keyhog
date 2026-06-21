#[cfg(feature = "entropy")]
mod gates;
#[cfg(feature = "entropy")]
pub(crate) mod helpers;
#[cfg(feature = "entropy")]
use super::*;
#[cfg(feature = "entropy")]
use gates::entropy_match_suppressed;
#[cfg(feature = "entropy")]
use keyhog_core::MatchLocation;
#[cfg(feature = "entropy")]
use std::collections::HashMap;
#[cfg(feature = "entropy")]
use std::sync::Arc;

#[cfg(feature = "entropy")]
impl CompiledScanner {
    pub(crate) fn scan_entropy_fallback(
        &self,
        preprocessed: &ScannerPreprocessedText<'_>,
        line_offsets: &[usize],
        chunk: &Chunk,
        scan_state: &mut ScanState,
    ) {
        if !self.config.entropy_enabled {
            return;
        }
        if chunk.metadata.source_type.contains("/caesar") {
            return;
        }
        let path_entropy_appropriate = crate::entropy::is_entropy_appropriate_with_content(
            chunk.metadata.path.as_deref(),
            self.config.entropy_in_source_files,
            &preprocessed.text,
            &self.config.secret_keywords,
        );
        let source_entropy_requires_same_line_credential = !self.config.entropy_in_source_files
            && crate::decode::caesar::is_program_source_code_path(chunk.metadata.path.as_deref());
        let isolated_bare_candidate = !path_entropy_appropriate
            && crate::entropy::scanner::has_isolated_bare_secret_candidate(
                &preprocessed.text,
                self.config.entropy_threshold,
                &self.config.placeholder_keywords,
            );
        #[cfg(feature = "simd")]
        let lower_dash_app_password_candidate = path_entropy_appropriate
            && crate::entropy::scanner::has_lower_dash_app_password_candidate(
                &preprocessed.text,
                &self.config,
            );
        if !path_entropy_appropriate && !isolated_bare_candidate {
            return;
        }

        // Avoid the full Shannon sweep unless a run proof or isolated candidate
        // already exists.
        #[cfg(feature = "simd")]
        if !isolated_bare_candidate
            && !lower_dash_app_password_candidate
            && !super::scan_filters::has_high_entropy_run_at_least(
                preprocessed.text.as_bytes(),
                self.config.min_secret_len,
            )
        {
            return;
        }

        // Avoid entropy duplicates on lines already claimed by named detectors.
        let mut skip_lines = std::collections::HashSet::new();
        if !scan_state.matches.is_empty() {
            for m in &scan_state.matches {
                let id = &*m.detector_id;
                if !id.starts_with("generic-") && !id.starts_with("entropy-") {
                    if let Some(line) = m.location.line {
                        skip_lines.insert(line);
                    }
                }
            }
        }

        let keyword_free_threshold =
            if crate::entropy::is_sensitive_file(chunk.metadata.path.as_deref()) {
                crate::entropy::SENSITIVE_FILE_VERY_HIGH_ENTROPY_THRESHOLD
            } else {
                crate::entropy::VERY_HIGH_ENTROPY_THRESHOLD
            };

        // With authoritative ML, credential-anchored canonical hash/UUID/serial
        // candidates may be generated for model arbitration.
        #[cfg(feature = "ml")]
        let allow_canonical_lift = self.config.ml_enabled && self.config.entropy_ml_authoritative;
        #[cfg(not(feature = "ml"))]
        let allow_canonical_lift = false;
        let entropy_matches = crate::entropy::scanner::find_entropy_secrets_with_canonical_lift(
            &preprocessed.text,
            self.config.min_secret_len,
            1,
            self.config.entropy_threshold,
            keyword_free_threshold,
            &self.config.secret_keywords,
            &self.config.test_keywords,
            &self.config.placeholder_keywords,
            Some(&skip_lines),
            allow_canonical_lift,
        );
        for entropy_match in entropy_matches {
            // Resolve metadata once; emit clones the pre-interned triple.
            let entropy_meta_idx = helpers::classify_entropy_detector_index(&entropy_match.keyword);
            let base_confidence =
                if entropy_match.entropy >= crate::entropy::VERY_HIGH_ENTROPY_THRESHOLD {
                    0.75
                } else if entropy_match.entropy >= crate::entropy::HIGH_ENTROPY_THRESHOLD {
                    0.65
                } else {
                    0.55_f64.min(entropy_match.entropy / 8.0)
                };
            let confidence = if entropy_match.keyword != "none (high-entropy)" {
                (base_confidence + 0.1).min(0.90_f64)
            } else {
                base_confidence
            };
            let mapped_line = crate::pipeline::match_line_number(
                preprocessed,
                line_offsets,
                entropy_match.offset,
            );
            let source_offset = preprocessed.source_offset_for_match(
                &chunk.data,
                entropy_match.offset,
                &entropy_match.value,
            );
            let offset = source_offset + chunk.metadata.base_offset;

            // Pass the lift switch only after generation; the gauntlet still
            // owns every non-canonical precision gate.
            if entropy_match_suppressed(
                &entropy_match,
                preprocessed,
                line_offsets,
                chunk,
                allow_canonical_lift,
                source_entropy_requires_same_line_credential,
            ) {
                continue;
            }

            let metadata = &self.entropy_metadata_by_index[entropy_meta_idx];
            let absolute_line = mapped_line + chunk.metadata.base_line;
            let build_raw_match = |scan_state: &mut ScanState, confidence| {
                // Clone metadata only for candidates that need an owned RawMatch.
                let detector_id = Arc::clone(&metadata.0);
                let detector_name = Arc::clone(&metadata.1);
                let service = Arc::clone(&metadata.2);
                let credential = scan_state.intern_credential(&entropy_match.value);
                let source = scan_state.intern_metadata(&chunk.metadata.source_type);
                let file_path = chunk
                    .metadata
                    .path
                    .as_ref()
                    .map(|path| scan_state.intern_metadata(path));
                let commit = chunk
                    .metadata
                    .commit
                    .as_ref()
                    .map(|commit| scan_state.intern_metadata(commit));
                let author = chunk
                    .metadata
                    .author
                    .as_ref()
                    .map(|author| scan_state.intern_metadata(author));
                let date = chunk
                    .metadata
                    .date
                    .as_ref()
                    .map(|date| scan_state.intern_metadata(date));

                RawMatch {
                    credential_hash: crate::sha256_hash(&entropy_match.value),
                    detector_id,
                    detector_name,
                    service,
                    severity: keyhog_core::Severity::High,
                    credential,
                    companions: HashMap::new(),
                    location: MatchLocation {
                        source,
                        file_path,
                        // Window-local line plus chunk base line.
                        line: Some(absolute_line),
                        offset,
                        commit,
                        author,
                        date,
                    },
                    entropy: Some(entropy_match.entropy),
                    confidence: Some(confidence),
                }
            };

            // UNIFIED SCORING. When ML is live, route the entropy candidate
            // through the SAME MoE batch the detector/generic matches use, with
            // the model AUTHORITATIVE (no entropy-magnitude floor — see
            // `MlPendingMatch::model_authoritative`). The MoE separates real
            // high-entropy secrets (~0.98) from high-entropy NON-secrets (FQDNs,
            // git SHAs, base64 blobs ~0.01) that the shape gates above don't
            // catch, and `apply_ml_batch_scores` then runs the ONE canonical
            // penalty / path / calibration / checksum / floor pipeline — so this
            // path no longer needs a bespoke `apply_post_ml_penalties` +
            // `checksum_adjusted_confidence` tail (the batch path applies both,
            // identically). The shape gates above remain cheap, recall-safe
            // pre-filters.
            #[cfg(feature = "ml")]
            if self.config.ml_enabled && self.config.entropy_ml_authoritative {
                let raw_match = build_raw_match(scan_state, confidence);
                let text_context = crate::pipeline::local_context_window(
                    &preprocessed.text,
                    entropy_match.line,
                    crate::types::ML_CONTEXT_RADIUS_LINES,
                );
                let ml_context = match chunk.metadata.path.as_deref() {
                    Some(path) => format!("file:{path}\n{text_context}"),
                    None => text_context.to_string(),
                };
                scan_state.ml_pending.push(crate::types::MlPendingMatch {
                    raw_match,
                    heuristic_conf: confidence,
                    // The entropy fallback infers no rich code context (its anchor
                    // is keyword PROXIMITY, not an assignment parse) and the
                    // surrounding gates already handle test/docs shapes; Unknown
                    // applies no extra context multiplier, matching the
                    // pre-unification entropy emit.
                    code_context: crate::context::CodeContext::Unknown,
                    credential: entropy_match.value.to_string(),
                    ml_context,
                    model_authoritative: true,
                });
                continue;
            }

            // Non-ML path (the `ml` feature is compiled out, or ML disabled at
            // runtime). Emit directly with the entropy heuristic, routed through
            // the post-ML shape penalties and the single checksum policy exactly
            // as before: the uniform-base64-blob / encoded-binary / placeholder /
            // diversity penalties (×0.02) apply, then a prefix-bearing token with
            // an Invalid embedded CRC is dropped and a Valid one floored.
            let confidence =
                crate::confidence::apply_post_ml_penalties(confidence, &entropy_match.value, false);
            let Some(confidence) =
                crate::checksum::checksum_adjusted_confidence(confidence, &entropy_match.value)
            else {
                continue;
            };
            scan_state.push_match_lazy(
                crate::scanner_config::RawMatchPriority {
                    confidence: Some(confidence),
                    severity: keyhog_core::Severity::High,
                    detector_id: metadata.0.as_ref(),
                    credential: &entropy_match.value,
                    offset,
                    line: Some(absolute_line),
                },
                self.config.max_matches_per_chunk,
                |scan_state| build_raw_match(scan_state, confidence),
            );
        }
    }
}
