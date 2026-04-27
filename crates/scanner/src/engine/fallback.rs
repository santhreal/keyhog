use super::*;
use std::collections::HashMap;

impl CompiledScanner {
    #[allow(clippy::too_many_arguments, dead_code)]
    pub(crate) fn scan_fallback_patterns(
        &self,
        preprocessed: &ScannerPreprocessedText,
        line_offsets: &[usize],
        code_lines: &[&str],
        documentation_lines: &[bool],
        chunk: &Chunk,
        scan_state: &mut ScanState,
        deadline: Option<std::time::Instant>,
    ) {
        if let Some(deadline) = deadline {
            if std::time::Instant::now() >= deadline {
                return;
            }
        }

        if preprocessed.text.len() > LARGE_FALLBACK_SCAN_THRESHOLD && !self.fallback.is_empty() {
            self.scan_large_fallback_patterns(
                preprocessed,
                line_offsets,
                code_lines,
                documentation_lines,
                chunk,
                scan_state,
                deadline,
            );
            return;
        }
        let active_patterns = self.active_fallback_patterns(&chunk.data);

        for (index, (entry, _keywords)) in self.fallback.iter().enumerate() {
            if !active_patterns[index] {
                continue;
            }
            if let Some(deadline) = deadline {
                if index.is_multiple_of(16) && std::time::Instant::now() >= deadline {
                    break;
                }
            }
            self.extract_matches(
                entry,
                preprocessed,
                line_offsets,
                code_lines,
                documentation_lines,
                chunk,
                scan_state,
                0,
                0,
            );
        }
    }

    fn active_fallback_patterns(&self, data: &str) -> Vec<bool> {
        if let Some(keyword_ac) = &self.fallback_keyword_ac {
            let mut active = vec![false; self.fallback.len()];
            for (index, (_pattern, keywords)) in self.fallback.iter().enumerate() {
                if !keywords.iter().any(|keyword| keyword.len() >= 4) {
                    active[index] = true;
                }
            }
            for mat in keyword_ac.find_iter(data) {
                let keyword_idx = mat.pattern().as_usize();
                if keyword_idx < self.fallback_keyword_to_patterns.len() {
                    for &pattern_idx in &self.fallback_keyword_to_patterns[keyword_idx] {
                        if pattern_idx < active.len() {
                            active[pattern_idx] = true;
                        }
                    }
                }
            }
            active
        } else {
            vec![true; self.fallback.len()]
        }
    }

    #[allow(clippy::too_many_arguments, dead_code)]
    fn scan_large_fallback_patterns(
        &self,
        preprocessed: &ScannerPreprocessedText,
        line_offsets: &[usize],
        code_lines: &[&str],
        documentation_lines: &[bool],
        chunk: &Chunk,
        scan_state: &mut ScanState,
        deadline: Option<std::time::Instant>,
    ) {
        let active_set = self.active_fallback_patterns(&chunk.data);
        let active_fallback: Vec<&CompiledPattern> = self
            .fallback
            .iter()
            .enumerate()
            .filter(|(index, _)| active_set[*index])
            .map(|(_, (entry, _))| entry)
            .collect();

        if active_fallback.is_empty() {
            return;
        }

        for (index, entry) in active_fallback.iter().enumerate() {
            if let Some(deadline) = deadline {
                if index.is_multiple_of(16) && std::time::Instant::now() >= deadline {
                    break;
                }
            }
            self.extract_matches(
                entry,
                preprocessed,
                line_offsets,
                code_lines,
                documentation_lines,
                chunk,
                scan_state,
                0,
                0,
            );
        }
    }

    pub(crate) fn match_companions(
        &self,
        entry: &CompiledPattern,
        preprocessed: &ScannerPreprocessedText,
        line: usize,
    ) -> Option<HashMap<String, String>> {
        let mut results = HashMap::new();
        if let Some(detector_companions) = self.companions.get(entry.detector_index) {
            for companion in detector_companions {
                if let Some(val) = find_companion(preprocessed, line, companion) {
                    results.insert(companion.name.clone(), val);
                } else if companion.required {
                    return None;
                }
            }
        }
        Some(results)
    }

    pub(crate) fn match_confidence(
        &self,
        entry: &CompiledPattern,
        detector: &DetectorSpec,
        code_lines: &[&str],
        documentation_lines: &[bool],
        chunk: &Chunk,
        credential: &str,
        data: &str,
        line: usize,
        entropy: f64,
        has_companion: bool,
        scan_state: &mut ScanState,
    ) -> Option<MlScoreResult> {
        let raw_conf =
            crate::confidence::compute_confidence(&crate::confidence::ConfidenceSignals {
                has_literal_prefix: extract_literal_prefix(entry.regex.as_str()).is_some(),
                has_context_anchor: entry.group.is_some(),
                entropy,
                keyword_nearby: detector
                    .keywords
                    .iter()
                    .any(|keyword| chunk.data.contains(keyword.as_str())),
                sensitive_file: chunk
                    .metadata
                    .path
                    .as_deref()
                    .map(crate::confidence::is_sensitive_path)
                    .unwrap_or(false),
                match_length: credential.len(),
                has_companion,
            });

        // Checksum validation is handled in process_match (early reject for Invalid,
        // confidence floor for Valid). No need to re-validate here.

        let context = context::infer_context_with_documentation(
            code_lines,
            line.saturating_sub(PREVIOUS_LINE_DISTANCE),
            chunk.metadata.path.as_deref(),
            documentation_lines,
        );
        let heuristic_conf = raw_conf * context.confidence_multiplier();
        let score_result = self.calculate_final_score(
            heuristic_conf,
            context,
            credential,
            data,
            line,
            chunk,
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

                if context.should_hard_suppress(final_score) {
                    None
                } else {
                    Some(MlScoreResult::Final(final_score))
                }
            }
            #[cfg(feature = "ml")]
            MlScoreResult::Pending { .. } => Some(score_result),
        }
    }

    fn calculate_final_score(
        &self,
        heuristic_conf: f64,
        context: CodeContext,
        credential: &str,
        data: &str,
        line: usize,
        chunk: &Chunk,
        _scan_state: &mut ScanState,
    ) -> Option<MlScoreResult> {
        #[cfg(not(feature = "ml"))]
        {
            let _ = (context, credential, data, line, chunk);
            Some(MlScoreResult::Final(heuristic_conf))
        }

        #[cfg(feature = "ml")]
        {
            if !crate::probabilistic_gate::ProbabilisticGate::looks_promising(credential) {
                return Some(MlScoreResult::Final(0.1));
            }

            let text_context = local_context_window(data, line, ML_CONTEXT_RADIUS_LINES);
            let ml_context = match chunk.metadata.path.as_deref() {
                Some(path) => format!("file:{path}\n{text_context}"),
                None => text_context,
            };

            Some(MlScoreResult::Pending {
                heuristic_conf,
                code_context: context,
                credential: credential.to_string(),
                ml_context,
            })
        }
    }
}
