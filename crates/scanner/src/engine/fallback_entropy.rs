use super::*;
use std::collections::HashMap;

impl CompiledScanner {
    #[cfg(feature = "entropy")]
    pub(crate) fn scan_entropy_fallback(
        &self,
        preprocessed: &ScannerPreprocessedText,
        line_offsets: &[usize],
        chunk: &Chunk,
        scan_state: &mut ScanState,
    ) {
        if !self.config.entropy_enabled {
            return;
        }
        if !crate::entropy::is_entropy_appropriate(
            chunk.metadata.path.as_deref(),
            self.config.entropy_in_source_files,
        ) {
            return;
        }

        // Skip entropy scanning on lines that already have named detector matches.
        let mut skip_lines = std::collections::HashSet::new();
        for m in &scan_state.matches {
            let id = &*m.0.detector_id;
            if !id.starts_with("generic-") && !id.starts_with("entropy-") {
                if let Some(line) = m.0.location.line {
                    skip_lines.insert(line);
                }
            }
        }

        let keyword_free_threshold =
            if crate::entropy::is_sensitive_file(chunk.metadata.path.as_deref()) {
                crate::entropy::SENSITIVE_FILE_VERY_HIGH_ENTROPY_THRESHOLD
            } else {
                crate::entropy::VERY_HIGH_ENTROPY_THRESHOLD
            };

        let entropy_matches = crate::entropy::find_entropy_secrets_with_threshold(
            &preprocessed.text,
            16,
            1,
            self.config.entropy_threshold,
            keyword_free_threshold,
            &self.config.secret_keywords,
            &self.config.test_keywords,
            &self.config.placeholder_keywords,
            Some(&skip_lines),
        );

        for entropy_match in entropy_matches {
            let (detector_id_value, detector_name_value, service_value) =
                classify_entropy_detector(&entropy_match.keyword);
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
            let offset = if entropy_match.line > 0 && entropy_match.line <= line_offsets.len() {
                line_offsets[entropy_match.line - 1] + entropy_match.offset
            } else {
                entropy_match.offset
            };

            let detector_id = scan_state.intern_metadata(detector_id_value);
            let detector_name = scan_state.intern_metadata(detector_name_value);
            let service = scan_state.intern_metadata(service_value);
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

            scan_state.push_match(
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
                        line: Some(entropy_match.line),
                        offset,
                        commit,
                        author,
                        date,
                    },
                    entropy: Some(entropy_match.entropy),
                    confidence: Some(confidence),
                },
                self.config.max_matches_per_chunk,
            );
        }
    }
}

#[cfg(feature = "entropy")]
fn classify_entropy_detector(keyword: &str) -> (&'static str, &'static str, &'static str) {
    if keyword == "none (high-entropy)" {
        ("entropy-generic", "Generic High-Entropy Secret", "generic")
    } else if keyword.contains("password") || keyword.contains("pwd") {
        ("entropy-password", "Password (Entropy Detected)", "generic")
    } else if keyword.contains("token") {
        ("entropy-token", "API Token (Entropy Detected)", "generic")
    } else {
        ("entropy-api-key", "API Key (Entropy Detected)", "generic")
    }
}
