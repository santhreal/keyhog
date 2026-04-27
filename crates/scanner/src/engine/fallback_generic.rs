use super::*;
use std::collections::HashMap;

impl CompiledScanner {
    /// Scan for generic `SECRET_NAME = "high_entropy_value"` patterns.
    /// This is the precision-gated equivalent of Gitleaks's `generic-api-key`.
    /// Only fires when:
    ///   1. The variable name contains a secret-related keyword
    ///   2. The value has entropy >= 3.5 (random-looking)
    ///   3. No named detector already matched the same line
    ///   4. The value is not a known placeholder/example
    pub(crate) fn scan_generic_assignments(
        &self,
        code_lines: &[&str],
        chunk: &Chunk,
        scan_state: &mut ScanState,
    ) {
        use std::sync::LazyLock;
        static GENERIC_RE: LazyLock<Option<regex::Regex>> = LazyLock::new(|| {
            regex::Regex::new(
                r#"(?i)(?:secret|password|passwd|pwd|token|api[_-]?key|apikey|auth[_-]?token|auth[_-]?key|credential|private[_-]?key|signing[_-]?key|encryption[_-]?key|access[_-]?key|client[_-]?secret|app[_-]?secret|master[_-]?key|license[_-]?key)\s*[=:]\s*["'`]?([a-zA-Z0-9/+=_.!@#$%^&*-]{8,128})["'`]?"#
            ).ok()
        });
        let Some(generic_re) = GENERIC_RE.as_ref() else {
            return;
        };

        let covered_lines: std::collections::HashSet<usize> = {
            let lines: Vec<usize> = scan_state
                .matches
                .iter()
                .filter_map(|m| m.0.location.line)
                .collect();
            lines.into_iter().collect()
        };

        for (line_idx, line) in code_lines.iter().enumerate() {
            let line_num = line_idx + 1;
            if covered_lines.contains(&line_num) {
                continue;
            }

            for caps in generic_re.captures_iter(line) {
                let Some(value_match) = caps.get(1) else {
                    continue;
                };
                let value = value_match.as_str();

                // Entropy gate: reject low-entropy values (variable names, prose)
                let entropy = crate::pipeline::match_entropy(value.as_bytes());
                // Per-length entropy floor: short tokens (API keys) have lower
                // entropy than long random strings. A blanket 3.5 misses them.
                let min_entropy = if value.len() <= 24 {
                    2.8
                } else if value.len() <= 40 {
                    3.2
                } else {
                    3.5
                };
                if entropy < min_entropy {
                    continue;
                }

                // Length gate
                if value.len() < 8 {
                    continue;
                }

                // Variable-name filter: real secrets have mixed character classes.
                // Reject if the value looks like a code expression (has parens,
                // brackets, dots, or is pure snake_case/camelCase).
                if value.contains('(')
                    || value.contains('[')
                    || value.contains('{')
                    || value.contains(' ')
                {
                    continue;
                }
                // Allow dots ONLY in JWT-like patterns (exactly 2 dots separating
                // base64 segments). Reject other dotted values (method chains, FQDNs).
                if value.contains('.') {
                    let dot_count = value.chars().filter(|&c| c == '.').count();
                    let segments: Vec<&str> = value.split('.').collect();
                    let is_jwt_like = dot_count == 2
                        && segments.len() == 3
                        && segments.iter().all(|s| {
                            s.len() >= 4
                                && s.chars().all(|c| {
                                    c.is_ascii_alphanumeric()
                                        || c == '+'
                                        || c == '/'
                                        || c == '='
                                        || c == '-'
                                        || c == '_'
                                })
                        });
                    if !is_jwt_like {
                        continue;
                    }
                }
                // Reject pure identifiers: only alphanumeric + underscore
                if value.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                    // Must have at least one digit AND one letter to not be a variable name
                    let has_digit = value.chars().any(|c| c.is_ascii_digit());
                    let has_upper = value.chars().any(|c| c.is_ascii_uppercase());
                    let has_lower = value.chars().any(|c| c.is_ascii_lowercase());
                    if !(has_digit && (has_upper || has_lower)) {
                        continue;
                    }
                }

                // Placeholder suppression
                if crate::pipeline::should_suppress_known_example_credential_with_source(
                    value,
                    chunk.metadata.path.as_deref(),
                    crate::context::CodeContext::Unknown,
                    Some(chunk.metadata.source_type.as_str()),
                ) {
                    continue;
                }

                // Context suppression: test files get lower confidence
                let context = crate::context::infer_context(
                    code_lines,
                    line_idx,
                    chunk.metadata.path.as_deref(),
                );
                let base_conf = match context {
                    crate::context::CodeContext::TestCode => 0.25,
                    crate::context::CodeContext::Comment
                    | crate::context::CodeContext::Documentation => 0.30,
                    _ => 0.60,
                };

                // Boost confidence for longer, higher-entropy values
                let entropy_boost = ((entropy - 3.5) * 0.1).min(0.25);
                let length_boost = ((value.len() as f64 - 16.0) * 0.005).clamp(0.0, 0.15);
                let confidence = (base_conf + entropy_boost + length_boost).min(0.95);

                if confidence < self.config.min_confidence {
                    continue;
                }

                let raw = keyhog_core::RawMatch {
                    credential_hash: crate::sha256_hash(value),
                    detector_id: Arc::from("generic-secret"),
                    detector_name: Arc::from("Generic Secret (Key=Value)"),
                    service: Arc::from("generic"),
                    severity: keyhog_core::Severity::Medium,
                    credential: Arc::from(value),
                    companions: HashMap::new(),
                    location: keyhog_core::MatchLocation {
                        source: Arc::from(chunk.metadata.source_type.as_str()),
                        file_path: chunk.metadata.path.as_deref().map(Arc::from),
                        line: Some(line_num),
                        offset: 0,
                        commit: chunk.metadata.commit.as_deref().map(Arc::from),
                        author: chunk.metadata.author.as_deref().map(Arc::from),
                        date: chunk.metadata.date.as_deref().map(Arc::from),
                    },
                    entropy: Some(entropy),
                    confidence: Some(confidence),
                };
                scan_state.push_match(raw, self.config.max_matches_per_chunk);
            }
        }
    }
}
