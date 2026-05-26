#[cfg(feature = "entropy")]
use super::*;
#[cfg(feature = "entropy")]
use keyhog_core::MatchLocation;
#[cfg(feature = "entropy")]
use std::collections::HashMap;

#[cfg(feature = "entropy")]
impl CompiledScanner {
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
            // `entropy_match.offset` is ALREADY the byte offset of the
            // start of the containing line (set by `collect_line_candidates`
            // from the same `line_offsets` table). The earlier
            // `line_offsets[entropy_match.line - 1] + entropy_match.offset`
            // double-counted that base, producing offsets ~2× the file
            // size for findings late in the file — defect #80, 130+
            // corrupted finding offsets across the dogfood corpora. Use
            // the value directly. `_line_offsets` retained as a
            // parameter for the windowed/multiline paths that still need
            // it. `chunk.metadata.base_offset` is added for windowed
            // chunks (>64 MiB files) so the reported offset is the
            // absolute file offset, not the per-window one.
            let _ = line_offsets;
            let offset = entropy_match.offset + chunk.metadata.base_offset;

            // Hash-shape / UUID / license-key / RFC-JWT suppression.
            // The named-detector + generic-secret paths call
            // `should_suppress_known_example_credential_with_source`
            // before emitting; the entropy fallback was skipping it,
            // letting UUIDs, sha256 hex, license-key serials,
            // `nginx@sha256:...` docker digests, npm-lock integrity
            // values and the RFC 7519 specimen JWT through as
            // false positives. SecretBench-medium 15k seed-0:
            // 387 leaked FPs across uuid (127) + sha256-hex (118) +
            // sha1-hex (61) + npm-lock-integrity (102) + others.
            // Calling the gate here closes the leak without
            // touching the other emit paths.
            if crate::pipeline::should_suppress_known_example_credential_with_source(
                &entropy_match.value,
                chunk.metadata.path.as_deref(),
                crate::context::CodeContext::Unknown,
                Some(chunk.metadata.source_type.as_str()),
            ) {
                continue;
            }

            // kebab-case-identifier suppression: short values made
            // mostly of lowercase letters with 1+ dashes (e.g.
            // `api-key-secret`, `token-secret`, `db-password`) are
            // k8s/yaml `name:` metadata fields, NOT credentials.
            // The entropy fallback was firing on these as
            // `entropy-api-key` because `key` matched a keyword
            // anchor near the value — but the value itself is an
            // identifier, not a high-entropy random string.
            if entropy_path_looks_like_kebab_identifier(&entropy_match.value) {
                continue;
            }

            // Same standard-base64-arbitrary-bytes suppression the
            // generic-secret path applies. Reuses the [40, 300]
            // window + `+/` requirement; covers protobuf wire
            // dumps and k8s `data:` field values that the named-
            // detector path missed because they have no service-
            // specific keyword anchor.
            if entropy_path_looks_like_random_base64_blob(&entropy_match.value) {
                continue;
            }

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

/// `api-key-secret`, `token-secret`, `db-password`, `redis-creds`
/// style values are k8s/yaml `name:` or `metadata.name` field
/// payloads, NOT credentials. The entropy fallback was emitting
/// them as `entropy-api-key` because the surrounding line had
/// a `key:`/`secret:`/`token:` keyword anchor; the captured value
/// was the identifier on the next line.
///
/// Suppress when:
///   - length ≤ 24
///   - at least 1 internal `-`
///   - alphabet is dominated by lowercase letters (≥ 50%)
///   - no `+`/`/`/`=` (rules out short base64)
#[cfg(feature = "entropy")]
fn entropy_path_looks_like_kebab_identifier(value: &str) -> bool {
    if value.len() > 24 {
        return false;
    }
    let bytes = value.as_bytes();
    let dash_count = bytes.iter().filter(|&&b| b == b'-').count();
    if dash_count == 0 {
        return false;
    }
    let lower_count = bytes
        .iter()
        .filter(|&&b| (b as char).is_ascii_lowercase())
        .count();
    if lower_count * 2 < bytes.len() {
        return false;
    }
    !bytes.iter().any(|&b| matches!(b as char, '+' | '/' | '='))
}

#[cfg(feature = "entropy")]
fn entropy_path_looks_like_random_base64_blob(value: &str) -> bool {
    if !(40..=300).contains(&value.len()) {
        return false;
    }
    let has_padding = value.ends_with("==") || value.ends_with('=');
    let length_mult_4 = value.len().is_multiple_of(4);
    if !has_padding && !length_mult_4 {
        return false;
    }
    let mut has_b64_punct = false;
    for c in value.chars() {
        match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '=' => {}
            '+' | '/' => has_b64_punct = true,
            _ => return false,
        }
    }
    // Pure base62 with `==` padding is still a base64-of-bytes
    // signal (no real provider token needs `=` because their
    // lengths aren't byte-aligned base64 derivations). The entropy
    // fallback's generic-bucketing makes this the second-largest
    // residual FP class on the SecretBench mirror corpus.
    has_b64_punct || has_padding
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
