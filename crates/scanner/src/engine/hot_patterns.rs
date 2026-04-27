use super::*;
use std::collections::HashMap;

#[cfg(feature = "simdsieve")]
impl CompiledScanner {
    pub(crate) fn scan_hot_patterns_fast(
        &self,
        text: &str,
        line_offsets: &[usize],
        chunk: &Chunk,
        scan_state: &mut ScanState,
    ) {
        use crate::simdsieve_prefilter::{HOT_PATTERNS, HOT_PATTERN_NAMES};
        use simdsieve::SimdSieve;

        let text_bytes = text.as_bytes();
        let patterns_ref: Vec<&[u8]> = HOT_PATTERNS.to_vec();
        let Ok(sieve) = SimdSieve::new(text_bytes, &patterns_ref) else {
            return;
        };

        for offset in sieve {
            if scan_state.matches.len() >= self.config.max_matches_per_chunk {
                break;
            }

            for (pattern_idx, pattern) in HOT_PATTERNS.iter().enumerate() {
                let end = offset + pattern.len();
                if end > text_bytes.len() || &text_bytes[offset..end] != *pattern {
                    continue;
                }

                let lookahead_end = (offset + 100).min(text_bytes.len());
                let candidate = &text_bytes[offset..lookahead_end];
                let cred_end = candidate
                    .iter()
                    .position(|&byte| {
                        byte == b' '
                            || byte == b'\n'
                            || byte == b'\r'
                            || byte == b'"'
                            || byte == b'\''
                    })
                    .unwrap_or(candidate.len());

                let credential = std::str::from_utf8(&candidate[..cred_end]).unwrap_or("");
                if credential.len() < 8
                    || crate::pipeline::should_suppress_known_example_credential_with_source(
                        credential,
                        chunk.metadata.path.as_deref(),
                        context::CodeContext::Unknown,
                        Some(chunk.metadata.source_type.as_str()),
                    )
                {
                    continue;
                }

                let line = line_offsets
                    .iter()
                    .position(|&line_offset| line_offset > offset)
                    .unwrap_or(line_offsets.len())
                    .saturating_sub(1)
                    + 1;

                let detector_id_value = format!("hot-{}", HOT_PATTERN_NAMES[pattern_idx]);
                let detector_name_value =
                    format!("Hot Pattern: {}", HOT_PATTERN_NAMES[pattern_idx]);
                let detector_id = scan_state.intern_metadata(&detector_id_value);
                let detector_name = scan_state.intern_metadata(&detector_name_value);
                let service = scan_state.intern_metadata(HOT_PATTERN_NAMES[pattern_idx]);
                let credential_shared = scan_state.intern_credential(credential);
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
                        credential_hash: crate::sha256_hash(credential),
                        detector_id,
                        detector_name,
                        service,
                        severity: Severity::Critical,
                        credential: credential_shared,
                        companions: HashMap::new(),
                        location: MatchLocation {
                            source,
                            file_path,
                            line: Some(line),
                            offset,
                            commit,
                            author,
                            date,
                        },
                        entropy: None,
                        confidence: Some(
                            crate::confidence::known_prefix_confidence_floor(credential)
                                .unwrap_or(0.7), // Hot patterns are high-confidence by definition
                        ),
                    },
                    self.config.max_matches_per_chunk,
                );
                break;
            }
        }
    }
}
