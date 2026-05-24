#[cfg(feature = "simdsieve")]
use super::*;
#[cfg(feature = "simdsieve")]
use keyhog_core::{MatchLocation, RawMatch, Severity};
#[cfg(feature = "simdsieve")]
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
        use crate::simdsieve_prefilter::{
            HOT_PATTERNS, HOT_PATTERN_DETECTOR_IDS, HOT_PATTERN_DISPLAY_NAMES, HOT_PATTERN_NAMES,
        };
        use simdsieve::SimdSieve;

        let text_bytes = text.as_bytes();
        // SimdSieve takes `&[&[u8]]`; HOT_PATTERNS is already exactly
        // that, so pass it through. The previous flow built a fresh
        // `Vec<&[u8]>` per chunk via `.to_vec()` — wasted on every
        // file in a 100k-file scan.
        let Ok(sieve) = SimdSieve::new(text_bytes, HOT_PATTERNS) else {
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

                // Per-pattern minimum credential length, in bytes.
                // The 8-byte blanket floor would let `AKIA12345`
                // (9 bytes, only 5 after the 4-byte `AKIA` prefix)
                // through as a "real" AWS access key. Real AKIA
                // tokens are AKIA + 16 = 20 bytes minimum — tighten
                // the floor per-pattern so the fast-path never emits
                // a credential the matching detector's regex would
                // reject. See
                // tests/adversarial/engine_cases/scanner_stress.rs::
                // stress_minified_js_finds_real_pat_not_truncated_aws.
                //
                // The other hot patterns keep the loose 8-byte floor
                // because tightening them speculatively breaks the
                // base64 / hex / multi-line-split evasion-corpus
                // tests that exercise SHORT decoded fragments. Each
                // additional tightening needs its own per-pattern
                // regression gate first.
                //
                // Index aligns with simdsieve_prefilter::HOT_PATTERNS:
                //   0 ghp_      8
                //   1 sk-proj-  8
                //   2 AKIA     20  (tightened — see scanner_stress)
                //   3 ASIA     20  (tightened — see scanner_stress)
                //   4 SG.       8
                //   5 xoxb-     8
                //   6 xoxp-     8
                //   7 sq0csp-   8
                const PER_PATTERN_MIN_LEN: &[usize] = &[8, 8, 20, 20, 8, 8, 8, 8];
                let min_len = PER_PATTERN_MIN_LEN.get(pattern_idx).copied().unwrap_or(8);
                if credential.len() < min_len
                    || crate::pipeline::should_suppress_known_example_credential_with_source(
                        credential,
                        chunk.metadata.path.as_deref(),
                        context::CodeContext::Unknown,
                        Some(chunk.metadata.source_type.as_str()),
                    )
                {
                    continue;
                }

                // Same partition_point binary-search idiom as
                // `match_line_number` — `line_offsets` is sorted
                // ascending, so the first offset > `offset` IS the
                // 1-based line number directly.
                let line = line_offsets.partition_point(|&lo| lo <= offset).max(1);

                // Use the pre-formatted static tables — eliminates the
                // two `format!()` heap allocations the perf kimi audit
                // flagged at this site (one per match, 16 bytes each).
                // Index-parallel with HOT_PATTERN_NAMES; the parallel-
                // array invariant is locked by unit tests in the parent
                // module.
                let detector_id = scan_state.intern_metadata(HOT_PATTERN_DETECTOR_IDS[pattern_idx]);
                let detector_name =
                    scan_state.intern_metadata(HOT_PATTERN_DISPLAY_NAMES[pattern_idx]);
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
