#[cfg(feature = "simdsieve")]
use super::*;

#[cfg(feature = "simdsieve")]
impl CompiledScanner {
    pub(crate) fn scan_hot_patterns_fast(
        &self,
        text: &str,
        preprocessed: &ScannerPreprocessedText<'_>,
        line_offsets: &[usize],
        code_lines: &[&str],
        documentation_lines: &[bool],
        chunk: &Chunk,
        scan_state: &mut ScanState,
    ) {
        use crate::simdsieve_prefilter::{hot_pattern_index_at, HOT_PATTERNS};
        use simdsieve::SimdSieve;

        let text_bytes = text.as_bytes();
        // SimdSieve takes `&[&[u8]]`; HOT_PATTERNS is already exactly
        // that, so pass it through. The previous flow built a fresh
        // `Vec<&[u8]>` per chunk via `.to_vec()` - wasted on every
        // file in a 100k-file scan.
        let sieve = match SimdSieve::new(text_bytes, HOT_PATTERNS) {
            Ok(sieve) => sieve,
            Err(error) => {
                tracing::warn!(
                    target: "keyhog::scanner::simdsieve",
                    %error,
                    "simdsieve hot-pattern acceleration unavailable for this chunk; standard scanner remains active"
                );
                return;
            }
        };

        for offset in sieve {
            // Resolve the SimdSieve offset to the table-owned hot-pattern slot.
            let Some(pattern_idx) = hot_pattern_index_at(text_bytes, offset) else {
                continue;
            };
            {
                let pattern = HOT_PATTERNS[pattern_idx];
                let end = offset + pattern.len();
                // Confirm the full literal at this offset. The table-owned
                // resolver already uses the same literal table, so this is a
                // cheap invariant check before span extraction.
                if end > text_bytes.len() || &text_bytes[offset..end] != pattern {
                    continue;
                }

                let ac_map_index = self.hot_ac_map_index_by_index[pattern_idx];
                let Some(ac_map_index) = ac_map_index else {
                    continue;
                };

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
                            || byte == b'\\'
                            || byte == b';'
                            || byte == b','
                            || byte == b'('
                            || byte == b')'
                            || byte == b'['
                            || byte == b']'
                            || byte == b'{'
                            || byte == b'}'
                            || byte < 0x20
                    })
                    .unwrap_or(candidate.len()); // LAW10: search/boundary miss => span end (whole remainder), recall-safe boundary default

                let credential_end = super::floor_char_boundary(text, offset + cred_end);
                if credential_end <= offset {
                    continue;
                }
                let credential = &text[offset..credential_end];
                let record_hot_drop =
                    |credential: &str, signal: crate::adjudicate::HotPatternSignal| {
                        let ctx = crate::adjudicate::MatchCtx::for_hot_pattern(signal);
                        crate::adjudicate::record_suppression(
                            chunk.metadata.path.as_deref(),
                            credential,
                            &ctx,
                        );
                    };

                // The literal-prefix hit is only a prefilter. The precise
                // validator owns the emitted token span; process_match owns
                // every suppression, checksum, confidence, ML, and reporting
                // policy after that.
                let credential = match &self.hot_pattern_validators[pattern_idx] {
                    Some(validator) => match validator.find(credential) {
                        // `^`-anchored, so any match starts at 0; trim the
                        // delimiter-bounded capture down to the real token.
                        Some(m) => {
                            if m.end() < credential.len()
                                && credential.as_bytes()[m.end()].is_ascii_alphanumeric()
                            {
                                record_hot_drop(
                                    credential,
                                    crate::adjudicate::HotPatternSignal::ShapeGate(
                                        "hot_regex_validation_rejected",
                                    ),
                                );
                                continue;
                            }
                            &credential[..m.end()]
                        }
                        None => {
                            record_hot_drop(
                                credential,
                                crate::adjudicate::HotPatternSignal::ShapeGate(
                                    "hot_regex_validation_rejected",
                                ),
                            );
                            continue;
                        }
                    },
                    None => continue,
                };

                let entry = &self.ac_map[ac_map_index];
                let detector = &self.detectors[entry.detector_index];
                let (keyword_nearby, sensitive_file) = super::scan_filters::compute_pattern_signals(
                    entry,
                    detector,
                    chunk,
                    preprocessed,
                );
                self.process_match(
                    entry,
                    detector,
                    text,
                    preprocessed,
                    line_offsets,
                    code_lines,
                    documentation_lines,
                    chunk,
                    scan_state,
                    credential,
                    offset,
                    offset + credential.len(),
                    0,
                    0,
                    keyword_nearby,
                    sensitive_file,
                );
                // A single sieve offset can match at most one hot literal
                // (the prefixes are mutually-exclusive), so there is no
                // remaining candidate to skip - fall through to the next
                // offset. This replaces the old per-offset pattern loop.
            }
        }
    }
}
