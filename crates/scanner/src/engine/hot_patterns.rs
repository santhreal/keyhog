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
        use crate::simdsieve_prefilter::hot_pattern_index_at;
        use simdsieve::SimdSieve;

        let text_bytes = text.as_bytes();
        if self.hot_pattern_slots.is_empty() {
            return;
        }
        let mut patterns: [&[u8]; 16] = [&[]; 16];
        for (target, slot) in patterns.iter_mut().zip(&self.hot_pattern_slots) {
            *target = &slot.prefix;
        }
        let patterns = &patterns[..self.hot_pattern_slots.len()];
        let sieve = match SimdSieve::new(text_bytes, patterns) {
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
            let Some(pattern_idx) =
                hot_pattern_index_at(&self.hot_pattern_slots, text_bytes, offset)
            else {
                continue;
            };
            {
                let pattern = self.hot_pattern_slots[pattern_idx].prefix.as_ref();
                let end = offset + pattern.len();
                // Confirm the full literal at this offset. The table-owned
                // resolver already uses the same literal table, so this is a
                // cheap invariant check before span extraction.
                if end > text_bytes.len() || &text_bytes[offset..end] != pattern {
                    continue;
                }

                // One slot owns BOTH this pattern's `ac_map` delegate and its
                // precise validator, so `pattern_idx` resolves them together and
                // they cannot drift apart. Direct `[pattern_idx]` indexing (not
                // `.get()`) keeps the construction-time length invariant loud:
                // an out-of-range slot is a corrupt build, not a silent skip.
                let slot = &self.hot_pattern_slots[pattern_idx];
                let ac_map_index = slot.ac_map_index;

                // Bound the delimiter search to a fixed lookahead window past the
                // literal prefix: every hot-pattern credential is well under this
                // many bytes, so scanning further only wastes work on an
                // adversarial no-delimiter run. The precise validator below still
                // owns the emitted span; this only caps the candidate slice fed to it.
                const HOT_CREDENTIAL_LOOKAHEAD_BYTES: usize = 100;
                let lookahead_end = (offset + HOT_CREDENTIAL_LOOKAHEAD_BYTES).min(text_bytes.len());
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
                let credential = match slot.validator.find(credential) {
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
                };

                let entry = &self.ac_map[ac_map_index];
                let detector_plan = self.detector_plans.get(entry.detector_index);
                let (keyword_nearby, sensitive_file) = super::scan_filters::compute_pattern_signals(
                    entry,
                    &detector_plan.execution,
                    chunk,
                    preprocessed,
                );
                self.process_match(
                    entry,
                    detector_plan,
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
