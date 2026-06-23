#[cfg(feature = "simdsieve")]
use super::*;
#[cfg(feature = "simdsieve")]
use keyhog_core::Severity;
#[cfg(feature = "simdsieve")]
use std::sync::Arc;

#[cfg(feature = "simdsieve")]
impl CompiledScanner {
    pub(crate) fn scan_hot_patterns_fast(
        &self,
        text: &str,
        preprocessed: &ScannerPreprocessedText<'_>,
        line_offsets: &[usize],
        chunk: &Chunk,
        scan_state: &mut ScanState,
    ) {
        // Metadata constants (HOT_PATTERN_DETECTOR_IDS/DISPLAY_NAMES/NAMES) are
        // no longer read here: they were pre-interned by slot index into
        // `self.hot_metadata_by_index` at construction and are cloned by index
        // below (PERF-locality_intern-1). Only the literal table is still
        // needed for the sieve + dispatch.
        use crate::simdsieve_prefilter::HOT_PATTERNS;
        use simdsieve::SimdSieve;

        let text_bytes = text.as_bytes();
        // SimdSieve takes `&[&[u8]]`; HOT_PATTERNS is already exactly
        // that, so pass it through. The previous flow built a fresh
        // `Vec<&[u8]>` per chunk via `.to_vec()` - wasted on every
        // file in a 100k-file scan.
        let Ok(sieve) = SimdSieve::new(text_bytes, HOT_PATTERNS) else {
            return;
        };

        for offset in sieve {
            // Resolve the SimdSieve offset to one table slot without a
            // linear HOT_PATTERNS scan. The full literal compare below remains
            // the verifier; this only handles first-byte collision families.
            let Some(pattern_idx) = hot_pattern_index_at(text_bytes, offset) else {
                continue;
            };
            {
                let pattern = HOT_PATTERNS[pattern_idx];
                let end = offset + pattern.len();
                // Confirm the full literal. `hot_pattern_index_at` only
                // inspects the first 1-2 bytes, so a candidate whose tail
                // diverges (e.g. `xoxq-`, `sk-pXoj-`) is rejected here exactly
                // as the old `&text_bytes[offset..end] != *pattern` guard did.
                if end > text_bytes.len() || &text_bytes[offset..end] != pattern {
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

                let credential = std::str::from_utf8(&candidate[..cred_end]).unwrap_or(""); // LAW10: missing/non-string field => empty; value then fails downstream shape/length checks, recall-safe
                let record_hot_drop =
                    |credential: &str, signal: crate::adjudicate::HotPatternSignal| {
                        let ctx = crate::adjudicate::MatchCtx::for_hot_pattern(signal);
                        crate::adjudicate::record_suppression(
                            chunk.metadata.path.as_deref(),
                            credential,
                            &ctx,
                        );
                    };

                // The literal-prefix hit plus length floor is only a prefilter.
                // The precise validator owns the emitted token span.
                let credential = match self.hot_pattern_validators.get(pattern_idx) {
                    Some(Some(validator)) => match validator.find(credential) {
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
                    // No validator for this slot (square, or out of range):
                    // fall back to the length-floor-only behavior below.
                    _ => credential,
                };
                // Per-pattern minimum credential length, in bytes.
                // Each pattern's floor matches the actual minimum length
                // a valid token of that shape can have - fast-path
                // findings are emitted as Critical severity without
                // re-running the full detector regex, so a too-loose
                // floor turns every `SG.length` / `ghp_xxxx` / `xoxb-abc`
                // substring into a hard finding.
                //
                // Index-parallel floors: ghp=40, sk-proj=20, AKIA/ASIA=20,
                // SG=26, Slack/Square=16, Stripe=32.
                //
                // Dogfood: pre-tightening the v0.5.19 binary fired
                // `SG.length` in claude-code's OAuthFlowStep.tsx
                // (PASTE_HERE_MSG.length substring) as Critical
                // sendgrid_key. SG. floor of 8 meant `SG.length` (9
                // chars) cleared. 26-floor leaves the first-segment
                // shape intact while killing the JS-property FP.
                const PER_PATTERN_MIN_LEN: &[usize] =
                    &[40, 20, 20, 20, 26, 16, 16, 16, 32, 32, 32, 32];
                let min_len = PER_PATTERN_MIN_LEN.get(pattern_idx).copied().unwrap_or(8); // LAW10: bounds-checked lookup; out-of-range => documented default (total fn), recall-safe
                let suppression_ctx = crate::suppression::HotPatternSuppressionCtx::new(
                    chunk.metadata.path.as_deref(),
                    chunk.metadata.source_type.as_str(),
                    min_len,
                );
                if let Some(signal) =
                    crate::suppression::hot_pattern_suppression_stage(credential, suppression_ctx)
                {
                    record_hot_drop(credential, signal);
                    continue;
                }

                let metadata = &self.hot_metadata_by_index[pattern_idx];
                let Some(confidence) = super::scoring::hot_pattern_confidence(
                    credential,
                    metadata.0.as_ref(),
                    chunk.metadata.path.as_deref(),
                    self.config.penalize_test_paths,
                    self.config.calibration.as_deref(),
                ) else {
                    record_hot_drop(
                        credential,
                        crate::adjudicate::HotPatternSignal::ChecksumInvalid,
                    );
                    continue;
                };

                let line = crate::pipeline::match_line_number(preprocessed, line_offsets, offset);

                let absolute_line = line + chunk.metadata.base_line;
                let source_offset =
                    preprocessed.source_offset_for_match(&chunk.data, offset, credential);
                let absolute_offset = source_offset + chunk.metadata.base_offset;
                scan_state.push_match_lazy(
                    crate::scanner_config::RawMatchPriority {
                        confidence: Some(confidence),
                        severity: Severity::Critical,
                        detector_id: metadata.0.as_ref(),
                        credential,
                        offset: absolute_offset,
                        line: Some(absolute_line),
                    },
                    self.config.max_matches_per_chunk,
                    |scan_state| {
                        // Clone the pre-interned metadata triple only after
                        // heap admission. Capped hot scans can fire many more
                        // candidates than they retain; rejected candidates must
                        // not still pay three metadata refcount bumps.
                        let detector_id = Arc::clone(&metadata.0);
                        let detector_name = Arc::clone(&metadata.1);
                        let service = Arc::clone(&metadata.2);
                        crate::pipeline::build_synthetic_raw_match(
                            (detector_id, detector_name, service),
                            Severity::Critical,
                            chunk,
                            credential,
                            absolute_offset,
                            Some(absolute_line),
                            None,
                            confidence,
                            scan_state,
                        )
                    },
                );
                // A single sieve offset can match at most one hot literal
                // (the prefixes are mutually-exclusive), so there is no
                // remaining candidate to skip - fall through to the next
                // offset. This replaces the old per-offset pattern loop.
            }
        }
    }
}

/// Resolve a sieve hit to the single HOT_PATTERNS slot that can begin there.
/// The caller still verifies the full literal; this is dispatch only.
#[cfg(feature = "simdsieve")]
#[inline]
fn hot_pattern_index_at(text_bytes: &[u8], offset: usize) -> Option<usize> {
    let rest = text_bytes.get(offset..)?;
    match *rest.first()? {
        b'g' => Some(0), // ghp_
        b'S' => Some(4), // SG.
        b's' => match *rest.get(1)? {
            b'k' if rest.starts_with(b"sk-proj-") => Some(1),
            b'k' if rest.starts_with(b"sk_live_") => Some(8),
            b'k' if rest.starts_with(b"sk_test_") => Some(9),
            b'q' => Some(7),
            _ => None,
        },
        b'r' => {
            if rest.starts_with(b"rk_live_") {
                Some(10)
            } else if rest.starts_with(b"rk_test_") {
                Some(11)
            } else {
                None
            }
        }
        b'A' => match *rest.get(1)? {
            // AKIA vs ASIA
            b'K' => Some(2),
            b'S' => Some(3),
            _ => None,
        },
        b'x' => match *rest.get(3)? {
            // xoxb- vs xoxp- (share `xox`)
            b'b' => Some(5),
            b'p' => Some(6),
            _ => None,
        },
        _ => None,
    }
}
