#[cfg(feature = "simdsieve")]
use super::*;
#[cfg(feature = "simdsieve")]
use crate::context;
#[cfg(feature = "simdsieve")]
use keyhog_core::{MatchLocation, RawMatch, Severity};
#[cfg(feature = "simdsieve")]
use std::collections::HashMap;

#[cfg(feature = "simdsieve")]
impl CompiledScanner {
    pub(crate) fn scan_hot_patterns_fast(
        &self,
        text: &str,
        preprocessed: &ScannerPreprocessedText,
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
        // `Vec<&[u8]>` per chunk via `.to_vec()` - wasted on every
        // file in a 100k-file scan.
        let Ok(sieve) = SimdSieve::new(text_bytes, HOT_PATTERNS) else {
            return;
        };

        for offset in sieve {
            if scan_state.matches.len() >= self.config.max_matches_per_chunk {
                break;
            }

            // First-byte (plus one disambiguating byte) dispatch instead of
            // an O(8) linear re-compare against every HOT_PATTERNS entry at
            // every sieve hit. SimdSieve already located the hit but only
            // yields the offset, so we still have to identify WHICH literal
            // matched - but the 8 hot literals are mutually-exclusive
            // prefixes keyed by their first byte (`g`/`s`/`A`/`S`/`x`), so a
            // single byte (two for the `s`/`A`/`x` collision pairs) selects
            // the lone candidate. That collapses the per-hit cost from 8 full
            // slice compares to one dispatch + one confirming compare. The
            // returned index is verified against the full literal below so
            // behavior is byte-identical to the old linear scan, just without
            // the redundant 7 compares.
            //
            //   0 ghp_     `g`
            //   1 sk-proj- `s` then `k`
            //   2 AKIA     `A` then `K`
            //   3 ASIA     `A` then `S`
            //   4 SG.      `S`
            //   5 xoxb-    `x` then 4th byte `b`
            //   6 xoxp-    `x` then 4th byte `p`
            //   7 sq0csp-  `s` then `q`
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
                    .unwrap_or(candidate.len());

                let credential = std::str::from_utf8(&candidate[..cred_end]).unwrap_or("");

                // Precise-regex gate. The literal-prefix hit + length floor
                // below is a fast prefilter, NOT proof of a real token: a
                // length floor admits wrong-character-class strings the
                // detector's own regex rejects (`ghp_THIS_HAS_UNDERSCORES…`
                // is 43 ≥ 40 but `_` is not in `[A-Za-z0-9]`;
                // `xoxp-123-456-789-abc` is 20 ≥ 16 but the segments are far
                // short of the 10-13-digit Slack shape). Validate the
                // candidate against the detector's regex (anchored at the
                // candidate start) and emit the PRECISE matched span, so the
                // fast path can never surface a finding the AC+regex path
                // would not. Slots with no canonical detector (square) carry
                // a `None` validator and keep the length-floor as their gate.
                let credential = match self.hot_pattern_validators.get(pattern_idx) {
                    Some(Some(validator)) => match validator.find(credential) {
                        // `^`-anchored, so any match starts at 0; trim the
                        // delimiter-bounded capture down to the real token.
                        Some(m) => {
                            if m.end() < credential.len()
                                && credential.as_bytes()[m.end()].is_ascii_alphanumeric()
                            {
                                continue;
                            }
                            &credential[..m.end()]
                        }
                        None => continue,
                    },
                    // No validator for this slot (square, or out of range):
                    // fall back to the length-floor-only behavior below.
                    _ => credential,
                };

                // Per-pattern minimum credential length, in bytes.
                // The 8-byte blanket floor would let `AKIA12345`
                // (9 bytes, only 5 after the 4-byte `AKIA` prefix)
                // through as a "real" AWS access key. Real AKIA
                // tokens are AKIA + 16 = 20 bytes minimum - tighten
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
                // Per-pattern minimum credential length, in bytes.
                // Each pattern's floor matches the actual minimum length
                // a valid token of that shape can have - fast-path
                // findings are emitted as Critical severity without
                // re-running the full detector regex, so a too-loose
                // floor turns every `SG.length` / `ghp_xxxx` / `xoxb-abc`
                // substring into a hard finding.
                //
                // Index aligns with simdsieve_prefilter::HOT_PATTERNS:
                //   0 ghp_      40  (ghp_ + 36 base62 = real GitHub PAT)
                //   1 sk-proj-  20  (sk-proj- + 12 - anthropic/openai newer keys)
                //   2 AKIA      20  (AKIA + 16 - already tightened, scanner_stress)
                //   3 ASIA      20  (ASIA + 16 - temporary AWS sts session creds)
                //   4 SG.       26  (SG. + 22 first-segment base64 minimum;
                //                    full SG.X22+.Y43+ is 69+ chars total)
                //   5 xoxb-     16  (xoxb- + 11 alnum minimum slack bot token)
                //   6 xoxp-     16  (xoxp- + 11 alnum minimum slack user token)
                //   7 sq0csp-   16  (sq0csp- + 9 alnum minimum square secret)
                //
                // Dogfood: pre-tightening the v0.5.19 binary fired
                // `SG.length` in claude-code's OAuthFlowStep.tsx
                // (PASTE_HERE_MSG.length substring) as Critical
                // sendgrid_key. SG. floor of 8 meant `SG.length` (9
                // chars) cleared. 26-floor leaves the first-segment
                // shape intact while killing the JS-property FP.
                const PER_PATTERN_MIN_LEN: &[usize] = &[40, 20, 20, 20, 26, 16, 16, 16];
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

                // Regex-literal suppression for the hot-pattern fast-path.
                // Source files that ship secret-scanner code (claude-code's
                // teamMemorySync/secretScanner.ts, components/Feedback.tsx,
                // every trufflehog / gitleaks competitor) emit hot findings
                // on their own regex DEFINITIONS - `AKIA[A-Z0-9]{16,17})/g`,
                // `ASIA[A-Z0-9]{16})\b`, `xoxb-[0-9-]*`. Real tokens never
                // end in regex sigils. The tail-suffix check is O(1).
                if crate::pipeline::looks_like_regex_literal_tail(credential) {
                    continue;
                }
                // Vendored 3rd-party minified bundle: same rationale as
                // the named-detector path. Random byte sequences in
                // minified codemirror/pdfjs/jquery/wp-includes bundles
                // routinely hit `AKIA…`/`ASIA…` literal-prefix patterns.
                if crate::pipeline::looks_like_vendored_minified_path(
                    chunk.metadata.path.as_deref(),
                ) {
                    continue;
                }
                // Native-binary string extraction: skip hot-pattern hits
                // on the strings-fallback source - same coverage rationale
                // as `should_suppress_named_detector_finding`.
                if chunk.metadata.source_type.contains("binary-strings")
                    || chunk.metadata.source_type.contains("archive-binary")
                {
                    continue;
                }
                // Secret-scanner source files (the dogfooded file IS itself
                // a secret scanner - claude-code's teamMemorySync/
                // secretScanner.ts, trufflehog/, gitleaks/, etc.) emit
                // hot-pattern findings on their own detector regex
                // DEFINITIONS. The `looks_like_regex_literal_tail` check
                // catches the common forms; decoder-mangled trailing
                // sigils slip past - this filter closes the gap.
                if crate::pipeline::looks_like_secret_scanner_source(chunk.metadata.path.as_deref())
                {
                    continue;
                }
                // Raw base64 / pure-alphabet files: alphabet-coincidence
                // matches inside the base64 stream (AKIA/ASIA/etc.) are
                // not credentials. Skim raw path bytes case-insensitively
                // so a per-match `.to_ascii_lowercase()` allocation never
                // lands on the hot-pattern path (this branch fires for
                // every AKIA/ASIA literal in every chunk).
                if chunk.metadata.path.as_deref().is_some_and(|p| {
                    let bytes = p.as_bytes();
                    if crate::ascii_ci::ends_with_ignore_ascii_case(bytes, b".b64")
                        || crate::ascii_ci::ends_with_ignore_ascii_case(bytes, b".base64")
                    {
                        return true;
                    }
                    // `/` AND `\\` for Windows paths - keeps the
                    // hot-pattern base64 filename gate working when
                    // the scanner runs against a Windows checkout.
                    let basename = bytes
                        .iter()
                        .rposition(|&b| b == b'/' || b == b'\\')
                        .map(|i| &bytes[i + 1..])
                        .unwrap_or(bytes);
                    (crate::ascii_ci::starts_with_ignore_ascii_case(basename, b"base64_")
                        || crate::ascii_ci::ci_find(basename, b"base64_string"))
                        && !crate::ascii_ci::ends_with_ignore_ascii_case(basename, b".json")
                        && !crate::ascii_ci::ends_with_ignore_ascii_case(basename, b".yml")
                        && !crate::ascii_ci::ends_with_ignore_ascii_case(basename, b".yaml")
                }) {
                    continue;
                }

                // Embedded-checksum adjudication for hot literals that carry a
                // self-verifying CRC (`ghp_`, `xoxb-`, `xoxp-`). The fast path
                // emits matches DIRECTLY - bypassing the regex/`process_match`
                // and ML scorers - so before this gate a fabricated `ghp_…`
                // survived at the 0.8 prefix floor and a confirmed one never
                // cleared the `--precision` 0.85 bar. Route through the single
                // shared policy so the fast path adjudicates checksums exactly
                // like every other emission path: `Invalid` drops the match,
                // `Valid` floors confidence at `CHECKSUM_VALID_FLOOR`, and a
                // checksum-less hot literal (AKIA/ASIA/SG./sk-proj-/sq0csp-)
                // keeps the prefix floor. Done before the metadata interning
                // below so a dropped token pays for none of it.
                let base_confidence =
                    crate::confidence::known_prefix_confidence_floor(credential).unwrap_or(0.7);
                let Some(confidence) =
                    crate::checksum::checksum_adjusted_confidence(base_confidence, credential)
                else {
                    continue;
                };

                let line = crate::pipeline::match_line_number(preprocessed, line_offsets, offset);

                // Use the pre-formatted static tables - eliminates the
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
                        confidence: Some(confidence),
                    },
                    self.config.max_matches_per_chunk,
                );
                // A single sieve offset can match at most one hot literal
                // (the 8 are mutually-exclusive prefixes), so there is no
                // remaining candidate to skip - fall through to the next
                // offset. This replaces the old `break` out of the per-offset
                // 8-pattern loop, which is now gone.
            }
        }
    }
}

/// Resolve a sieve hit at `offset` to the single
/// [`crate::simdsieve_prefilter::HOT_PATTERNS`] index whose literal can begin
/// there, or `None` if no hot literal does.
///
/// SimdSieve yields only the offset of a prefix hit, not which needle fired,
/// so the caller would otherwise re-compare all 8 hot literals at every hit
/// (`O(hits x 8 x patternlen)`). The 8 hot literals are mutually-exclusive
/// prefixes keyed almost entirely by their first byte, so one byte (a second
/// byte for the `s`/`A`/`x` collision pairs) selects the lone candidate. The
/// caller still confirms the full literal, so this is a dispatch, not the
/// verification - a wrong tail (`xoxq-`, `sk-Xroj-`) is rejected by the
/// caller's full-slice compare exactly as before.
///
/// Index-parallel with [`crate::simdsieve_prefilter::HOT_PATTERNS`]:
///   0 `ghp_`  1 `sk-proj-`  2 `AKIA`  3 `ASIA`
///   4 `SG.`   5 `xoxb-`     6 `xoxp-` 7 `sq0csp-`
#[cfg(feature = "simdsieve")]
#[inline]
fn hot_pattern_index_at(text_bytes: &[u8], offset: usize) -> Option<usize> {
    let rest = text_bytes.get(offset..)?;
    match *rest.first()? {
        b'g' => Some(0), // ghp_
        b'S' => Some(4), // SG.
        b's' => match *rest.get(1)? {
            // sk-proj- vs sq0csp-
            b'k' => Some(1),
            b'q' => Some(7),
            _ => None,
        },
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
