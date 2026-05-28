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
                // not credentials.
                if chunk.metadata.path.as_deref().is_some_and(|p| {
                    let lower = p.to_ascii_lowercase();
                    if lower.ends_with(".b64") || lower.ends_with(".base64") {
                        return true;
                    }
                    // `/` AND `\\` for Windows paths - keeps the
                    // hot-pattern base64 filename gate working when
                    // the scanner runs against a Windows checkout.
                    let basename = lower.rsplit(['/', '\\']).next().unwrap_or(&lower);
                    basename.starts_with("base64_") || basename.contains("base64_string")
                }) {
                    continue;
                }

                // Same partition_point binary-search idiom as
                // `match_line_number` - `line_offsets` is sorted
                // ascending, so the first offset > `offset` IS the
                // 1-based line number directly.
                let line = line_offsets.partition_point(|&lo| lo <= offset).max(1);

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
