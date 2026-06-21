use super::*;
use std::cell::RefCell;
use std::sync::LazyLock;

mod auth_value;
pub(crate) mod keywords;
mod line_mapping;
mod metrics;
pub(crate) mod shape_helpers;

use self::auth_value::bare_auth_value_allowed;
use self::keywords::{
    collect_generic_keyword_lines, collect_generic_keyword_lines_from_positions,
    is_strong_keyword_anchored_encoded_text_secret, is_strong_keyword_anchored_hex_key,
    keyword_has_word_boundary, normalize_assignment_keyword,
    normalized_assignment_keyword_has_secret_suffix,
};
use self::line_mapping::line_at_index;
pub(crate) use self::metrics::{generic_profile_dump, generic_profile_reset};

static GENERIC_RE: LazyLock<Option<regex::Regex>> = LazyLock::new(|| {
    // Group 1 is the keyword, group 2 is the value. The regex accepts common
    // assignment syntaxes, benign secret suffixes, and bounded vendor-prefixed
    // `*_key` / `*_secret` / `*_token` anchors. Whole-word and shape precision
    // stay in code gates below, where camelCase and hash-decoy handling are
    // testable without regex lookbehind.
    match regex::Regex::new(
        r#"(?i)(secret|passphrase|password|passwd|pwd|pass|token|webhook[._-]?url|api[._-]?key|apikey|auth[._-]?token|auth[._-]?key|authorization|auth|credential|private[._-]?key|signing[._-]?key|encryption[._-]?key|access[._-]?key|client[._-]?secret|app[._-]?secret|master[._-]?key|license[._-]?key|[a-z][a-z0-9]*(?:[._-][a-z0-9]+){0,2}[._-](?:key|secret|token))(?:[._-]?(?:key|base|value|val|string|str|enc|raw|b64)){0,2}["'`]?\s*(?::\s*(?:&?[a-zA-Z_][a-zA-Z0-9_<>]{0,31}\s*[=:]\s*)?|=\s*)["'`]?([a-zA-Z0-9/+=_.:!@#$%^&*-]{8,128})["'`]?"#,
    ) {
        Ok(re) => Some(re),
        // Law 10: this static, build-from-constant regex compiling is a build
        // invariant. If it ever fails the generic value bridge (the dominant
        // CredData `*_PASS=` / `secret:` surface) goes dark — there is no
        // recall-preserving alternative, so surface it as loudly as possible.
        Err(e) => {
            crate::prefilter_degrade::warn_prefilter_disabled(
                "generic-assignment value bridge (GENERIC_RE)",
                &e,
            );
            None
        }
    }
});

pub(crate) fn warm_generic_assignment_runtime() {
    let _ = GENERIC_RE.as_ref(); // LAW10: forces lazy-static/regex eager init (warm-up); not a fallback
}

thread_local! {
    /// Per-thread pool for the `lines_with_keyword` scratch buffer.
    ///
    /// `scan_generic_assignments` runs on every chunk and previously did a
    /// fresh `Vec::new()` + grow per chunk. Across a 100k-file scan on rayon
    /// workers that is a flood of tiny allocations. Pool one buffer per worker:
    /// take it out, fill it, drain it, hand it back - resized once, resliced
    /// thereafter. Mirrors `ACTIVE_PATTERNS_POOL` / `TRIGGER_POOL`.
    static KEYWORD_LINES_POOL: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
}

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
        preprocessed: &ScannerPreprocessedText<'_>,
        line_offsets: &[usize],
        code_lines: &[&str],
        documentation_lines: &[bool],
        chunk: &Chunk,
        scan_state: &mut ScanState,
        generic_keyword_positions: Option<&[u32]>,
    ) {
        let Some(generic_re) = GENERIC_RE.as_ref() else {
            return;
        };

        // Lines already carrying named findings do not need a generic bridge
        // echo. Include ML-pending findings too: they have not been finalized
        // yet, but they already represent named detector matches on the line.
        let covered_lines: std::collections::HashSet<usize> = scan_state
            .matches
            .iter()
            .filter_map(|m| m.location.line)
            .collect();
        #[cfg(feature = "ml")]
        let covered_lines = {
            let mut lines = covered_lines;
            lines.extend(
                scan_state
                    .ml_pending
                    .iter()
                    .filter_map(|pending| pending.raw_match.location.line),
            );
            lines
        };

        // ONE chunk-level derived-stem scan instead of N per-line scans.
        // Profile showed scan_generic_assignments at ~500 µs/chunk -
        // dominant non-ML cost. The keyword owner derives the same compact stem
        // set from the generic keyword list, walks bytes once, tracks line
        // numbers during the pass, and skips the rest of a line after the first
        // stem hit because the heavier regex needs only a per-line admission
        // decision.
        let scan_text: &str = &preprocessed.text;
        let identity_offsets = std::ptr::eq(scan_text.as_ptr(), chunk.data.as_ptr())
            && scan_text.len() == chunk.data.len();
        // Borrow the pooled scratch buffer for the duration of this scan.
        // `take` leaves an empty Vec in the cell so the heavy consume loop
        // below does not hold a live RefCell borrow (which would conflict
        // with any re-entrant pool use); the buffer is returned at function
        // exit, preserving its capacity for the next chunk on this worker.
        let mut lines_with_keyword = KEYWORD_LINES_POOL.with(|cell| cell.take());
        lines_with_keyword.clear();
        let profile_enabled = super::profile::enabled();
        let prefilter_start = profile_enabled.then(std::time::Instant::now);
        if let Some(positions) = generic_keyword_positions {
            collect_generic_keyword_lines_from_positions(
                line_offsets,
                positions,
                &mut lines_with_keyword,
            );
        } else {
            collect_generic_keyword_lines(scan_text, &mut lines_with_keyword);
        }
        metrics::record_prefilter_ns(prefilter_start);
        if profile_enabled {
            metrics::record_prefilter_call(lines_with_keyword.len());
        }
        if lines_with_keyword.is_empty() {
            // Return the (now-empty) buffer to the pool before bailing so its
            // capacity survives for the next chunk.
            KEYWORD_LINES_POOL.with(|cell| cell.replace(lines_with_keyword));
            return;
        }

        let extract_start = profile_enabled.then(std::time::Instant::now);
        let mut preprocessed_code_lines_cache: Option<Vec<&str>> = None;
        let mut preprocessed_documentation_lines_cache: Option<Vec<bool>> = None;
        for &line_idx in &lines_with_keyword {
            let Some(&line_offset) = line_offsets.get(line_idx) else {
                continue;
            };
            let mapped_line =
                crate::pipeline::match_line_number(preprocessed, line_offsets, line_offset);
            let absolute_line = mapped_line + chunk.metadata.base_line;
            if covered_lines.contains(&absolute_line) {
                continue;
            }
            let Some(raw_line) = line_at_index(scan_text, line_offsets, line_idx) else {
                continue;
            };
            // The chunk-level AC told us this line has a keyword;
            // proceed straight to the heavy regex extraction.
            //
            // Evasion-resistant extraction: the named-detector path matches on
            // the homoglyph/zero-width-normalized chunk text, but this generic
            // fallback historically captured from the raw line, so a soft hyphen
            // (U+00AD) or other zero-width byte planted *inside* a value
            // truncated the capture (`abcde12345abcde<U+00AD>12345` ->
            // `abcde12345abcde`). Normalize the candidate line the same way
            // before extraction so an evaded secret is recovered whole. The Cow
            // borrows for pure-ASCII lines (the 99% case), so there is no alloc
            // and no behavior change off the evasion path. Line indexing, the
            // keyword AC prefilter, context inference and the reported offset all
            // remain in raw coordinates; only the captured value is de-evaded,
            // and an in-value zero-width never shifts the value's start offset.
            let normalized_line = crate::unicode_hardening::normalize_homoglyphs(raw_line);
            let line: &str = &normalized_line;

            for caps in generic_re.captures_iter(line) {
                if profile_enabled {
                    metrics::record_regex_capture();
                }
                let Some(keyword_match) = caps.get(1) else {
                    continue;
                };
                let Some(value_match) = caps.get(2) else {
                    continue;
                };
                // Whole-word left boundary, enforced ONLY for the short,
                // substring-ambiguous abbreviation `pass` (the tail of
                // `bypass`/`compass`/`surpass`/...). The longer keywords
                // (`password`, `token`, `secret`, `api_key`, ...) deliberately
                // keep substring matching so concatenated no-separator keys like
                // `DBPASSWORD=` / `apitoken=` still bridge — measured on CredData,
                // enforcing the boundary on every keyword cost ~36 real positives
                // for no precision gain. `pass` alone needs the guard because its
                // false-substring family (`bypass=`/`compass=`) is common.
                let keyword = keyword_match.as_str();
                if (keyword.eq_ignore_ascii_case("pass") || keyword.eq_ignore_ascii_case("auth"))
                    && !keyword_has_word_boundary(line, keyword_match.start())
                {
                    continue;
                }
                if self.generic_keyword_owned_by_named_detector(keyword) {
                    crate::telemetry::record_shape_suppression(
                        chunk.metadata.path.as_deref(),
                        keyword,
                        "generic_named_detector_owned_keyword",
                    );
                    continue;
                }
                let value = value_match.as_str();
                if keyword.eq_ignore_ascii_case("auth") && !bare_auth_value_allowed(value) {
                    crate::telemetry::record_shape_suppression(
                        chunk.metadata.path.as_deref(),
                        value,
                        "bare_auth_unstructured",
                    );
                    continue;
                }
                // Entropy gate: reject low-entropy values (variable names, prose).
                // Routed through the SINGLE threshold-aware
                // `generic_entropy_floor` helper (engine/scan_filters.rs) — the
                // same source of truth the named-detector generic path uses — so
                // the per-length base floor (2.8 / 3.2 / 3.5 at the default) is
                // identical AND the operator's Tier-A `--entropy-threshold`
                // tightens this gate too. Raising the knob above its 4.5 default
                // lifts the floor to that bits/byte value, suppressing values
                // below it.
                let entropy = crate::pipeline::match_entropy(value.as_bytes());
                // KH-L-0110: a complete pure-hex value of canonical key length
                // (32/48) under a STRONG credential keyword is a real key, not a
                // hash digest — exempt it from the bare-hex-digest shape gate
                // (every other gate still applies). See the helper for the
                // CredData/mirror soundness argument.
                let allow_canonical_hex_key =
                    is_strong_keyword_anchored_hex_key(keyword_match.as_str(), value);
                let allow_encoded_text_secret =
                    is_strong_keyword_anchored_encoded_text_secret(keyword_match.as_str(), value)
                        || crate::decode_structure::decodes_to_printable_text(value);
                // KH-L-0412: the generic-bridge shape gauntlet was the last
                // SILENT suppression path. Record the firing gate's name so a
                // dropped generic-secret candidate is visible to `--dogfood`
                // (Law-10), then continue. Zero-cost when dogfood is off (the
                // `is_dogfood_enabled()` atomic short-circuits before any work).
                if let Some(reason) = self.generic_value_shape_rejected(
                    value,
                    entropy,
                    chunk,
                    allow_canonical_hex_key,
                    allow_encoded_text_secret,
                ) {
                    crate::telemetry::record_shape_suppression(
                        chunk.metadata.path.as_deref(),
                        value,
                        reason,
                    );
                    continue;
                }

                // Context suppression: test files get lower confidence. On the
                // byte-identical common path, reuse the lines and documentation
                // flags already computed by the phase-2 caller; recomputing
                // documentation flags for every generic candidate was
                // O(candidates * lines). Synthesized structured/multiline text
                // still builds its own cached context view so appended lines
                // keep correct line indices.
                let context = if identity_offsets {
                    crate::context::infer_context_with_documentation(
                        code_lines,
                        line_idx,
                        chunk.metadata.path.as_deref(),
                        documentation_lines,
                    )
                } else {
                    let preprocessed_code_lines = preprocessed_code_lines_cache
                        .get_or_insert_with(|| scan_text.lines().collect());
                    let preprocessed_documentation_lines = preprocessed_documentation_lines_cache
                        .get_or_insert_with(|| {
                            crate::context::documentation_line_flags(
                                preprocessed_code_lines.as_slice(),
                            )
                        });
                    crate::context::infer_context_with_documentation(
                        preprocessed_code_lines.as_slice(),
                        line_idx,
                        chunk.metadata.path.as_deref(),
                        preprocessed_documentation_lines.as_slice(),
                    )
                };
                let confidence = super::scoring::generic_secret_confidence(
                    context,
                    self.config.scan_comments,
                    self.config.penalize_test_paths,
                    entropy,
                    value.len(),
                );

                // Route through the SAME canonical post-ML penalty pipeline the
                // ML / named-detector emit path uses (scan_postprocess/ml.rs). The
                // generic-secret fallback historically emitted via `push_match`
                // and BYPASSED it, so the random-base64 / encoded-binary /
                // placeholder blob penalties (×0.02) never reached this path -
                // that bypass IS the base64-protobuf FP class (the lost
                // separation pipeline closed exactly this wiring gap). `is_named
                // = false`: generic-secret is an unanchored fallback, so the
                // shape penalties (char-diversity / repeat-run / uniform-base64
                // -blob / encoded-binary) all apply. A real short/base62 secret
                // clears every check unchanged; only a 44+ char raw-base64-blob
                // or encoded-binary value (the decoy class) is slammed ×0.02
                // below the floor. Applied BEFORE the checksum floor so a valid
                // embedded CRC still overrides shape and surfaces the token, and
                // a user can recover the penalized blob with `--min-confidence`.
                let confidence = crate::confidence::apply_post_ml_penalties_with_encoded_text_lift(
                    confidence,
                    value,
                    false,
                    allow_encoded_text_secret,
                );

                // Shared checksum policy on the generic-secret fallback emit
                // path: a prefix-bearing token (`ghp_`/`npm_`/…) with an
                // Invalid embedded CRC is dropped, and a Valid one is floored
                // before the min-confidence gate so a confirmed token clears
                // the bar even on the phase-2 path.
                let Some(confidence) = super::scoring::apply_checksum_confidence(confidence, value)
                else {
                    // A prefix-bearing token with an INVALID embedded checksum is a
                    // confirmed false positive — trace the drop (KH-L-0412, Law-10)
                    // so it is not silent, mirroring the named path's
                    // `checksum_invalid` engine gate.
                    crate::telemetry::record_shape_suppression(
                        chunk.metadata.path.as_deref(),
                        value,
                        "checksum_invalid",
                    );
                    continue;
                };

                if confidence < self.config.min_confidence {
                    continue;
                }

                // Defect #80: this branch hard-coded `offset: 0` for every
                // generic-secret finding, so a `KEY = <secret>` on line 845
                // of a 137 KiB file reported offset 0 - the start of the
                // file - making the JSON impossible to navigate or grep.
                // The real offset is the start of the value within the
                // line, plus the line's start in the chunk, plus the
                // chunk's base offset in the original file (non-zero on
                // windowed >64 MiB scans).
                let preprocessed_offset = line_offset + value_match.start();
                let mapped_line = crate::pipeline::match_line_number(
                    preprocessed,
                    line_offsets,
                    preprocessed_offset,
                );
                let source_offset =
                    preprocessed.source_offset_for_match(&chunk.data, preprocessed_offset, value);
                let absolute_offset = chunk.metadata.base_offset + source_offset;
                let raw = crate::pipeline::build_synthetic_raw_match(
                    (
                        Arc::from(crate::detector_ids::GENERIC_SECRET),
                        Arc::from("Generic Secret (Key=Value)"),
                        Arc::from("generic"),
                    ),
                    keyhog_core::Severity::Medium,
                    chunk,
                    value,
                    absolute_offset,
                    Some(mapped_line + chunk.metadata.base_line),
                    Some(entropy),
                    confidence,
                    scan_state,
                );
                scan_state.push_match(raw, self.config.max_matches_per_chunk);
                if profile_enabled {
                    metrics::record_emit();
                }
            }
        }
        metrics::record_extract_ns(extract_start);
        // Return the scratch buffer to the pool, preserving its capacity for
        // the next chunk this worker handles.
        KEYWORD_LINES_POOL.with(|cell| cell.replace(lines_with_keyword));
    }

    fn generic_keyword_owned_by_named_detector(&self, keyword: &str) -> bool {
        if self.generic_named_assignment_keywords.is_empty() {
            return false;
        }
        let Some(normalized) = normalize_assignment_keyword(keyword) else {
            return false;
        };
        if !normalized_assignment_keyword_has_secret_suffix(&normalized) {
            return false;
        }
        self.generic_named_assignment_keywords
            .binary_search_by(|owned| owned.as_ref().cmp(normalized.as_str()))
            .is_ok()
    }
}
