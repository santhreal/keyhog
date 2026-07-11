use super::*;
use std::cell::RefCell;
use std::sync::LazyLock;

pub(crate) mod keywords;
mod line_mapping;
mod metrics;

use self::keywords::{
    collect_generic_keyword_lines, collect_generic_keyword_lines_from_positions,
    is_strong_keyword_anchored_encoded_text_secret, is_strong_keyword_anchored_hex_key,
};
use self::line_mapping::line_at_index;
pub(crate) use self::metrics::{generic_profile_dump, generic_profile_reset};

// The value/assignment tail of `GENERIC_RE`: the assignment-syntax grammar,
// benign secret-suffix hops, and the group-2 value shape. Held as ONE named
// constant so the alternation builder (below) and any test compile the exact
// same grammar — there is no second copy of this pattern.
// PER-DETECTOR-MIGRATION-BLOCKED: The static regex tail bounds (8..128) cannot be made per-detector at compile-time as they are baked into the single global GENERIC_RE.
const GENERIC_RE_ASSIGNMENT_TAIL: &str = r#"(?:[._-]?(?:key|base|value|val|string|str|enc|raw|b64)){0,2}["'`]?\s*(?::\s*(?:&?[a-zA-Z_][a-zA-Z0-9_<>]{0,31}\s*[=:]\s*)?|=\s*)["'`]?([a-zA-Z0-9/+=_.:!@#$%^&*-]{8,128})["'`]?"#;

// Structural (non-literal) group-1 arm: any bounded `<vendor>_key` / `_secret` /
// `_token` compound, so a vendor-prefixed credential key bridges even when its
// exact spelling is not one of the derived keyword literals. This is a SHAPE, not
// a keyword, so it is NOT part of the vocabulary — it is appended after the
// derived literals. (The `regression_creddata_vendor_prefixed_key_recall` test
// locks its behavior.)
pub(crate) const GENERIC_RE_VENDOR_SUFFIX_ARM: &str =
    r"[a-z][a-z0-9]*(?:[._-][a-z0-9]+){0,2}[._-](?:key|secret|token)";

/// Build the group-1 keyword alternation from the SINGLE derived vocabulary
/// (`crate::assignment_keywords::assignment_keywords()`): regex-escaped literals,
/// longest-first, with the vendor structural arm appended last.
///
/// ONE HOME: the keyword vocabulary is NOT hand-maintained here — it is the same
/// list the phase-2 prefilter (`assignment_keywords`) derives by unioning the
/// generic phase-2 detector specs. Widening a generic detector's `keywords`
/// widens this alternation automatically, and a second hand-kept list cannot
/// reappear without the dedup-lock test failing.
pub(crate) fn generic_keyword_alternation() -> String {
    let mut literals: Vec<&str> = crate::assignment_keywords::assignment_keywords()
        .iter()
        .map(String::as_str)
        .collect();
    // Longest-first (ties broken lexically) keeps a longer keyword alternative
    // preferred and the alternation byte-stable across builds. (The assignment
    // tail already forces the longest full match, so this is determinism, not
    // correctness.)
    literals.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
    let mut alternation = String::new();
    for literal in literals {
        alternation.push_str(&regex::escape(literal));
        alternation.push('|');
    }
    alternation.push_str(GENERIC_RE_VENDOR_SUFFIX_ARM);
    alternation
}

/// Compile `GENERIC_RE` from a pre-built group-1 alternation. Kept separate from
/// the `LazyLock` init so the exact construction is unit-testable AND so the
/// fail-closed contract can be exercised with a deliberately malformed alternation.
pub(crate) fn compile_generic_re(
    alternation: &str,
) -> std::result::Result<regex::Regex, regex::Error> {
    // Group 1 is the keyword, group 2 is the value.
    regex::Regex::new(&format!("(?i)({alternation}){GENERIC_RE_ASSIGNMENT_TAIL}"))
}

/// Compile `GENERIC_RE` from the live derived vocabulary.
pub(crate) fn build_generic_re() -> std::result::Result<regex::Regex, regex::Error> {
    compile_generic_re(&generic_keyword_alternation())
}

pub(crate) static GENERIC_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    // LAW 10 — FAIL CLOSED. This regex is built from a hardcoded assignment
    // grammar plus the binary-baked derived keyword vocabulary. A compile failure
    // is a BUILD/SOURCE defect, never a runtime condition an operator can act on.
    // The previous code returned `None` on failure, which SILENTLY disabled the
    // ENTIRE generic value bridge (the dominant CredData `*_PASS=` / `secret:`
    // recall surface) — an invisible recall hole. There is no recall-preserving
    // alternative, so panic: the build/CI must catch it, and we refuse to ship a
    // scanner with its generic bridge gone dark.
    build_generic_re().unwrap_or_else(|error| {
        panic!(
            "GENERIC_RE failed to compile: {error}. It is built from a hardcoded assignment \
             grammar and the derived generic-keyword vocabulary \
             (crate::assignment_keywords::assignment_keywords()); a compile failure is a build \
             defect, not a runtime condition. Refusing to run with the generic-secret value \
             bridge disabled."
        )
    })
});

pub(crate) fn warm_generic_assignment_runtime() {
    // LAW10: eager init/warm-up. Also validates the fail-closed compile invariant
    // up front (a broken vocabulary panics here, at warm-up, not mid-scan).
    LazyLock::force(&GENERIC_RE);
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
    ///   2. The value clears the length-tiered Tier-B family entropy floor
    ///      (random-looking), tightened further by the `--entropy-threshold` knob
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
        deadline: Option<std::time::Instant>,
    ) {
        // LAW10 fail-closed: `GENERIC_RE` is an infallible `LazyLock<Regex>` — a
        // compile failure panics at init (build defect), it never silently
        // disables the bridge here.
        let generic_re: &regex::Regex = &GENERIC_RE;

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
            scan_state.extend_lines_with_pending_ml_matches(&mut lines);
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
        if crate::deadline::expired(deadline) {
            KEYWORD_LINES_POOL.with(|cell| cell.replace(lines_with_keyword));
            return;
        }

        let extract_start = profile_enabled.then(std::time::Instant::now);
        let mut preprocessed_code_lines_cache: Option<Vec<&str>> = None;
        let mut preprocessed_documentation_lines_cache: Option<Vec<bool>> = None;
        for line_iter in 0..lines_with_keyword.len() {
            if crate::deadline::expired_on_cadence(
                deadline,
                line_iter,
                crate::deadline::HOT_LOOP_DEADLINE_CADENCE,
            ) {
                metrics::record_extract_ns(extract_start);
                KEYWORD_LINES_POOL.with(|cell| cell.replace(lines_with_keyword));
                return;
            }
            let line_idx = lines_with_keyword[line_iter];
            let Some(&line_offset) = line_offsets.get(line_idx) else {
                continue;
            };
            let mapped_line =
                crate::pipeline::match_line_number(preprocessed, line_offsets, line_offset);
            let abs_line_num = absolute_line(chunk.metadata.base_line, mapped_line);
            if covered_lines.contains(&abs_line_num) {
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

            for (capture_iter, caps) in generic_re.captures_iter(line).enumerate() {
                if crate::deadline::expired_on_cadence(
                    deadline,
                    capture_iter,
                    crate::deadline::HOT_LOOP_DEADLINE_CADENCE,
                ) {
                    metrics::record_extract_ns(extract_start);
                    KEYWORD_LINES_POOL.with(|cell| cell.replace(lines_with_keyword));
                    return;
                }
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
                if crate::adjudicate::generic_bridge_keyword_boundary_rejected(
                    keyword,
                    line,
                    keyword_match.start(),
                ) {
                    let generic_ctx = crate::adjudicate::MatchCtx::for_generic_bridge(
                        crate::adjudicate::GenericBridgeSignal::KeywordBoundary,
                    );
                    crate::adjudicate::record_suppression(
                        chunk.metadata.path.as_deref(),
                        keyword,
                        &generic_ctx,
                    );
                    continue;
                }
                if crate::generic_keyword_owner::keyword_span_owned_by_named_detector(
                    &self.generic_named_assignment_keywords,
                    line,
                    keyword_match.start(),
                    keyword_match.end(),
                ) {
                    let generic_ctx = crate::adjudicate::MatchCtx::for_generic_bridge(
                        crate::adjudicate::GenericBridgeSignal::NamedDetectorOwnedKeyword,
                    );
                    crate::adjudicate::record_suppression(
                        chunk.metadata.path.as_deref(),
                        keyword,
                        &generic_ctx,
                    );
                    continue;
                }
                let value = value_match.as_str();
                if crate::adjudicate::generic_bridge_bare_auth_rejected(keyword, value) {
                    let generic_ctx = crate::adjudicate::MatchCtx::for_generic_bridge(
                        crate::adjudicate::GenericBridgeSignal::BareAuthUnstructured,
                    );
                    crate::adjudicate::record_suppression(
                        chunk.metadata.path.as_deref(),
                        value,
                        &generic_ctx,
                    );
                    continue;
                }
                // Entropy gate: reject low-entropy values (variable names, prose).
                // Routed through the SINGLE threshold-aware
                // `crate::adjudicate::generic_entropy_floor` owner (via
                // `generic_bridge_entropy_below_floor`) — the same source of truth
                // the named-detector generic path uses — so the per-family,
                // length-bucketed base floor (Tier-B `entropy_floor` data in each
                // generic detector's TOML) is identical AND the operator's Tier-A
                // `--entropy-threshold` tightens this gate too. Raising the knob
                // above its 4.5 default lifts the floor to that bits/byte value,
                // suppressing values below it.
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

                // O(1) compiled lookup of the owning generic detector (or the
                // GENERIC_SECRET fallback), replacing a per-candidate linear
                // `self.detectors.iter().find(...)` scan over every detector.
                // `generic_owning_detector` preserves the exact original
                // first-match-by-exact-or-normalized-keyword semantics.
                let owning_detector = self
                    .generic_owning_detector
                    .owning_index(keyword)
                    .map(|index| &self.detectors[index]);

                let owning_detector_min_len = owning_detector.and_then(|d| d.min_len).unwrap_or(8);
                let owning_detector_entropy_high = owning_detector
                    .and_then(|d| d.entropy_high)
                    .unwrap_or(crate::entropy::HIGH_ENTROPY_THRESHOLD);
                let owning_detector_id = owning_detector
                    .map(|d| d.id.as_str())
                    .unwrap_or(crate::detector_ids::GENERIC_SECRET);
                let owning_detector_name = owning_detector
                    .map(|d| d.name.as_str())
                    .unwrap_or("Generic Secret (Key=Value)");
                let owning_detector_service = owning_detector
                    .map(|d| d.service.as_str())
                    .unwrap_or("generic");
                let owning_detector_severity = owning_detector
                    .map(|d| d.severity)
                    .unwrap_or(keyhog_core::Severity::Medium);

                let entropy_threshold = if self.config.entropy_threshold.is_finite()
                    && self.config.entropy_threshold > crate::entropy::HIGH_ENTROPY_THRESHOLD
                {
                    owning_detector_entropy_high.max(self.config.entropy_threshold)
                } else {
                    owning_detector_entropy_high
                };

                // KH-L-0412: the generic-bridge shape gauntlet was the last
                // SILENT suppression path. Record the firing gate's name so a
                // dropped generic-secret candidate is visible to `--dogfood`
                // (Law-10), then continue. Zero-cost when dogfood is off (the
                // `is_dogfood_enabled()` atomic short-circuits before any work).
                let mut shape_rejected = self.generic_value_shape_rejected(
                    value,
                    entropy,
                    chunk,
                    allow_canonical_hex_key,
                    allow_encoded_text_secret,
                );

                // The `--keyword-low-entropy` knob relaxes the generic-bridge
                // entropy floor to the GENERIC_KEYWORD_SECRET floor for EVERY
                // generic assignment; when off, each candidate is held to its
                // owning detector's calibrated floor. This per-detector
                // re-validation MUST honor the knob exactly as the shape-file
                // gate (`generic_value_shape_rejected` →
                // `generic_bridge_entropy_below_floor`) does — otherwise the knob
                // is silently HALF-WIRED: the shape gate admits the low-entropy
                // value under the relaxed floor, then this re-check drops it again
                // under the strict owning-detector floor (the #9 regression).
                let floor_detector_id = if self.config.generic_keyword_low_entropy {
                    crate::detector_ids::GENERIC_KEYWORD_SECRET
                } else {
                    owning_detector_id
                };
                if let Some(reason) = shape_rejected {
                    match reason {
                        crate::adjudicate::GenericValueShapeStage::ValueTooShort => {
                            if value.len() >= owning_detector_min_len {
                                shape_rejected = None;
                            }
                        }
                        crate::adjudicate::GenericValueShapeStage::EntropyBelowFloor => {
                            if !crate::adjudicate::generic_entropy_below_floor(
                                entropy,
                                entropy_threshold,
                                floor_detector_id,
                                value.len(),
                            ) {
                                shape_rejected = None;
                            }
                        }
                        _ => {}
                    }
                } else {
                    // Even if shape_rejected is None, we still need to enforce the per-detector length & entropy gates!
                    if value.len() < owning_detector_min_len {
                        shape_rejected =
                            Some(crate::adjudicate::GenericValueShapeStage::ValueTooShort);
                    } else if crate::adjudicate::generic_entropy_below_floor(
                        entropy,
                        entropy_threshold,
                        floor_detector_id,
                        value.len(),
                    ) {
                        shape_rejected =
                            Some(crate::adjudicate::GenericValueShapeStage::EntropyBelowFloor);
                    }
                }

                // BPE "rare-not-random" gate — LAST, so it only tokenizes values
                // that survived every cheaper generic shape gate (bounded cost),
                // mirroring the entropy path. Word-like values (dotted API paths,
                // prose, XML) are non-secrets. Mirror-safe: verified 0 word-like
                // generic TP on the mirror corpus, so recall is untouched. Gated on
                // `entropy` (the tokenizer rides that feature); when off, generic
                // FP simply aren't BPE-filtered.
                #[cfg(feature = "entropy")]
                if shape_rejected.is_none() {
                    let bpe_bound = crate::entropy::bpe::max_bytes_per_token_for_detector(
                        owning_detector,
                        self.config.entropy_bpe_max_bytes_per_token,
                        self.config.entropy_bpe_max_bytes_per_token_override,
                    );
                    if crate::entropy::bpe::is_word_like_low_bpe(value, bpe_bound) {
                        shape_rejected =
                            Some(crate::adjudicate::GenericValueShapeStage::WordLikeLowBpe);
                    }
                }

                if let Some(reason) = shape_rejected {
                    let generic_ctx = crate::adjudicate::MatchCtx::for_generic_bridge(
                        crate::adjudicate::GenericBridgeSignal::ValueShape(reason),
                    );
                    // A VALUE-SHAPE rejection is about the captured value's shape,
                    // so the suppression telemetry must be keyed on `value` — NOT
                    // the anchoring `keyword` (matching the `BareAuthUnstructured`
                    // value-based drop above). Keying it on the keyword hid the
                    // gate name (`base64_blob`, …) behind the keyword token, so the
                    // dropped value was untraceable through `--dogfood` (KH-L-0412).
                    crate::adjudicate::record_suppression(
                        chunk.metadata.path.as_deref(),
                        value,
                        &generic_ctx,
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
                let policy_conf = crate::confidence::policy::generic_secret_confidence(
                    context,
                    self.config.scan_comments,
                    self.config.penalize_test_paths,
                    entropy,
                    value.len(),
                );

                // Route through the SAME report-confidence finalizer the ML and
                // named-detector emit paths use. `is_named=false` keeps the
                // generic fallback's shape penalties active; the encoded-text
                // lift is the one extra raw signal this path contributes.
                let min_confidence_floor = crate::adjudicate::detector_min_confidence_floor(
                    owning_detector.and_then(|detector| detector.min_confidence),
                    self.config.min_confidence,
                );
                let Some(report_conf) = crate::adjudicate::finalize_report_candidate(
                    chunk.metadata.path.as_deref(),
                    value,
                    crate::adjudicate::ReportAdjudicationPolicy {
                        detector_id: owning_detector_id,
                        code_context: context,
                        confidence: policy_conf,
                        min_confidence_floor,
                        penalize_test_paths: self.config.penalize_test_paths,
                        file_path: chunk.metadata.path.as_deref(),
                        is_named_detector: false,
                        allow_encoded_text_lift: allow_encoded_text_secret,
                        calibration: self.config.calibration.as_deref(),
                    },
                ) else {
                    continue;
                };

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
                let Some(absolute_offset) =
                    absolute_offset(chunk.metadata.base_offset, source_offset)
                else {
                    continue;
                };
                let raw = crate::pipeline::build_synthetic_raw_match(
                    (
                        Arc::from(owning_detector_id),
                        Arc::from(owning_detector_name),
                        Arc::from(owning_detector_service),
                    ),
                    owning_detector_severity,
                    chunk,
                    value,
                    absolute_offset,
                    Some(absolute_line(chunk.metadata.base_line, mapped_line)),
                    Some(entropy),
                    report_conf,
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
}
