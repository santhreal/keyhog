use super::*;
use std::cell::RefCell;

pub(crate) mod keywords;
mod line_mapping;
mod metrics;
mod pattern;

use self::keywords::{
    collect_generic_keyword_lines_from_positions, collect_generic_keyword_lines_with,
    is_strong_keyword_anchored_encoded_text_secret,
};
use self::line_mapping::line_at_index;
pub(crate) use self::metrics::{generic_profile_dump, generic_profile_reset};
pub(crate) use self::pattern::{
    build_generic_re, compile_generic_re_with_max, generic_keyword_alternation,
    generic_keyword_alternation_from_with_vendor_fallback, GENERIC_RE_VENDOR_SUFFIX_ARM,
};

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
        let Some(generic_re) = self.generic_assignment_re.as_ref() else {
            return;
        };
        let Some(generic_keyword_stems) = self.generic_keyword_stems.as_ref() else {
            tracing::error!(
                "generic assignment regex exists without its compiled keyword prefilter"
            );
            return;
        };

        // Lines already carrying finalized named findings do not need a generic
        // bridge echo. ML-pending candidates deliberately do NOT claim the line:
        // the model may reject them, and suppressing the generic bridge before
        // that verdict creates a recall hole. If the named candidate survives,
        // the normal resolution pass removes the generic duplicate.
        let covered_lines: std::collections::HashSet<usize> = scan_state
            .matches
            .iter()
            .filter_map(|m| m.location.line)
            .collect();

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
            collect_generic_keyword_lines_with(
                generic_keyword_stems,
                scan_text,
                &mut lines_with_keyword,
            );
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
                // `DBPASSWORD=` / `apitoken=` still bridge, measured on CredData,
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
                // Resolve the detector before any detector-specific value gate.
                // The bare-auth bridge must use the same compiled TOML policy as
                // the entropy, shape, and BPE stages below.
                let Some(owner_resolution) = self.generic_owning_detector.resolve(keyword) else {
                    tracing::error!(
                        keyword,
                        "compiled generic assignment matched without a detector owner; dropping candidate"
                    );
                    continue;
                };
                let owning_detector_index = owner_resolution.owning_index;
                let detector_plan = self.detector_plans.get(owning_detector_index);
                let execution_policy = &detector_plan.execution;
                let metadata = &detector_plan.metadata;
                let Some(owning_policy) = detector_plan.entropy.as_ref() else {
                    tracing::error!(
                        detector_id = metadata.0.as_ref(),
                        "generic assignment owner has no compiled entropy policy; dropping candidate"
                    );
                    continue;
                };
                let preprocessed_offset = line_offset + value_match.start();
                let transport_decoded =
                    preprocessed.transport_decoded_for_offset(preprocessed_offset);
                if crate::adjudicate::generic_bridge_bare_auth_rejected(
                    keyword,
                    value,
                    owning_policy,
                ) {
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
                // `generic_entropy_below_floor`), the same source of truth
                // the named-detector generic path uses, so the per-family,
                // length-bucketed base floor (Tier-B `entropy_floor` data in each
                // generic detector's TOML) is identical AND the operator's Tier-A
                // `--entropy-threshold` tightens this gate too. The shared owner
                // compares the raw scan setting with the selected detector's
                // `entropy_high`, then lifts the floor when the setting is
                // stricter. This bridge must not pre-resolve against a global
                // threshold because detector-local calibration can differ.
                let entropy = crate::pipeline::match_entropy(value.as_bytes());
                let owning_detector_max_len = owning_policy.max_len;
                let canonical_key_material_policy =
                    self.detector_plans.get(owner_resolution.canonical_index);
                // A complete pure-hex value admitted by the detector that
                // declares its canonical policy is key material rather than a
                // digest. Missing detector policy fails closed. Ordinary
                // keyword policy ownership remains separate for entropy/BPE.
                let allow_canonical_hex_key = {
                    if transport_decoded {
                        canonical_key_material_policy
                            .key_material
                            .allows_decoded_hex(value)
                    } else {
                        canonical_key_material_policy
                            .key_material
                            .allows_canonical_hex(keyword_match.as_str(), value)
                    }
                };
                let allow_encoded_text_secret =
                    is_strong_keyword_anchored_encoded_text_secret(keyword_match.as_str(), value)
                        || crate::decode_structure::decodes_to_printable_text(value);
                let allow_decoded_hex_key_material = self
                    .detector_plans
                    .get(owning_detector_index)
                    .key_material
                    .allows_decoded_hex_len(
                        crate::decode_structure::evidence(value).decoded_hex_text_len(),
                    );

                // KH-L-0412: the generic-bridge shape gauntlet was the last
                // SILENT suppression path. Record the firing gate's name so a
                // dropped generic-secret candidate is visible to `--dogfood`
                // (Law-10), then continue. Zero-cost when dogfood is off (the
                // `is_dogfood_enabled()` atomic short-circuits before any work).
                let shape_rejected = if value.len() > owning_detector_max_len {
                    Some(crate::adjudicate::GenericValueShapeStage::ValueTooLong)
                } else {
                    self.generic_value_shape_rejected(
                        value,
                        entropy,
                        chunk,
                        owning_detector_index,
                        owning_policy,
                        allow_canonical_hex_key,
                        allow_encoded_text_secret,
                        allow_decoded_hex_key_material,
                    )
                };

                // BPE "rare-not-random" gate. LAST, so it only tokenizes values
                // that survived every cheaper generic shape gate (bounded cost),
                // mirroring the entropy path. Word-like values (dotted API paths,
                // prose, XML) are non-secrets. Mirror-safe: verified 0 word-like
                // generic TP on the mirror corpus, so recall is untouched. Gated on
                // `entropy` (the tokenizer rides that feature); when off, generic
                // FP simply aren't BPE-filtered. Detector-owned canonical hex
                // key material skips this language-likeness test: hexadecimal
                // subwords tokenize efficiently by construction, and the exact
                // keyword/length policy is the stronger signal for that shape.
                #[cfg(feature = "entropy")]
                let shape_rejected = shape_rejected.or_else(|| {
                    if allow_canonical_hex_key || allow_encoded_text_secret {
                        return None;
                    }
                    owning_policy
                        .bpe_bound(self.config.entropy_bpe_max_bytes_per_token_override)
                        .filter(|bound| crate::entropy::bpe::is_word_like_low_bpe(value, *bound))
                        .map(|_| crate::adjudicate::GenericValueShapeStage::WordLikeLowBpe)
                });

                if let Some(reason) = shape_rejected {
                    let generic_ctx = crate::adjudicate::MatchCtx::for_generic_bridge(
                        crate::adjudicate::GenericBridgeSignal::ValueShape(reason),
                    );
                    // A VALUE-SHAPE rejection is about the captured value's shape,
                    // so the suppression telemetry must be keyed on `value`: NOT
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

                if let Some(stage_id) = detector_plan
                    .suppression
                    .as_ref()
                    .and_then(|policy| policy.full_stage(chunk.metadata.path.as_deref(), value))
                {
                    crate::adjudicate::record_suppression(
                        chunk.metadata.path.as_deref(),
                        value,
                        &crate::adjudicate::MatchCtx::for_stage(stage_id),
                    );
                    continue;
                }

                let checksum_decision = self.detector_plans.validate_any(value);
                if checksum_decision.is_invalid() {
                    crate::adjudicate::record_checksum_invalid_suppression(
                        chunk.metadata.path.as_deref(),
                        value,
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
                    execution_policy.min_confidence,
                    self.config.min_confidence,
                );
                // Defect #80: this branch hard-coded `offset: 0` for every
                // generic-secret finding, so a `KEY = <secret>` on line 845
                // of a 137 KiB file reported offset 0 - the start of the
                // file - making the JSON impossible to navigate or grep.
                // The real offset is the start of the value within the
                // line, plus the line's start in the chunk, plus the
                // chunk's base offset in the original file (non-zero on
                // windowed >64 MiB scans).
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
                let line_number = absolute_line(chunk.metadata.base_line, mapped_line);
                let build_raw = |scan_state: &mut ScanState, confidence| {
                    crate::pipeline::build_synthetic_raw_match(
                        (
                            Arc::clone(&metadata.0),
                            Arc::clone(&metadata.1),
                            Arc::clone(&metadata.2),
                        ),
                        execution_policy.severity,
                        chunk,
                        value,
                        absolute_offset,
                        Some(line_number),
                        Some(entropy),
                        confidence,
                        scan_state,
                    )
                };

                #[cfg(feature = "ml")]
                let ml_policy = detector_plan.ml;
                #[cfg(feature = "ml")]
                if let Some(ml_mode) = self
                    .config
                    .ml_enabled
                    .then_some(ml_policy.match_mode)
                    .flatten()
                {
                    let ml_features = crate::types::ml_features_for_candidate(
                        scan_text,
                        line_idx,
                        chunk.metadata.path.as_deref(),
                        value,
                        ml_policy.context_radius_lines,
                        &self.config,
                        metadata.2.as_ref(),
                        ml_policy.features,
                        crate::ml_scorer::MlCandidateChannel::Pattern,
                    );
                    let raw = build_raw(scan_state, policy_conf);
                    let inserted = scan_state.push_detector_ml_pending(
                        raw,
                        policy_conf,
                        context,
                        ml_features,
                        ml_policy.effective_weight(&self.config),
                        min_confidence_floor,
                        false,
                        true,
                        allow_canonical_hex_key,
                        allow_encoded_text_secret,
                        checksum_decision,
                        ml_mode,
                    );
                    if profile_enabled && inserted {
                        metrics::record_emit();
                    }
                    continue;
                }

                let Some(report_conf) = crate::adjudicate::finalize_report_candidate(
                    chunk.metadata.path.as_deref(),
                    value,
                    crate::adjudicate::ReportAdjudicationPolicy {
                        detector_id: metadata.0.as_ref(),
                        code_context: context,
                        confidence: policy_conf,
                        min_confidence_floor,
                        penalize_test_paths: self.config.penalize_test_paths,
                        file_path: chunk.metadata.path.as_deref(),
                        is_named_detector: false,
                        is_generic_detector: true,
                        allow_encoded_text_lift: allow_encoded_text_secret,
                        allow_canonical_hex_key,
                        checksum: checksum_decision,
                        calibration: self.config.calibration.as_deref(),
                    },
                ) else {
                    continue;
                };
                let raw = build_raw(scan_state, report_conf);
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
