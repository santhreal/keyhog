use super::super::*;
use super::phase2::Phase2AlwaysActiveGpuEvidence;
use keyhog_core::RawMatch;

impl CompiledScanner {
    pub(crate) fn scan_prepared_with_triggered(
        &self,
        prepared: PreparedChunk<'_>,
        triggered_patterns: &[u64],
        deadline: Option<std::time::Instant>,
        confirmed_patterns_absence: bool,
        entropy_absence: bool,
        phase2_keyword_hints: Option<&[u32]>,
        phase2_always_active_gpu_evidence: Option<Phase2AlwaysActiveGpuEvidence<'_>>,
        confirmed_anchor_literal_matches: Option<&[(u32, u32)]>,
        generic_keyword_positions: Option<&[u32]>,
        backend: crate::hw_probe::ScanBackend,
        route: crate::ScanExecutionRoute,
    ) -> crate::error::Result<Vec<RawMatch>> {
        let scan_state = self.scan_prepared_state_with_triggered(
            prepared,
            triggered_patterns,
            deadline,
            confirmed_patterns_absence,
            entropy_absence,
            phase2_keyword_hints,
            phase2_always_active_gpu_evidence,
            confirmed_anchor_literal_matches,
            generic_keyword_positions,
            route,
        )?;
        #[cfg(feature = "ml")]
        if !crate::deadline::expired(deadline) {
            let mut scan_state = scan_state;
            let _g = profile::span(keyhog_profile::Stage::MachineLearning);
            self.apply_ml_batch_scores(&mut scan_state, backend, deadline)?;
            return Ok(scan_state.into_matches(self.detector_digest));
        }
        Ok(scan_state.into_matches(self.detector_digest))
    }

    pub(crate) fn scan_prepared_state_with_triggered(
        &self,
        prepared: PreparedChunk<'_>,
        triggered_patterns: &[u64],
        deadline: Option<std::time::Instant>,
        confirmed_patterns_absence: bool,
        entropy_absence: bool,
        phase2_keyword_hints: Option<&[u32]>,
        phase2_always_active_gpu_evidence: Option<Phase2AlwaysActiveGpuEvidence<'_>>,
        confirmed_anchor_literal_matches: Option<&[(u32, u32)]>,
        generic_keyword_positions: Option<&[u32]>,
        route: crate::ScanExecutionRoute,
    ) -> crate::error::Result<ScanState> {
        if crate::deadline::expired(deadline) {
            return Ok(ScanState::with_static_intern(self.static_intern.clone()));
        }
        let line_index = prepared.line_index();
        let mut scan_state = ScanState::with_static_intern(self.static_intern.clone());
        let vocab_path_class = super::scan::vocab_path_class(
            prepared.chunk.metadata.source_type.as_ref(),
            prepared.chunk.metadata.path.as_deref(),
        );
        let windowed_parent = prepared.chunk.metadata.decoded_span.is_none()
            && prepared.chunk.metadata.source_type.as_ref() == "filesystem/windowed";
        // Digest is cached on the scanner; still skip the call for non-windowed.
        let vocab_cfg = windowed_parent
            .then(|| self.entropy_evidence_config_digest())
            .unwrap_or([0u8; 32]);

        // Parent windows only: decode sub-chunks create new adjacencies and must
        // not inherit a parent vocabulary clean proof.
        if windowed_parent
            && super::scan::vocab_previously_clean(
                &self.vocab_stage_absence_cache,
                self.detector_digest,
                vocab_cfg,
                vocab_path_class,
                &prepared.chunk.data,
            )
        {
            return Ok(scan_state);
        }

        {
            let _g = profile::span(keyhog_profile::Stage::HotPatterns);
            #[cfg(feature = "simdsieve")]
            self.scan_hot_patterns_fast(
                &prepared.preprocessed.text,
                &prepared.preprocessed,
                line_index,
                prepared.chunk,
                &mut scan_state,
            );
        }
        if crate::deadline::expired(deadline) {
            return Ok(scan_state);
        }

        let raw_text_unchanged = std::ptr::eq(
            prepared.preprocessed.text.as_ptr(),
            prepared.chunk.data.as_ptr(),
        ) && prepared.preprocessed.text.len() == prepared.chunk.data.len()
            || prepared.preprocessed.text.as_bytes() == prepared.chunk.data.as_bytes();
        let normalized_triggered;
        let triggered_patterns = if raw_text_unchanged {
            triggered_patterns
        } else {
            normalized_triggered = {
                let mut normalized =
                    self.collect_triggered_patterns_cpu(&prepared.preprocessed.text);
                for (word, raw_word) in normalized.iter_mut().zip(triggered_patterns) {
                    *word |= *raw_word;
                }
                normalized
            };
            normalized_triggered.as_slice()
        };
        let expanded_patterns = self.expand_triggered_patterns(triggered_patterns);
        let phase2_keyword_hints = phase2_keyword_hints.filter(|_| raw_text_unchanged);
        let phase2_always_active_gpu_evidence =
            phase2_always_active_gpu_evidence.filter(|_| raw_text_unchanged);
        let confirmed_anchor_literal_matches =
            confirmed_anchor_literal_matches.filter(|_| raw_text_unchanged);
        let generic_keyword_positions = generic_keyword_positions.filter(|_| raw_text_unchanged);
        let confirmed_patterns_absence = confirmed_patterns_absence && raw_text_unchanged;
        let entropy_absence = entropy_absence && raw_text_unchanged;
        // Repetitive multi-line corpora share a stable unique-line vocabulary across
        // overlapping windows. After the first window proves confirmed/entropy
        // absence for that vocabulary, later windows skip those stages.
        let vocab_absence = (raw_text_unchanged && windowed_parent)
            .then(|| {
                super::scan::vocab_stage_absence(
                    &self.vocab_stage_absence_cache,
                    self.detector_digest,
                    vocab_cfg,
                    vocab_path_class,
                    &prepared.chunk.data,
                )
            })
            .flatten();
        let confirmed_patterns_absence =
            confirmed_patterns_absence || vocab_absence.is_some_and(|absence| absence.confirmed);
        let entropy_absence =
            entropy_absence || vocab_absence.is_some_and(|absence| absence.entropy);

        if !confirmed_patterns_absence && expanded_patterns.iter().any(|&w| w != 0) {
            let _g = profile::span(keyhog_profile::Stage::ConfirmedPatterns);
            #[cfg(debug_assertions)]
            self.confirmed_pattern_scanned_bytes.fetch_add(
                // LAW10: debug accounting saturates on impossible usize-to-u64 overflow; scan behavior is unchanged.
                u64::try_from(prepared.preprocessed.text.len()).unwrap_or(u64::MAX),
                std::sync::atomic::Ordering::Relaxed,
            );
            let set_bits: usize = expanded_patterns
                .iter()
                .map(|w| w.count_ones() as usize)
                .sum();
            let mut confirmed_patterns: Vec<usize> = Vec::with_capacity(set_bits);
            super::trigger_bitmap::for_each_set_bit(&expanded_patterns, |idx| {
                if idx < self.ac_map.len() {
                    confirmed_patterns.push(idx);
                }
            });

            // Heap len is not an emptiness signal once max_matches_per_chunk is
            // reached (push_match replaces in place). Count accepted push events.
            let accepts_before = scan_state.accepted_match_events;
            #[cfg(feature = "ml")]
            let ml_before = scan_state.accepted_ml_events;
            self.extract_confirmed_patterns(
                &confirmed_patterns,
                &prepared.preprocessed,
                line_index,
                prepared.chunk,
                &mut scan_state,
                deadline,
                confirmed_anchor_literal_matches,
            );
            let confirmed_empty = scan_state.accepted_match_events == accepts_before;
            #[cfg(feature = "ml")]
            let confirmed_empty = confirmed_empty && scan_state.accepted_ml_events == ml_before;
            // Do not record absence when the heap is at capacity: a rejected
            // candidate leaves accepted_match_events unchanged and must not
            // poison later overlapping windows.
            if confirmed_empty
                && raw_text_unchanged
                && windowed_parent
                && scan_state.matches.len() < self.config.max_matches_per_chunk
                && !crate::deadline::expired(deadline)
            {
                super::scan::mark_vocab_confirmed_absent(
                    &self.vocab_stage_absence_cache,
                    self.detector_digest,
                    vocab_cfg,
                    vocab_path_class,
                    &prepared.chunk.data,
                );
            }
        }

        if crate::deadline::expired(deadline) {
            return Ok(scan_state);
        }

        let focus = prepared.chunk.metadata.decoded_span.filter(|_| {
            self.tuning.decode_focus_enabled()
                && std::ptr::eq(
                    prepared.preprocessed.text.as_ptr(),
                    prepared.chunk.data.as_ptr(),
                )
                && prepared.preprocessed.text.len() == prepared.chunk.data.len()
        });
        match focus {
            Some(span) => self.scan_phase2_patterns_focused(
                &prepared.preprocessed,
                line_index,
                prepared.chunk,
                &mut scan_state,
                deadline,
                span,
                phase2_keyword_hints,
                phase2_always_active_gpu_evidence,
                route,
            ),
            None => self.scan_phase2_patterns(
                &prepared.preprocessed,
                line_index,
                prepared.chunk,
                &mut scan_state,
                deadline,
                phase2_keyword_hints,
                phase2_always_active_gpu_evidence,
                route,
            ),
        }?;
        if crate::deadline::expired(deadline) {
            return Ok(scan_state);
        }

        {
            let _g = profile::span(keyhog_profile::Stage::GenericDetection);
            self.scan_generic_assignments(
                &prepared.preprocessed,
                line_index,
                prepared.chunk,
                &mut scan_state,
                generic_keyword_positions,
                deadline,
            );
        }
        if crate::deadline::expired(deadline) {
            return Ok(scan_state);
        }

        #[cfg(feature = "entropy")]
        if !entropy_absence {
            let _g = profile::span(keyhog_profile::Stage::Entropy);
            #[cfg(debug_assertions)]
            self.entropy_scanned_bytes.fetch_add(
                // LAW10: debug accounting saturates on impossible usize-to-u64 overflow; scan behavior is unchanged.
                u64::try_from(prepared.preprocessed.text.len()).unwrap_or(u64::MAX),
                std::sync::atomic::Ordering::Relaxed,
            );
            let accepts_before = scan_state.accepted_match_events;
            #[cfg(feature = "ml")]
            let ml_before = scan_state.accepted_ml_events;
            self.scan_entropy_fallback(
                &prepared.preprocessed,
                line_index,
                prepared.chunk,
                &mut scan_state,
            );
            let entropy_empty = scan_state.accepted_match_events == accepts_before;
            #[cfg(feature = "ml")]
            let entropy_empty = entropy_empty && scan_state.accepted_ml_events == ml_before;
            if entropy_empty
                && raw_text_unchanged
                && windowed_parent
                && scan_state.matches.len() < self.config.max_matches_per_chunk
                && !crate::deadline::expired(deadline)
            {
                super::scan::mark_vocab_entropy_absent(
                    &self.vocab_stage_absence_cache,
                    self.detector_digest,
                    vocab_cfg,
                    vocab_path_class,
                    &prepared.chunk.data,
                );
            }
        }
        if crate::deadline::expired(deadline) {
            return Ok(scan_state);
        }

        let clean = scan_state.matches.is_empty();
        #[cfg(feature = "ml")]
        let clean = clean && scan_state.ml_pending.is_empty();
        if clean
            && raw_text_unchanged
            && prepared.chunk.metadata.decoded_span.is_none()
            && prepared.chunk.metadata.source_type.as_ref() == "filesystem/windowed"
        {
            super::scan::mark_vocab_clean(
                &self.vocab_stage_absence_cache,
                self.detector_digest,
                vocab_cfg,
                vocab_path_class,
                &prepared.chunk.data,
            );
        }

        Ok(scan_state)
    }
}
