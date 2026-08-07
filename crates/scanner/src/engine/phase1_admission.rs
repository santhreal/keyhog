//! Scanner-owned direct-literal admission classification.

use super::{CompiledScanner, BIGRAM_BLOOM_MIN_CHUNK_BYTES};
use keyhog_core::Chunk;

/// Route-neutral admission state used to classify workload before a backend is materialized.
pub(crate) struct RouteClassificationPlan {
    pub(crate) alphabet_screen: Option<crate::alphabet_filter::AlphabetScreen>,
    pub(crate) bigram_bloom: crate::bigram_bloom::BigramBloom,
    pub(crate) phase2_keyword_ac: Option<aho_corasick::AhoCorasick>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Phase1Admission {
    AlphabetRejected,
    BigramRejected,
    Admitted,
}

/// Exact direct-literal admission totals for one routed scan batch.
///
/// Autoroute persists these totals after logarithmic bucketing. The summary is
/// scanner-owned so routing uses the same compiled alphabet and bigram filters
/// as production dispatch instead of reimplementing detector admission in the
/// CLI.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Phase1AdmissionSummary {
    pub alphabet_rejected_chunks: u64,
    pub alphabet_rejected_bytes: u64,
    pub bigram_rejected_chunks: u64,
    pub bigram_rejected_bytes: u64,
    pub admitted_chunks: u64,
    pub admitted_bytes: u64,
}

/// Exact phase-2 keyword-trigger density for one routed scan batch.
///
/// Keyword localization changes the amount of phase-2 work only when the
/// compiled keyword automaton fires. Autoroute buckets this scanner-owned
/// summary so sparse and trigger-dense payloads cannot reuse timing evidence.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Phase2KeywordTriggerSummary {
    pub keyword_trigger_chunks: u64,
    pub keyword_trigger_bytes: u64,
    pub keyword_trigger_count: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Phase1AdmissionPlanIdentityError {
    Malformed,
    Mismatch,
}

/// Exact per-chunk phase-1 admissions computed while an autoroute key is
/// built. The plan is intentionally opaque: callers can only reuse it through
/// the scanner boundary that verifies its internal totals and exact live chunk
/// identity. GPU region presence does not consume this plan because VYRE owns
/// that path's trigger admission.
#[derive(Debug)]
pub struct Phase1AdmissionPlan {
    admissions: Vec<Phase1Admission>,
    chunk_shapes: Vec<(usize, usize)>,
    summary: Phase1AdmissionSummary,
    phase2_keyword_triggers: Phase2KeywordTriggerSummary,
    phase2_keyword_hints: Vec<Vec<u32>>,
    phase2_keyword_hint_rows: Vec<usize>,
    generic_keyword_positions: Vec<Vec<u32>>,
    generic_keyword_position_rows: Vec<usize>,
    phase2_always_active_absence: Vec<bool>,
    cpu_trigger_hints: Vec<Option<Vec<u64>>>,
    #[cfg(debug_assertions)]
    unique_payloads: usize,
}

impl Phase1AdmissionPlan {
    #[must_use]
    pub fn summary(&self) -> Phase1AdmissionSummary {
        self.summary
    }

    #[must_use]
    pub fn phase2_keyword_triggers(&self) -> Phase2KeywordTriggerSummary {
        self.phase2_keyword_triggers
    }

    /// Number of byte-distinct payloads classified while building this plan.
    #[doc(hidden)]
    #[cfg(debug_assertions)]
    #[must_use]
    pub fn unique_payloads_for_diagnostics(&self) -> usize {
        self.unique_payloads
    }

    #[doc(hidden)]
    #[cfg(debug_assertions)]
    #[must_use]
    pub fn phase2_keyword_hints_for_diagnostics(&self, index: usize) -> Option<&[u32]> {
        self.phase2_keyword_hints_for(index)
    }

    #[doc(hidden)]
    #[cfg(debug_assertions)]
    #[must_use]
    pub fn generic_keyword_positions_for_diagnostics(&self, index: usize) -> Option<&[u32]> {
        self.generic_keyword_positions_for(index)
    }

    #[doc(hidden)]
    #[cfg(debug_assertions)]
    #[must_use]
    pub fn phase2_always_active_absence_for_diagnostics(&self, index: usize) -> Option<bool> {
        self.phase2_always_active_absence_for(index)
    }

    #[doc(hidden)]
    #[cfg(debug_assertions)]
    #[must_use]
    pub fn cpu_trigger_hints_for_diagnostics(&self, index: usize) -> Option<&[u64]> {
        self.cpu_trigger_hints_for(index)
    }

    #[inline]
    pub(crate) fn admission_for(&self, index: usize) -> Option<Phase1Admission> {
        self.admissions.get(index).copied()
    }

    #[inline]
    pub(crate) fn phase2_keyword_hints_for(&self, index: usize) -> Option<&[u32]> {
        let row = *self.phase2_keyword_hint_rows.get(index)?;
        self.phase2_keyword_hints.get(row).map(Vec::as_slice)
    }

    #[inline]
    pub(crate) fn generic_keyword_positions_for(&self, index: usize) -> Option<&[u32]> {
        let row = *self.generic_keyword_position_rows.get(index)?;
        self.generic_keyword_positions.get(row).map(Vec::as_slice)
    }

    #[inline]
    pub(crate) fn phase2_always_active_absence_for(&self, index: usize) -> Option<bool> {
        let row = *self.phase2_keyword_hint_rows.get(index)?;
        self.phase2_always_active_absence.get(row).copied()
    }

    #[inline]
    pub(crate) fn cpu_trigger_hints_for(&self, index: usize) -> Option<&[u64]> {
        let row = *self.phase2_keyword_hint_rows.get(index)?;
        self.cpu_trigger_hints.get(row)?.as_deref()
    }

    #[inline]
    pub(crate) fn validate_chunks(
        &self,
        chunks: &[Chunk],
    ) -> Result<(), Phase1AdmissionPlanIdentityError> {
        let Some(summary_chunks) = self
            .summary
            .alphabet_rejected_chunks
            .checked_add(self.summary.bigram_rejected_chunks)
            .and_then(|count| count.checked_add(self.summary.admitted_chunks))
        else {
            return Err(Phase1AdmissionPlanIdentityError::Malformed);
        };
        let Some(summary_bytes) = self
            .summary
            .alphabet_rejected_bytes
            .checked_add(self.summary.bigram_rejected_bytes)
            .and_then(|count| count.checked_add(self.summary.admitted_bytes))
        else {
            return Err(Phase1AdmissionPlanIdentityError::Malformed);
        };
        let Ok(shape_count) = u64::try_from(self.chunk_shapes.len()) else {
            return Err(Phase1AdmissionPlanIdentityError::Malformed);
        };
        let mut shape_bytes = 0u64;
        for &(_, len) in &self.chunk_shapes {
            let Ok(len) = u64::try_from(len) else {
                return Err(Phase1AdmissionPlanIdentityError::Malformed);
            };
            let Some(total) = shape_bytes.checked_add(len) else {
                return Err(Phase1AdmissionPlanIdentityError::Malformed);
            };
            shape_bytes = total;
        }
        let keyword_summary_valid = self.phase2_keyword_triggers.keyword_trigger_chunks
            <= shape_count
            && self.phase2_keyword_triggers.keyword_trigger_bytes <= shape_bytes
            && self.phase2_keyword_triggers.keyword_trigger_count
                >= self.phase2_keyword_triggers.keyword_trigger_chunks
            && (self.phase2_keyword_triggers.keyword_trigger_chunks == 0)
                == (self.phase2_keyword_triggers.keyword_trigger_count == 0);
        let keyword_hints_valid = self.phase2_keyword_hint_rows.len() == self.chunk_shapes.len()
            && self
                .phase2_keyword_hint_rows
                .iter()
                .all(|&row| row < self.phase2_keyword_hints.len());
        let generic_positions_valid = self.generic_keyword_position_rows.len()
            == self.chunk_shapes.len()
            && self
                .generic_keyword_position_rows
                .iter()
                .all(|&row| row < self.generic_keyword_positions.len());
        let always_active_absence_valid =
            self.phase2_always_active_absence.len() == self.phase2_keyword_hints.len();
        let cpu_trigger_hints_valid =
            self.cpu_trigger_hints.len() == self.phase2_keyword_hints.len();
        if self.admissions.len() != self.chunk_shapes.len()
            || summary_chunks != shape_count
            || summary_bytes != shape_bytes
            || !keyword_summary_valid
            || !keyword_hints_valid
            || !generic_positions_valid
            || !always_active_absence_valid
            || !cpu_trigger_hints_valid
            || self
                .chunk_shapes
                .iter()
                .any(|&(ptr, len)| len != 0 && ptr == 0)
        {
            return Err(Phase1AdmissionPlanIdentityError::Malformed);
        }
        if chunks.len() != self.chunk_shapes.len() {
            return Err(Phase1AdmissionPlanIdentityError::Malformed);
        }
        if !chunks
            .iter()
            .zip(&self.chunk_shapes)
            .all(|(chunk, &(ptr, len))| {
                let bytes = chunk.data.as_bytes();
                bytes.as_ptr() as usize == ptr && bytes.len() == len
            })
        {
            return Err(Phase1AdmissionPlanIdentityError::Mismatch);
        }
        Ok(())
    }
}

impl Phase1AdmissionSummary {
    /// Construct a summary for a caller that has independently proved every
    /// chunk advances past direct-literal admission.
    pub fn all_admitted(chunks: u64, bytes: u64) -> Self {
        Self {
            admitted_chunks: chunks,
            admitted_bytes: bytes,
            ..Self::default()
        }
    }

    #[inline]
    fn record(&mut self, admission: Phase1Admission, bytes: u64) {
        match admission {
            Phase1Admission::AlphabetRejected => {
                self.alphabet_rejected_chunks += 1;
                self.alphabet_rejected_bytes += bytes;
            }
            Phase1Admission::BigramRejected => {
                self.bigram_rejected_chunks += 1;
                self.bigram_rejected_bytes += bytes;
            }
            Phase1Admission::Admitted => {
                self.admitted_chunks += 1;
                self.admitted_bytes += bytes;
            }
        }
    }

    #[inline]
    fn merge(self, other: Self) -> Self {
        Self {
            alphabet_rejected_chunks: self
                .alphabet_rejected_chunks
                .saturating_add(other.alphabet_rejected_chunks),
            alphabet_rejected_bytes: self
                .alphabet_rejected_bytes
                .saturating_add(other.alphabet_rejected_bytes),
            bigram_rejected_chunks: self
                .bigram_rejected_chunks
                .saturating_add(other.bigram_rejected_chunks),
            bigram_rejected_bytes: self
                .bigram_rejected_bytes
                .saturating_add(other.bigram_rejected_bytes),
            admitted_chunks: self.admitted_chunks.saturating_add(other.admitted_chunks),
            admitted_bytes: self.admitted_bytes.saturating_add(other.admitted_bytes),
        }
    }
}

fn phase1_payload_fingerprint(data: &[u8]) -> [u8; 32] {
    const SAMPLE_COUNT: usize = 8;
    const SAMPLE_BYTES: usize = 64;

    let mut hasher = blake3::Hasher::new();
    hasher.update(&(data.len() as u64).to_le_bytes());
    if data.len() <= SAMPLE_COUNT * SAMPLE_BYTES {
        hasher.update(data);
    } else {
        let max_start = data.len() - SAMPLE_BYTES;
        for sample in 0..SAMPLE_COUNT {
            let start = max_start * sample / (SAMPLE_COUNT - 1);
            hasher.update(&data[start..start + SAMPLE_BYTES]);
        }
    }
    *hasher.finalize().as_bytes()
}

impl CompiledScanner {
    #[inline]
    pub(crate) fn phase1_admission(&self, data: &[u8]) -> Phase1Admission {
        if self
            .route_classification
            .alphabet_screen
            .as_ref()
            .is_some_and(|screen| !screen.screen(data))
        {
            return Phase1Admission::AlphabetRejected;
        }
        if data.len() >= BIGRAM_BLOOM_MIN_CHUNK_BYTES
            && !self.route_classification.bigram_bloom.maybe_overlaps(data)
        {
            return Phase1Admission::BigramRejected;
        }
        Phase1Admission::Admitted
    }

    #[inline]
    fn phase1_admission_bypassing_bigram(&self, data: &[u8]) -> Phase1Admission {
        if self
            .route_classification
            .alphabet_screen
            .as_ref()
            .is_some_and(|screen| !screen.screen(data))
        {
            return Phase1Admission::AlphabetRejected;
        }
        Phase1Admission::Admitted
    }

    fn phase2_keyword_triggers(&self, data: &str) -> (u64, Vec<u32>) {
        let Some(keyword_ac) = self.route_classification.phase2_keyword_ac.as_ref() else {
            return (0, Vec::new());
        };
        let mut count = 0u64;
        let mut hints = Vec::new();
        for mat in keyword_ac.find_iter(data) {
            count = count.saturating_add(1);
            let Ok(keyword_idx) = u32::try_from(mat.pattern().as_usize()) else {
                continue;
            };
            if !hints.contains(&keyword_idx) {
                hints.push(keyword_idx);
            }
        }
        (count, hints)
    }

    /// Classify direct-literal phase-1 work with the exact compiled prefilters
    /// production scanning uses. Decode work is intentionally separate and is
    /// represented by the scanner's decode workload plan.
    pub fn phase1_admission_summary(&self, chunks: &[Chunk]) -> Phase1AdmissionSummary {
        // Fused batches otherwise serialize the exact admission probes on one
        // thread immediately before the production Rayon scan. Keep tiny
        // batches allocation-free, but fold larger batches in parallel so
        // route selection does not become a serial pre-scan bottleneck.
        if chunks.len() >= 4
            && chunks.iter().map(|chunk| chunk.data.len()).sum::<usize>() >= 64 * 1024
        {
            use rayon::prelude::*;

            return chunks
                .par_iter()
                .map(|chunk| {
                    let mut summary = Phase1AdmissionSummary::default();
                    summary.record(
                        self.phase1_admission(chunk.data.as_bytes()),
                        chunk.data.len() as u64,
                    );
                    summary
                })
                .reduce(
                    Phase1AdmissionSummary::default,
                    Phase1AdmissionSummary::merge,
                );
        }

        let mut summary = Phase1AdmissionSummary::default();
        for chunk in chunks {
            summary.record(
                self.phase1_admission(chunk.data.as_bytes()),
                chunk.data.len() as u64,
            );
        }
        summary
    }

    /// Build exact per-chunk evidence for autoroute and the next production scan.
    /// Reuse avoids duplicate gates; malformed or mismatched identity is recomputed
    /// with an exact recovery receipt.
    pub fn phase1_admission_plan(&self, chunks: &[Chunk]) -> Phase1AdmissionPlan {
        self.phase1_admission_plan_with_bigram_mode(chunks, false)
    }

    /// Build admission evidence with only the bigram gate bypassed.
    ///
    /// This is a diagnostic oracle for corpus differential benchmarks. The
    /// alphabet screen and every downstream matcher remain unchanged, so an
    /// enabled-versus-bypassed comparison isolates whether the bigram gate
    /// dropped a finding. Production scans must use [`Self::phase1_admission_plan`].
    pub fn phase1_admission_plan_bypassing_bigram_for_diagnostics(
        &self,
        chunks: &[Chunk],
    ) -> Phase1AdmissionPlan {
        self.phase1_admission_plan_with_bigram_mode(chunks, true)
    }

    fn phase2_always_active_absence(&self, data: &str) -> bool {
        if self.route_classification.phase2_keyword_ac.is_none() {
            return false;
        }
        match &self.phase2_always_active_prefilter {
            Some(prefilter) => !prefilter.any_active_match(
                &self.phase2_patterns,
                data,
                &self.tuning.resolve(),
                false,
            ),
            None => self.phase2_always_active_indices.is_empty(),
        }
    }

    fn phase1_admission_plan_with_bigram_mode(
        &self,
        chunks: &[Chunk],
        bypass_bigram: bool,
    ) -> Phase1AdmissionPlan {
        let classify = |chunk: &Chunk, classify_reusable_evidence: bool| {
            let admission = if bypass_bigram {
                self.phase1_admission_bypassing_bigram(chunk.data.as_bytes())
            } else {
                self.phase1_admission(chunk.data.as_bytes())
            };
            let (keyword_trigger_count, keyword_hints) = self.phase2_keyword_triggers(&chunk.data);
            let mut generic_positions = Vec::new();
            if let Some(generic_plan) = self.detector_plans.generic_assignment() {
                crate::engine::phase2_generic::keywords::collect_generic_keyword_positions_with(
                    generic_plan.stems(),
                    &chunk.data,
                    &mut generic_positions,
                );
            }
            let cpu_trigger_hints = classify_reusable_evidence
                .then(|| self.collect_triggered_patterns_cpu(&chunk.data));
            (
                admission,
                keyword_trigger_count,
                keyword_hints,
                generic_positions,
                classify_reusable_evidence && self.phase2_always_active_absence(&chunk.data),
                cpu_trigger_hints,
            )
        };

        let mut representatives = Vec::<([u8; 32], usize)>::new();
        let mut representative_for = Vec::with_capacity(chunks.len());
        for (index, chunk) in chunks.iter().enumerate() {
            let data = chunk.data.as_bytes();
            let fingerprint = phase1_payload_fingerprint(data);
            let mut representative_position = None;
            for (position, (candidate, representative_index)) in representatives.iter().enumerate()
            {
                if *candidate == fingerprint
                    && chunks[*representative_index].data.as_bytes() == data
                {
                    representative_position = Some(position);
                    break;
                }
            }
            let position = representative_position.unwrap_or_else(|| {
                representatives.push((fingerprint, index));
                representatives.len() - 1
            });
            representative_for.push(position);
        }
        let mut representative_counts = vec![0usize; representatives.len()];
        for &position in &representative_for {
            representative_counts[position] += 1;
        }

        let representative_bytes = representatives
            .iter()
            .map(|(_, index)| chunks[*index].data.len())
            .sum::<usize>();
        let classified = if representatives.len() >= 4 && representative_bytes >= 64 * 1024 {
            use rayon::prelude::*;

            representatives
                .par_iter()
                .enumerate()
                .map(|(position, (_, index))| {
                    classify(&chunks[*index], representative_counts[position] > 1)
                })
                .collect::<Vec<_>>()
        } else {
            representatives
                .iter()
                .enumerate()
                .map(|(position, (_, index))| {
                    classify(&chunks[*index], representative_counts[position] > 1)
                })
                .collect::<Vec<_>>()
        };

        let mut summary = Phase1AdmissionSummary::default();
        let mut phase2_keyword_triggers = Phase2KeywordTriggerSummary::default();
        let mut admissions = Vec::with_capacity(chunks.len());
        let mut chunk_shapes = Vec::with_capacity(chunks.len());
        for (chunk, representative_position) in
            chunks.iter().zip(representative_for.iter().copied())
        {
            let (admission, keyword_trigger_count, _, _, _, _) =
                &classified[representative_position];
            let data = chunk.data.as_bytes();
            let len = data.len();
            summary.record(*admission, len as u64);
            if *keyword_trigger_count != 0 {
                phase2_keyword_triggers.keyword_trigger_chunks += 1;
                phase2_keyword_triggers.keyword_trigger_bytes += len as u64;
                phase2_keyword_triggers.keyword_trigger_count = phase2_keyword_triggers
                    .keyword_trigger_count
                    .saturating_add(*keyword_trigger_count);
            }
            admissions.push(*admission);
            chunk_shapes.push((data.as_ptr() as usize, len));
        }
        let mut phase2_keyword_hints = Vec::with_capacity(classified.len());
        let mut generic_keyword_positions = Vec::with_capacity(classified.len());
        let mut phase2_always_active_absence = Vec::with_capacity(classified.len());
        let mut cpu_trigger_hints = Vec::with_capacity(classified.len());
        for (_, _, hints, positions, absence, triggers) in classified {
            phase2_keyword_hints.push(hints);
            generic_keyword_positions.push(positions);
            phase2_always_active_absence.push(absence);
            cpu_trigger_hints.push(triggers);
        }
        Phase1AdmissionPlan {
            admissions,
            chunk_shapes,
            summary,
            phase2_keyword_triggers,
            phase2_keyword_hints,
            phase2_keyword_hint_rows: representative_for.clone(),
            generic_keyword_positions,
            generic_keyword_position_rows: representative_for,
            phase2_always_active_absence,
            cpu_trigger_hints,
            #[cfg(debug_assertions)]
            unique_payloads: representatives.len(),
        }
    }
}
