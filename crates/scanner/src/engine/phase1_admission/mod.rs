//! Scanner-owned direct-literal admission classification.

use super::{CompiledScanner, BIGRAM_BLOOM_MIN_CHUNK_BYTES};
use keyhog_core::{Chunk, SensitiveString};
use std::collections::VecDeque;
use std::sync::Arc;

/// Route-neutral admission state used to classify workload before a backend is materialized.
pub(crate) struct RouteClassificationPlan {
    pub(crate) alphabet_screen: Option<crate::alphabet_filter::AlphabetScreen>,
    pub(crate) bigram_bloom: crate::bigram_bloom::BigramBloom,
    pub(crate) phase2_keyword_index: Option<crate::compiler::Phase2KeywordIndex>,
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
    normalization_passthrough: Vec<bool>,
    unicode_normalization_enabled: bool,
    confirmed_patterns_absence: Vec<bool>,
    entropy_absence: Vec<bool>,
    multiline_absence: Vec<bool>,
    line_context_indices: Vec<Option<Arc<crate::context::LineContextIndex>>>,
    decoder_admission_contexts: Vec<Option<u8>>,
    decoder_absence: Vec<bool>,
    entropy_config_digest: [u8; 32],
    #[cfg(debug_assertions)]
    unique_payloads: usize,
}

const REUSABLE_EVIDENCE_MAX_BYTES: usize = 1024 * 1024;
const REUSABLE_EVIDENCE_MAX_ENTRIES: usize = 16;

#[derive(Clone, Debug)]
pub(crate) struct ReusablePhase1Evidence {
    pub(crate) admission: Phase1Admission,
    pub(crate) keyword_trigger_count: u64,
    pub(crate) keyword_hints: Vec<u32>,
    pub(crate) generic_positions: Vec<u32>,
    pub(crate) phase2_always_active_absence: bool,
    pub(crate) cpu_trigger_hints: Option<Vec<u64>>,
    pub(crate) normalization_passthrough: bool,
    pub(crate) confirmed_patterns_absence: bool,
    pub(crate) entropy_absence: bool,
    pub(crate) multiline_absence: bool,
    pub(crate) line_context_index: Option<Arc<crate::context::LineContextIndex>>,
    pub(crate) decoder_absence: bool,
}

impl ReusablePhase1Evidence {
    fn resident_bytes(&self) -> usize {
        self.keyword_hints
            .capacity()
            .saturating_mul(std::mem::size_of::<u32>())
            .saturating_add(
                self.generic_positions
                    .capacity()
                    .saturating_mul(std::mem::size_of::<u32>()),
            )
            .saturating_add(self.cpu_trigger_hints.as_ref().map_or(0, |hints| {
                hints.capacity().saturating_mul(std::mem::size_of::<u64>())
            }))
            .saturating_add(
                self.line_context_index
                    .as_ref()
                    .map_or(0, |index| index.storage_bytes()),
            )
    }
}

#[derive(Debug)]
struct CachedReusablePhase1Evidence {
    fingerprint: [u8; 32],
    bypass_bigram: bool,
    unicode_normalization_enabled: bool,
    entropy_config_digest: [u8; 32],
    decoder_admission_context: Option<u8>,
    payload: SensitiveString,
    evidence: ReusablePhase1Evidence,
}

impl CachedReusablePhase1Evidence {
    fn resident_bytes(&self) -> usize {
        self.payload
            .len()
            .saturating_add(self.evidence.resident_bytes())
    }
}

#[derive(Debug, Default)]
pub(crate) struct ReusablePhase1EvidenceCache {
    entries: VecDeque<CachedReusablePhase1Evidence>,
    resident_bytes: usize,
    #[cfg(debug_assertions)]
    hits: u64,
}

impl ReusablePhase1EvidenceCache {
    pub(crate) fn resident_bytes(&self) -> usize {
        self.resident_bytes
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn aggregate_resident_bytes(&self) -> usize {
        self.entries.iter().fold(0, |total, entry| {
            total.saturating_add(entry.resident_bytes())
        })
    }

    pub(crate) fn contains_fingerprint(&self, fingerprint: [u8; 32]) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.fingerprint == fingerprint)
    }

    pub(crate) const fn max_resident_bytes() -> usize {
        REUSABLE_EVIDENCE_MAX_BYTES
    }

    pub(crate) const fn max_entries() -> usize {
        REUSABLE_EVIDENCE_MAX_ENTRIES
    }

    pub(crate) fn clear(&mut self) {
        self.entries.clear();
        self.entries.shrink_to_fit();
        self.resident_bytes = 0;
    }
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    fn get(
        &mut self,
        fingerprint: [u8; 32],
        bypass_bigram: bool,
        unicode_normalization_enabled: bool,
        entropy_config_digest: [u8; 32],
        decoder_admission_context: Option<u8>,
        payload: &SensitiveString,
    ) -> Option<ReusablePhase1Evidence> {
        let position = self.entries.iter().position(|entry| {
            entry.fingerprint == fingerprint
                && entry.bypass_bigram == bypass_bigram
                && entry.unicode_normalization_enabled == unicode_normalization_enabled
                && entry.entropy_config_digest == entropy_config_digest
                && entry.decoder_admission_context == decoder_admission_context
                && entry.payload.eq(payload)
        })?;
        let entry = self
            .entries
            .remove(position)
            .expect("cache position came from the same deque");
        let evidence = entry.evidence.clone();
        self.entries.push_back(entry);
        #[cfg(debug_assertions)]
        {
            self.hits = self.hits.saturating_add(1);
        }
        Some(evidence)
    }

    pub(crate) fn insert(
        &mut self,
        fingerprint: [u8; 32],
        bypass_bigram: bool,
        unicode_normalization_enabled: bool,
        entropy_config_digest: [u8; 32],
        decoder_admission_context: Option<u8>,
        payload: SensitiveString,
        evidence: ReusablePhase1Evidence,
    ) {
        let resident_bytes = payload.len().saturating_add(evidence.resident_bytes());
        if let Some(position) = self.entries.iter().position(|entry| {
            entry.fingerprint == fingerprint
                && entry.bypass_bigram == bypass_bigram
                && entry.unicode_normalization_enabled == unicode_normalization_enabled
                && entry.entropy_config_digest == entropy_config_digest
                && entry.decoder_admission_context == decoder_admission_context
                && entry.payload.eq(&payload)
        }) {
            if let Some(mut entry) = self.entries.remove(position) {
                self.resident_bytes = self.resident_bytes.saturating_sub(entry.resident_bytes());
                if resident_bytes > REUSABLE_EVIDENCE_MAX_BYTES {
                    return;
                }
                entry.evidence = evidence;
                let updated_bytes = entry.resident_bytes();
                while self.entries.len() >= REUSABLE_EVIDENCE_MAX_ENTRIES
                    || self.resident_bytes.saturating_add(updated_bytes)
                        > REUSABLE_EVIDENCE_MAX_BYTES
                {
                    let Some(evicted) = self.entries.pop_front() else {
                        break;
                    };
                    self.resident_bytes =
                        self.resident_bytes.saturating_sub(evicted.resident_bytes());
                }
                self.resident_bytes = self.resident_bytes.saturating_add(updated_bytes);
                self.entries.push_back(entry);
            }
            return;
        }
        if resident_bytes > REUSABLE_EVIDENCE_MAX_BYTES {
            return;
        }
        while self.entries.len() >= REUSABLE_EVIDENCE_MAX_ENTRIES
            || self.resident_bytes.saturating_add(resident_bytes) > REUSABLE_EVIDENCE_MAX_BYTES
        {
            let Some(evicted) = self.entries.pop_front() else {
                break;
            };
            self.resident_bytes = self.resident_bytes.saturating_sub(evicted.resident_bytes());
        }
        self.resident_bytes = self.resident_bytes.saturating_add(resident_bytes);
        self.entries.push_back(CachedReusablePhase1Evidence {
            fingerprint,
            bypass_bigram,
            unicode_normalization_enabled,
            entropy_config_digest,
            decoder_admission_context,
            payload,
            evidence,
        });
    }
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

    #[doc(hidden)]
    #[cfg(debug_assertions)]
    #[must_use]
    pub fn normalization_passthrough_for_diagnostics(&self, index: usize) -> Option<bool> {
        self.normalization_passthrough_for(index, self.unicode_normalization_enabled)
    }

    #[doc(hidden)]
    #[cfg(debug_assertions)]
    #[must_use]
    pub fn confirmed_patterns_absence_for_diagnostics(&self, index: usize) -> Option<bool> {
        self.confirmed_patterns_absence_for(index)
    }

    #[doc(hidden)]
    #[cfg(debug_assertions)]
    #[must_use]
    pub fn entropy_absence_for_diagnostics(&self, index: usize) -> Option<bool> {
        let row = *self.phase2_keyword_hint_rows.get(index)?;
        self.entropy_absence.get(row).copied()
    }

    #[doc(hidden)]
    #[cfg(debug_assertions)]
    #[must_use]
    pub fn multiline_absence_for_diagnostics(&self, index: usize) -> Option<bool> {
        let row = *self.phase2_keyword_hint_rows.get(index)?;
        self.multiline_absence.get(row).copied()
    }

    #[doc(hidden)]
    #[cfg(debug_assertions)]
    #[must_use]
    pub fn line_context_index_for_diagnostics(&self, index: usize) -> Option<bool> {
        let row = *self.phase2_keyword_hint_rows.get(index)?;
        self.line_context_indices
            .get(row)
            .map(|index| index.is_some())
    }

    #[doc(hidden)]
    #[cfg(debug_assertions)]
    #[must_use]
    pub fn decoder_absence_for_diagnostics(&self, index: usize) -> Option<bool> {
        let row = *self.phase2_keyword_hint_rows.get(index)?;
        self.decoder_absence.get(row).copied()
    }

    #[doc(hidden)]
    #[cfg(debug_assertions)]
    #[must_use]
    pub fn direct_scan_absence_for_diagnostics(&self, index: usize) -> Option<bool> {
        let row = *self.phase2_keyword_hint_rows.get(index)?;
        self.direct_scan_absence_at_row(row)
    }

    #[doc(hidden)]
    #[cfg(debug_assertions)]
    #[must_use]
    pub fn simd_phase2_tail_absence_for_diagnostics(&self, index: usize) -> Option<bool> {
        let row = *self.phase2_keyword_hint_rows.get(index)?;
        self.phase2_tail_absence_at_row(row)
    }

    #[inline]
    pub(crate) fn admission_for(&self, index: usize) -> Option<Phase1Admission> {
        self.admissions.get(index).copied()
    }

    #[inline]
    pub(crate) fn payload_evidence_row_for(&self, index: usize) -> Option<usize> {
        self.phase2_keyword_hint_rows.get(index).copied()
    }

    #[inline]
    pub(crate) fn payload_evidence_row_count(&self) -> usize {
        self.phase2_keyword_hints.len()
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
    pub(crate) fn normalization_passthrough_for(
        &self,
        index: usize,
        unicode_normalization_enabled: bool,
    ) -> Option<bool> {
        if unicode_normalization_enabled != self.unicode_normalization_enabled {
            return None;
        }
        let row = *self.phase2_keyword_hint_rows.get(index)?;
        self.normalization_passthrough.get(row).copied()
    }

    #[inline]
    pub(crate) fn confirmed_patterns_absence_for(&self, index: usize) -> Option<bool> {
        let row = *self.phase2_keyword_hint_rows.get(index)?;
        self.confirmed_patterns_absence.get(row).copied()
    }

    #[inline]
    pub(crate) fn entropy_absence_for(
        &self,
        index: usize,
        entropy_config_digest: [u8; 32],
    ) -> Option<bool> {
        if entropy_config_digest != self.entropy_config_digest {
            return None;
        }
        let row = *self.phase2_keyword_hint_rows.get(index)?;
        self.entropy_absence.get(row).copied()
    }

    #[inline]
    pub(crate) fn multiline_absence_for(
        &self,
        index: usize,
        evidence_config_digest: [u8; 32],
    ) -> Option<bool> {
        if evidence_config_digest != self.entropy_config_digest {
            return None;
        }
        let row = *self.phase2_keyword_hint_rows.get(index)?;
        self.multiline_absence.get(row).copied()
    }

    #[inline]
    pub(crate) fn line_context_index_for(
        &self,
        index: usize,
    ) -> Option<&Arc<crate::context::LineContextIndex>> {
        let row = *self.phase2_keyword_hint_rows.get(index)?;
        self.line_context_indices.get(row)?.as_ref()
    }
    #[inline]
    pub(crate) fn decoder_absence_for(
        &self,
        index: usize,
        decoder_admission_context: Option<u8>,
    ) -> Option<bool> {
        let row = *self.phase2_keyword_hint_rows.get(index)?;
        if self.decoder_admission_contexts.get(row).copied()? != decoder_admission_context {
            return None;
        }
        self.decoder_absence.get(row).copied()
    }

    #[inline]
    fn phase2_tail_absence_at_row(&self, row: usize) -> Option<bool> {
        Some(
            *self.normalization_passthrough.get(row)?
                && *self.confirmed_patterns_absence.get(row)?
                && *self.entropy_absence.get(row)?
                && *self.multiline_absence.get(row)?
                && *self.decoder_absence.get(row)?
                && *self.phase2_always_active_absence.get(row)?
                && self.phase2_keyword_hints.get(row)?.is_empty()
                && self.generic_keyword_positions.get(row)?.is_empty(),
        )
    }

    #[inline]
    fn direct_scan_absence_at_row(&self, row: usize) -> Option<bool> {
        Some(self.phase2_tail_absence_at_row(row)? && self.cpu_trigger_hints.get(row)?.is_some())
    }

    #[inline]
    pub(crate) fn simd_phase2_tail_absence_for(
        &self,
        index: usize,
        unicode_normalization_enabled: bool,
        evidence_config_digest: [u8; 32],
        decoder_admission_context: Option<u8>,
    ) -> Option<bool> {
        if unicode_normalization_enabled != self.unicode_normalization_enabled
            || evidence_config_digest != self.entropy_config_digest
        {
            return None;
        }
        let row = *self.phase2_keyword_hint_rows.get(index)?;
        if self.decoder_admission_contexts.get(row).copied()? != decoder_admission_context {
            return None;
        }
        self.phase2_tail_absence_at_row(row)
    }

    #[inline]
    pub(crate) fn direct_scan_absence_for(
        &self,
        index: usize,
        unicode_normalization_enabled: bool,
        evidence_config_digest: [u8; 32],
        decoder_admission_context: Option<u8>,
    ) -> Option<bool> {
        if unicode_normalization_enabled != self.unicode_normalization_enabled
            || evidence_config_digest != self.entropy_config_digest
        {
            return None;
        }
        let row = *self.phase2_keyword_hint_rows.get(index)?;
        if self.decoder_admission_contexts.get(row).copied()? != decoder_admission_context {
            return None;
        }
        self.direct_scan_absence_at_row(row)
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
        let normalization_passthrough_valid =
            self.normalization_passthrough.len() == self.phase2_keyword_hints.len();
        let confirmed_patterns_absence_valid =
            self.confirmed_patterns_absence.len() == self.phase2_keyword_hints.len();
        let entropy_absence_valid = self.entropy_absence.len() == self.phase2_keyword_hints.len();
        let multiline_absence_valid =
            self.multiline_absence.len() == self.phase2_keyword_hints.len();
        let line_context_indices_valid =
            self.line_context_indices.len() == self.phase2_keyword_hints.len();
        let decoder_admission_contexts_valid =
            self.decoder_admission_contexts.len() == self.phase2_keyword_hints.len();
        let decoder_absence_valid = self.decoder_absence.len() == self.phase2_keyword_hints.len();
        if self.admissions.len() != self.chunk_shapes.len()
            || summary_chunks != shape_count
            || summary_bytes != shape_bytes
            || !keyword_summary_valid
            || !keyword_hints_valid
            || !generic_positions_valid
            || !always_active_absence_valid
            || !cpu_trigger_hints_valid
            || !normalization_passthrough_valid
            || !confirmed_patterns_absence_valid
            || !entropy_absence_valid
            || !multiline_absence_valid
            || !line_context_indices_valid
            || !decoder_admission_contexts_valid
            || !decoder_absence_valid
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

pub(super) fn phase1_payload_fingerprint(data: &[u8]) -> [u8; 32] {
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
        let Some(keyword_index) = self.route_classification.phase2_keyword_index.as_ref() else {
            return (0, Vec::new());
        };
        let mut count = 0u64;
        let mut hints = Vec::new();
        for keyword_idx in keyword_index.find_iter(data) {
            count = count.saturating_add(1);
            let Ok(keyword_idx) = u32::try_from(keyword_idx) else {
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
        if self.route_classification.phase2_keyword_index.is_none() {
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

    fn normalization_passthrough(&self, data: &str) -> bool {
        if !self.config.unicode_normalization {
            return true;
        }
        matches!(
            crate::unicode_hardening::normalize_homoglyphs(data),
            std::borrow::Cow::Borrowed(_)
        ) && matches!(
            crate::unicode_hardening::strip_interior_evasion_controls(data),
            std::borrow::Cow::Borrowed(_)
        )
    }

    fn confirmed_patterns_absent(&self, data: &str, triggered_patterns: &[u64]) -> bool {
        let expanded = self.expand_triggered_patterns(triggered_patterns);
        for (word_index, &word) in expanded.iter().enumerate() {
            let mut remaining = word;
            while remaining != 0 {
                let bit = remaining.trailing_zeros() as usize;
                let pattern_index = word_index * 64 + bit;
                if self
                    .ac_map
                    .get(pattern_index)
                    .is_some_and(|entry| entry.regex.get().is_match(data))
                {
                    return false;
                }
                remaining &= remaining - 1;
            }
        }
        true
    }

    pub(crate) fn entropy_evidence_config_digest(&self) -> [u8; 32] {
        fn update_strings(hasher: &mut blake3::Hasher, values: &[String]) {
            hasher.update(&(values.len() as u64).to_le_bytes());
            for value in values {
                hasher.update(&(value.len() as u64).to_le_bytes());
                hasher.update(value.as_bytes());
            }
        }

        let mut hasher = blake3::Hasher::new();
        hasher.update(&[u8::from(self.config.entropy_enabled)]);
        hasher.update(&[u8::from(self.config.entropy_in_source_files)]);
        hasher.update(&(self.config.min_secret_len as u64).to_le_bytes());
        hasher.update(&self.config.entropy_threshold.to_bits().to_le_bytes());
        update_strings(&mut hasher, &self.config.secret_keywords);
        update_strings(&mut hasher, &self.config.test_keywords);
        update_strings(&mut hasher, &self.config.placeholder_keywords);
        *hasher.finalize().as_bytes()
    }

    #[cfg(feature = "entropy")]
    fn entropy_absent(&self, data: &str, line_index: &crate::context::LineContextIndex) -> bool {
        if !self.config.entropy_enabled {
            return true;
        }
        let keyword_matcher = self
            .assignment_keyword_matcher
            .lock()
            // LAW10: poison recovery retains the complete immutable matcher cache value.
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .resolve(
                &self.config.secret_keywords,
                self.detector_plans.generic_ownership().policy_keywords(),
            );
        let keyword_assignment_lines =
            crate::entropy::keywords::find_keyword_assignment_line_ids_with_matcher(
                data,
                &line_index,
                &keyword_matcher,
            );
        let regular_threshold = self.keyword_free_entropy_threshold(false);
        let sensitive_threshold = self.keyword_free_entropy_threshold(true);
        let keyword_free_threshold = match (regular_threshold, sensitive_threshold) {
            (Some(regular), Some(sensitive)) => Some(regular.min(sensitive)),
            (Some(threshold), None) | (None, Some(threshold)) => Some(threshold),
            (None, None) => None,
        };
        let _g = super::profile::span(keyhog_profile::Stage::Entropy);
        crate::entropy::scanner::find_classified_entropy_secrets_indexed(
            data,
            &line_index,
            &keyword_assignment_lines,
            self.config.min_secret_len,
            1,
            self.config.entropy_threshold,
            keyword_free_threshold,
            &self.config.secret_keywords,
            &self.config.test_keywords,
            &self.config.placeholder_keywords,
            None,
            Some(crate::entropy::scanner::ActiveDetectorPolicy::new(
                &self.detector_plans.generic_ownership(),
                &self.detector_plans,
            )),
            crate::entropy::scanner::KeywordFreeLineScope::All,
        )
        .is_empty()
    }

    #[cfg(not(feature = "entropy"))]
    fn entropy_absent(&self, _data: &str, _line_index: &crate::context::LineContextIndex) -> bool {
        true
    }

    #[cfg(feature = "multiline")]
    fn multiline_absent(&self, data: &str) -> bool {
        !crate::multiline::config::has_concatenation_indicators_with_keyword_gate(data, |bytes| {
            let matcher = self
                .assignment_keyword_matcher
                .lock()
                // LAW10: poison recovery retains the complete immutable matcher cache value.
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .resolve(
                    &self.config.secret_keywords,
                    self.detector_plans.generic_ownership().policy_keywords(),
                );
            matcher.matches(bytes)
        })
    }

    #[cfg(not(feature = "multiline"))]
    fn multiline_absent(&self, _data: &str) -> bool {
        true
    }

    #[cfg(feature = "decode")]
    fn decoder_admission_absent(&self, chunk: &Chunk) -> bool {
        crate::decode::decoder_admission(
            chunk,
            self.detector_plans.decode_transforms(),
            self.detector_plans.decoder_plan(),
        ) == crate::decode::DecodeAdmission::Impossible
    }

    #[cfg(not(feature = "decode"))]
    fn decoder_admission_absent(&self, _chunk: &Chunk) -> bool {
        true
    }

    fn classify_phase1_payload(
        &self,
        chunk: &Chunk,
        fingerprint: [u8; 32],
        bypass_bigram: bool,
        classify_reusable_evidence: bool,
        entropy_config_digest: [u8; 32],
        decoder_admission_context: Option<u8>,
    ) -> ReusablePhase1Evidence {
        let mut reusable_cache =
            classify_reusable_evidence.then(|| self.reusable_phase1_evidence.lock());
        if let Some(evidence) = reusable_cache.as_mut().and_then(|cache| {
            cache.get(
                fingerprint,
                bypass_bigram,
                self.config.unicode_normalization,
                entropy_config_digest,
                decoder_admission_context,
                &chunk.data,
            )
        }) {
            return evidence;
        }

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
        let cpu_trigger_hints =
            classify_reusable_evidence.then(|| self.collect_triggered_patterns_cpu(&chunk.data));
        let confirmed_patterns_absence = cpu_trigger_hints
            .as_deref()
            .is_some_and(|triggers| self.confirmed_patterns_absent(&chunk.data, triggers));
        let normalization_passthrough =
            classify_reusable_evidence && self.normalization_passthrough(&chunk.data);
        let built_line_context_index = classify_reusable_evidence
            // LAW10: line-index construction failure disables evidence reuse; the later scan rebuilds context normally.
            .then(|| crate::context::LineContextIndex::try_new(&chunk.data).ok())
            .flatten()
            .map(Arc::new);
        let entropy_absence = built_line_context_index
            .as_deref()
            .is_some_and(|index| self.entropy_absent(&chunk.data, index));
        let line_context_index = normalization_passthrough
            .then(|| built_line_context_index)
            .flatten();
        let evidence = ReusablePhase1Evidence {
            admission,
            keyword_trigger_count,
            keyword_hints,
            generic_positions,
            phase2_always_active_absence: classify_reusable_evidence
                && self.phase2_always_active_absence(&chunk.data),
            cpu_trigger_hints,
            normalization_passthrough,
            confirmed_patterns_absence,
            entropy_absence,
            multiline_absence: classify_reusable_evidence && self.multiline_absent(&chunk.data),
            decoder_absence: classify_reusable_evidence
                && decoder_admission_context.is_some()
                && self.decoder_admission_absent(chunk),
            line_context_index,
        };
        if let Some(cache) = reusable_cache.as_mut() {
            cache.insert(
                fingerprint,
                bypass_bigram,
                self.config.unicode_normalization,
                entropy_config_digest,
                decoder_admission_context,
                chunk.data.clone(),
                evidence.clone(),
            );
        }
        evidence
    }

    #[doc(hidden)]
    #[cfg(debug_assertions)]
    pub fn reset_reusable_phase1_evidence_hits_for_diagnostics(&self) {
        self.reusable_phase1_evidence.lock().hits = 0;
    }

    #[doc(hidden)]
    #[cfg(debug_assertions)]
    #[must_use]
    pub fn reusable_phase1_evidence_hits_for_diagnostics(&self) -> u64 {
        self.reusable_phase1_evidence.lock().hits
    }

    fn phase1_admission_plan_with_bigram_mode(
        &self,
        chunks: &[Chunk],
        bypass_bigram: bool,
    ) -> Phase1AdmissionPlan {
        let entropy_config_digest = self.entropy_evidence_config_digest();

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
            // LAW10: no exact representative creates a new exact payload class instead of reusing evidence.
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
        let mut representative_decoder_contexts = representatives
            .iter()
            .map(|(_, index)| self.decoder_admission_context_key(&chunks[*index]))
            .collect::<Vec<_>>();
        for (chunk, position) in chunks.iter().zip(representative_for.iter().copied()) {
            let context = self.decoder_admission_context_key(chunk);
            if representative_decoder_contexts[position] != context {
                representative_decoder_contexts[position] = None;
            }
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
                .map(|(position, (fingerprint, index))| {
                    self.classify_phase1_payload(
                        &chunks[*index],
                        *fingerprint,
                        bypass_bigram,
                        representative_counts[position] > 1,
                        entropy_config_digest,
                        representative_decoder_contexts[position],
                    )
                })
                .collect::<Vec<_>>()
        } else {
            representatives
                .iter()
                .enumerate()
                .map(|(position, (fingerprint, index))| {
                    self.classify_phase1_payload(
                        &chunks[*index],
                        *fingerprint,
                        bypass_bigram,
                        representative_counts[position] > 1,
                        entropy_config_digest,
                        representative_decoder_contexts[position],
                    )
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
            let evidence = &classified[representative_position];
            let data = chunk.data.as_bytes();
            let len = data.len();
            summary.record(evidence.admission, len as u64);
            if evidence.keyword_trigger_count != 0 {
                phase2_keyword_triggers.keyword_trigger_chunks += 1;
                phase2_keyword_triggers.keyword_trigger_bytes += len as u64;
                phase2_keyword_triggers.keyword_trigger_count = phase2_keyword_triggers
                    .keyword_trigger_count
                    .saturating_add(evidence.keyword_trigger_count);
            }
            admissions.push(evidence.admission);
            chunk_shapes.push((data.as_ptr() as usize, len));
        }
        let mut phase2_keyword_hints = Vec::with_capacity(classified.len());
        let mut generic_keyword_positions = Vec::with_capacity(classified.len());
        let mut phase2_always_active_absence = Vec::with_capacity(classified.len());
        let mut cpu_trigger_hints = Vec::with_capacity(classified.len());
        let mut normalization_passthrough = Vec::with_capacity(classified.len());
        let mut confirmed_patterns_absence = Vec::with_capacity(classified.len());
        let mut entropy_absence = Vec::with_capacity(classified.len());
        let mut multiline_absence = Vec::with_capacity(classified.len());
        let mut line_context_indices = Vec::with_capacity(classified.len());
        let mut decoder_absence = Vec::with_capacity(classified.len());
        for evidence in classified {
            phase2_keyword_hints.push(evidence.keyword_hints);
            generic_keyword_positions.push(evidence.generic_positions);
            phase2_always_active_absence.push(evidence.phase2_always_active_absence);
            cpu_trigger_hints.push(evidence.cpu_trigger_hints);
            normalization_passthrough.push(evidence.normalization_passthrough);
            confirmed_patterns_absence.push(evidence.confirmed_patterns_absence);
            entropy_absence.push(evidence.entropy_absence);
            multiline_absence.push(evidence.multiline_absence);
            line_context_indices.push(evidence.line_context_index);
            decoder_absence.push(evidence.decoder_absence);
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
            normalization_passthrough,
            unicode_normalization_enabled: self.config.unicode_normalization,
            confirmed_patterns_absence,
            entropy_absence,
            multiline_absence,
            line_context_indices,
            decoder_admission_contexts: representative_decoder_contexts,
            decoder_absence,
            entropy_config_digest,
            #[cfg(debug_assertions)]
            unique_payloads: representatives.len(),
        }
    }
}
