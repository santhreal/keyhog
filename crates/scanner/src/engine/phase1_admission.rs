//! Scanner-owned direct-literal admission classification.

use super::{CompiledScanner, BIGRAM_BLOOM_MIN_CHUNK_BYTES};
use keyhog_core::Chunk;

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

/// Exact per-chunk phase-1 admissions computed while an autoroute key is
/// built. The plan is intentionally opaque: callers can only reuse it through
/// the scanner method that verifies the same chunk slice shape. GPU region
/// presence does not consume this plan because VYRE owns that path's trigger
/// admission.
#[derive(Debug)]
pub struct Phase1AdmissionPlan {
    admissions: Vec<Phase1Admission>,
    chunk_shapes: Vec<(usize, usize)>,
    summary: Phase1AdmissionSummary,
    phase2_keyword_triggers: Phase2KeywordTriggerSummary,
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

    #[inline]
    pub(crate) fn admission_for(&self, index: usize) -> Option<Phase1Admission> {
        self.admissions.get(index).copied()
    }

    #[inline]
    pub(crate) fn matches_chunks(&self, chunks: &[Chunk]) -> bool {
        chunks.len() == self.chunk_shapes.len()
            && chunks
                .iter()
                .zip(&self.chunk_shapes)
                .all(|(chunk, &(ptr, len))| {
                    let bytes = chunk.data.as_bytes();
                    bytes.as_ptr() as usize == ptr && bytes.len() == len
                })
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

impl CompiledScanner {
    #[inline]
    pub(crate) fn phase1_admission(&self, data: &[u8]) -> Phase1Admission {
        if self
            .alphabet_screen
            .as_ref()
            .is_some_and(|screen| !screen.screen(data))
        {
            return Phase1Admission::AlphabetRejected;
        }
        if data.len() >= BIGRAM_BLOOM_MIN_CHUNK_BYTES && !self.bigram_bloom.maybe_overlaps(data) {
            return Phase1Admission::BigramRejected;
        }
        Phase1Admission::Admitted
    }

    #[inline]
    fn phase2_keyword_trigger_count(&self, data: &str) -> u64 {
        self.phase2_keyword_ac.as_ref().map_or(0, |keyword_ac| {
            keyword_ac
                .find_iter(data)
                .fold(0u64, |count, _| count.saturating_add(1))
        })
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

    /// Build the exact per-chunk admission evidence used by autoroute and
    /// retain it for the immediately following production scan. Reusing this
    /// plan removes a duplicate alphabet/bigram pass on SIMD and CPU routes;
    /// the scan boundary rejects a plan for a different chunk slice and
    /// recomputes admissions instead of trusting stale evidence.
    pub fn phase1_admission_plan(&self, chunks: &[Chunk]) -> Phase1AdmissionPlan {
        let classified = if chunks.len() >= 4
            && chunks.iter().map(|chunk| chunk.data.len()).sum::<usize>() >= 64 * 1024
        {
            use rayon::prelude::*;

            chunks
                .par_iter()
                .map(|chunk| {
                    (
                        self.phase1_admission(chunk.data.as_bytes()),
                        self.phase2_keyword_trigger_count(&chunk.data),
                        chunk.data.as_bytes().as_ptr() as usize,
                        chunk.data.len(),
                    )
                })
                .collect::<Vec<_>>()
        } else {
            chunks
                .iter()
                .map(|chunk| {
                    (
                        self.phase1_admission(chunk.data.as_bytes()),
                        self.phase2_keyword_trigger_count(&chunk.data),
                        chunk.data.as_bytes().as_ptr() as usize,
                        chunk.data.len(),
                    )
                })
                .collect::<Vec<_>>()
        };
        let mut summary = Phase1AdmissionSummary::default();
        let mut phase2_keyword_triggers = Phase2KeywordTriggerSummary::default();
        let mut admissions = Vec::with_capacity(classified.len());
        let mut chunk_shapes = Vec::with_capacity(classified.len());
        for (admission, keyword_trigger_count, ptr, len) in classified {
            summary.record(admission, len as u64);
            if keyword_trigger_count != 0 {
                phase2_keyword_triggers.keyword_trigger_chunks += 1;
                phase2_keyword_triggers.keyword_trigger_bytes += len as u64;
                phase2_keyword_triggers.keyword_trigger_count = phase2_keyword_triggers
                    .keyword_trigger_count
                    .saturating_add(keyword_trigger_count);
            }
            admissions.push(admission);
            chunk_shapes.push((ptr, len));
        }
        Phase1AdmissionPlan {
            admissions,
            chunk_shapes,
            summary,
            phase2_keyword_triggers,
        }
    }
}
