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
                .reduce(Phase1AdmissionSummary::default, Phase1AdmissionSummary::merge);
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
}
