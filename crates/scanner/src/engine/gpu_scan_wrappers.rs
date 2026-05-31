use super::*;
use crate::hw_probe::ScanBackend;

/// Two-phase output of [`CompiledScanner::scan_coalesced_gpu_phase1`].
pub enum GpuPhase1Output {
    Hits(Vec<Vec<(u32, u32, u32)>>),
    Done(Vec<Vec<keyhog_core::RawMatch>>),
}

impl CompiledScanner {
    pub fn scan_coalesced_gpu(
        &self,
        chunks: &[keyhog_core::Chunk],
    ) -> Vec<Vec<keyhog_core::RawMatch>> {
        match self.scan_coalesced_gpu_phase1(chunks) {
            GpuPhase1Output::Hits(hits) => self.scan_coalesced_gpu_phase2(chunks, hits),
            GpuPhase1Output::Done(results) => results,
        }
    }

    pub fn scan_coalesced_gpu_ac(
        &self,
        chunks: &[keyhog_core::Chunk],
    ) -> Vec<Vec<keyhog_core::RawMatch>> {
        match self.scan_coalesced_gpu_ac_phase1(chunks) {
            GpuPhase1Output::Hits(hits) => self.scan_coalesced_gpu_phase2(chunks, hits),
            GpuPhase1Output::Done(results) => results,
        }
    }

    pub(crate) fn scan_coalesced_non_gpu(
        &self,
        chunks: &[keyhog_core::Chunk],
    ) -> Vec<Vec<keyhog_core::RawMatch>> {
        #[cfg(feature = "simd")]
        {
            self.scan_coalesced(chunks)
        }
        #[cfg(not(feature = "simd"))]
        {
            chunks.iter().map(|c| self.scan(c)).collect()
        }
    }

    pub(crate) fn gpu_degrade_done(
        &self,
        chunks: &[keyhog_core::Chunk],
        backend: ScanBackend,
    ) -> GpuPhase1Output {
        self.gpu_degrade_done_with_reason(chunks, backend, None)
    }

    pub(crate) fn gpu_degrade_done_with_reason(
        &self,
        chunks: &[keyhog_core::Chunk],
        backend: ScanBackend,
        reason: Option<&str>,
    ) -> GpuPhase1Output {
        super::gpu_forced::deny_silent_gpu_degrade_with_reason(self, backend, reason);
        GpuPhase1Output::Done(self.scan_coalesced_non_gpu(chunks))
    }
}
