use super::scan_inner_profile::{
    scan_inner_prof_enabled, SCAN_INNER_CALLS, SCAN_PHASE1_NS, SCAN_PREPARE_NS,
};
use super::*;

impl CompiledScanner {
    #[cfg(feature = "decode")]
    #[inline]
    pub(super) fn chunk_needs_decode_postprocess(&self, chunk: &keyhog_core::Chunk) -> bool {
        self.config.max_decode_depth > 0
            && chunk.data.len() <= self.config.max_decode_bytes
            && crate::decode::has_decodable_payload(chunk.data.as_bytes())
    }

    #[cfg(not(feature = "decode"))]
    #[inline]
    pub(super) fn chunk_needs_decode_postprocess(&self, _chunk: &keyhog_core::Chunk) -> bool {
        false
    }

    pub(crate) fn scan_inner(
        &self,
        chunk: &Chunk,
        backend: crate::hw_probe::ScanBackend,
        deadline: Option<std::time::Instant>,
    ) -> Vec<RawMatch> {
        // KH-116: Record scan metrics atomically
        crate::telemetry::record_file_scanned(chunk.data.len());
        if backend == crate::hw_probe::ScanBackend::Gpu
            || backend == crate::hw_probe::ScanBackend::MegaScan
        {
            crate::telemetry::record_gpu_dispatch();
        }
        let prof = scan_inner_prof_enabled();
        let t0 = prof.then(std::time::Instant::now);
        let prepared = self.prepare_chunk(chunk);
        if let Some(t) = t0 {
            SCAN_PREPARE_NS.fetch_add(
                t.elapsed().as_nanos() as u64,
                std::sync::atomic::Ordering::Relaxed,
            );
        }
        let t1 = prof.then(std::time::Instant::now);
        let triggered =
            self.collect_triggered_patterns_for_backend(&prepared.preprocessed.text, backend);
        if let Some(t) = t1 {
            SCAN_PHASE1_NS.fetch_add(
                t.elapsed().as_nanos() as u64,
                std::sync::atomic::Ordering::Relaxed,
            );
            SCAN_INNER_CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        self.scan_prepared_with_triggered(prepared, backend, triggered, deadline, None)
    }
}
