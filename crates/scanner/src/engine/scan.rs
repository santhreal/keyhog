use super::*;

impl CompiledScanner {
    /// Capture the effective decode policy consumed by this scanner.
    pub fn decode_workload_plan(&self) -> crate::decode::DecodeWorkloadPlan {
        crate::decode::DecodeWorkloadPlan::from_compiled_limits(
            self.config.max_decode_depth,
            self.config.max_decode_bytes,
            self.detector_plans.decode_transforms_arc(),
            self.detector_plans.decoder_plan_arc(),
        )
    }

    #[cfg(feature = "decode")]
    #[inline]
    pub(crate) fn chunk_needs_decode_postprocess(&self, chunk: &keyhog_core::Chunk) -> bool {
        self.config.max_decode_depth > 0
            && chunk.data.len() <= self.config.max_decode_bytes
            && crate::decode::decoder_admission(
                chunk,
                self.detector_plans.decode_transforms(),
                self.detector_plans.decoder_plan(),
            ) != crate::decode::DecodeAdmission::Impossible
    }

    #[cfg(not(feature = "decode"))]
    #[inline]
    pub(crate) fn chunk_needs_decode_postprocess(&self, _chunk: &keyhog_core::Chunk) -> bool {
        false
    }

    pub(crate) fn scan_inner(
        &self,
        chunk: &Chunk,
        backend: crate::hw_probe::ScanBackend,
        deadline: Option<std::time::Instant>,
        route: crate::ScanExecutionRoute,
    ) -> crate::error::Result<Vec<RawMatch>> {
        if crate::deadline::expired(deadline) {
            return Ok(Vec::new());
        }
        // KH-116: Record scan metrics atomically
        crate::telemetry::record_file_scanned(chunk.data.len());
        if backend.is_gpu() {
            crate::telemetry::record_gpu_dispatch();
        }
        // prepare_chunk and phase-1 timing are owned by the unified profiler's
        // Preprocess / Phase1Triggers leaf spans (opened inside those calls).
        let prepared = self.prepare_chunk(chunk);
        if crate::deadline::expired(deadline) {
            return Ok(Vec::new());
        }
        let triggered = self.collect_triggered_patterns_for_backend(&chunk.data, backend)?;
        if crate::deadline::expired(deadline) {
            return Ok(Vec::new());
        }
        self.scan_prepared_with_triggered(
            prepared, &triggered, deadline, None, None, None, None, route,
        )
    }
}
