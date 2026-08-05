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
    /// Surface the decode-through pass that `chunk_needs_decode_postprocess`
    /// declines purely because the chunk is larger than `max_decode_bytes`.
    ///
    /// The raw bytes still get scanned, but nothing base64/hex/URL-encoded
    /// inside an oversize chunk is recovered. Lowering `--decode-size-limit`
    /// therefore drops findings, and before this counter existed it did so with
    /// no operator-visible signal: the report just showed a smaller number.
    ///
    /// Deliberately keyed on size alone, not on `decoder_admission`. Admission is
    /// an O(chunk) alphabet probe that the size gate currently short-circuits, so
    /// probing here would add a full extra pass over every large chunk. The
    /// decline is a fact regardless: the operator's own limit stopped the pass
    /// from running, which is exactly what the coverage gap reports. With the
    /// compiled 512 KiB default no ordinary chunk reaches it, so the counter
    /// stays at zero unless a limit or a genuinely large input makes it true.
    ///
    /// INVARIANT: this is called at exactly the sites that call
    /// `record_file_scanned`, and the two must stay paired. An earlier version of
    /// this comment claimed `scan_inner` was "the one guaranteed once-per-chunk
    /// site"; that was wrong, and `engine/scan_coalesced.rs` says so three
    /// modules over: the coalesced SIMD route bypasses `scan_inner` entirely and
    /// records the scanner telemetry itself. The consequence was a
    /// BACKEND-DEPENDENT coverage gap, caught by a peer's calibration guard and
    /// then reproduced directly: on `crates/`, `--backend cpu` reported one
    /// declined chunk and `--backend simd` reported none, for byte-identical
    /// findings (25, same identity digest). Recall never differed; only the
    /// operator's warning did, which is worse in the sense that it was invisible.
    /// Pairing with `record_file_scanned` is what makes the count route-agnostic,
    /// because that event already has one call per chunk per route by contract.
    #[cfg(feature = "decode")]
    #[inline]
    pub(crate) fn record_decode_size_decline(&self, chunk: &Chunk) {
        if self.config.max_decode_depth > 0 && chunk.data.len() > self.config.max_decode_bytes {
            crate::telemetry::record_decode_oversize_skip();
            tracing::warn!(
                chunk_bytes = chunk.data.len(),
                ceiling = self.config.max_decode_bytes,
                "chunk exceeds max_decode_bytes; decode-through did NOT run, encoded secrets inside it were not recovered"
            );
        }
    }

    #[cfg(not(feature = "decode"))]
    #[inline]
    fn record_decode_size_decline(&self, _chunk: &Chunk) {}


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
        self.record_decode_size_decline(chunk);
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
