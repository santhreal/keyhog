use super::*;
use crate::hw_probe::ScanBackend;
use keyhog_core::Chunk;

impl CompiledScanner {
    pub(crate) fn scan_chunks_with_backend_internal(
        &self,
        chunks: &[Chunk],
        backend: ScanBackend,
    ) -> Vec<Vec<RawMatch>> {
        // GPU paths: literal-set (Gpu) and regex-NFA (MegaScan). Both
        // require a working GPU adapter + compiled matchers; the lazy
        // compile is gated below so a missing GPU silently degrades to
        // SIMD via `scan_with_backend` per chunk.
        let gpu_path = matches!(backend, ScanBackend::Gpu | ScanBackend::MegaScan);
        if !gpu_path || chunks.is_empty() {
            // Parallel CPU path: rayon's global pool is configured by the
            // CLI orchestrator with --threads / KEYHOG_THREADS / physical
            // core count. Hyperscan + AC scans are CPU-bound and trivially
            // independent per-chunk, so par_iter() saturates cores cleanly
            // - was previously a serial iter().map() that pinned to one
            // worker even on 32-core boxes.
            use rayon::prelude::*;
            let mut results: Vec<Vec<RawMatch>> = chunks
                .par_iter()
                .map(|chunk| self.scan_with_backend(chunk, backend))
                .collect();
            // Cross-chunk window-boundary reassembly. Without this, a
            // secret straddling the seam between two adjacent gapless
            // chunks from the same file is invisible - both halves are
            // too short to match the regex on their own. The GPU paths
            // below call `scan_chunk_boundaries` after their batch
            // dispatch (see `scan_coalesced_megascan`/`scan_coalesced_gpu`);
            // the CPU path historically did NOT, so callers using
            // `scan_chunks_with_backend(_, SimdCpu | CpuFallback)` lost
            // boundary recall silently. P3 proptest regression: a 38-byte
            // tail chunk plus 911-byte head chunk dropped an ASIA…
            // credential that straddled byte 911. Boundary scan
            // synthesises a 2 KiB tail+head buffer per adjacent pair
            // (`MAX_BOUNDARY` per side) and runs a fresh in-chunk scan;
            // cost is `(N-1) × ~2 KiB` total, negligible vs per-chunk
            // scan cost on the same dataset.
            super::boundary::scan_chunk_boundaries(self, chunks, &mut results);
            return results;
        }

        // GPU batch path: `scan_coalesced_gpu` produces full per-chunk
        // RawMatch results in one device dispatch + parallel post-process.
        // The previous `populate_gpu_batch_triggers` was a comment-only TODO
        // that threw the GPU results away - see audit release-2026-04-26.
        if self.gpu_literals.is_none() || self.gpu_backend.is_none() {
            super::gpu_forced::deny_silent_gpu_degrade(self, backend);
            let fallback_backend = self.degraded_backend_after_gpu_failure();
            use rayon::prelude::*;
            let mut results: Vec<Vec<RawMatch>> = chunks
                .par_iter()
                .map(|chunk| self.scan_with_backend(chunk, fallback_backend))
                .collect();
            super::boundary::scan_chunk_boundaries(self, chunks, &mut results);
            return results;
        }

        match backend {
            ScanBackend::MegaScan => self.scan_coalesced_megascan(chunks),
            _ => self.scan_coalesced_gpu(chunks),
        }
    }

    pub(crate) fn prepare_chunk<'a>(&self, chunk: &'a Chunk) -> PreparedChunk<'a> {
        // Note: non-ASCII normalization used to swap `chunk` to an
        // owned `Chunk` via `normalize_scannable_chunk`. That path
        // is rarely-hit (most source code is pure ASCII) and the
        // returned Chunk was immediately consumed via clone into the
        // owned PreparedChunk anyway, so the borrow design works:
        // for non-ASCII inputs we still feed the normalization
        // through `unicode_hardening::normalize_homoglyphs` Cow
        // below, which lands the normalized text in
        // `preprocessed.text`. The raw `chunk.data` borrow remains
        // intact for the few downstream consumers that read it
        // (extract_confirmed_patterns uses preprocessed.text by
        // default; raw `chunk.data` only via the drift fallback).

        // Homoglyph normalization: zero-allocation Cow fast path. Pure-ASCII
        // and evasion-free inputs (the 99% case) borrow `chunk.data` directly.
        // Only inputs containing actual homoglyphs/zero-width/RTL allocate.
        let data_to_pp: std::borrow::Cow<'_, str> = if self.config.unicode_normalization {
            let normalized = crate::unicode_hardening::normalize_homoglyphs(&chunk.data);
            // Prefix-anchored interior-control strip: same evasion-hardening
            // stage as homoglyph normalization (offsets are already in
            // normalized-text space here). Removes `\t`/`\r` an attacker
            // inserted inside a credential body after a known structured prefix
            // (`AKIA<TAB>…`), while leaving structural whitespace untouched.
            // Borrowed fast path unless such a control is actually present.
            match crate::unicode_hardening::strip_interior_evasion_controls(&normalized) {
                std::borrow::Cow::Owned(stripped) => std::borrow::Cow::Owned(stripped),
                std::borrow::Cow::Borrowed(_) => normalized,
            }
        } else {
            std::borrow::Cow::Borrowed(&chunk.data)
        };
        let data_ref: &str = &data_to_pp;

        let preprocessed = if let Some(pp) =
            crate::structured::preprocess(data_ref, chunk.metadata.path.as_deref())
        {
            pp
        } else {
            #[cfg(feature = "multiline")]
            if crate::multiline::has_concatenation_indicators(data_ref) {
                crate::multiline::preprocess_multiline(
                    data_ref,
                    &self.config.multiline,
                    &self.fragment_cache,
                )
            } else {
                ScannerPreprocessedText::passthrough(data_ref)
            }
            #[cfg(not(feature = "multiline"))]
            ScannerPreprocessedText::passthrough(data_ref)
        };

        PreparedChunk {
            chunk,
            preprocessed,
            line_offsets: std::sync::OnceLock::new(),
        }
    }
}
