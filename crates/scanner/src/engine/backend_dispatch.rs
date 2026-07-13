use super::*;
use crate::hw_probe::ScanBackend;
use keyhog_core::Chunk;

impl CompiledScanner {
    pub(crate) fn scan_chunks_with_backend_internal(
        &self,
        chunks: &[Chunk],
        backend: ScanBackend,
    ) -> Vec<Vec<RawMatch>> {
        // Non-GPU backends (and empty batches) run the parallel CPU path. rayon's
        // global pool is configured by the CLI orchestrator (--threads /
        // [scan].threads / physical cores); Hyperscan + AC scans are CPU-bound
        // and independent per-chunk, so par_iter() saturates cores. The
        // `scan_chunk_boundaries` pass reassembles secrets straddling the seam
        // between adjacent gapless chunks of the same file (a per-chunk scan sees
        // each half too short to match) (load-bearing recall, not optional).
        let gpu_path = matches!(backend, ScanBackend::Gpu);
        if !gpu_path || chunks.is_empty() {
            return self.scan_chunks_cpu_parallel(chunks, backend);
        }

        // The batched region-presence literal set is the SINGLE on-GPU trigger
        // producer. It acquires the compiled GPU literal matcher and hard-fails
        // the selected route on dispatch degradation, so it runs whenever a GPU
        // backend is selected without silently substituting CPU/SIMD.
        #[cfg(feature = "gpu")]
        {
            self.scan_coalesced_gpu_region_presence(chunks)
        }
        // GPU compiled out: the public entry guard rejects a selected GPU route
        // before this internal compatibility arm can execute.
        #[cfg(not(feature = "gpu"))]
        {
            self.scan_chunks_cpu_parallel(chunks, backend)
        }
    }

    /// Parallel per-chunk CPU scan + cross-chunk boundary reassembly. The single
    /// owner of this path: it is taken both for any non-GPU backend (and empty
    /// batches) and as the GPU-compiled-out / GPU-request degrade, which were
    /// otherwise two byte-identical copies that could drift apart (the
    /// `scan_chunk_boundaries` seam pass is load-bearing recall on both).
    fn scan_chunks_cpu_parallel(
        &self,
        chunks: &[Chunk],
        backend: ScanBackend,
    ) -> Vec<Vec<RawMatch>> {
        use rayon::prelude::*;
        let mut results: Vec<Vec<RawMatch>> = chunks
            .par_iter()
            .map(|chunk| self.scan_with_backend(chunk, backend))
            .collect();
        super::boundary::scan_chunk_boundaries(self, chunks, &mut results);
        results
    }

    pub(crate) fn prepare_chunk<'a>(&self, chunk: &'a Chunk) -> PreparedChunk<'a> {
        let _g = super::profile::span(super::profile::P::Preprocess);
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
        //
        // The Cow MUST borrow `chunk.data` (lifetime `'a`) on the no-op path,
        // not a local, so the borrowed passthrough text below can outlive this
        // call inside `PreparedChunk<'a>`. We therefore chain the two
        // normalization stages explicitly: a stage that rewrites bytes yields
        // `Cow::Owned`; a no-op stage preserves the `&'a chunk.data` borrow.
        let data_to_pp: std::borrow::Cow<'a, str> = if self.config.unicode_normalization {
            match crate::unicode_hardening::normalize_homoglyphs(&chunk.data) {
                // Homoglyph stage rewrote the bytes: the owned String is the
                // canonical text. The interior-control strip then operates on
                // that owned buffer; either outcome stays owned.
                std::borrow::Cow::Owned(normalized) => {
                    match crate::unicode_hardening::strip_interior_evasion_controls(&normalized) {
                        std::borrow::Cow::Owned(stripped) => std::borrow::Cow::Owned(stripped),
                        std::borrow::Cow::Borrowed(_) => std::borrow::Cow::Owned(normalized),
                    }
                }
                // Homoglyph stage was a no-op: bytes are still `chunk.data`.
                // Run the interior-control strip against `chunk.data` itself so
                // a no-op there preserves the `'a` borrow on the chunk.
                std::borrow::Cow::Borrowed(_) => {
                    crate::unicode_hardening::strip_interior_evasion_controls(&chunk.data)
                }
            }
        } else {
            std::borrow::Cow::Borrowed(&chunk.data)
        };

        // For the structured / multiline-join paths the preprocessed text is
        // freshly synthesized (owned regardless of `data_to_pp`), so they read
        // it through a plain `&str`. The passthrough path, by contrast, is
        // byte-identical to `data_to_pp` and carries the Cow through unchanged
        // so a borrowed chunk stays borrowed (no full-body copy).
        // A chunk the decode-through pipeline produced carries `decoded_span`;
        // on such a derived buffer a structured-format parse failure is expected
        // and loses nothing (the encoded surface was already decoded + scanned),
        // so it must not be counted/announced as a lost decode surface.
        let decode_derived = chunk.metadata.decoded_span.is_some();
        let preprocessed = if let Some(pp) = crate::structured::preprocess(
            &data_to_pp,
            chunk.metadata.path.as_deref(),
            decode_derived,
        ) {
            pp
        } else {
            #[cfg(feature = "multiline")]
            {
                if crate::multiline::has_concatenation_indicators(&data_to_pp) {
                    crate::multiline::preprocess_multiline(
                        data_to_pp,
                        &self.config.multiline,
                        &self.fragment_cache,
                    )
                } else {
                    ScannerPreprocessedText::passthrough(data_to_pp)
                }
            }
            #[cfg(not(feature = "multiline"))]
            ScannerPreprocessedText::passthrough(data_to_pp)
        };

        PreparedChunk {
            chunk,
            preprocessed,
            line_offsets: std::sync::OnceLock::new(),
        }
    }
}
