use super::scan_filters::{
    has_generic_assignment_keyword, has_high_entropy_run_fast, has_secret_keyword_fast,
};
use super::*;

impl CompiledScanner {
    pub fn scan_coalesced_gpu_phase2(
        &self,
        chunks: &[keyhog_core::Chunk],
        per_chunk_hits: Vec<Vec<(u32, u32, u32)>>,
    ) -> Vec<Vec<keyhog_core::RawMatch>> {
        use rayon::prelude::*;
        let mut results: Vec<Vec<keyhog_core::RawMatch>> = chunks
            .par_iter()
            .zip(per_chunk_hits.into_par_iter())
            .map(|(chunk, hits)| {
                if hits.is_empty() && !gpu_phase2_should_scan_no_hit_chunk(chunk) {
                    return Vec::new();
                }
                let prepared = self.prepare_chunk(chunk);
                let mut matches = self.scan_prepared_with_pattern_hits(prepared, hits, None);
                // Parity with SIMD's `scan_chunks_with_backend` path:
                // `scan_with_backend` → `scan_with_deadline_and_backend`
                // calls `post_process_matches` after the in-chunk scan,
                // which decode-recurses (base64/hex/url) and reassembles
                // cross-chunk-fragment secrets. The GPU path previously
                // skipped this - the gpu_parity test catches the
                // missed StackBlitz finding extracted from the
                // base64-decoded sub-chunk of the stripe-aws fixture.
                // A prior comment here claimed SIMD's `scan_coalesced`
                // also skips post-process; that's true for the bulk-
                // scan entry point but NOT for `scan_chunks_with_backend`,
                // which is the API the parity test (and operators
                // forcing `--backend gpu`) actually call.
                self.post_process_matches(chunk, &mut matches, None);
                matches
            })
            .collect();

        // Cross-chunk boundary reassembly: identical contract to the
        // SIMD path. Without this, a secret straddling the seam between
        // two adjacent windows of one big file slips through the GPU
        // dispatch (the inter-chunk separator bytes intentionally make
        // the literal-set engine ignore the seam) AND through the
        // per-chunk extraction loop above (each chunk only sees its
        // own slice). The boundary helper synthesises a thin tail+head
        // buffer per gapless pair and rescans it on the CPU path, so
        // GPU users get the same recall as SIMD users on big files.
        super::boundary::scan_chunk_boundaries(self, chunks, &mut results);
        results
    }
}

fn gpu_phase2_should_scan_no_hit_chunk(chunk: &keyhog_core::Chunk) -> bool {
    let data = chunk.data.as_bytes();

    #[cfg(feature = "multiline")]
    if crate::multiline::has_concatenation_indicators(&chunk.data) && has_secret_keyword_fast(data)
    {
        return true;
    }

    chunk.data.len() <= 32 * 1024
        && (has_generic_assignment_keyword(data)
            || has_secret_keyword_fast(data)
            || has_high_entropy_run_fast(data))
}
