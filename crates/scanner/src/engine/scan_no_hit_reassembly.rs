use super::*;

impl CompiledScanner {
    /// Record no-hit branch matches into the cross-file fragment cache and scan
    /// any reassembled candidates. This keeps monorepo scans able to pair an
    /// access-key fragment in one file with a secret fragment in another.
    #[cfg(feature = "simd")]
    pub(super) fn record_and_reassemble_for_no_hit_chunk(
        &self,
        chunk: &Chunk,
        matches: &mut Vec<RawMatch>,
    ) {
        if matches.is_empty() {
            return;
        }
        // Same assignment+quote prefilter as the in-chunk fragment scan — route
        // it through the one shared predicate (which itself uses memchr2/memchr3,
        // two SIMD passes) instead of re-open-coding five `memchr` calls here.
        if !Self::has_fragment_assignment_syntax(chunk.data.as_bytes()) {
            return;
        }

        let mut reassembled_candidates = Vec::with_capacity(16);
        let path_arc: Option<std::sync::Arc<str>> = chunk
            .metadata
            .path
            .as_deref()
            .map(std::sync::Arc::<str>::from);
        if matches.capacity() < matches.len() + 16 {
            matches.reserve(16);
        }
        for item in matches.iter() {
            if let Some(path) = path_arc.as_ref() {
                let fragment = crate::fragment_cache::SecretFragment {
                    prefix: item.detector_id.to_string(),
                    var_name: item.detector_name.to_string(),
                    value: zeroize::Zeroizing::new(item.credential.to_string()),
                    line: item.location.line.unwrap_or(0), // LAW10: absent line remains metadata-only; candidate stays eligible.
                    path: Some(std::sync::Arc::clone(path)),
                };
                reassembled_candidates
                    .extend(self.fragment_cache.record_and_reassemble_stamped(fragment));
            }
        }
        // ONE owner for the reassembly admission floors and the synthetic probe
        // shape: `scan_postprocess_fragments`. The in-chunk fragment scan and this
        // no-phase-1-hit path MUST gate on the same entropy/length thresholds and
        // build the same `reassembled_key = "…"` probe, or a credential glued
        // across chunks would be admitted by one path and dropped by the other.
        use super::scan_postprocess_fragments::{
            reassembly_probe_data, REASSEMBLY_MIN_ENTROPY, REASSEMBLY_MIN_VALUE_LEN,
        };
        for candidate in reassembled_candidates {
            let entropy = crate::pipeline::match_entropy(candidate.value.as_bytes());
            if entropy < REASSEMBLY_MIN_ENTROPY || candidate.value.len() < REASSEMBLY_MIN_VALUE_LEN
            {
                continue;
            }
            let synthetic_data = reassembly_probe_data(candidate.value.as_str());

            let mut synthetic_metadata = chunk.metadata.clone();
            if let Some(frag_path) = candidate.path.as_deref() {
                synthetic_metadata.path = Some(frag_path.into());
            }
            let synthetic_chunk = Chunk {
                data: synthetic_data.into(),
                metadata: synthetic_metadata,
            };
            let backend = self.live_cpu_backend();
            let mut reassembled_matches = self.scan_inner(&synthetic_chunk, backend, None);
            for raw_match in &mut reassembled_matches {
                raw_match.location.line = Some(candidate.line);
            }
            matches.append(&mut reassembled_matches);
        }
    }
}
