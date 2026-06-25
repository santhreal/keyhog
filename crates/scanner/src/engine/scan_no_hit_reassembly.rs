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
        let data = chunk.data.as_bytes();
        let has_assignment =
            memchr::memchr(b'=', data).is_some() || memchr::memchr(b':', data).is_some();
        let has_quote = memchr::memchr(b'"', data).is_some()
            || memchr::memchr(b'\'', data).is_some()
            || memchr::memchr(b'`', data).is_some();
        if !(has_assignment && has_quote) {
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
        for candidate in reassembled_candidates {
            let entropy = crate::pipeline::match_entropy(candidate.value.as_bytes());
            if entropy < 3.0 || candidate.value.len() < 16 {
                continue;
            }
            let mut synthetic_data = String::with_capacity(candidate.value.len() + 24);
            synthetic_data.push_str("reassembled_key = \"");
            synthetic_data.push_str(candidate.value.as_str());
            synthetic_data.push('"');

            let mut synthetic_metadata = chunk.metadata.clone();
            if let Some(frag_path) = candidate.path.as_deref() {
                synthetic_metadata.path = Some(frag_path.to_string());
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
