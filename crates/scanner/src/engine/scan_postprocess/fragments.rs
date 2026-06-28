//! Cross-chunk SECRET-FRAGMENT reassembly scan, extracted from
//! `scan_postprocess.rs` (Law 5). `scan_cross_chunk_fragments` records each
//! `var = "value"` fragment into the `FragmentCache` and rescans any
//! reassembled same-path candidate, stamping the trigger fragment's real
//! source line+offset. `pub(crate)` so `post_process_matches_inner` (still in
//! `scan_postprocess.rs`) can call it across the module boundary. Pure move.
use super::CompiledScanner;
use keyhog_core::{Chunk, RawMatch};

impl CompiledScanner {
    pub(crate) fn scan_cross_chunk_fragments(
        &self,
        chunk: &Chunk,
        matches: &mut Vec<RawMatch>,
        deadline: Option<std::time::Instant>,
    ) {
        if crate::deadline::expired(deadline) {
            return;
        }
        if !Self::has_fragment_assignment_syntax(chunk.data.as_bytes()) {
            return;
        }

        let Some(assign_re) = crate::shared_regexes::ASSIGN_RE.as_ref() else {
            return;
        };

        for (line_idx, line) in chunk.data.lines().enumerate() {
            if crate::deadline::expired(deadline) {
                return;
            }
            if let Some(caps) = assign_re.captures(line) {
                let Some(var_name_match) = caps.get(1) else {
                    continue;
                };
                let Some(value_match) = caps.get(2) else {
                    continue;
                };
                if !crate::multiline::fragment_assignment_name_is_credential_like(
                    var_name_match.as_str(),
                ) {
                    continue;
                }

                let fragment_line = line_idx + 1;
                // Compute the trigger value's byte offset within chunk.data.
                // `line` borrows from chunk.data so pointer arithmetic gives
                // the line's offset; value_match.start() is offset within
                // `line`. Used below to give reassembled findings a REAL
                // source-file position instead of the synthetic
                // synthetic chunk offset (which used to read ~19 - the length
                // of the `reassembled_key = "` prefix). Synthetic offsets
                // broke the chunk-boundary recall invariant (proptest
                // gpu_proptest_invariants P3): identical credentials got
                // different offsets depending on whether the source was
                // scanned as one chunk or two, making the test see false
                // "drops". Real-source-offset removes that asymmetry.
                let fragment_value_offset = {
                    let line_offset =
                        line.as_ptr() as usize - chunk.data.as_ref().as_ptr() as usize;
                    line_offset + value_match.start()
                };
                // The contributing fragment's path. Reassembly is same-path
                // only (see `FragmentCache::record_and_reassemble`), so this
                // is the authoritative attribution for every candidate the
                // trigger fragment produces. Captured before the move below
                // so the reassembled finding's `file_path` can be stamped
                // from it instead of inherited from `chunk.metadata.clone()`.
                let fragment_path: Option<std::sync::Arc<str>> = chunk
                    .metadata
                    .path
                    .as_ref()
                    .map(|p| std::sync::Arc::from(p.as_str()));
                let fragment = crate::fragment_cache::SecretFragment {
                    prefix: crate::multiline::extract_prefix(var_name_match.as_str()),
                    var_name: var_name_match.as_str().to_string(),
                    value: zeroize::Zeroizing::new(value_match.as_str().to_string()),
                    line: fragment_line,
                    path: fragment_path.clone(),
                };

                let candidates = self.fragment_cache.record_and_reassemble(fragment);
                for candidate in candidates {
                    if crate::deadline::expired(deadline) {
                        return;
                    }
                    // `candidate` is `Zeroizing<String>` (kimi-wave1 fix).
                    let entropy = crate::pipeline::match_entropy(candidate.as_str().as_bytes());
                    if entropy < 3.0 || candidate.len() < 16 {
                        continue;
                    }

                    let mut synthetic_data = String::with_capacity(candidate.len() + 24);
                    synthetic_data.push_str("reassembled_key = \"");
                    synthetic_data.push_str(candidate.as_str());
                    synthetic_data.push('"');
                    let synthetic_chunk = Chunk {
                        data: synthetic_data.into(),
                        metadata: chunk.metadata.clone(),
                    };

                    // Tiny synthesized chunk - NEVER dispatch through
                    // GPU even if `--backend gpu` is set; the
                    // per-dispatch overhead (~10-100 ms) is orders of
                    // magnitude larger than scanning ~50 bytes on the
                    // CPU. The previous flow leaked the env override
                    // into `select_backend_for_file` and turned a
                    // 64 MiB messy-corpus scan into ~60 s of synthetic
                    // GPU launches.
                    let backend = {
                        #[cfg(feature = "simd")]
                        {
                            crate::hw_probe::ScanBackend::SimdCpu
                        }
                        #[cfg(not(feature = "simd"))]
                        {
                            crate::hw_probe::ScanBackend::CpuFallback
                        }
                    };
                    let mut reassembled_matches =
                        self.scan_inner(&synthetic_chunk, backend, deadline);
                    if crate::deadline::expired(deadline) {
                        return;
                    }
                    for m in &mut reassembled_matches {
                        m.detector_id = format!("{}:reassembled", m.detector_id).into();
                        // Stamp the finding's path from the CONTRIBUTING
                        // fragment, not the synthetic chunk (which
                        // cloned the outer chunk's metadata). A candidate can
                        // be glued from a fragment recorded by an earlier
                        // chunk plus this trigger fragment; inheriting the
                        // synthetic chunk's path mis-attributed the reassembled
                        // finding to whatever chunk happened to be scanning
                        // when reassembly fired - the cross-file attribution
                        // mangling that produced `:reassembled` FPs. Reassembly
                        // is same-path only, so `fragment_path` is the correct
                        // source for every candidate this fragment yields.
                        m.location.file_path = fragment_path.clone();
                        // Point the finding to the trigger fragment's
                        // line AND byte offset in the source chunk.
                        // Previously offset was the synthetic position
                        // inside `"reassembled_key = \"…\""` (~19 bytes
                        // from synthetic chunk start), which broke the
                        // chunk-boundary recall invariant since the
                        // same credential got different synthetic
                        // offsets depending on chunk topology.
                        // fragment_line is window-local to `chunk`; add the
                        // chunk's base line so the reassembled finding reports
                        // the absolute file line, matching the `+ base_offset`
                        // on `m.location.offset` below. 0 on non-windowed.
                        m.location.line = Some(fragment_line + chunk.metadata.base_line);
                        // kimi-engine audit: chunk metadata can carry
                        // `base_offset` near usize::MAX (custom sources
                        // synthesizing chunks). Unchecked addition would
                        // panic in debug / wrap in release; saturating
                        // pins to MAX which is a benign garbage offset
                        // (no legitimate file is 18 EB long) but does
                        // not panic mid-scan.
                        m.location.offset =
                            fragment_value_offset.saturating_add(chunk.metadata.base_offset);
                    }
                    matches.append(&mut reassembled_matches);
                    // Zeroized automatically on drop (SensitiveString)
                }
            }
        }
    }

    pub(crate) fn has_fragment_assignment_syntax(data: &[u8]) -> bool {
        // One SIMD pass per byte-class instead of one per byte: `memchr2`/
        // `memchr3` find the first occurrence of ANY of their needles, so
        // `.is_some()` is true iff at least one is present — byte-identical to
        // the OR-of-`memchr` chain, but 2 passes over `data` instead of 5.
        let has_assignment = memchr::memchr2(b'=', b':', data).is_some();
        let has_quote = memchr::memchr3(b'"', b'\'', b'`', data).is_some();
        has_assignment && has_quote
    }
}
