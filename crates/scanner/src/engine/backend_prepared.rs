use super::*;
use keyhog_core::Chunk;

pub(crate) struct PreparedChunk<'a> {
    /// Borrowed handle on the caller's chunk. Was `Chunk` (owned)
    /// historically - every consumer reads `prepared.chunk.foo` via
    /// auto-deref, never moves out, and the caller already owns the
    /// chunk for the call's duration. Borrowing drops one full
    /// ChunkMetadata clone per chunk (5+ String allocations on
    /// every code-tree scan).
    pub(crate) chunk: &'a Chunk,
    /// Preprocessed scan text. Borrows `chunk.data` (`Cow::Borrowed`) on the
    /// passthrough common path — no per-chunk full-body copy — and owns a
    /// synthesized `String` only on the structured/multiline-join paths.
    pub(crate) preprocessed: ScannerPreprocessedText<'a>,
    /// Cached `compute_line_offsets(&preprocessed.text)`. Both the
    /// triggered-pattern path and the pattern-hits path used to call
    /// `compute_line_offsets` separately, walking the entire
    /// preprocessed text twice per chunk to count newlines. Cache
    /// it once at first access via OnceLock so the second caller
    /// hits a memoized Vec instead of re-scanning. Task #93.
    pub(crate) line_offsets: std::sync::OnceLock<Vec<usize>>,
}

impl<'a> PreparedChunk<'a> {
    /// Lazily-computed cumulative line-start offsets for the
    /// preprocessed text. Cheap to call repeatedly; the first call
    /// walks the text once, subsequent calls return a borrow into
    /// the cached Vec.
    pub(crate) fn line_offsets(&self) -> &[usize] {
        self.line_offsets
            .get_or_init(|| compute_line_offsets(&self.preprocessed.text))
    }
}

#[cfg(feature = "simd")]
/// Returns the Hyperscan scanner, the hs_id -> ac_map index map, and the
/// list of ac_map indices whose regex Hyperscan could NOT compile
/// (over-long, or an unsupported construct like a large `{100,200}`
/// bounded repeat). Those patterns produce zero HS matches, so the caller
/// MUST route them into the backend-independent keyword fallback or they
/// are silently dead in every HS-backed scan. Before this was returned,
/// ~10 context-anchored detectors (line/paloalto/tower/keystonejs/...)
/// never fired on their own positives. See contracts_runner.
pub(crate) fn build_simd_scanner(
    ac_map: &[CompiledPattern],
    _fallback: &[(CompiledPattern, Vec<String>)],
    tuning: &crate::scanner_config::ScannerTuningConfig,
) -> Option<(crate::simd::backend::HsScanner, Vec<Vec<usize>>, Vec<usize>)> {
    use std::collections::HashMap;

    let mut regex_to_hs_id: HashMap<String, usize> = HashMap::new();
    let mut hs_patterns: Vec<(usize, usize, String, bool)> = Vec::new();
    let mut index_map: Vec<Vec<usize>> = Vec::new();

    for (idx, entry) in ac_map.iter().enumerate() {
        let regex_str = entry.regex.as_str();
        let hs_id = *regex_to_hs_id
            .entry(regex_str.to_string())
            .or_insert_with(|| {
                let id = hs_patterns.len();
                hs_patterns.push((
                    entry.detector_index,
                    id,
                    regex_str.to_string(),
                    entry.group.is_some(),
                ));
                index_map.push(Vec::new());
                id
            });
        index_map[hs_id].push(idx);
    }

    let pattern_refs: Vec<(usize, usize, &str, bool)> = hs_patterns
        .iter()
        .map(|(a, b, c, d)| (*a, *b, c.as_str(), *d))
        .collect();

    tracing::info!(
        unique = hs_patterns.len(),
        raw = ac_map.len(),
        "compiling deduplicated AC regexes into Hyperscan"
    );

    let opts = crate::simd::backend::HsCompileOpts {
        shard_target: tuning.hs_shard_target,
        ..Default::default()
    };
    match crate::simd::backend::HsScanner::compile_with_opts(&pattern_refs, opts) {
        Ok((scanner, unsupported)) => {
            // Map the unsupported hs_ids back to the ac_map indices that
            // share each dropped regex. These never match under HS, so the
            // caller reroutes them to the keyword fallback.
            let unsupported_ac: Vec<usize> = unsupported
                .iter()
                .filter_map(|&hs_id| index_map.get(hs_id))
                .flatten()
                .copied()
                .collect();
            tracing::info!(
                compiled = scanner.pattern_count(),
                unsupported = unsupported.len(),
                unsupported_ac = unsupported_ac.len(),
                "HS ready"
            );
            Some((scanner, index_map, unsupported_ac))
        }
        Err(error) => {
            tracing::warn!("HS compilation failed: {error}");
            None
        }
    }
}
