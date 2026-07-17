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
    /// passthrough common path, no per-chunk full-body copy, and owns a
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

    pub(crate) fn code_lines(&self, line_offsets: &[usize]) -> Vec<&str> {
        if self.preprocessed.text.as_bytes() == self.chunk.data.as_bytes() {
            code_lines_from_offsets(&self.chunk.data, line_offsets)
        } else {
            self.chunk.data.lines().collect()
        }
    }
}

pub(crate) fn code_lines_from_offsets<'a>(text: &'a str, line_offsets: &[usize]) -> Vec<&'a str> {
    let mut lines = Vec::with_capacity(line_offsets.len());
    for (idx, &start) in line_offsets.iter().enumerate() {
        if start >= text.len() {
            break;
        }
        let has_next_line = idx + 1 < line_offsets.len();
        let end = if has_next_line {
            line_offsets[idx + 1].saturating_sub(1)
        } else {
            text.len()
        };
        let mut line = &text[start..end];
        if has_next_line && line.as_bytes().last() == Some(&b'\r') {
            line = &line[..line.len() - 1];
        }
        lines.push(line);
    }
    lines
}

#[cfg(feature = "simd")]
struct SimdRecoveryPrefilter {
    ac: aho_corasick::AhoCorasick,
    ac_map_indices: Box<[usize]>,
}

#[cfg(feature = "simd")]
pub(crate) struct SimdPhase1Prefilter {
    scanner: crate::simd::backend::HsScanner,
    index_map: super::CsrU32,
    recovery: Option<SimdRecoveryPrefilter>,
}

#[cfg(feature = "simd")]
impl SimdPhase1Prefilter {
    pub(crate) fn new(
        scanner: crate::simd::backend::HsScanner,
        index_map: Vec<Vec<usize>>,
        ac_literals: &[String],
        unsupported_ac: &[usize],
    ) -> crate::error::Result<Self> {
        Ok(Self {
            scanner,
            index_map: super::CsrU32::from(index_map),
            recovery: SimdRecoveryPrefilter::build(ac_literals, unsupported_ac)?,
        })
    }

    pub(crate) fn scanner(&self) -> &crate::simd::backend::HsScanner {
        &self.scanner
    }

    pub(crate) fn original_indices(&self, hs_id: usize) -> Option<&[u32]> {
        let (_, dedup_id, _) = self.scanner.pattern_info(hs_id)?;
        self.index_map.get(dedup_id)
    }

    pub(crate) fn for_each_recovery_match(&self, data: &[u8], visit: impl FnMut(usize)) {
        if let Some(recovery) = &self.recovery {
            recovery.for_each_match(data, visit);
        }
    }

    #[cfg(test)]
    pub(crate) fn has_recovery(&self) -> bool {
        self.recovery.is_some()
    }
}

#[cfg(feature = "simd")]
impl SimdRecoveryPrefilter {
    fn build(
        ac_literals: &[String],
        unsupported_ac: &[usize],
    ) -> crate::error::Result<Option<Self>> {
        if unsupported_ac.is_empty() {
            return Ok(None);
        }
        let mut indices = unsupported_ac.to_vec();
        indices.sort_unstable();
        indices.dedup();
        let mut literals = Vec::with_capacity(indices.len());
        let mut mapped = Vec::with_capacity(indices.len());
        for index in indices {
            let literal = ac_literals.get(index).ok_or_else(|| {
                crate::error::ScanError::Simd(format!(
                    "Hyperscan returned unsupported AC index {index}, but the canonical literal plan has only {} row(s)",
                    ac_literals.len()
                ))
            })?;
            literals.push(literal.clone());
            mapped.push(index);
        }
        let ac = crate::compiler::build_ac_pattern_set(&literals)?.ok_or_else(|| {
            crate::error::ScanError::Simd(
                "unsupported Hyperscan rows produced an empty recovery literal plan".into(),
            )
        })?;
        Ok(Some(Self {
            ac,
            ac_map_indices: mapped.into_boxed_slice(),
        }))
    }

    fn for_each_match(&self, data: &[u8], mut visit: impl FnMut(usize)) {
        for matched in self.ac.find_overlapping_iter(data) {
            let pattern = matched.pattern().as_usize();
            visit(self.ac_map_indices[pattern]);
        }
    }
}

#[cfg(feature = "simd")]
/// Builds the Hyperscan scanner, the hs_id -> ac_map index map, and the list
/// of ac_map indices whose regex Hyperscan could not compile
/// (over-long, or an unsupported construct like a large `{100,200}`
/// bounded repeat). The caller builds an exact literal recovery prefilter for
/// those rows so they remain on the confirmed route. A whole-database compile
/// failure leaves SIMD unavailable; inconsistent returned IDs are an error.
pub(crate) fn build_simd_scanner(
    ac_map: &[CompiledPattern],
    tuning: &crate::scanner_config::ScannerTuningConfig,
) -> crate::error::Result<Option<(crate::simd::backend::HsScanner, Vec<Vec<usize>>, Vec<usize>)>> {
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
        // Phase 1 consumes set membership only: every callback marks a pattern
        // bit, and match positions/multiplicity are discarded. Retiring a
        // pattern after its first hit avoids callback storms on repetitive
        // multi-MiB inputs without changing the triggered-pattern set.
        singlematch: true,
        shard_target: tuning.hs_shard_target,
        ..Default::default()
    };
    match crate::simd::backend::HsScanner::compile_with_opts(&pattern_refs, opts) {
        Ok((scanner, unsupported)) => {
            // Map the unsupported hs_ids back to the ac_map indices that
            // share each dropped regex. These never match under HS, so the
            // caller retains their canonical literal triggers separately.
            let mut unsupported_ac = Vec::new();
            for &hs_id in &unsupported {
                let Some(indices) = index_map.get(hs_id) else {
                    return Err(crate::error::ScanError::Simd(format!(
                        "Hyperscan returned unsupported pattern id {hs_id}, but the canonical SIMD plan has only {} unique row(s)",
                        hs_patterns.len()
                    )));
                };
                unsupported_ac.extend(indices.iter().copied());
            }
            tracing::info!(
                compiled = scanner.pattern_count(),
                unsupported = unsupported.len(),
                unsupported_ac = unsupported_ac.len(),
                "HS ready"
            );
            Ok(Some((scanner, index_map, unsupported_ac)))
        }
        Err(error) => {
            tracing::warn!("HS compilation failed: {error}");
            Ok(None)
        }
    }
}
