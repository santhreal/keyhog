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
        // `line_offsets` describes `preprocessed.text` (see `line_offsets()`), and
        // match line numbers are derived from those same offsets, so the per-line
        // slices used for comment/documentation context inference MUST come from
        // `preprocessed.text` too. Slicing raw `chunk.data` when preprocessing
        // rewrote the bytes (structured extraction, multiline join) drifts the
        // line text against the offset table, misclassifying which line a match
        // sits on. On the passthrough path the two buffers are byte-identical, so
        // this is also the single line-walk shared with `line_offsets`.
        code_lines_from_offsets(&self.preprocessed.text, line_offsets)
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
struct SimdPatternPlan {
    detector_index: usize,
    hyperscan_id: usize,
    regex: String,
    reports_start: bool,
}

#[cfg(feature = "simd")]
pub(crate) struct SimdPhase1CompilePlan {
    patterns: Box<[SimdPatternPlan]>,
    index_map: Vec<Vec<usize>>,
    ac_literals: Box<[String]>,
    shard_target: Option<usize>,
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
/// Builds the backend-neutral phase-one plan without creating a Hyperscan
/// database. The exact selected backend materializes this plan on first use.
pub(crate) fn build_simd_compile_plan(
    ac_map: &[CompiledPattern],
    ac_literals: &[String],
    tuning: &crate::scanner_config::ScannerTuningConfig,
) -> Option<SimdPhase1CompilePlan> {
    use std::collections::HashMap;

    let mut regex_to_hs_id: HashMap<String, usize> = HashMap::new();
    let mut hs_patterns = Vec::new();
    let mut index_map: Vec<Vec<usize>> = Vec::new();

    for (idx, entry) in ac_map.iter().enumerate() {
        let regex_str = entry.regex.as_str();
        let hs_id = *regex_to_hs_id
            .entry(regex_str.to_string())
            .or_insert_with(|| {
                let id = hs_patterns.len();
                hs_patterns.push(SimdPatternPlan {
                    detector_index: entry.detector_index,
                    hyperscan_id: id,
                    regex: regex_str.to_string(),
                    reports_start: entry.group.is_some(),
                });
                index_map.push(Vec::new());
                id
            });
        index_map[hs_id].push(idx);
    }

    (!hs_patterns.is_empty()).then(|| SimdPhase1CompilePlan {
        patterns: hs_patterns.into_boxed_slice(),
        index_map,
        ac_literals: ac_literals.to_vec().into_boxed_slice(),
        shard_target: tuning.hs_shard_target,
    })
}

#[cfg(feature = "simd")]
impl SimdPhase1CompilePlan {
    pub(crate) fn materialize(self) -> std::result::Result<SimdPhase1Prefilter, String> {
        let pattern_refs: Vec<(usize, usize, &str, bool)> = self
            .patterns
            .iter()
            .map(|pattern| {
                (
                    pattern.detector_index,
                    pattern.hyperscan_id,
                    pattern.regex.as_str(),
                    pattern.reports_start,
                )
            })
            .collect();

        tracing::info!(
            unique = self.patterns.len(),
            raw = self.ac_literals.len(),
            "materializing deduplicated AC regexes in Hyperscan"
        );

        let opts = crate::simd::backend::HsCompileOpts {
            // Phase 1 consumes set membership only: every callback marks a
            // pattern bit, and match positions/multiplicity are discarded.
            singlematch: true,
            shard_target: self.shard_target,
            ..Default::default()
        };
        let (scanner, unsupported) =
            crate::simd::backend::HsScanner::compile_with_opts(&pattern_refs, opts)
                .map_err(|error| format!("Hyperscan phase-one compilation failed: {error}"))?;

        // Map unsupported deduplicated ids back to every canonical pattern
        // that shares the regex. Their detector-owned literals form the exact
        // recovery prefilter rather than silently disappearing from SIMD.
        let mut unsupported_ac = Vec::new();
        for &hs_id in &unsupported {
            let Some(indices) = self.index_map.get(hs_id) else {
                return Err(format!(
                    "Hyperscan returned unsupported pattern id {hs_id}, but the canonical SIMD plan has only {} unique row(s)",
                    self.patterns.len()
                ));
            };
            unsupported_ac.extend(indices.iter().copied());
        }

        let prefilter =
            SimdPhase1Prefilter::new(scanner, self.index_map, &self.ac_literals, &unsupported_ac)
                .map_err(|error| error.to_string())?;
        tracing::info!(
            compiled = prefilter.scanner().pattern_count(),
            unsupported = unsupported.len(),
            unsupported_ac = unsupported_ac.len(),
            "Hyperscan phase-one backend ready"
        );
        Ok(prefilter)
    }
}

#[cfg(test)]
mod code_lines_tests {
    use super::*;
    use keyhog_core::Chunk;
    use std::sync::OnceLock;

    // KH-1226: `line_offsets` is computed on `preprocessed.text`, and every match
    // line number is derived from that same offset table, so `code_lines` must
    // slice `preprocessed.text` even when preprocessing rewrote the bytes.
    // Slicing raw `chunk.data` there drifted the per-line comment/documentation
    // context text against the offsets, misclassifying which line a match sits
    // on. This pins the aligned-buffer contract.
    #[test]
    fn code_lines_follow_preprocessed_text_not_raw_chunk_when_bytes_differ() {
        let raw = "AAAAAA\nBBBBBB\nCCCCCC";
        let preprocessed_text = "xxx\nyyy\nzzz";
        assert_ne!(raw.as_bytes(), preprocessed_text.as_bytes());

        let chunk: Chunk = raw.to_string().into();
        let prepared = PreparedChunk {
            chunk: &chunk,
            preprocessed: ScannerPreprocessedText::passthrough(preprocessed_text),
            line_offsets: OnceLock::new(),
        };

        let offsets = prepared.line_offsets().to_vec();
        let lines = prepared.code_lines(&offsets);
        // Lines come from the preprocessed buffer the offsets describe, one entry
        // per offset, never the raw chunk lines that would misalign context.
        assert_eq!(lines, ["xxx", "yyy", "zzz"]);
        assert!(!lines.iter().any(|l| l.starts_with('A')));
    }

    // Passthrough (preprocessed == raw): the same aligned slice, exercised through
    // the single offset table shared with `line_offsets()`.
    #[test]
    fn code_lines_passthrough_slices_shared_offset_table() {
        let text = "key = one\nother = two\nlast = three";
        let chunk: Chunk = text.to_string().into();
        let prepared = PreparedChunk {
            chunk: &chunk,
            preprocessed: ScannerPreprocessedText::passthrough(text),
            line_offsets: OnceLock::new(),
        };
        let offsets = prepared.line_offsets().to_vec();
        let lines = prepared.code_lines(&offsets);
        assert_eq!(lines, ["key = one", "other = two", "last = three"]);
    }
}
