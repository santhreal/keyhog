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
    /// Lazily built compact line starts and documentation classification for
    /// `preprocessed.text`.
    pub(crate) line_index: std::sync::OnceLock<crate::context::LineContextIndex>,
}

impl<'a> PreparedChunk<'a> {
    pub(crate) fn line_index(&self) -> &crate::context::LineContextIndex {
        self.line_index.get_or_init(|| {
            crate::context::LineContextIndex::try_new(&self.preprocessed.text)
                .expect("preprocessed chunk length exceeds the checked u32 line-index boundary")
        })
    }
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
        index_map: super::CsrU32,
        ac_literals: &[String],
        unsupported_ac: &[usize],
    ) -> crate::error::Result<Self> {
        Ok(Self {
            scanner,
            index_map,
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
enum SimdPhase1PlanSource {
    Compile {
        patterns: Box<[SimdPatternPlan]>,
        shard_target: Option<usize>,
    },
    Serialized {
        shards: Box<[crate::execution_pack::simd_program::SerializedHyperscanShard]>,
        pattern_map: Vec<(usize, usize, usize, bool)>,
        unsupported_pattern_ids: Box<[usize]>,
    },
}

#[cfg(feature = "simd")]
pub(crate) struct SimdPhase1CompilePlan {
    source: SimdPhase1PlanSource,
    index_map: super::CsrU32,
    ac_literals: std::sync::Arc<[String]>,
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
    ac_literals: std::sync::Arc<[String]>,
    tuning: &crate::scanner_config::ScannerTuningConfig,
) -> Option<SimdPhase1CompilePlan> {
    use std::collections::HashMap;

    let mut regex_to_hs_id: HashMap<String, usize> = HashMap::new();
    let mut hs_patterns = Vec::new();
    let mut index_pairs = Vec::with_capacity(ac_map.len());

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
                id
            });
        index_pairs.push((hs_id, idx));
    }

    let pattern_count = hs_patterns.len();
    (!hs_patterns.is_empty()).then(|| SimdPhase1CompilePlan {
        source: SimdPhase1PlanSource::Compile {
            patterns: hs_patterns.into_boxed_slice(),
            shard_target: tuning.hs_shard_target,
        },
        index_map: super::CsrU32::from_pairs(pattern_count, index_pairs),
        ac_literals,
    })
}

#[cfg(feature = "simd")]
pub(crate) fn build_packed_simd_compile_plan(
    program: crate::execution_pack::HyperscanSimdExecutionProgram,
    ac_map: &[CompiledPattern],
    ac_literals: std::sync::Arc<[String]>,
) -> std::result::Result<SimdPhase1CompilePlan, String> {
    let mut covered_ac = vec![false; ac_map.len()];
    let mut index_pairs = Vec::with_capacity(ac_map.len());

    for (hs_id, pattern) in program.patterns.iter().enumerate() {
        if pattern.pattern_index as usize != hs_id {
            return Err(format!(
                "packed SIMD pattern row {hs_id} claims canonical pattern id {}",
                pattern.pattern_index
            ));
        }

        let mut first = None;
        for &raw_index in &pattern.ac_map_indices {
            let index = raw_index as usize;
            let entry = ac_map.get(index).ok_or_else(|| {
                format!(
                    "packed SIMD pattern {hs_id} references AC index {index}, but the canonical plan has only {} row(s)",
                    ac_map.len()
                )
            })?;
            if covered_ac[index] {
                return Err(format!(
                    "packed SIMD AC index {index} is mapped more than once"
                ));
            }
            if entry.regex.as_str() != pattern.regex
                || entry.group.is_some() != pattern.reports_start
            {
                return Err(format!(
                    "packed SIMD pattern {hs_id} identity does not match canonical AC index {index}"
                ));
            }
            covered_ac[index] = true;
            first.get_or_insert(index);
            index_pairs.push((hs_id, index));
        }
        let first = first
            .ok_or_else(|| format!("packed SIMD pattern {hs_id} has no canonical AC mapping"))?;
        if ac_map[first].detector_index != pattern.detector_index as usize {
            return Err(format!(
                "packed SIMD pattern {hs_id} detector identity does not match its first canonical AC row"
            ));
        }
    }
    if let Some(index) = covered_ac.iter().position(|covered| !covered) {
        return Err(format!(
            "packed SIMD program does not own canonical AC index {index}"
        ));
    }

    let unsupported = program
        .unsupported_pattern_ids
        .iter()
        .map(|&id| id as usize)
        .collect::<Vec<_>>();
    let unsupported_set = unsupported
        .iter()
        .copied()
        .collect::<std::collections::HashSet<_>>();
    let pattern_map = program
        .patterns
        .iter()
        .enumerate()
        .filter(|(id, _)| !unsupported_set.contains(id))
        .map(|(id, pattern)| {
            (
                id,
                pattern.detector_index as usize,
                pattern.pattern_index as usize,
                pattern.reports_start,
            )
        })
        .collect();
    let pattern_count = program.patterns.len();

    Ok(SimdPhase1CompilePlan {
        source: SimdPhase1PlanSource::Serialized {
            shards: program.serialized_shards.into_boxed_slice(),
            pattern_map,
            unsupported_pattern_ids: unsupported.into_boxed_slice(),
        },
        index_map: super::CsrU32::from_pairs(pattern_count, index_pairs),
        ac_literals,
    })
}

#[cfg(feature = "simd")]
impl SimdPhase1CompilePlan {
    pub(crate) fn materialize(self) -> std::result::Result<SimdPhase1Prefilter, String> {
        let (scanner, unsupported) = match self.source {
            SimdPhase1PlanSource::Compile {
                patterns,
                shard_target,
            } => {
                let pattern_refs: Vec<(usize, usize, &str, bool)> = patterns
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
                let opts = crate::simd::backend::HsCompileOpts {
                    singlematch: true,
                    shard_target,
                    utf8: true,
                    ucp: true,
                    ..Default::default()
                };
                crate::simd::backend::HsScanner::compile_with_opts(&pattern_refs, opts)
                    .map_err(|error| format!("Hyperscan phase-one compilation failed: {error}"))?
            }
            SimdPhase1PlanSource::Serialized {
                shards,
                pattern_map,
                unsupported_pattern_ids,
            } => (
                crate::simd::backend::HsScanner::from_serialized_database_shards(
                    &shards,
                    pattern_map,
                )?,
                unsupported_pattern_ids.into_vec(),
            ),
        };

        let mut unsupported_ac = Vec::new();
        for &hs_id in &unsupported {
            let Some(indices) = self.index_map.get(hs_id) else {
                return Err(format!(
                    "Hyperscan returned unsupported pattern id {hs_id}, but the canonical SIMD plan has only {} unique row(s)",
                    self.index_map.len()
                ));
            };
            unsupported_ac.extend(indices.iter().map(|&index| index as usize));
        }

        SimdPhase1Prefilter::new(scanner, self.index_map, &self.ac_literals, &unsupported_ac)
            .map_err(|error| error.to_string())
    }
}

#[cfg(test)]
mod line_index_tests {
    use super::*;
    use keyhog_core::Chunk;
    use std::sync::OnceLock;

    /// WHY: line context must use the rewritten preprocessed bytes whose offsets
    /// locate matches, never the differently shaped raw chunk.
    #[test]
    fn line_index_follows_preprocessed_text_not_raw_chunk_when_bytes_differ() {
        let raw = "AAAAAA\nBBBBBB\nCCCCCC";
        let preprocessed_text = "xxx\nyyy\nzzz";
        let chunk: Chunk = raw.to_string().into();
        let prepared = PreparedChunk {
            chunk: &chunk,
            preprocessed: ScannerPreprocessedText::passthrough(preprocessed_text),
            line_index: OnceLock::new(),
        };

        let lines: Vec<_> = prepared
            .line_index()
            .lines(&prepared.preprocessed.text)
            .collect();
        assert_eq!(lines, ["xxx", "yyy", "zzz"]);
        assert!(!lines.iter().any(|line| line.starts_with('A')));
        assert_eq!(prepared.line_index().line_number_for_offset(5), 2);
    }

    #[test]
    fn passthrough_lines_are_sliced_on_demand() {
        let text = "key = one\nother = two\nlast = three";
        let chunk: Chunk = text.to_string().into();
        let prepared = PreparedChunk {
            chunk: &chunk,
            preprocessed: ScannerPreprocessedText::passthrough(text),
            line_index: OnceLock::new(),
        };
        assert_eq!(
            prepared
                .line_index()
                .lines(&prepared.preprocessed.text)
                .collect::<Vec<_>>(),
            ["key = one", "other = two", "last = three"]
        );
    }
}

#[cfg(all(test, feature = "simd"))]
mod simd_literal_ownership_tests {
    use super::*;

    fn pattern(regex: &str) -> CompiledPattern {
        CompiledPattern {
            detector_index: 0,
            regex: LazyRegex::detector(regex),
            group: None,
            client_safe: false,
            weak_anchor: false,
            structural_password_slot: false,
            match_proves_keyword_nearby: false,
            homoglyph_variant: false,
        }
    }

    /// WHY: copying every canonical literal into the lazy SIMD plan doubled the complete literal table until first backend use.
    #[test]
    fn simd_compile_plan_shares_the_canonical_literal_table() {
        let literals: std::sync::Arc<[String]> = vec!["STATIC_SECRET_".to_owned()].into();
        let plan = build_simd_compile_plan(
            &[pattern(r"STATIC_SECRET_[A-Z0-9]{16}")],
            std::sync::Arc::clone(&literals),
            &crate::scanner_config::ScannerTuningConfig::default(),
        )
        .expect("fixture produces a SIMD plan");

        assert!(
            std::sync::Arc::ptr_eq(&plan.ac_literals, &literals),
            "SIMD plan must share the canonical literal allocation"
        );
    }
}
