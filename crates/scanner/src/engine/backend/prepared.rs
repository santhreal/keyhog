use super::super::*;
use keyhog_core::Chunk;

pub(crate) struct PreparedChunk<'a> {
    /// Borrowed caller chunk. Consumers only read through this handle, avoiding
    /// a full `ChunkMetadata` clone with at least five string allocations per
    /// chunk.
    pub(crate) chunk: &'a Chunk,
    /// Preprocessed scan text. Borrows `chunk.data` (`Cow::Borrowed`) on the
    /// passthrough common path, no per-chunk full-body copy, and owns a
    /// synthesized `String` only on the structured/multiline-join paths.
    pub(crate) preprocessed: ScannerPreprocessedText<'a>,
    /// Lazily built or admission-shared compact line starts and documentation
    /// classification for `preprocessed.text`.
    pub(crate) line_index: std::sync::OnceLock<std::sync::Arc<crate::context::LineContextIndex>>,
    #[cfg(debug_assertions)]
    pub(crate) line_index_scanned_bytes: Option<&'a std::sync::atomic::AtomicU64>,
}

impl<'a> PreparedChunk<'a> {
    pub(crate) fn line_index(&self) -> &crate::context::LineContextIndex {
        self.line_index
            .get_or_init(|| {
                #[cfg(debug_assertions)]
                if let Some(scanned_bytes) = self.line_index_scanned_bytes {
                    scanned_bytes.fetch_add(
                        // LAW10: debug accounting saturates on impossible usize-to-u64 overflow; line indexing is unchanged.
                        u64::try_from(self.preprocessed.text.len()).unwrap_or(u64::MAX),
                        std::sync::atomic::Ordering::Relaxed,
                    );
                }
                match crate::context::LineContextIndex::try_new(&self.preprocessed.text) {
                    Ok(line_index) => std::sync::Arc::new(line_index),
                    // LAW10: fail-closed; exceeding u32 line boundary panics cleanly rather than truncating offsets.
                    Err(_) => panic!(
                        "preprocessed chunk length exceeds the checked u32 line-index boundary"
                    ),
                }
            })
            .as_ref()
    }
}

impl CompiledScanner {
    pub(crate) fn prepare_chunk<'a>(&'a self, chunk: &'a Chunk) -> PreparedChunk<'a> {
        self.prepare_chunk_with_normalization_passthrough(chunk, false, false, None)
    }

    pub(crate) fn prepare_chunk_with_normalization_passthrough<'a>(
        &'a self,
        chunk: &'a Chunk,
        normalization_passthrough: bool,
        #[cfg_attr(not(feature = "multiline"), allow(unused_variables))] multiline_absence: bool,
        line_context_index: Option<&std::sync::Arc<crate::context::LineContextIndex>>,
    ) -> PreparedChunk<'a> {
        let _g = super::super::profile::span(keyhog_profile::Stage::Preprocess);
        #[cfg(debug_assertions)]
        if self.config.unicode_normalization && !normalization_passthrough {
            self.normalization_scanned_bytes.fetch_add(
                u64::try_from(chunk.data.len()).unwrap_or(u64::MAX), // LAW10: debug accounting saturates on impossible usize-to-u64 overflow; normalization accounting is unchanged.
                std::sync::atomic::Ordering::Relaxed,
            );
        }
        let data_to_pp: std::borrow::Cow<'a, str> = if normalization_passthrough {
            std::borrow::Cow::Borrowed(&chunk.data)
        } else if self.config.unicode_normalization {
            match crate::unicode_hardening::normalize_homoglyphs(&chunk.data) {
                std::borrow::Cow::Owned(normalized) => {
                    match crate::unicode_hardening::strip_interior_evasion_controls(&normalized) {
                        std::borrow::Cow::Owned(stripped) => std::borrow::Cow::Owned(stripped),
                        std::borrow::Cow::Borrowed(_) => std::borrow::Cow::Owned(normalized),
                    }
                }
                std::borrow::Cow::Borrowed(_) => {
                    crate::unicode_hardening::strip_interior_evasion_controls(&chunk.data)
                }
            }
        } else {
            std::borrow::Cow::Borrowed(&chunk.data)
        };

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
                #[cfg(debug_assertions)]
                if !multiline_absence {
                    self.multiline_admission_scanned_bytes.fetch_add(
                        u64::try_from(data_to_pp.len()).unwrap_or(u64::MAX), // LAW10: debug accounting saturates on impossible usize-to-u64 overflow; multiline admission accounting is unchanged.
                        std::sync::atomic::Ordering::Relaxed,
                    );
                }
                let has_multiline_candidate = !multiline_absence
                    && crate::multiline::config::has_concatenation_indicators_with_keyword_gate(
                        &data_to_pp,
                        |bytes| {
                            let matcher = self
                                .assignment_keyword_matcher
                                .lock()
                                // LAW10: poisoned mutex recovery retains inner matcher; findings are unchanged.
                                .unwrap_or_else(|poisoned| poisoned.into_inner())
                                .resolve(
                                    &self.config.secret_keywords,
                                    self.detector_plans.generic_ownership().policy_keywords(),
                                );
                            matcher.matches(bytes)
                        },
                    );
                if has_multiline_candidate {
                    crate::multiline::preprocess_multiline_admitted(
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

        let line_index = line_context_index
            .filter(|_| {
                preprocessed.text.as_ptr() == chunk.data.as_ptr()
                    && preprocessed.text.len() == chunk.data.len()
            })
            .map_or_else(std::sync::OnceLock::new, |index| {
                std::sync::OnceLock::from(std::sync::Arc::clone(index))
            });
        PreparedChunk {
            chunk,
            preprocessed,
            line_index,
            #[cfg(debug_assertions)]
            line_index_scanned_bytes: Some(&self.line_index_scanned_bytes),
        }
    }

    #[doc(hidden)]
    #[cfg(debug_assertions)]
    pub fn reset_normalization_scanned_bytes_for_diagnostics(&self) {
        self.normalization_scanned_bytes
            .store(0, std::sync::atomic::Ordering::Relaxed);
    }

    #[doc(hidden)]
    #[cfg(debug_assertions)]
    #[must_use]
    pub fn normalization_scanned_bytes_for_diagnostics(&self) -> u64 {
        self.normalization_scanned_bytes
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    #[doc(hidden)]
    #[cfg(debug_assertions)]
    pub fn reset_line_index_scanned_bytes_for_diagnostics(&self) {
        self.line_index_scanned_bytes
            .store(0, std::sync::atomic::Ordering::Relaxed);
    }

    #[doc(hidden)]
    #[cfg(debug_assertions)]
    #[must_use]
    pub fn line_index_scanned_bytes_for_diagnostics(&self) -> u64 {
        self.line_index_scanned_bytes
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    #[doc(hidden)]
    #[cfg(debug_assertions)]
    pub fn reset_multiline_admission_scanned_bytes_for_diagnostics(&self) {
        self.multiline_admission_scanned_bytes
            .store(0, std::sync::atomic::Ordering::Relaxed);
    }

    #[doc(hidden)]
    #[cfg(debug_assertions)]
    #[must_use]
    pub fn multiline_admission_scanned_bytes_for_diagnostics(&self) -> u64 {
        self.multiline_admission_scanned_bytes
            .load(std::sync::atomic::Ordering::Relaxed)
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

    #[allow(dead_code)]
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
    pub(crate) ac_literals: std::sync::Arc<[String]>,
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

    let unsupported: Vec<usize> = program
        .unsupported_pattern_ids
        .iter()
        .map(|&id| id as usize)
        .collect();
    let unsupported_set: std::collections::HashSet<usize> = unsupported.iter().copied().collect();
    let pattern_map = program
        .patterns
        .iter()
        .enumerate()
        .filter(|(id, _)| !unsupported_set.contains(id))
        .map(|(id, p)| {
            (
                id,
                p.detector_index as usize,
                p.pattern_index as usize,
                p.reports_start,
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
