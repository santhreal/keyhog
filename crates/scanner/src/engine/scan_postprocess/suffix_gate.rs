//! Confirmed-pass SUFFIX GATE builder, extracted from `scan_postprocess.rs`
//! (Law 5). Builds one ASCII-case-insensitive Aho-Corasick over every ac_map
//! pattern's required trailing literals so the confirmed pass can skip a pattern
//! whose suffix is absent (it cannot match), recall-identical, see the unit
//! gate. `build_confirmed_suffix_gate` is re-exported through `scan_postprocess`.
//! The runtime ENABLE/override toggle lives on the per-scanner `ScannerTuning`
//! (`tuning::ScannerTuning::confirmed_suffix_gate_enabled`), not here, there is
//! no process-global gate state.
use crate::types::*;

/// Extract a pattern's required SUFFIX literals: every match ENDS with one of
/// these, so if NONE appears in the chunk the pattern cannot match and its
/// whole-chunk regex run can be skipped. Used to skip the O(chunk) `.*<sitename>`
/// scans of site-specific key detectors that trigger on the common prefix
/// ("key") but require a rare trailing literal the regex prefilter never uses.
///
/// Case-SENSITIVE parse (the runtime regex's case-insensitivity is matched by
/// the ASCII-case-insensitive gate AC) so the suffix doesn't case-explode.
/// `None`/empty unless the suffix is a finite set of <=4 literals each >= 6
/// bytes (selective enough to be worth gating); lowercased for the caseless AC.
pub(crate) fn suffix_gate_literals(src: &str) -> Vec<String> {
    use regex_syntax::hir::literal::{ExtractKind, Extractor};
    const MIN_LEN: usize = 6;
    const MAX_LITS: usize = 4;
    let Ok(hir) = regex_syntax::ParserBuilder::new().build().parse(src) else {
        return Vec::new();
    };
    let mut ex = Extractor::new();
    ex.kind(ExtractKind::Suffix);
    let seq = ex.extract(&hir);
    if !seq.is_finite() {
        return Vec::new();
    }
    let Some(lits) = seq.literals() else {
        return Vec::new();
    };
    if lits.is_empty() || lits.len() > MAX_LITS {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(lits.len());
    for l in lits {
        if l.len() < MIN_LEN {
            return Vec::new();
        }
        let Ok(s) = std::str::from_utf8(l.as_bytes()) else {
            return Vec::new();
        };
        out.push(s.to_ascii_lowercase());
    }
    out.sort_unstable();
    out.dedup();
    out
}

pub(crate) struct LazyConfirmedSuffixGate {
    literals: std::sync::Mutex<Option<Box<[String]>>>,
    automaton: std::sync::OnceLock<Option<aho_corasick::AhoCorasick>>,
}

impl LazyConfirmedSuffixGate {
    fn new(literals: Vec<String>) -> Self {
        Self {
            literals: std::sync::Mutex::new(Some(literals.into_boxed_slice())),
            automaton: std::sync::OnceLock::new(),
        }
    }

    fn build(&self) -> Option<aho_corasick::AhoCorasick> {
        let literals = self
            .literals
            .lock()
            // LAW10: poison recovery retains the immutable literal set for full construction.
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .expect("lazy confirmed suffix literals must exist before initialization");
        match aho_corasick::AhoCorasickBuilder::new()
            .match_kind(aho_corasick::MatchKind::Standard)
            .ascii_case_insensitive(true)
            .build(&literals)
        {
            Ok(ac) => Some(ac),
            Err(error) => {
                tracing::warn!(
                    literals = literals.len(),
                    %error,
                    "confirmed-pass suffix-gate Aho-Corasick build failed; suffix-gate optimization disabled (recall preserved)"
                );
                None
            }
        }
    }

    pub(crate) fn get(&self) -> Option<&aho_corasick::AhoCorasick> {
        self.automaton.get_or_init(|| self.build()).as_ref()
    }

    /// Materialize before per-chunk scratch. Returns whether this call built
    /// the automaton so the caller can purge compiler arenas.
    pub(crate) fn materialize(&self) -> bool {
        let already_materialized = self.automaton.get().is_some();
        let _materialized = self.get();
        !already_materialized
    }
}

pub(crate) fn build_confirmed_suffix_gate_with_hints(
    ac_map: &[CompiledPattern],
    localization_hints: Option<Vec<Vec<String>>>,
) -> (Option<LazyConfirmedSuffixGate>, super::CsrU32) {
    use std::collections::HashMap;
    let mut literals: Vec<String> = Vec::new();
    let mut literal_id: HashMap<String, usize> = HashMap::new();
    let mut pattern_literal_pairs = Vec::new();
    let mut register = |pattern_index: usize, pattern_literals: &[String]| {
        for literal in pattern_literals {
            let id =
                super::scan_postprocess::register_literal(&mut literals, &mut literal_id, literal);
            pattern_literal_pairs.push((pattern_index, id));
        }
    };
    if let Some(hints) = localization_hints {
        for (pattern_index, pattern_literals) in hints.iter().enumerate() {
            register(pattern_index, pattern_literals);
        }
    } else {
        crate::execution_pack::matcher_sections::record_runtime_localization_hint_fallback();
        // Development corpora compute the same facts once per unique source.
        let mut source_cache: HashMap<&str, Vec<String>> = HashMap::new();
        for (pattern_index, pattern) in ac_map.iter().enumerate() {
            let source = pattern.regex.as_str();
            let pattern_literals = source_cache
                .entry(source)
                .or_insert_with(|| suffix_gate_literals(source));
            register(pattern_index, pattern_literals);
        }
    }
    if literals.is_empty() {
        return (
            None,
            super::CsrU32::from_pairs(ac_map.len(), pattern_literal_pairs),
        );
    }
    (
        Some(LazyConfirmedSuffixGate::new(literals)),
        super::CsrU32::from_pairs(ac_map.len(), pattern_literal_pairs),
    )
}
