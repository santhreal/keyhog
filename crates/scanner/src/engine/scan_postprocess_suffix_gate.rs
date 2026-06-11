//! Confirmed-pass SUFFIX GATE, extracted from `scan_postprocess.rs` (Law 5).
//! Builds one ASCII-case-insensitive Aho-Corasick over every ac_map pattern's
//! required trailing literals so the confirmed pass can skip a pattern whose
//! suffix is absent (it cannot match) — recall-identical, see the unit gate.
//! `build_confirmed_suffix_gate` / `set_confirmed_suffix_gate` /
//! `confirmed_suffix_gate_enabled` are re-exported through `scan_postprocess`.
use crate::types::*;
use std::sync::atomic::{AtomicU8, Ordering::Relaxed};
use std::sync::OnceLock;

static CONFIRMED_GATE_OVERRIDE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

/// Override the confirmed-pass suffix gate (test/diagnostic). `Some(true)`
/// forces it on, `Some(false)` off, `None` = env default (on). Recall is
/// identical either way — the gate only skips patterns whose required suffix
/// literal is absent (so they cannot match), so it is safe to flip.
pub fn set_confirmed_suffix_gate(mode: Option<bool>) {
    CONFIRMED_GATE_OVERRIDE.store(
        match mode {
            None => 0,
            Some(true) => 1,
            Some(false) => 2,
        },
        Relaxed,
    );
}

pub(crate) fn confirmed_suffix_gate_enabled() -> bool {
    match CONFIRMED_GATE_OVERRIDE.load(Relaxed) {
        1 => return true,
        2 => return false,
        _ => {}
    }
    static EN: OnceLock<bool> = OnceLock::new();
    *EN.get_or_init(|| std::env::var("KEYHOG_CONFIRMED_GATE").as_deref() != Ok("0"))
}

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
fn suffix_gate_literals(src: &str) -> Vec<String> {
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

/// Build the confirmed-pass suffix gate: one ASCII-case-insensitive AC over
/// every ac_map pattern's required suffix literals, plus per-pattern literal
/// ids. Returns `(ac, per_pattern_literal_ids)`; the AC is `None` when no
/// pattern has a gateable suffix.
pub(crate) fn build_confirmed_suffix_gate(
    ac_map: &[CompiledPattern],
) -> (Option<aho_corasick::AhoCorasick>, Vec<Vec<u32>>) {
    use std::collections::HashMap;
    let mut literals: Vec<String> = Vec::new();
    let mut literal_id: HashMap<String, usize> = HashMap::new();
    let mut per_pattern: Vec<Vec<u32>> = vec![Vec::new(); ac_map.len()];
    // The embedded corpus has ~6-15% duplicate regex sources; cache the suffix
    // extraction per source so we parse each unique pattern at most once.
    let mut src_cache: HashMap<&str, Vec<String>> = HashMap::new();
    for (i, p) in ac_map.iter().enumerate() {
        let src = p.regex.as_str();
        let lits = src_cache
            .entry(src)
            .or_insert_with(|| suffix_gate_literals(src));
        for lit in lits.clone() {
            let id = *literal_id.entry(lit.clone()).or_insert_with(|| {
                literals.push(lit.clone());
                literals.len() - 1
            });
            per_pattern[i].push(id as u32);
        }
    }
    if literals.is_empty() {
        return (None, per_pattern);
    }
    let ac = aho_corasick::AhoCorasickBuilder::new()
        .match_kind(aho_corasick::MatchKind::Standard)
        .ascii_case_insensitive(true)
        .build(&literals)
        .ok();
    (ac, per_pattern)
}
