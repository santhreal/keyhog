//! Confirmed companion-literal presence gate.
//!
//! Phase-1 triggers on short `required_literals` (e.g. `"123"`, `"IP"`, `"ps"`)
//! can activate confirmed patterns whose regex also requires rarer companion
//! literals (`form`+`builder`, `api`, `webhook`, …). Without a presence check
//! those patterns fall into whole-chunk or short-prefix anchored extract and
//! burn milliseconds per chunk on inert padding (`ordinary_value = 1234567890`,
//! lorem `ipsum` / `adipiscing`).
//!
//! This gate parses each regex once (thread-local cache) into an OR-of-AND of
//! lowercase ASCII literal runs (at least [`MIN_COMPANION_BYTES`]). A pattern is
//! skipped only when every alternation arm is missing at least one required
//! run. Fail-open on parse/empty so recall is preserved.
//!
//! Per-chunk evaluation builds one temporary Aho-Corasick over the unique
//! companion literals of the active set and marks presence in a single pass,
//! instead of one full-haystack memmem per literal (measured: multi-memmem
//! dominated confirmed time on large inert lorem).

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, AhoCorasickKind, MatchKind};
use lru::LruCache;
use regex_syntax::ast::{parse::Parser, Ast};
use std::cell::RefCell;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::Arc;

use super::phase2_first_bigram::FirstBigramSet;

/// Minimum literal-run length worth gating on. Shorter runs (`ip`, `ps`) are
/// too common in ordinary text to reject work on their own.
pub(crate) const MIN_COMPANION_BYTES: usize = 3;

struct CompanionDerived {
    literals: Vec<String>,
    armed: Vec<(usize, Vec<Vec<usize>>)>,
    bigrams: FirstBigramSet,
    ac: AhoCorasick,
}

/// Bound per-thread parsed-arm memo so heterogeneous repos cannot grow it without
/// limit across distinct regex sources.
const COMPANION_ARMS_CACHE_CAP: usize = 1024;
/// Bound per-thread derived AC tables. A single slot thrashes when consecutive
/// chunks trigger different detectors; a small LRU keeps recent sets hot.
const COMPANION_DERIVED_CACHE_CAP: usize = 16;

thread_local! {
    static COMPANION_ARMS_CACHE: RefCell<LruCache<String, Arc<Vec<Vec<String>>>>> =
        RefCell::new(LruCache::new(
            // LAW10: NonZeroUsize::new never fails for positive CAP constants.
            NonZeroUsize::new(COMPANION_ARMS_CACHE_CAP).expect("companion arms cache cap is non-zero"),
        ));
    /// Reuse derived companion gate structures across chunks that share an
    /// active pattern set (multi-window scans and recurring trigger mixes).
    static COMPANION_DERIVED_CACHE: RefCell<LruCache<(u64, Vec<usize>), CompanionDerived>> =
        RefCell::new(LruCache::new(
            // LAW10: NonZeroUsize::new never fails for positive CAP constants.
            NonZeroUsize::new(COMPANION_DERIVED_CACHE_CAP)
                .expect("companion derived cache cap is non-zero"),
        ));
    /// Reusable presence bitset for the companion AC walk.
    static COMPANION_PRESENT_SCRATCH: RefCell<Vec<bool>> = const { RefCell::new(Vec::new()) };
}

/// OR-of-AND companion arms for `src`. Empty means "no gate" (fail-open).
pub(crate) fn companion_arms(src: &str) -> Arc<Vec<Vec<String>>> {
    COMPANION_ARMS_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        if let Some(arms) = cache.get(src) {
            return Arc::clone(arms);
        }
        let arms = Arc::new(compute_companion_arms(src));
        cache.put(src.to_string(), Arc::clone(&arms));
        arms
    })
}

/// Evaluate companion gates for every active confirmed pattern in one haystack
/// pass. `out[pat_idx]` is true when the pattern may still match.
pub(crate) fn companions_allow_batch(patterns: &[(usize, &str)], text: &str, out: &mut [bool]) {
    out.fill(true);
    if patterns.is_empty() {
        return;
    }

    let mut literal_ids: HashMap<String, usize> = HashMap::new();
    let mut literals: Vec<String> = Vec::new();
    // pat_idx -> arms as literal-id conjunctions
    let mut armed: Vec<(usize, Vec<Vec<usize>>)> = Vec::with_capacity(patterns.len());

    for &(pat_idx, src) in patterns {
        let arms = companion_arms(src);
        if arms.is_empty() {
            continue;
        }
        let mut id_arms: Vec<Vec<usize>> = Vec::with_capacity(arms.len());
        for conj in arms.iter() {
            let mut ids = Vec::with_capacity(conj.len());
            for lit in conj {
                let id = *literal_ids.entry(lit.clone()).or_insert_with(|| {
                    literals.push(lit.clone());
                    literals.len() - 1
                });
                ids.push(id);
            }
            id_arms.push(ids);
        }
        armed.push((pat_idx, id_arms));
    }

    if literals.is_empty() || armed.is_empty() {
        return;
    }

    let Ok(ac) = AhoCorasickBuilder::new()
        .match_kind(MatchKind::Standard)
        .kind(Some(AhoCorasickKind::ContiguousNFA))
        .ascii_case_insensitive(true)
        .build(&literals)
    else {
        // Fail-open: keep every pattern allowed.
        return;
    };

    let mut present = vec![false; literals.len()];
    for mat in ac.find_overlapping_iter(text) {
        present[mat.pattern().as_usize()] = true;
    }

    for (pat_idx, id_arms) in armed {
        let allow = id_arms
            .iter()
            .any(|conj| conj.iter().all(|&id| present[id]));
        if let Some(slot) = out.get_mut(pat_idx) {
            *slot = allow;
        }
    }
}

/// Like [`companions_allow_batch`], but only reports denials through `deny`
/// (patterns that stay allowed never touch the callback). Starts from an
/// all-allowed bitset owned by the caller.
pub(crate) fn companions_deny_absent(
    detector_digest: u64,
    patterns: &[(usize, &str)],
    text: &str,
    mut deny: impl FnMut(usize),
) {
    if patterns.is_empty() {
        return;
    }

    let pattern_key: Vec<usize> = patterns.iter().map(|(idx, _)| *idx).collect();
    let cache_key = (detector_digest, pattern_key);
    COMPANION_DERIVED_CACHE.with(|cell| {
        let mut cache = cell.borrow_mut();
        if !cache.contains(&cache_key) {
            let mut literal_ids: HashMap<String, usize> = HashMap::new();
            let mut literals: Vec<String> = Vec::new();
            let mut armed: Vec<(usize, Vec<Vec<usize>>)> = Vec::with_capacity(patterns.len());

            for &(pat_idx, src) in patterns {
                let arms = companion_arms(src);
                if arms.is_empty() {
                    continue;
                }
                let mut id_arms: Vec<Vec<usize>> = Vec::with_capacity(arms.len());
                for conj in arms.iter() {
                    let mut ids = Vec::with_capacity(conj.len());
                    for lit in conj {
                        let id = *literal_ids.entry(lit.clone()).or_insert_with(|| {
                            literals.push(lit.clone());
                            literals.len() - 1
                        });
                        ids.push(id);
                    }
                    id_arms.push(ids);
                }
                armed.push((pat_idx, id_arms));
            }

            if literals.is_empty() || armed.is_empty() {
                return;
            }

            let bigrams =
                FirstBigramSet::from_literals(literals.iter().map(String::as_bytes), true);
            let Ok(ac) = AhoCorasickBuilder::new()
                .match_kind(MatchKind::Standard)
                .kind(Some(AhoCorasickKind::ContiguousNFA))
                .ascii_case_insensitive(true)
                .build(&literals)
            else {
                // Fail-open: keep every pattern allowed.
                return;
            };
            cache.put(
                cache_key.clone(),
                CompanionDerived {
                    literals,
                    armed,
                    bigrams,
                    ac,
                },
            );
        }

        let Some(derived) = cache.get(&cache_key) else {
            return;
        };

        // Exact first-bigram absence => no companion literal can match.
        if !derived.bigrams.may_have_match(text) {
            for (pat_idx, _) in &derived.armed {
                deny(*pat_idx);
            }
            return;
        }

        COMPANION_PRESENT_SCRATCH.with(|present_cell| {
            let mut present = present_cell.borrow_mut();
            // Resize to the active literal count, then clear EVERY slot.
            // Growing with `resize(_, false)` alone leaves `0..old_len` intact,
            // so leftover `true` bits from a shorter prior set would over-admit
            // on the first chunk after growth. Shrinking truncates unused tail.
            present.resize(derived.literals.len(), false);
            present.fill(false);
            for mat in derived.ac.find_overlapping_iter(text) {
                present[mat.pattern().as_usize()] = true;
            }

            for (pat_idx, id_arms) in &derived.armed {
                let allow = id_arms
                    .iter()
                    .any(|conj| conj.iter().all(|&id| present[id]));
                if !allow {
                    deny(*pat_idx);
                }
            }
        });
    });
}

/// True when the pattern may still match: no gate, or at least one arm has
/// every required companion literal present in `text` (ASCII case-insensitive).
/// Test/diagnostic helper; production uses [`companions_deny_absent`].
pub(crate) fn companions_allow(src: &str, text: &str) -> bool {
    let mut out = vec![true; 1];
    companions_allow_batch(&[(0, src)], text, &mut out);
    out[0]
}

fn compute_companion_arms(src: &str) -> Vec<Vec<String>> {
    let Ok(ast) = Parser::new().parse(src) else {
        return Vec::new();
    };
    let mut arms = Vec::new();
    collect_arms(&ast, &mut arms);
    // An arm with no gateable literal is trivially satisfied, so the whole
    // gate must fail open rather than enforcing the other arms' literals.
    if arms.iter().any(Vec::is_empty) {
        return Vec::new();
    }
    arms
}

fn collect_arms(ast: &Ast, out: &mut Vec<Vec<String>>) {
    match ast {
        Ast::Alternation(alt) => {
            for branch in &alt.asts {
                collect_arms(branch, out);
            }
        }
        Ast::Group(group) => collect_arms(&group.ast, out),
        other => {
            let mut conj = Vec::new();
            collect_runs(other, &mut conj);
            conj.sort_unstable();
            conj.dedup();
            out.push(conj);
        }
    }
}

fn collect_runs(ast: &Ast, out: &mut Vec<String>) {
    match ast {
        Ast::Concat(concat) => {
            let mut run = String::new();
            for inner in &concat.asts {
                match inner {
                    Ast::Literal(lit) => {
                        if lit.c.is_ascii() {
                            run.push(lit.c.to_ascii_lowercase());
                        } else {
                            flush_run(&mut run, out);
                        }
                    }
                    _ => {
                        flush_run(&mut run, out);
                        collect_runs(inner, out);
                    }
                }
            }
            flush_run(&mut run, out);
        }
        Ast::Group(group) => collect_runs(&group.ast, out),
        Ast::Alternation(alt) => {
            let mut iter = alt.asts.iter();
            let Some(first) = iter.next() else {
                return;
            };
            let mut common: Vec<String> = Vec::new();
            collect_runs(first, &mut common);
            common.sort_unstable();
            common.dedup();
            for branch in iter {
                let mut branch_runs = Vec::new();
                collect_runs(branch, &mut branch_runs);
                branch_runs.sort_unstable();
                branch_runs.dedup();
                common.retain(|lit| branch_runs.binary_search(lit).is_ok());
            }
            out.extend(common);
        }
        Ast::Literal(lit) if lit.c.is_ascii() => {
            let mut run = lit.c.to_ascii_lowercase().to_string();
            flush_run(&mut run, out);
        }
        Ast::Repetition(_)
        | Ast::ClassUnicode(_)
        | Ast::ClassPerl(_)
        | Ast::ClassBracketed(_)
        | Ast::Dot(_)
        | Ast::Empty(_)
        | Ast::Flags(_)
        | Ast::Assertion(_)
        | Ast::Literal(_) => {}
    }
}

fn flush_run(run: &mut String, out: &mut Vec<String>) {
    if run.len() >= MIN_COMPANION_BYTES {
        out.push(std::mem::take(run));
    } else {
        run.clear();
    }
}
