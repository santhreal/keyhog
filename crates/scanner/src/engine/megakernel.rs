//! On-GPU detection via vyre's batched DFA rule-catalog megakernel.
#![cfg(feature = "gpu")]

use std::sync::Arc;

use vyre_driver_wgpu::megakernel::segmentation::catalog_sync_overlap;
use vyre_driver_wgpu::megakernel::{
    BatchDispatchConfig, BatchDispatcher, BatchFile, FileBatch, HitRecord,
};
use vyre_driver_wgpu::WgpuBackend;
use vyre_libs::scan::build_regex_dfa_unanchored;
use vyre_runtime::megakernel::rule_catalog::pack_rule_catalog;
use vyre_runtime::megakernel::BatchRuleProgram;

const PER_RULE_MAX_DFA_STATES: usize = 16_384;
const PER_RULE_MAX_MATCHES: u32 = 200_000;
const MEGAKERNEL_HIT_CAPACITY: u32 = 1_000_000;
// v8: Keyhog builds against the published `vyre-driver-wgpu 0.6.3` megakernel API
// and engages intra-file segmentation at dispatch (see `scan`). The catalog (DFA
// transition tables) is unchanged by segmentation — geometry is a per-batch
// work-queue property, not a catalog property — but the bump invalidates caches
// packed by the older 0.6.2-only whole-file build.
// v10: literals are GROUPED into combined multi-pattern DFAs (GPU_LITERAL_RULE_GROUPS
// rules instead of one-per-literal) with a per-rule byte-check disambiguation table
// (`group_literals`). The packed catalog AND the cached wire layout both changed, so
// the bump invalidates v9 (per-literal) blobs and forces a rebuild.
const MEGAKERNEL_CATALOG_CACHE_VERSION: u32 = 10;
pub(super) const CATALOG_WIRE_MAGIC: [u8; 4] = *b"KHMK";

/// Target number of GPU work-items (`segment_count * rule_count`) a single batch
/// should produce so a large file saturates the device instead of leaving
/// occupancy bounded by `rule_count`. ~64Ki covers an RTX 5090's resident-lane
/// count with headroom; a file shorter than the resulting `seg_len` stays whole.
const GPU_SATURATION_WORK_ITEMS: u64 = 64 * 1024;
/// Floor on a window's owned width so DFA warm-up (the `overlap` bytes each window
/// re-scans) stays a small fraction of useful work.
const MIN_SEG_OWNED_BYTES: u32 = 1024;

/// Pick the intra-file segment (owned-window) width that saturates the GPU for a
/// batch of `total_bytes` against `rule_count` rules, given the catalog warm-up
/// `overlap`. Splitting each file into `ceil(file_len / seg_len)` windows turns one
/// large file into many `(segment, rule)` work-items; this sizes `seg_len` so the
/// batch yields ~[`GPU_SATURATION_WORK_ITEMS`] of them. Floored so warm-up overhead
/// stays low and windows stay wider than the overlap; a file shorter than the
/// result is left as a single whole-file window by the planner.
fn choose_seg_len(total_bytes: usize, rule_count: u32, overlap: u32) -> u32 {
    if rule_count == 0 {
        return u32::MAX; // no rules -> nothing to segment
    }
    let target_segments = (GPU_SATURATION_WORK_ITEMS / u64::from(rule_count)).max(1);
    let bytes_per_segment = (total_bytes as u64 / target_segments).max(1);
    let seg_len = match u32::try_from(bytes_per_segment) {
        Ok(value) => value,
        Err(error) => {
            eprintln!(
                "keyhog megakernel: requested segment length {bytes_per_segment} exceeds \
                 u32::MAX; clamping to the Vyre segment-length limit (recall preserved, \
                 GPU occupancy may be lower): {error}."
            );
            u32::MAX
        }
    };
    seg_len
        .max(MIN_SEG_OWNED_BYTES)
        .max(overlap.saturating_add(1))
}

/// Number of GPU literal RULES the unique-literal set is packed into. Each rule is
/// ONE combined multi-pattern DFA that matches ~`unique_literals / N` distinct
/// literals in a SINGLE pass over the haystack, instead of one DFA per literal
/// scanned independently. The kernel cost is ~linear in `rule_count × bytes`, so
/// collapsing ~1.6k per-literal rules into this many combined rules is the dominant
/// dispatch lever (measured RTX 5090, 8 MiB bench: per-literal kernel 278 ms → a few
/// ms grouped). A grouped hit names only the rule + match-end offset, never which
/// literal accepted, so each is byte-checked against the group's literals
/// (`group_literals`) to fan to exactly the right anchors. Bounded so the kernel
/// stays cheap as the catalog grows; a group's combined DFA stays far below
/// `PER_RULE_MAX_DFA_STATES` for short token literals (a group of ~50 ≤16-byte
/// literals is ~hundreds of states). Tier-A-tunable later; a constant for now.
const GPU_LITERAL_RULE_GROUPS: usize = 32;

/// Recover the raw literal bytes a `regex::escape`d pattern matches, or `None` when
/// the pattern is a genuine regex (an UNescaped regex metacharacter) rather than an
/// escaped literal.
///
/// `regex::escape` backslash-prefixes every metacharacter and leaves ordinary bytes
/// bare, so the inverse is: a `\` takes the next byte literally; a BARE
/// metacharacter means "this is a real regex" — the non-UTF8-literal tail in
/// `megakernel_catalog` that falls back to the detector's FULL regex. Those are kept
/// as their own single-pattern rule (empty `group_literals`), never grouped, because
/// there is no fixed literal to byte-check at a hit offset.
///
/// Soundness for recall (Law 10): the only failure that loses a firing is
/// misclassifying a real regex AS a literal (its "unescaped" bytes would byte-check
/// against the haystack and never match), so the bare-metacharacter set below is the
/// FULL `regex_syntax::is_meta_character` set — erring toward "treat as regex". The
/// reverse misclassification (a literal seen as a regex) only costs a grouping
/// opportunity, never a firing. `unescape_literal_roundtrips` proves the inverse on
/// representative literals; the byte-check at the hit offset is the runtime backstop.
fn unescape_literal(pattern: &str) -> Option<Vec<u8>> {
    // Exactly `regex_syntax::is_meta_character`: any of these appearing UNescaped
    // means the pattern is a regex, not a `regex::escape`d literal.
    const META: &[u8] = br"\.+*?()|[]{}^$#&-~";
    let bytes = pattern.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'\\' {
            // Escaped metacharacter: the next byte is the literal one.
            let next = *bytes.get(i + 1)?; // trailing backslash ⇒ not a clean literal
            out.push(next);
            i += 2;
        } else if META.contains(&b) {
            return None; // bare metacharacter ⇒ genuine regex, never grouped
        } else {
            out.push(b);
            i += 1;
        }
    }
    Some(out)
}

pub(crate) struct MegakernelCatalog {
    pub(super) rules: Vec<BatchRuleProgram>,
    /// GPU rule index → the anchor(s) (ac_map indices) it fires for. Identical
    /// literal anchors are deduplicated into ONE rule that fans out to every
    /// anchor sharing the literal, so `rules.len()` is the count of UNIQUE
    /// literals (≤ anchors). Every anchor appears in exactly one rule's list.
    pub(super) rule_to_detectors: Vec<Vec<usize>>,
    /// GPU rule index → byte-check disambiguation table for a GROUPED literal rule.
    /// A grouped rule's combined DFA matches ANY of several distinct literals in one
    /// pass; the GPU `HitRecord` names only the rule + match-end offset, not which
    /// literal accepted. `group_literals[rule]` is `(lowercased literal bytes,
    /// anchors sharing that literal)` for every literal in the group, so a hit at
    /// `match_offset` is byte-checked (the literal must END exactly at `match_offset`)
    /// to fan ONLY to the anchors of the literal that actually matched — not the whole
    /// group. EMPTY for a single-pattern / regex (un-groupable) rule, where the hit
    /// fans straight to `rule_to_detectors[rule]` (the validate oracle filters), so
    /// the two paths compose without a flag. `rule_to_detectors[rule]` always holds
    /// the rule's COMPLETE anchor set (grouped: the union; single: the one anchor),
    /// keeping the every-anchor-in-exactly-one-rule invariant for coverage checks.
    pub(super) group_literals: Vec<Vec<(Vec<u8>, Vec<usize>)>>,
    pub(super) host_detectors: Vec<usize>,
    pub(super) dispatcher: std::sync::Mutex<Option<BatchDispatcher>>,
    pub(super) resident_batch: std::sync::Mutex<Option<FileBatch>>,
    /// Catalog synchronization-distance overlap, computed once (lazily) from
    /// `rules`: `Some(o)` is the minimum warm-up that keeps intra-file
    /// segmentation byte-identical to a whole-file scan; `None` means some rule
    /// has unbounded memory and the catalog must be scanned whole-file. Cached
    /// because the per-rule product-automaton analysis is far too costly to
    /// repeat per scan.
    pub(super) segment_overlap: std::sync::OnceLock<Option<u32>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Firing {
    pub file_index: usize,
    pub detector: usize,
    pub match_offset: usize,
}

impl MegakernelCatalog {
    /// Compile `(regex, detector_index)` patterns into the resident catalog.
    ///
    /// Patterns are compiled to unanchored DFAs in parallel (rayon); each that
    /// fails to lower is recorded in `host_detectors` (the loud host path),
    /// never dropped. Always returns a catalog: if NOT ONE pattern lowered (or
    /// the catalog fails to pack) it returns one with zero GPU rules — both
    /// cases LOUDLY logged — and the caller treats `rule_count() == 0` as "no
    /// GPU path" and degrades loudly. Always returning `Self` (not `Option`)
    /// lets the on-disk cache compose with the generic `cached_load_or_compile`.
    pub(crate) fn build(patterns: &[(String, usize)]) -> Self {
        use rayon::prelude::*;

        // The unanchored-DFA subset construction is the expensive part — minutes
        // for the full detector set. A cold build prints NOTHING for that whole
        // time, which dogfooding showed reads as a hang. Surface it LOUDLY on
        // stderr (it runs only on a cache MISS via `build_cached`, so this is
        // one-time per pattern set + DFA budget; the result is cached at
        // ~/.cache/keyhog/programs/).
        let announce = patterns.len() > 256;
        if announce {
            eprintln!(
                "keyhog: building GPU detection catalog for {} detectors \
                 (one-time, can take a few minutes; cached afterward)…",
                patterns.len()
            );
        }

        // GROUP + DEDUP. The kernel cost is ~linear in `rule_count × bytes`, so the
        // catalog packs the unique literals into GPU_LITERAL_RULE_GROUPS combined
        // multi-pattern DFAs (each scanned ONCE over the haystack) instead of one DFA
        // per literal. Step 1 classifies + dedups; step 2 groups; step 3 builds the
        // combined DFAs in parallel; step 4 assembles deterministically.
        use std::collections::HashMap;

        // 1. Classify each pattern as a pure literal (groupable, byte-checkable) or a
        //    genuine regex (the non-UTF8 tail that fell back to the full detector
        //    regex — no fixed literal to byte-check). Dedup literals by escaped
        //    pattern, preserving first-seen order, accumulating every anchor that
        //    shares the literal (the fan target — exactly the old dedup, now feeding
        //    a grouped rule). `pattern.as_str()` borrows `patterns` (lives the fn).
        let mut lit_index: HashMap<&str, usize> = HashMap::new();
        // (escaped pattern, raw lowercased literal bytes, anchors sharing it)
        let mut unique_lits: Vec<(&str, Vec<u8>, Vec<usize>)> = Vec::new();
        // (escaped regex, anchor) — non-literal patterns, never grouped.
        let mut regex_rules: Vec<(&str, usize)> = Vec::new();
        for (pattern, detector) in patterns {
            match unescape_literal(pattern) {
                Some(raw) => match lit_index.get(pattern.as_str()) {
                    Some(&idx) => unique_lits[idx].2.push(*detector),
                    None => {
                        lit_index.insert(pattern.as_str(), unique_lits.len());
                        unique_lits.push((pattern.as_str(), raw, vec![*detector]));
                    }
                },
                None => regex_rules.push((pattern.as_str(), *detector)),
            }
        }

        // 2. Group the unique literals. Sorting by literal co-locates shared-prefix
        //    literals so each group's combined DFA shares transitions and stays small.
        unique_lits.sort_by(|a, b| a.1.cmp(&b.1));
        let group_count = GPU_LITERAL_RULE_GROUPS.min(unique_lits.len()).max(1);
        let per_group = unique_lits.len().div_ceil(group_count).max(1);

        // 3. Build each group's COMBINED DFA in parallel. On lower failure (state
        //    explosion past PER_RULE_MAX_DFA_STATES) the group is rebuilt
        //    literal-by-literal so recall is preserved — never dropped (Law 10).
        struct GroupBuilt {
            combined: Option<(Vec<u32>, Vec<u32>, u32)>,
            // (raw literal bytes, anchors) for every literal in the group.
            lits: Vec<(Vec<u8>, Vec<usize>)>,
            // Per-literal DFAs, built ONLY when the combined build failed.
            split: Vec<Option<(Vec<u32>, Vec<u32>, u32)>>,
        }
        let lower = |pats: &[&str]| {
            build_regex_dfa_unanchored(pats, PER_RULE_MAX_MATCHES, PER_RULE_MAX_DFA_STATES)
                .ok() // LAW10: lower failure ⇒ recall-preserving host/split path, surfaced below
                .map(|p| (p.dfa.transitions, p.dfa.accept, p.dfa.state_count))
        };
        let groups: Vec<GroupBuilt> = if unique_lits.is_empty() {
            Vec::new()
        } else {
            unique_lits
                .par_chunks(per_group)
                .map(|chunk| {
                    let pats: Vec<&str> = chunk.iter().map(|(esc, _, _)| *esc).collect();
                    let combined = lower(&pats);
                    let lits: Vec<(Vec<u8>, Vec<usize>)> = chunk
                        .iter()
                        .map(|(_, raw, anchors)| (raw.clone(), anchors.clone()))
                        .collect();
                    let split = if combined.is_some() {
                        Vec::new()
                    } else {
                        chunk.iter().map(|(esc, _, _)| lower(std::slice::from_ref(esc))).collect()
                    };
                    GroupBuilt { combined, lits, split }
                })
                .collect()
        };
        // Regex (non-literal) rules: one DFA each, no byte-check.
        let regex_built: Vec<(Option<(Vec<u32>, Vec<u32>, u32)>, usize)> = regex_rules
            .par_iter()
            .map(|(esc, detector)| (lower(std::slice::from_ref(esc)), *detector))
            .collect();

        // 4. Assemble (sequential ⇒ deterministic rule_idx). A grouped rule carries a
        //    non-empty `group_literals[rule]` (byte-check disambiguation); a single /
        //    regex rule has an EMPTY entry (hit fans straight to rule_to_detectors,
        //    validate filters). Every anchor lands in exactly one rule's
        //    rule_to_detectors (the coverage invariant).
        let mut rules: Vec<BatchRuleProgram> = Vec::new();
        let mut rule_to_detectors: Vec<Vec<usize>> = Vec::new();
        let mut group_literals: Vec<Vec<(Vec<u8>, Vec<usize>)>> = Vec::new();
        let mut host_detectors = Vec::new();
        let mut host_lower_failed = 0usize; // DFA build / BatchRuleProgram failure
        // Law 10: a DFA that lowered but fails BatchRuleProgram shape validation, or
        // that never lowered, routes its anchors to the loud host path — never
        // dropped. Host runs that set anyway, so the cost is a rounding error.
        let to_host = |anchors: Vec<usize>, host: &mut Vec<usize>, failed: &mut usize| {
            *failed += anchors.len();
            host.extend(anchors);
        };
        for GroupBuilt { combined, lits, split } in groups {
            match combined {
                Some((t, a, sc)) => {
                    let anchors: Vec<usize> =
                        lits.iter().flat_map(|(_, an)| an.iter().copied()).collect();
                    match BatchRuleProgram::new(rules.len() as u32, t, a, sc) {
                        Ok(rule) => {
                            rules.push(rule);
                            rule_to_detectors.push(anchors);
                            group_literals.push(lits);
                        }
                        Err(_error) => to_host(anchors, &mut host_detectors, &mut host_lower_failed),
                    }
                }
                // Combined DFA didn't lower: one rule per literal (or host).
                None => {
                    for ((raw, anchors), dfa) in lits.into_iter().zip(split) {
                        match dfa {
                            Some((t, a, sc)) => {
                                match BatchRuleProgram::new(rules.len() as u32, t, a, sc) {
                                    Ok(rule) => {
                                        rules.push(rule);
                                        rule_to_detectors.push(anchors.clone());
                                        group_literals.push(vec![(raw, anchors)]);
                                    }
                                    Err(_error) => {
                                        to_host(anchors, &mut host_detectors, &mut host_lower_failed)
                                    }
                                }
                            }
                            None => to_host(anchors, &mut host_detectors, &mut host_lower_failed),
                        }
                    }
                }
            }
        }
        for (dfa, detector) in regex_built {
            match dfa {
                Some((t, a, sc)) => match BatchRuleProgram::new(rules.len() as u32, t, a, sc) {
                    Ok(rule) => {
                        rules.push(rule);
                        rule_to_detectors.push(vec![detector]);
                        group_literals.push(Vec::new());
                    }
                    Err(_error) => {
                        host_detectors.push(detector);
                        host_lower_failed += 1;
                    }
                },
                None => {
                    host_detectors.push(detector);
                    host_lower_failed += 1;
                }
            }
        }
        if std::env::var_os("KH_PERF").is_some() {
            // Dedup ceiling: how many of the GPU rules are DISTINCT pattern strings.
            // The kernel cost is ~linear in rule_count x files, so collapsing
            // duplicate literal rules (many detectors share a prefix like `key`) to
            // one rule fanning out to N detectors is the lever that keeps the kernel
            // cheap as the catalog grows (e.g. absorbing the fallback anchors).
            let unique_patterns: std::collections::HashSet<&str> =
                patterns.iter().map(|(p, _)| p.as_str()).collect();
            let grouped_rules = group_literals.iter().filter(|g| !g.is_empty()).count();
            let grouped_lits: usize = group_literals.iter().map(Vec::len).sum();
            eprintln!(
                "KH_PERF megakernel classify: gpu_rules={} (grouped={} carrying {} literals, target_groups={}) unique_patterns={}/{} | host: lower_failed={host_lower_failed}",
                rules.len(),
                grouped_rules,
                grouped_lits,
                GPU_LITERAL_RULE_GROUPS,
                unique_patterns.len(),
                patterns.len(),
            );
        }

        if rules.is_empty() {
            tracing::error!(
                target: "keyhog::gpu",
                host_path = host_detectors.len(),
                "megakernel catalog: NO detector pattern lowered to a GPU DFA — the whole pass runs on the loud host path",
            );
        } else if !host_detectors.is_empty() {
            tracing::info!(
                target: "keyhog::gpu",
                gpu_rules = rules.len(),
                host_path = host_detectors.len(),
                "megakernel catalog: {} detector pattern(s) on the loud host path (un-lowerable)",
                host_detectors.len(),
            );
        }
        // Validate the catalog packs (the resident layout the dispatcher uses);
        // a pack failure means it can't be dispatched — drop ALL rules to the
        // loud host path rather than ship an undispatchable catalog (so the
        // caller sees rule_count()==0 and degrades loudly, never a silent empty).
        if !rules.is_empty() && pack_rule_catalog(&rules).is_err() {
            tracing::error!(
                target: "keyhog::gpu",
                "megakernel catalog: rule catalog failed to pack — disabling all {} GPU rules (host path only)",
                rules.len(),
            );
            host_detectors.extend(rule_to_detectors.drain(..).flatten());
            group_literals.clear();
            rules.clear();
        }
        if std::env::var_os("KH_PERF").is_some() {
            let bytes_of = |r: &BatchRuleProgram| {
                (r.transitions.len() + r.accept.len()) * std::mem::size_of::<u32>()
            };
            let words: usize = rules
                .iter()
                .map(|r| r.transitions.len() + r.accept.len())
                .sum();
            // State-count buckets + MiB attributable to each, to see whether a
            // few explosive DFAs dominate the catalog size (lower the cap, push
            // them to the host/HS path) or it is uniform.
            let hi = [512usize, 2048, 8192, usize::MAX];
            let mut cnt = [0usize; 4];
            let mut mib = [0f64; 4];
            for r in &rules {
                let sc = r.state_count as usize;
                let b = hi.iter().position(|&h| sc <= h).unwrap_or(3); // LAW10: empty/absent => documented numeric/sentinel default, recall-safe
                cnt[b] += 1;
                mib[b] += bytes_of(r) as f64 / (1024.0 * 1024.0);
            }
            eprintln!(
                "KH_PERF megakernel catalog: {} gpu rules, {} host, {:.1} MiB total",
                rules.len(),
                host_detectors.len(),
                (words * std::mem::size_of::<u32>()) as f64 / (1024.0 * 1024.0),
            );
            eprintln!(
                "KH_PERF megakernel states: <=512: {} rules {:.0}MiB | <=2048: {} {:.0}MiB | <=8192: {} {:.0}MiB | >8192: {} {:.0}MiB",
                cnt[0], mib[0], cnt[1], mib[1], cnt[2], mib[2], cnt[3], mib[3],
            );
        }
        Self {
            rules,
            rule_to_detectors,
            group_literals,
            host_detectors,
            dispatcher: std::sync::Mutex::new(None),
            resident_batch: std::sync::Mutex::new(None),
            segment_overlap: std::sync::OnceLock::new(),
        }
    }

    /// On-disk-cached [`build`](Self::build): loads the compiled catalog from
    /// `~/.cache/keyhog/programs/` when a blob for this exact pattern set + DFA
    /// parameters exists, else runs the (minutes-long) subset construction and
    /// caches it. The key folds in the pattern set, DFA budgets, and a catalog
    /// format version, so any of those changing invalidates automatically; a
    /// stale/corrupt blob is dropped and rebuilt by `cached_load_or_compile`.
    /// A missing cache directory just means a direct build (identical catalog,
    /// no recall difference — not a silent fallback).
    pub(crate) fn build_cached(patterns: &[(String, usize)]) -> Self {
        let Some(cache_dir) = super::gpu_cache::gpu_matcher_cache_dir() else {
            return Self::build(patterns);
        };
        let key = megakernel_catalog_cache_key(patterns);
        vyre_libs::scan::cached_load_or_compile(&cache_dir, &key, || Self::build(patterns))
    }

    /// Detector indices on the loud host path (un-lowerable patterns).
    pub(crate) fn host_detectors(&self) -> &[usize] {
        &self.host_detectors
    }

    /// Number of GPU-resident DFA rules.
    pub(crate) fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Scan a coalesced batch of files on the GPU, returning detection firings.
    ///
    /// `files[i]` is `(path_hash, bytes)`; the returned `Firing.file_index`
    /// indexes `files`. One device dispatch covers the whole batch. Errors
    /// (upload / dispatch / readback) propagate so the caller fails CLOSED
    /// rather than silently returning an empty result.
    ///
    /// # Errors
    ///
    /// Returns the dispatcher's error string on upload/dispatch/readback failure.
    pub(crate) fn scan(
        &self,
        backend: &Arc<WgpuBackend>,
        files: Vec<(u64, Vec<u8>)>,
    ) -> Result<Vec<Firing>, String> {
        if files.is_empty() || self.rules.is_empty() {
            return Ok(Vec::new());
        }
        let file_count = files.len();
        // Total coalesced bytes (before `files` is consumed into `batch_files`),
        // used to size the intra-file segment width below.
        let total_bytes: usize = files.iter().map(|(_, bytes)| bytes.len()).sum();

        // Fixed hit-ring capacity (see MEGAKERNEL_HIT_CAPACITY): the batch ring
        // and the reused dispatcher's compiled pipeline MUST agree on capacity,
        // and a stable value keeps it to a single compiled pipeline variant.
        let hit_capacity = MEGAKERNEL_HIT_CAPACITY;

        let batch_files: Vec<BatchFile> = files
            .into_iter()
            .enumerate()
            .map(|(i, (hash, bytes))| BatchFile::new(hash ^ i as u64, 0, bytes))
            .collect();

        // Resident GPU batch: upload once, then REFRESH in place every scan.
        // `FileBatch::upload` allocates all six GPU buffers (haystack, offsets,
        // metadata, segments, queue_state, hit_ring) via
        // `device.create_buffer` — a driver round-trip that dominated dispatch
        // time (the realloc, not the compute). `refresh` reuses the resident
        // buffers (`queue.write_buffer`) when the new batch fits the fixed
        // `MEGAKERNEL_HIT_CAPACITY` ring, so only the FIRST scan pays the
        // allocation. Fail-closed: `refresh` returns `Err` on a shape it can't
        // fit, never a silent stale-buffer reuse.
        let mut batch_guard = self
            .resident_batch
            .lock()
            .map_err(|e| format!("megakernel batch mutex poisoned: {e}"))?;
        match batch_guard.as_mut() {
            Some(batch) => batch
                .refresh(&batch_files, self.rules.len() as u32, hit_capacity)
                .map_err(|e| format!("megakernel FileBatch refresh: {e:?}"))?,
            None => {
                *batch_guard = Some(
                    FileBatch::upload(
                        backend.device_queue(),
                        &batch_files,
                        self.rules.len() as u32,
                        hit_capacity,
                    )
                    .map_err(|e| format!("megakernel FileBatch upload: {e:?}"))?,
                );
            }
        }
        // Engage intra-file segmentation (vyre 0.6.3): tile each file into
        // overlapping windows so one large file saturates the GPU instead of
        // leaving occupancy bounded by `rule_count`. The overlap is the catalog's
        // synchronization distance — the minimum warm-up that keeps a windowed scan
        // byte-identical to a whole-file scan — computed once and cached. `None`
        // means some rule has unbounded memory (an `a.*b`-style gap) that CANNOT be
        // soundly segmented: fail safe to whole-file scanning, surfaced LOUDLY
        // (recall is fully preserved; never a silent slow-or-wrong path). `refresh`
        // above reset the batch to the whole-file default, so this re-applies the
        // geometry for the current file lengths every scan.
        let overlap = *self
            .segment_overlap
            .get_or_init(|| catalog_sync_overlap(&self.rules));
        {
            let batch = batch_guard
                .as_mut()
                .expect("resident batch initialized immediately above");
            match overlap {
                Some(overlap) => {
                    let seg_len = choose_seg_len(total_bytes, self.rules.len() as u32, overlap);
                    batch.set_segmentation(seg_len, overlap).map_err(|e| {
                        format!(
                            "megakernel set_segmentation(seg_len={seg_len}, overlap={overlap}): {e:?}"
                        )
                    })?;
                    if std::env::var_os("KH_PERF").is_some() {
                        eprintln!(
                            "KH_PERF mk-segment: total_bytes={total_bytes} rules={} seg_len={seg_len} overlap={overlap} segments~={}",
                            self.rules.len(),
                            (total_bytes as u64).div_ceil(u64::from(seg_len.max(1)))
                        );
                    }
                }
                None => {
                    eprintln!(
                        "keyhog megakernel: catalog has an unbounded-memory rule; intra-file \
                         segmentation disabled, scanning whole-file (recall preserved, large-file \
                         GPU occupancy limited to rule_count)."
                    );
                }
            }
        }
        let batch = batch_guard
            .as_ref()
            .expect("resident batch initialized immediately above");

        // Create the dispatcher ONCE and reuse it for every batch. The first
        // dispatch compiles the WGSL pipeline and uploads the DFA catalog;
        // subsequent dispatches reuse the cached pipeline and skip the rule
        // upload (fingerprints unchanged). Recreating it per batch — the old
        // code — recompiled + re-uploaded the whole catalog every batch (~10s).
        let mut guard = self
            .dispatcher
            .lock()
            .map_err(|e| format!("megakernel dispatcher mutex poisoned: {e}"))?;
        if guard.is_none() {
            let config = BatchDispatchConfig {
                workgroup_size_x: 64,
                // 0 => the dispatcher derives worker_groups from device limits.
                // Occupancy is NOT the megakernel bottleneck: at 100% occupancy
                // proxy the kernel is already ~0.4 s/batch; the dominant single-
                // scan cost is the ~1 GB DFA-catalog upload (one-time/process)
                // and the CPU phase-2 tail, neither of which worker_groups moves
                // (measured task #35, RTX 5090: WG 255→1024 left dispatch flat).
                worker_groups: 0,
                hit_capacity,
                timeout: std::time::Duration::from_secs(30),
                ..Default::default()
            };
            *guard = Some(
                BatchDispatcher::new((**backend).clone(), config)
                    .map_err(|e| format!("megakernel dispatcher init: {e:?}"))?,
            );
        }
        let dispatcher = guard
            .as_mut()
            .expect("dispatcher initialized immediately above");

        let mut hits: Vec<HitRecord> = Vec::with_capacity(4096);
        let summary = dispatcher
            .dispatch_into(batch, &self.rules, &mut hits)
            .map_err(|e| format!("megakernel dispatch: {e:?}"))?;
        if std::env::var_os("KH_PERF").is_some() {
            let t = &summary.telemetry;
            eprintln!(
                "KH_PERF mk-dispatch: files={} rules={} kernel_wall={:.3}s items={} hits={} occupancy_bps={} bytes_up={} bytes_back={} launches={}",
                file_count,
                self.rules.len(),
                summary.wall_time.as_secs_f64(),
                summary.items_processed,
                summary.hit_count,
                t.occupancy_proxy_bps,
                t.bytes_uploaded,
                t.bytes_read_back,
                t.kernel_launches,
            );
        }

        // LAW 10: published Vyre 0.6.2 caps the device hit counter at the ring
        // capacity and does not expose a separate dropped-hit counter. An exact
        // full ring is therefore ambiguous: it may be exactly full or it may have
        // saturated. Fail CLOSED and let the caller run the complete CPU scan for
        // this batch rather than returning a potentially truncated firing set.
        if hits.len() >= hit_capacity as usize {
            static OVERFLOW_WARNED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
            if OVERFLOW_WARNED.set(()).is_ok() {
                eprintln!(
                    "keyhog: GPU megakernel hit ring reached capacity {}; \
                     falling back to the complete CPU scan for this batch. \
                     Fix: raise MEGAKERNEL_HIT_CAPACITY or shard the batch.",
                    MEGAKERNEL_HIT_CAPACITY,
                );
            }
            tracing::warn!(
                target: "keyhog::gpu",
                returned = hits.len(),
                capacity = MEGAKERNEL_HIT_CAPACITY,
                "GPU megakernel hit-ring capacity reached; degrading this batch to the CPU scan for complete recall",
            );
            return Err(format!(
                "GPU hit ring reached capacity {MEGAKERNEL_HIT_CAPACITY}; degrading to CPU for complete recall",
            ));
        }

        let mut firings: Vec<Firing> = Vec::with_capacity(hits.len());
        for h in &hits {
            let file_index = h.file_idx as usize;
            let match_offset = h.match_offset as usize;
            let rule_idx = h.rule_idx as usize;
            match self.group_literals.get(rule_idx) {
                // GROUPED rule: the combined DFA matched SOME literal in the group
                // ENDING at `match_offset`, but can't say which. Byte-check each group
                // literal against the scanned bytes — it must end exactly at
                // `match_offset` — and fan ONLY to the anchors of the literal(s) that
                // actually matched. The bytes are what the GPU scanned, so a hit
                // implies at least one literal byte-matches; every fanned anchor is
                // still re-confirmed against its own full regex in validate.
                Some(lits) if !lits.is_empty() => {
                    let bytes = batch_files.get(file_index).map(|f| f.bytes.as_slice());
                    let end = match_offset.saturating_add(1);
                    for (lit, anchors) in lits {
                        let len = lit.len();
                        if len == 0 || end < len {
                            continue;
                        }
                        if bytes.and_then(|b| b.get(end - len..end)) == Some(lit.as_slice()) {
                            for &detector in anchors {
                                firings.push(Firing { file_index, detector, match_offset });
                            }
                        }
                    }
                }
                // SINGLE / regex rule (empty disambiguation table): no fixed literal
                // to byte-check — fan to every anchor on the rule (validate filters).
                _ => {
                    if let Some(dets) = self.rule_to_detectors.get(rule_idx) {
                        for &detector in dets {
                            firings.push(Firing { file_index, detector, match_offset });
                        }
                    }
                }
            }
        }
        Ok(firings)
    }
}

/// Cache key for the on-disk compiled catalog: SHA-256 over the catalog magic +
/// version, the DFA budgets, and every `(detector_index, regex)` in order. Any
/// change to the pattern set, the budgets, or the version yields a fresh key, so
/// a stale catalog is never loaded for a changed detector set.
fn megakernel_catalog_cache_key(patterns: &[(String, usize)]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(CATALOG_WIRE_MAGIC);
    h.update(MEGAKERNEL_CATALOG_CACHE_VERSION.to_le_bytes());
    h.update((PER_RULE_MAX_DFA_STATES as u64).to_le_bytes());
    h.update((PER_RULE_MAX_MATCHES as u64).to_le_bytes());
    h.update((patterns.len() as u64).to_le_bytes());
    for (regex, detector) in patterns {
        h.update((*detector as u64).to_le_bytes());
        h.update((regex.len() as u64).to_le_bytes());
        h.update(regex.as_bytes());
    }
    let digest: [u8; 32] = h.finalize().into();
    format!("mk-{}", keyhog_core::hex_encode(&digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The catalog build must lower compact regular patterns to GPU DFA rules
    /// and route the genuine state-explosion (`AIza` with a 64-byte alphabet
    /// class × 35) to the loud host path — never silently drop it.
    #[test]
    fn catalog_classifies_lowerable_vs_host() {
        let patterns = vec![
            ("ghp_[A-Za-z0-9]{36}".to_string(), 0),   // overlap-free → GPU
            ("AKIA[A-Z0-9]{16}".to_string(), 1),      // 2468 states < budget → GPU
            ("AIza[A-Za-z0-9_-]{35}".to_string(), 2), // explodes → host path
        ];
        let catalog = MegakernelCatalog::build(&patterns);
        assert!(
            catalog.rule_count() >= 2,
            "ghp_ and AKIA must lower to GPU rules, got {}",
            catalog.rule_count()
        );
        assert!(
            catalog.host_detectors().contains(&2),
            "AIza (state explosion) must take the loud host path, host={:?}",
            catalog.host_detectors()
        );
    }

    /// An all-unlowerable set yields a catalog with ZERO GPU rules (the caller
    /// treats `rule_count() == 0` as "no GPU path" and degrades loudly) rather
    /// than a catalog that would silently match nothing.
    #[test]
    fn catalog_empty_when_nothing_lowers() {
        // A backreference is not a regular language — the DFA builder rejects it.
        let patterns = vec![(r"(\w+)\s+\1".to_string(), 0)];
        let catalog = MegakernelCatalog::build(&patterns);
        assert_eq!(catalog.rule_count(), 0);
        // The un-lowerable detector must land on the loud host path, not vanish.
        assert_eq!(catalog.host_detectors(), &[0]);
    }

    /// The over-firing mask in `scan_coalesced_megakernel` is sound ONLY if the
    /// catalog partitions detectors into EXACTLY two disjoint sets that together
    /// cover every detector: GPU-covered (`rule_to_detector`) and host-only
    /// (`host_detectors`). If a detector were in BOTH, masking the CPU bits to
    /// host-only would drop nothing but seeding from GPU would double-count it;
    /// if a detector were in NEITHER, it would be silently uncovered on the GPU
    /// path (a recall hole, Law 10). This pins the precondition so a future
    /// catalog change that leaks or drops a detector goes red.
    #[test]
    fn every_detector_is_covered_by_exactly_one_path() {
        use std::collections::BTreeSet;
        let patterns = vec![
            ("ghp_[A-Za-z0-9]{36}".to_string(), 0),   // GPU
            ("AKIA[A-Z0-9]{16}".to_string(), 1),      // GPU
            (r"(\w+)\s+\1".to_string(), 2),           // host (backref)
            ("AIza[A-Za-z0-9_-]{35}".to_string(), 3), // host (state explosion)
        ];
        let catalog = MegakernelCatalog::build(&patterns);
        let gpu: BTreeSet<usize> =
            catalog.rule_to_detectors.iter().flatten().copied().collect();
        let host: BTreeSet<usize> = catalog.host_detectors.iter().copied().collect();

        // Disjoint: no detector is on both paths (no double-counting).
        assert!(
            gpu.is_disjoint(&host),
            "a detector appears on BOTH the GPU and host path: gpu={gpu:?} host={host:?}"
        );
        // Complete: every input detector index is covered exactly once.
        let mut union: BTreeSet<usize> = gpu.clone();
        union.extend(host.iter().copied());
        let expected: BTreeSet<usize> = (0..patterns.len()).collect();
        assert_eq!(
            union, expected,
            "detector coverage gap: every detector must be on exactly one path"
        );
        // Each anchor is on exactly one GPU rule: the flattened fan-out lists have
        // no duplicate anchor, so their total length equals the distinct-anchor
        // count (dedup fans literals to multiple anchors, never an anchor to two
        // rules).
        let flat_len: usize = catalog.rule_to_detectors.iter().map(Vec::len).sum();
        assert_eq!(
            flat_len,
            gpu.len(),
            "an anchor appears on more than one GPU rule (fan-out must be disjoint)"
        );
    }

    /// Identical literal anchors collapse to ONE GPU rule that fans out to every
    /// anchor sharing the literal — fewer rules (cheaper dispatch, ~linear in
    /// rule_count) with zero dropped anchors (each is still re-confirmed on its own
    /// regex via the firing). This is the dedup lever the kernel-cost comment names.
    #[test]
    fn duplicate_literals_dedup_to_one_rule_fanning_out() {
        // Anchors 0 and 2 share the SAME literal `key`; anchor 1 is a different
        // literal. Expect 2 GPU rules, with the `key` rule fanning to BOTH 0 and 2.
        let patterns = vec![
            ("key".to_string(), 0),
            ("akia".to_string(), 1),
            ("key".to_string(), 2),
        ];
        let catalog = MegakernelCatalog::build(&patterns);
        assert_eq!(
            catalog.rule_count(),
            2,
            "identical `key` literal must dedup to a single GPU rule, got {}",
            catalog.rule_count()
        );
        // Every anchor still covered exactly once across the fan-out lists.
        let mut covered: Vec<usize> =
            catalog.rule_to_detectors.iter().flatten().copied().collect();
        covered.sort_unstable();
        assert_eq!(covered, vec![0, 1, 2], "dedup dropped or duplicated an anchor");
        // The shared literal's rule fans out to BOTH anchors that used it.
        let key_rule = catalog
            .rule_to_detectors
            .iter()
            .find(|dets| dets.contains(&0))
            .expect("anchor 0 must be on a GPU rule");
        assert!(
            key_rule.contains(&2),
            "the deduped `key` rule must fan out to both anchors 0 and 2, got {key_rule:?}"
        );
    }

    /// `unescape_literal` must invert `regex::escape` on real token literals (so a
    /// grouped rule's byte-check sees the exact bytes the GPU DFA matches) and reject
    /// genuine regexes (so the non-UTF8 tail stays a single, un-byte-checked rule).
    /// A wrong answer is a RECALL bug: a regex misread as a literal would byte-check
    /// against the haystack and never fan its anchor.
    #[test]
    fn unescape_literal_roundtrips_and_rejects_regexes() {
        // Round-trip: escape(lit) then unescape == lit, including metacharacter bytes
        // that `regex::escape` backslash-protects (`.`, `+`, `-`).
        for lit in [
            "ghp_", "AKIA", "xoxb-", "glpat-", "sk-ant-api03", "tok_123", "v1/secret",
            "key.value", "a+b", "name@host",
        ] {
            let escaped = regex::escape(lit);
            assert_eq!(
                unescape_literal(&escaped).as_deref(),
                Some(lit.as_bytes()),
                "escape→unescape must reproduce the literal {lit:?} (escaped {escaped:?})"
            );
        }
        // Genuine regexes (bare metacharacters) must classify as NON-literal so they
        // are kept as a single rule, never grouped + byte-checked.
        for rx in [
            "ghp_[A-Za-z0-9]{36}",
            r"AIza[\w-]{35}",
            r"(\w+)\s+\1",
            "a|b",
            "ab+",
        ] {
            assert_eq!(
                unescape_literal(rx),
                None,
                "regex {rx:?} must NOT be misclassified as an escaped literal"
            );
        }
    }

    /// Many distinct literals must PACK into at most `GPU_LITERAL_RULE_GROUPS`
    /// combined rules (the dispatch lever) while every anchor stays covered exactly
    /// once and each literal maps — in `group_literals` — to its own anchor with the
    /// exact bytes the GPU will byte-check. This pins the grouping contract that the
    /// 8 MiB GPU win depends on.
    #[test]
    fn many_literals_pack_into_bounded_groups_covering_all_anchors() {
        const N: usize = 200;
        // Distinct pure-literal patterns (no metacharacters ⇒ all groupable), anchor
        // i ↦ literal `tok{i:03}`.
        let patterns: Vec<(String, usize)> =
            (0..N).map(|i| (format!("tok{i:03}"), i)).collect();
        let catalog = MegakernelCatalog::build(&patterns);

        // Grouped: far fewer rules than literals, bounded by the group target.
        assert!(
            catalog.rule_count() <= GPU_LITERAL_RULE_GROUPS,
            "200 literals must pack into ≤{} rules, got {}",
            GPU_LITERAL_RULE_GROUPS,
            catalog.rule_count()
        );
        assert!(
            catalog.rule_count() < N,
            "grouping did not happen: {} rules for {N} literals",
            catalog.rule_count()
        );
        assert!(catalog.host_detectors().is_empty(), "no literal should fall to host");

        // Every anchor covered exactly once via rule_to_detectors.
        let mut covered: Vec<usize> =
            catalog.rule_to_detectors.iter().flatten().copied().collect();
        covered.sort_unstable();
        assert_eq!(covered, (0..N).collect::<Vec<_>>(), "anchor coverage gap/dup");

        // Every rule carries a non-empty byte-check table (all rules here are grouped
        // literals), and rule_to_detectors[r] == the union of that rule's group anchors.
        for (r, lits) in catalog.group_literals.iter().enumerate() {
            assert!(!lits.is_empty(), "grouped rule {r} has an empty disambiguation table");
            let mut from_lits: Vec<usize> =
                lits.iter().flat_map(|(_, a)| a.iter().copied()).collect();
            from_lits.sort_unstable();
            let mut from_rtd = catalog.rule_to_detectors[r].clone();
            from_rtd.sort_unstable();
            assert_eq!(from_lits, from_rtd, "rule {r}: group_literals anchors != rule_to_detectors");
        }

        // Each literal maps to its own anchor with the exact lowercased bytes.
        let mut seen = std::collections::BTreeSet::new();
        for lits in &catalog.group_literals {
            for (lit, anchors) in lits {
                assert_eq!(anchors.len(), 1, "each distinct test literal has exactly one anchor");
                let anchor = anchors[0];
                assert_eq!(lit, format!("tok{anchor:03}").as_bytes(), "literal↔anchor mismatch");
                assert!(seen.insert(anchor), "anchor {anchor} appears in two groups");
            }
        }
        assert_eq!(seen.len(), N, "every literal must appear in exactly one group");
    }

    /// `choose_seg_len` must split a large batch into a saturating number of
    /// windows while leaving small batches and large-overlap catalogs sound.
    #[test]
    fn choose_seg_len_saturates_large_and_floors_small() {
        const MIB: usize = 1024 * 1024;
        // 8 MiB, 8 rules, small overlap: target 64Ki/8 = 8192 segments ⇒
        // seg_len = 8 MiB / 8192 = 1024 bytes (the floor, exactly).
        assert_eq!(choose_seg_len(8 * MIB, 8, 8), 1024);
        // 8 MiB, 512 rules: target 128 segments ⇒ seg_len = 8 MiB/128 = 65536.
        assert_eq!(choose_seg_len(8 * MIB, 512, 8), 65_536);
        // Tiny batch floors to MIN_SEG_OWNED_BYTES so a short file stays a single
        // whole-file window (seg_len > file_len ⇒ 1 window in plan_segments).
        assert_eq!(choose_seg_len(100, 8, 8), MIN_SEG_OWNED_BYTES);
        // Overlap above the computed/floored width raises seg_len above it, so
        // warm-up never exceeds the owned region (seg_len > overlap always).
        assert_eq!(choose_seg_len(4096, 8, 4000), 4001);
        // Zero rules ⇒ no-segmentation sentinel (whole-file).
        assert_eq!(choose_seg_len(8 * MIB, 0, 0), u32::MAX);
    }
}
