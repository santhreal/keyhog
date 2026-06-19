//! Megakernel trigger merge and validation helpers.
//!
//! The dispatch impl owns GPU routing and degradation. This module owns the pure
//! transform from raw GPU firings plus optional CPU floor triggers into the
//! validated phase-2 trigger bitmap.

#[cfg(feature = "gpu")]
pub(crate) struct MergedTriggers {
    /// Per-chunk trigger bitmap fed straight to `scan_coalesced_phase2`. A bit
    /// for `(chunk, detector)` is set iff the validation oracle confirmed a real
    /// detector match in that chunk (validated GPU firing) OR the detector is a
    /// host_detector the CPU net fired on, OR the CPU floor recovered a GPU
    /// under-fire (also validated). Never a raw, unvalidated GPU firing.
    pub(crate) triggers: Vec<Option<Vec<u64>>>,
    /// Distinct `(chunk, detector)` firing pairs the GPU produced, pre-validation.
    pub(crate) raw_pairs: usize,
    /// Pairs the validation oracle rejected.
    pub(crate) gpu_overfire_dropped: usize,
    /// Pairs the CPU recall floor recovered.
    pub(crate) gpu_underfire_recovered: usize,
}

#[cfg(feature = "gpu")]
pub(crate) fn merge_validated_triggers(
    chunk_count: usize,
    words: usize,
    ac_len: usize,
    firings: &[super::megakernel::Firing],
    cpu_triggers: Option<&[Option<Vec<u64>>]>,
    host_dets: &[usize],
    mut validate: impl FnMut(usize, usize, Option<usize>) -> bool,
) -> MergedTriggers {
    use std::collections::{HashMap, HashSet};

    type PairSet = HashSet<(usize, usize), ahash::RandomState>;
    type PairOffsetMap = HashMap<(usize, usize), usize, ahash::RandomState>;

    let mut candidate_offsets: PairOffsetMap =
        HashMap::with_capacity_and_hasher(firings.len(), ahash::RandomState::new());
    for f in firings {
        if f.file_index < chunk_count && f.detector < ac_len {
            candidate_offsets
                .entry((f.file_index, f.detector))
                .or_insert(f.match_offset);
        }
    }
    let raw_pairs = candidate_offsets.len();

    let mut triggers: Vec<Option<Vec<u64>>> = vec![None; chunk_count];
    let set_bit = |triggers: &mut Vec<Option<Vec<u64>>>, ci: usize, det: usize| {
        let slot = triggers[ci].get_or_insert_with(|| vec![0u64; words]);
        if slot.len() < words {
            slot.resize(words, 0);
        }
        slot[det / 64] |= 1u64 << (det % 64);
    };

    let mut gpu_validated: PairSet =
        HashSet::with_capacity_and_hasher(candidate_offsets.len(), ahash::RandomState::new());
    let mut gpu_overfire_dropped = 0usize;
    for (&(ci, det), &match_offset) in &candidate_offsets {
        if validate(ci, det, Some(match_offset)) {
            set_bit(&mut triggers, ci, det);
            gpu_validated.insert((ci, det));
        } else {
            gpu_overfire_dropped += 1;
        }
    }

    let mut host_mask = vec![0u64; words];
    for &d in host_dets {
        if d < ac_len {
            host_mask[d / 64] |= 1u64 << (d % 64);
        }
    }
    let mut gpu_underfire_recovered = 0usize;
    if let Some(cpu_triggers) = cpu_triggers {
        for (ci, cpu_opt) in cpu_triggers.iter().enumerate() {
            let Some(cpu_bits) = cpu_opt else { continue };
            if ci >= chunk_count {
                break;
            }
            for w in 0..words {
                let bits = cpu_bits.get(w).copied().unwrap_or(0); // LAW10: bounds-checked lookup; out-of-range => documented default (total fn), recall-safe
                if bits == 0 {
                    continue;
                }
                let mut rest = bits;
                while rest != 0 {
                    let lo = rest.trailing_zeros() as usize;
                    rest &= rest - 1;
                    let det = w * 64 + lo;
                    if det >= ac_len {
                        continue;
                    }
                    if (host_mask[w] >> lo) & 1 == 1 {
                        set_bit(&mut triggers, ci, det);
                        continue;
                    }
                    if gpu_validated.contains(&(ci, det)) {
                        continue;
                    }
                    if validate(ci, det, None) {
                        set_bit(&mut triggers, ci, det);
                        gpu_underfire_recovered += 1;
                    }
                }
            }
        }
    }

    MergedTriggers {
        triggers,
        raw_pairs,
        gpu_overfire_dropped,
        gpu_underfire_recovered,
    }
}

#[cfg(feature = "gpu")]
pub(crate) fn validation_window_range(
    text: &str,
    match_offset: usize,
    max_match_width: usize,
) -> Option<(usize, usize)> {
    if text.is_empty() || max_match_width == 0 {
        return None;
    }
    let hit = match_offset.min(text.len());
    let start = super::floor_char_boundary(text, hit.saturating_sub(max_match_width));
    let end = super::ceil_char_boundary(text, hit.saturating_add(max_match_width).min(text.len()));
    (start < end).then_some((start, end))
}

#[cfg(feature = "gpu")]
pub(crate) fn validate_detector_match(
    text: &str,
    rx: &regex::Regex,
    match_offset: Option<usize>,
    max_match_width: Option<usize>,
) -> bool {
    let Some(match_offset) = match_offset else {
        return rx.is_match(text);
    };
    let Some(max_match_width) = max_match_width else {
        return rx.is_match(text);
    };
    let Some((start, end)) = validation_window_range(text, match_offset, max_match_width) else {
        return false;
    };
    rx.is_match(&text[start..end])
}
