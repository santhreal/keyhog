//! C1 substrate: whole-megakernel optimization domain.
//!
//! Per-arm optimization (the existing CSE/DCE per arm, then fuse) is
//! conservative â€” it can't see structural redundancy ACROSS arms.
//! When two adjacent arms produce the same intermediate result the
//! first arm could compute it once and the second arm could just
//! read it.
//!
//! This substrate owns the *cross-arm redundancy detector*: given a
//! per-arm sequence of `MegakernelWorkItem`s, identify pairs of arms that
//! emit the same opâ†’inputâ†’output triple. The dispatcher uses the
//! verdict to skip the redundant compute.
//!
//! Pure substrate â€” no Program walk, no allocation outside the
//! returned redundancy report. The actual rewrite (collapse
//! redundant arms into one + rewire downstream readers) is the
//! Codex-side runtime work; this substrate just names the
//! optimization opportunity.

use crate::megakernel::planner::MegakernelWorkItem;
use std::collections::hash_map::Entry;
use rustc_hash::FxHashMap;

const DENSE_OUTPUT_UNIQUE_BITS: usize = 4096;
const DENSE_OUTPUT_UNIQUE_WORDS: usize = DENSE_OUTPUT_UNIQUE_BITS / u64::BITS as usize;

/// Report of cross-arm redundancy in a megakernel arm sequence.
///
/// Each pair `(early, late)` means arm `late` emits a MegakernelWorkItem that
/// is structurally identical to one already emitted by arm `early`
/// (and that arm has not been overwritten since). The runtime can
/// drop the `late` arm's redundant op and rewire its readers to the
/// `early` arm's output handle.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CrossArmRedundancy {
    /// (early_arm_index, late_arm_index, redundant_op_index_in_late_arm).
    /// `early_arm_index < late_arm_index` always; the late arm is
    /// the one whose op is redundant.
    pub redundant_pairs: Vec<(usize, usize, usize)>,
    /// Total redundant ops detected across the whole sequence.
    /// Equal to `redundant_pairs.len()` but exposed separately so
    /// the dispatcher can budget telemetry without scanning the vec.
    pub total_redundant_ops: usize,
}

impl CrossArmRedundancy {
    /// Empty report â€” no redundancy across arms.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether this report names any opportunity.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.redundant_pairs.is_empty()
    }
}

/// Walk `arms` and detect cross-arm structural redundancy.
///
/// For each (op_handle, input_handle, output_handle) triple the
/// substrate sees in arm N, it remembers which arm produced it. If
/// an identical triple appears in a later arm M > N, the substrate
/// records `(N, M, op_idx_in_M)`. WorkItems are compared by the
/// `(op_handle, input_handle, output_handle)` triple alone â€” the
/// `param` field is treated as separate launch metadata.
///
/// O(total_ops) â€” uses one pass + one hash table. Allocation only
/// for the redundancy report and the seen-set.
#[must_use]
pub fn detect_cross_arm_redundancy(arms: &[&[MegakernelWorkItem]]) -> CrossArmRedundancy {
    // (op_handle, input_handle, output_handle) â†’ (arm_idx, op_idx)
    let total_ops = arms.iter().map(|arm| arm.len()).sum();
    if total_ops <= 1 {
        return CrossArmRedundancy::new();
    }
    let mut first_seen: FxHashMap<(u32, u32, u32), usize> =
        FxHashMap::with_capacity_and_hasher(total_ops, Default::default());
    let mut report = CrossArmRedundancy {
        redundant_pairs: Vec::with_capacity(total_ops.saturating_sub(arms.len())),
        total_redundant_ops: 0,
    };
    for (arm_idx, arm) in arms.iter().enumerate() {
        for (op_idx, item) in arm.iter().enumerate() {
            let key = (item.op_handle, item.input_handle, item.output_handle);
            match first_seen.entry(key) {
                Entry::Occupied(entry) => {
                    if *entry.get() < arm_idx {
                        report
                            .redundant_pairs
                            .push((*entry.get(), arm_idx, op_idx));
                    }
                }
                Entry::Vacant(vacant) => {
                    vacant.insert(arm_idx);
                }
            }
        }
    }
    report.total_redundant_ops = report.redundant_pairs.len();
    report
}

/// Copy `items` into `out`, dropping later work items that are byte-for-byte
/// redundant with an earlier item.
///
/// This is the runtime-safe rewrite for the opportunity named by
/// [`detect_cross_arm_redundancy`]. The detector intentionally ignores `param`
/// so it can flag broad structural reuse; the rewrite is stricter because
/// concrete megakernel publishers pass `param` as an opcode argument. A
/// duplicate `(op_handle, input_handle, output_handle, param)` writes the same
/// result slot from the same input through the same operation with the same
/// argument, so the later item only burns queue capacity and GPU cycles. The
/// first item is retained; all later duplicates are omitted from `out`.
///
/// When no duplicates are found, `out` is left empty so hot callers can keep
/// using the original borrowed queue without paying an avoidable copy.
///
pub fn prune_redundant_work_items_into(
    items: &[MegakernelWorkItem],
    out: &mut Vec<MegakernelWorkItem>,
) -> CrossArmRedundancy {
    out.clear();
    if items.len() <= 1 {
        return CrossArmRedundancy::new();
    }

    if output_handles_are_dense_unique(items) {
        return CrossArmRedundancy::new();
    }

    let mut first_seen: FxHashMap<(u32, u32, u32, u32), usize> =
        FxHashMap::with_capacity_and_hasher(items.len(), Default::default());
    let mut report = CrossArmRedundancy {
        redundant_pairs: Vec::new(),
        total_redundant_ops: 0,
    };
    let mut found_duplicate = false;

    for (idx, item) in items.iter().copied().enumerate() {
        let key = (
            item.op_handle,
            item.input_handle,
            item.output_handle,
            item.param,
        );
        match first_seen.entry(key) {
            Entry::Occupied(entry) => {
                if !found_duplicate {
                    out.reserve(items.len().saturating_sub(1));
                    out.extend_from_slice(&items[..idx]);
                    found_duplicate = true;
                }
                report.redundant_pairs.push((*entry.get(), idx, 0));
            }
            Entry::Vacant(vacant) => {
                vacant.insert(idx);
                if found_duplicate {
                    out.push(item);
                }
            }
        }
    }

    report.total_redundant_ops = report.redundant_pairs.len();
    report
}

fn output_handles_are_dense_unique(items: &[MegakernelWorkItem]) -> bool {
    if items.len() <= 1 {
        return true;
    }
    if items.len() > DENSE_OUTPUT_UNIQUE_BITS {
        return false;
    }

    let mut min = u32::MAX;
    let mut max = 0u32;
    for item in items {
        min = min.min(item.output_handle);
        max = max.max(item.output_handle);
    }
    let range = u64::from(max) - u64::from(min) + 1;
    if range > DENSE_OUTPUT_UNIQUE_BITS as u64 {
        return false;
    }

    let mut seen = [0u64; DENSE_OUTPUT_UNIQUE_WORDS];
    for item in items {
        let offset = (item.output_handle - min) as usize;
        let word = offset / u64::BITS as usize;
        let bit = 1u64 << (offset % u64::BITS as usize);
        if (seen[word] & bit) != 0 {
            return false;
        }
        seen[word] |= bit;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(op: u32, inp: u32, out: u32) -> MegakernelWorkItem {
        MegakernelWorkItem {
            op_handle: op,
            input_handle: inp,
            output_handle: out,
            param: 0,
        }
    }

    #[test]
    fn empty_arms_have_no_redundancy() {
        let arms: [&[MegakernelWorkItem]; 0] = [];
        assert_eq!(
            detect_cross_arm_redundancy(&arms),
            CrossArmRedundancy::new()
        );
    }

    #[test]
    fn single_arm_with_repeats_has_no_cross_arm_redundancy() {
        let a = vec![item(1, 0, 5), item(1, 0, 5), item(2, 5, 6)];
        let arms: [&[MegakernelWorkItem]; 1] = [&a];
        let report = detect_cross_arm_redundancy(&arms);
        assert!(report.is_empty(), "intra-arm repeats are not cross-arm");
        assert_eq!(report.total_redundant_ops, 0);
    }

    #[test]
    fn identical_arms_report_full_overlap() {
        let a = vec![item(1, 0, 5), item(2, 5, 6)];
        let b = vec![item(1, 0, 5), item(2, 5, 6)];
        let arms: [&[MegakernelWorkItem]; 2] = [&a, &b];
        let report = detect_cross_arm_redundancy(&arms);
        assert_eq!(report.total_redundant_ops, 2);
        assert_eq!(report.redundant_pairs, vec![(0, 1, 0), (0, 1, 1)]);
    }

    #[test]
    fn fully_disjoint_arms_have_no_redundancy() {
        let a = vec![item(1, 0, 5)];
        let b = vec![item(2, 7, 8)];
        let arms: [&[MegakernelWorkItem]; 2] = [&a, &b];
        assert!(detect_cross_arm_redundancy(&arms).is_empty());
    }

    #[test]
    fn redundancy_uses_first_seen_arm_index() {
        // Op appears in arms 0, 2, 3 â€” both 2 and 3 should reference 0.
        let a = vec![item(1, 0, 5)];
        let b = vec![item(99, 0, 0)];
        let c = vec![item(1, 0, 5)];
        let d = vec![item(1, 0, 5)];
        let arms: [&[MegakernelWorkItem]; 4] = [&a, &b, &c, &d];
        let report = detect_cross_arm_redundancy(&arms);
        assert_eq!(report.total_redundant_ops, 2);
        assert_eq!(report.redundant_pairs, vec![(0, 2, 0), (0, 3, 0)]);
    }

    #[test]
    fn param_field_does_not_affect_redundancy() {
        // Same (op, in, out) triple but different param â€” still
        // cross-arm redundant by this substrate's contract.
        let a = vec![MegakernelWorkItem {
            op_handle: 1,
            input_handle: 0,
            output_handle: 5,
            param: 7,
        }];
        let b = vec![MegakernelWorkItem {
            op_handle: 1,
            input_handle: 0,
            output_handle: 5,
            param: 99,
        }];
        let arms: [&[MegakernelWorkItem]; 2] = [&a, &b];
        let report = detect_cross_arm_redundancy(&arms);
        assert_eq!(report.total_redundant_ops, 1);
    }

    #[test]
    fn different_inputs_are_not_redundant() {
        let a = vec![item(1, 0, 5)];
        let b = vec![item(1, 1, 5)]; // different input handle
        let arms: [&[MegakernelWorkItem]; 2] = [&a, &b];
        assert!(detect_cross_arm_redundancy(&arms).is_empty());
    }

    #[test]
    fn different_outputs_are_not_redundant() {
        let a = vec![item(1, 0, 5)];
        let b = vec![item(1, 0, 6)]; // different output handle
        let arms: [&[MegakernelWorkItem]; 2] = [&a, &b];
        assert!(detect_cross_arm_redundancy(&arms).is_empty());
    }

    #[test]
    fn op_index_refers_to_late_arm_position() {
        // Verify the third tuple element is the index WITHIN the
        // late arm, not a global op index.
        let a = vec![item(1, 0, 5)];
        let b = vec![item(99, 0, 0), item(1, 0, 5), item(42, 0, 0)];
        let arms: [&[MegakernelWorkItem]; 2] = [&a, &b];
        let report = detect_cross_arm_redundancy(&arms);
        assert_eq!(report.redundant_pairs, vec![(0, 1, 1)]);
    }

    #[test]
    fn prune_redundant_work_items_drops_later_duplicates() {
        let items = vec![
            item(1, 0, 5),
            item(2, 5, 6),
            item(1, 0, 5),
            item(3, 6, 7),
            item(2, 5, 6),
        ];
        let mut out = Vec::new();

        let report = prune_redundant_work_items_into(&items, &mut out);

        assert_eq!(out, vec![item(1, 0, 5), item(2, 5, 6), item(3, 6, 7)]);
        assert_eq!(report.total_redundant_ops, 2);
        assert_eq!(report.redundant_pairs, vec![(0, 2, 0), (1, 4, 0)]);
    }

    #[test]
    fn prune_redundant_work_items_handles_empty_input() {
        let mut out = vec![item(99, 99, 99)];

        let report = prune_redundant_work_items_into(&[], &mut out);

        assert!(report.is_empty());
        assert!(out.is_empty());
    }

    #[test]
    fn prune_redundant_work_items_all_duplicates_keep_one() {
        let items = vec![item(1, 0, 5), item(1, 0, 5), item(1, 0, 5)];
        let mut out = Vec::new();

        let report = prune_redundant_work_items_into(&items, &mut out);

        assert_eq!(out, vec![item(1, 0, 5)]);
        assert_eq!(report.total_redundant_ops, 2);
        assert_eq!(report.redundant_pairs, vec![(0, 1, 0), (0, 2, 0)]);
    }

    #[test]
    fn prune_redundant_work_items_preserves_order_after_first_duplicate() {
        let items = vec![
            item(1, 0, 5),
            item(2, 5, 6),
            item(1, 0, 5),
            item(3, 6, 7),
            item(4, 7, 8),
        ];
        let mut out = Vec::new();

        let report = prune_redundant_work_items_into(&items, &mut out);

        assert_eq!(
            out,
            vec![item(1, 0, 5), item(2, 5, 6), item(3, 6, 7), item(4, 7, 8)]
        );
        assert_eq!(report.redundant_pairs, vec![(0, 2, 0)]);
    }

    #[test]
    fn prune_redundant_work_items_leaves_output_empty_when_no_copy_needed() {
        let items = vec![item(1, 0, 5)];
        let mut out = vec![item(99, 99, 99)];

        let report = prune_redundant_work_items_into(&items, &mut out);

        assert!(report.is_empty());
        assert!(out.is_empty());
    }

    #[test]
    fn prune_redundant_work_items_keeps_distinct_params() {
        let mut a = item(1, 0, 5);
        a.param = 7;
        let mut b = item(1, 0, 5);
        b.param = 99;
        let items = vec![a, b];
        let mut out = Vec::new();

        let report = prune_redundant_work_items_into(&items, &mut out);

        assert!(report.is_empty());
        assert!(out.is_empty());
    }

    #[test]
    fn output_handles_dense_unique_accepts_single_owner_outputs() {
        let items = vec![item(1, 0, 5), item(1, 0, 6), item(1, 0, 7)];

        assert!(output_handles_are_dense_unique(&items));
    }

    #[test]
    fn output_handles_dense_unique_rejects_repeated_output() {
        let items = vec![item(1, 0, 5), item(2, 0, 5)];

        assert!(!output_handles_are_dense_unique(&items));
    }

    #[test]
    fn prune_redundant_work_items_still_catches_duplicate_with_repeated_output() {
        let items = vec![item(1, 0, 5), item(2, 0, 6), item(1, 0, 5)];
        let mut out = Vec::new();

        let report = prune_redundant_work_items_into(&items, &mut out);

        assert_eq!(report.total_redundant_ops, 1);
        assert_eq!(out, vec![item(1, 0, 5), item(2, 0, 6)]);
    }
}
