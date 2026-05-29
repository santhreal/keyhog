//! DFA rule catalog packing for batched megakernel dispatch.

use super::staging_reserve::{
    reserve_hash_map_capacity as reserve_catalog_map, reserve_vec_capacity as reserve_catalog_vec,
};
use crate::PipelineError;
use rustc_hash::FxHashMap;

/// Dense byte alphabet used by the DFA transition table.
pub const ALPHABET_SIZE: u32 = 256;
const ALPHABET_SIZE_USIZE: usize = 256;

/// Number of `u32` words per rule metadata entry.
pub const RULE_META_WORDS: usize = 3;

/// One compiled DFA-backed rule program consumed by the batch dispatcher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchRuleProgram {
    /// Stable rule-table index.
    pub rule_idx: u32,
    /// Dense DFA transition table (`state * 256 + byte -> next_state`).
    pub transitions: Vec<u32>,
    /// Dense DFA accept table (`state -> non-zero match marker`).
    pub accept: Vec<u32>,
    /// DFA state count.
    pub state_count: u32,
}

impl BatchRuleProgram {
    /// Build one DFA-backed rule program.
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError::Backend`] when the DFA buffers do not match
    /// `state_count`.
    pub fn new(
        rule_idx: u32,
        transitions: Vec<u32>,
        accept: Vec<u32>,
        state_count: u32,
    ) -> Result<Self, PipelineError> {
        validate_rule_shape(rule_idx, &transitions, &accept, state_count)?;
        Ok(Self {
            rule_idx,
            transitions,
            accept,
            state_count,
        })
    }
}

/// Packed metadata for one dense DFA rule entry.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
pub struct RuleMeta {
    /// Word offset into the flattened transition table.
    pub transition_base: u32,
    /// Word offset into the flattened accept table.
    pub accept_base: u32,
    /// DFA state count for this rule.
    pub state_count: u32,
}

/// One rule rejected from a megakernel batch while other rules still ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchRuleRejection {
    /// Caller-supplied rule index when present.
    pub rule_idx: Option<u32>,
    /// Human-readable rejection reason.
    pub reason: String,
}

/// Packed rule catalog uploaded to device storage buffers.
pub struct PackedRuleCatalog {
    /// Dense per-rule metadata table.
    pub rule_meta: Vec<RuleMeta>,
    /// Deduplicated flattened DFA transition storage.
    pub transitions: Vec<u32>,
    /// Deduplicated flattened DFA accept storage.
    pub accept: Vec<u32>,
    /// Rules rejected during validation or dense-slot assignment.
    pub rejected_rules: Vec<BatchRuleRejection>,
}

/// Caller-owned storage for packing rule catalogs without rebuilding host
/// allocations on every refresh.
#[derive(Default)]
pub struct RuleCatalogPackingScratch {
    /// Dense per-rule metadata table.
    pub rule_meta: Vec<RuleMeta>,
    /// Deduplicated flattened DFA transition storage.
    pub transitions: Vec<u32>,
    /// Deduplicated flattened DFA accept storage.
    pub accept: Vec<u32>,
    /// Rules rejected during validation or dense-slot assignment.
    pub rejected_rules: Vec<BatchRuleRejection>,
    unique_storage: FxHashMap<[u8; 32], (u32, u32, u32)>,
    occupied: Vec<bool>,
    addressed: Vec<bool>,
}

/// Fingerprints for the valid dense catalog entries.
#[must_use]
pub fn accepted_rule_fingerprints(
    rules: &[BatchRuleProgram],
) -> (Vec<[u8; 32]>, Vec<BatchRuleRejection>) {
    let mut fingerprints = Vec::new();
    let mut occupied = Vec::new();
    let mut addressed = Vec::new();
    let rejections =
        accepted_rule_fingerprints_into(rules, &mut fingerprints, &mut occupied, &mut addressed);
    (fingerprints, rejections)
}

/// Fill caller-owned storage with fingerprints for valid dense catalog entries.
///
/// The output fingerprint order matches dense rule-table order, not input
/// order. `fingerprints`, `occupied`, and `addressed` are cleared and reused so
/// dispatchers can check resident catalog identity without allocating on every
/// cache-hit dispatch.
pub fn accepted_rule_fingerprints_into(
    rules: &[BatchRuleProgram],
    fingerprints: &mut Vec<[u8; 32]>,
    occupied: &mut Vec<bool>,
    addressed: &mut Vec<bool>,
) -> Vec<BatchRuleRejection> {
    let mut rejections = Vec::new();
    accepted_rule_fingerprints_and_rejections_into(
        rules,
        fingerprints,
        occupied,
        addressed,
        &mut rejections,
    );
    rejections
}

/// Fill caller-owned storage with fingerprints and rejection details for valid
/// dense catalog entries.
///
/// This is the allocation-stable form used by hot dispatchers. All scratch
/// vectors are cleared and reused; valid unchanged catalogs perform no host
/// allocations while checking resident rule-buffer identity.
pub fn accepted_rule_fingerprints_and_rejections_into(
    rules: &[BatchRuleProgram],
    fingerprints: &mut Vec<[u8; 32]>,
    occupied: &mut Vec<bool>,
    addressed: &mut Vec<bool>,
    rejections: &mut Vec<BatchRuleRejection>,
) {
    fingerprints.clear();
    fingerprints.resize(rules.len(), [0; 32]);
    occupied.clear();
    occupied.resize(rules.len(), false);
    addressed.clear();
    addressed.resize(rules.len(), false);
    rejections.clear();

    for rule in rules {
        mark_addressed(addressed, rule.rule_idx);
        match validate_rule_shape(
            rule.rule_idx,
            &rule.transitions,
            &rule.accept,
            rule.state_count,
        ) {
            Ok(()) => match claim_dense_index(occupied, rule.rule_idx, rules.len()) {
                Ok(index) => fingerprints[index] = rule_fingerprint(rule),
                Err(rejection) => rejections.push(rejection),
            },
            Err(error) => rejections.push(BatchRuleRejection {
                rule_idx: Some(rule.rule_idx),
                reason: error.to_string(),
            }),
        }
    }

    extend_missing_rejections(occupied, addressed, rejections);
    let mut write = 0;
    for read in 0..occupied.len() {
        if occupied[read] {
            fingerprints[write] = fingerprints[read];
            write += 1;
        }
    }
    fingerprints.truncate(write);
}

/// Pack valid DFA rules into compact shared device tables.
///
/// Rules with identical `(transitions, accept, state_count)` share backing
/// transition and accept storage while retaining distinct dense metadata slots.
pub fn pack_rule_catalog(rules: &[BatchRuleProgram]) -> Result<PackedRuleCatalog, PipelineError> {
    let mut scratch = RuleCatalogPackingScratch::default();
    pack_rule_catalog_into(rules, &mut scratch)?;
    Ok(PackedRuleCatalog {
        rule_meta: scratch.rule_meta,
        transitions: scratch.transitions,
        accept: scratch.accept,
        rejected_rules: scratch.rejected_rules,
    })
}

/// Pack valid DFA rules into caller-owned storage.
///
/// Existing vector and hash-map allocations in `scratch` are reused across
/// calls. This is the hot-path form for resident megakernel dispatchers that
/// refresh device rule buffers repeatedly.
pub fn pack_rule_catalog_into(
    rules: &[BatchRuleProgram],
    scratch: &mut RuleCatalogPackingScratch,
) -> Result<(), PipelineError> {
    scratch.unique_storage.clear();
    reserve_catalog_map(
        &mut scratch.unique_storage,
        rules.len(),
        "unique DFA storage",
    )?;
    scratch.transitions.clear();
    reserve_catalog_vec(
        &mut scratch.transitions,
        ALPHABET_SIZE_USIZE,
        "inert transition row",
    )?;
    scratch.transitions.resize(ALPHABET_SIZE_USIZE, 0);
    scratch.accept.clear();
    reserve_catalog_vec(&mut scratch.accept, 1, "inert accept row")?;
    scratch.accept.push(0);
    scratch.rule_meta.clear();
    reserve_catalog_vec(&mut scratch.rule_meta, rules.len(), "rule metadata")?;
    scratch.rule_meta.resize(
        rules.len(),
        RuleMeta {
            transition_base: 0,
            accept_base: 0,
            state_count: 1,
        },
    );
    scratch.rejected_rules.clear();
    reserve_catalog_vec(
        &mut scratch.rejected_rules,
        rules.len(),
        "rule rejection rows",
    )?;
    scratch.occupied.clear();
    reserve_catalog_vec(&mut scratch.occupied, rules.len(), "dense occupancy bitmap")?;
    scratch.occupied.resize(rules.len(), false);
    scratch.addressed.clear();
    reserve_catalog_vec(
        &mut scratch.addressed,
        rules.len(),
        "dense addressed bitmap",
    )?;
    scratch.addressed.resize(rules.len(), false);

    for rule in rules {
        mark_addressed(&mut scratch.addressed, rule.rule_idx);
        if let Err(error) = validate_rule_shape(
            rule.rule_idx,
            &rule.transitions,
            &rule.accept,
            rule.state_count,
        ) {
            scratch.rejected_rules.push(BatchRuleRejection {
                rule_idx: Some(rule.rule_idx),
                reason: error.to_string(),
            });
            continue;
        }

        let meta_index = match claim_dense_index(
            &mut scratch.occupied,
            rule.rule_idx,
            scratch.rule_meta.len(),
        ) {
            Ok(index) => index,
            Err(rejection) => {
                scratch.rejected_rules.push(rejection);
                continue;
            }
        };

        let storage_fingerprint = dfa_storage_fingerprint(rule);
        let (transition_base, accept_base, state_count) = if let Some(layout) =
            scratch.unique_storage.get(&storage_fingerprint)
        {
            *layout
        } else {
            let transition_base =
                u32::try_from(scratch.transitions.len()).map_err(|_| PipelineError::QueueFull {
                    queue: "submission",
                    fix: "flattened transition table exceeds u32::MAX words; split the rule catalog into smaller groups",
                })?;
            let accept_base = u32::try_from(scratch.accept.len()).map_err(|_| PipelineError::QueueFull {
                queue: "submission",
                fix: "flattened accept table exceeds u32::MAX words; split the rule catalog into smaller groups",
            })?;
            let transition_target = scratch
                .transitions
                .len()
                .checked_add(rule.transitions.len())
                .ok_or(PipelineError::QueueFull {
                    queue: "submission",
                    fix: "flattened transition table length overflows usize; split the rule catalog into smaller groups",
                })?;
            reserve_catalog_vec(
                &mut scratch.transitions,
                transition_target,
                "flattened transition storage",
            )?;
            let accept_target = scratch
                .accept
                .len()
                .checked_add(rule.accept.len())
                .ok_or(PipelineError::QueueFull {
                    queue: "submission",
                    fix: "flattened accept table length overflows usize; split the rule catalog into smaller groups",
                })?;
            reserve_catalog_vec(
                &mut scratch.accept,
                accept_target,
                "flattened accept storage",
            )?;
            scratch.transitions.extend_from_slice(&rule.transitions);
            scratch.accept.extend_from_slice(&rule.accept);
            scratch.unique_storage.insert(
                storage_fingerprint,
                (transition_base, accept_base, rule.state_count),
            );
            (transition_base, accept_base, rule.state_count)
        };
        scratch.rule_meta[meta_index] = RuleMeta {
            transition_base,
            accept_base,
            state_count,
        };
    }

    extend_missing_rejections(
        &scratch.occupied,
        &scratch.addressed,
        &mut scratch.rejected_rules,
    );
    Ok(())
}

fn validate_rule_shape(
    rule_idx: u32,
    transitions: &[u32],
    accept: &[u32],
    state_count: u32,
) -> Result<(), PipelineError> {
    let expected_transitions = usize::try_from(state_count)
        .ok()
        .and_then(|count| count.checked_mul(ALPHABET_SIZE_USIZE))
        .ok_or_else(|| {
            PipelineError::Backend("rule transition table size overflowed usize".to_string())
        })?;
    if transitions.len() != expected_transitions {
        return Err(PipelineError::Backend(format!(
            "rule {rule_idx} transition table has {} words, expected {expected_transitions}. Fix: compile a dense state_count * 256 DFA table before batch dispatch.",
            transitions.len()
        )));
    }
    let state_count_usize = usize::try_from(state_count).map_err(|source| {
        PipelineError::Backend(format!(
            "rule {rule_idx} state_count {state_count} cannot fit usize: {source}. Fix: shard the DFA state space before batch dispatch."
        ))
    })?;
    if accept.len() != state_count_usize {
        return Err(PipelineError::Backend(format!(
            "rule {rule_idx} accept table has {} words, expected {state_count}. Fix: emit one accept entry per DFA state before batch dispatch.",
            accept.len()
        )));
    }
    Ok(())
}

fn rule_fingerprint(rule: &BatchRuleProgram) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&rule.rule_idx.to_le_bytes());
    hasher.update(bytemuck::cast_slice(&rule.transitions));
    hasher.update(bytemuck::cast_slice(&rule.accept));
    hasher.update(&rule.state_count.to_le_bytes());
    *hasher.finalize().as_bytes()
}

fn dfa_storage_fingerprint(rule: &BatchRuleProgram) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(bytemuck::cast_slice(&rule.transitions));
    hasher.update(bytemuck::cast_slice(&rule.accept));
    hasher.update(&rule.state_count.to_le_bytes());
    *hasher.finalize().as_bytes()
}

fn mark_addressed(addressed: &mut [bool], rule_idx: u32) {
    if let Some(index) = usize::try_from(rule_idx)
        .ok()
        .filter(|index| *index < addressed.len())
    {
        addressed[index] = true;
    }
}

fn claim_dense_index(
    occupied: &mut [bool],
    rule_idx: u32,
    slot_count: usize,
) -> Result<usize, BatchRuleRejection> {
    let Some(meta_index) = usize::try_from(rule_idx).ok() else {
        return Err(BatchRuleRejection {
            rule_idx: Some(rule_idx),
            reason: "rule_idx exceeds usize. Fix: rebuild the batch with a smaller rule catalog"
                .to_string(),
        });
    };
    if meta_index >= slot_count {
        return Err(BatchRuleRejection {
            rule_idx: Some(rule_idx),
            reason: format!(
                "rule_idx {rule_idx} falls outside 0..{slot_count}. Fix: keep the rule catalog dense so the batch work queue can address every rule"
            ),
        });
    }
    if occupied[meta_index] {
        return Err(BatchRuleRejection {
            rule_idx: Some(rule_idx),
            reason: format!(
                "duplicate rule_idx {rule_idx}. Fix: keep exactly one rule per dense rule-table slot"
            ),
        });
    }
    occupied[meta_index] = true;
    Ok(meta_index)
}

fn extend_missing_rejections(
    occupied: &[bool],
    addressed: &[bool],
    out: &mut Vec<BatchRuleRejection>,
) {
    for (rule_idx, (occupied, addressed)) in occupied
        .iter()
        .copied()
        .zip(addressed.iter().copied())
        .enumerate()
    {
        if !occupied && !addressed {
            let rule_idx_u32 = u32::try_from(rule_idx).unwrap_or_else(|source| {
                panic!(
                    "rule catalog dense index {rule_idx} cannot fit u32: {source}. Fix: shard the rule catalog before rejection reporting."
                )
            });
            out.push(BatchRuleRejection {
                rule_idx: Some(rule_idx_u32),
                reason: format!(
                    "rule_idx {rule_idx} has no valid catalog entry. Fix: provide a well-formed DFA for every dense rule slot before batch dispatch"
                ),
            });
        }
    }
}

#[cfg(test)]

mod tests {
    use super::*;

    #[test]
    fn duplicate_dfas_share_catalog_storage() {
        let first = BatchRuleProgram::new(0, vec![0; 256], vec![0], 1).unwrap();
        let second = BatchRuleProgram::new(1, vec![0; 256], vec![0], 1).unwrap();
        let packed = pack_rule_catalog(&[first, second]).unwrap();
        assert_eq!(
            packed.rule_meta[0].transition_base,
            packed.rule_meta[1].transition_base
        );
        assert_eq!(
            packed.rule_meta[0].accept_base,
            packed.rule_meta[1].accept_base
        );
        assert_eq!(
            packed.transitions.len(),
            packed.rule_meta[0].transition_base as usize + ALPHABET_SIZE as usize
        );
        assert_eq!(
            packed.accept.len(),
            packed.rule_meta[0].accept_base as usize + 1
        );
        assert!(packed.rejected_rules.is_empty());
    }

    #[test]
    fn duplicate_dfas_do_not_reserve_raw_duplicate_storage() {
        let rules = (0..32)
            .map(|rule_idx| BatchRuleProgram::new(rule_idx, vec![0; 256], vec![0], 1).unwrap())
            .collect::<Vec<_>>();

        let packed = pack_rule_catalog(&rules).unwrap();

        assert_eq!(packed.transitions.len(), ALPHABET_SIZE as usize * 2);
        assert!(
            packed.transitions.capacity() < ALPHABET_SIZE as usize * rules.len(),
            "Fix: duplicate DFA catalogs must not reserve memory as if every rule had unique transition storage."
        );
        assert_eq!(packed.accept.len(), 2);
        assert!(
            packed.accept.capacity() < rules.len(),
            "Fix: duplicate DFA catalogs must not reserve accept storage for every duplicate rule."
        );
    }

    #[test]
    fn accepted_rule_fingerprints_into_reuses_caller_storage() {
        let rules = (0..8)
            .map(|rule_idx| BatchRuleProgram::new(rule_idx, vec![0; 256], vec![0], 1).unwrap())
            .collect::<Vec<_>>();
        let mut fingerprints = Vec::with_capacity(16);
        let mut occupied = Vec::with_capacity(16);
        let mut addressed = Vec::with_capacity(16);
        let fingerprint_ptr = fingerprints.as_ptr();
        let occupied_ptr = occupied.as_ptr();
        let addressed_ptr = addressed.as_ptr();

        let rejections = accepted_rule_fingerprints_into(
            &rules,
            &mut fingerprints,
            &mut occupied,
            &mut addressed,
        );

        assert!(rejections.is_empty());
        assert_eq!(fingerprints.len(), rules.len());
        assert_eq!(fingerprints.as_ptr(), fingerprint_ptr);
        assert_eq!(occupied.as_ptr(), occupied_ptr);
        assert_eq!(addressed.as_ptr(), addressed_ptr);
    }

    #[test]
    fn invalid_rules_are_isolated_to_inert_catalog_entries() {
        let valid = BatchRuleProgram::new(0, vec![0; 256], vec![1], 1).unwrap();
        let invalid = BatchRuleProgram {
            rule_idx: 1,
            transitions: vec![0; 8],
            accept: vec![0],
            state_count: 1,
        };

        let packed = pack_rule_catalog(&[valid, invalid]).unwrap();
        assert_eq!(packed.rejected_rules.len(), 1);
        assert_eq!(packed.rejected_rules[0].rule_idx, Some(1));
        assert_eq!(packed.rule_meta[0].state_count, 1);
        assert!(packed.rule_meta[0].transition_base >= ALPHABET_SIZE);
        assert_eq!(packed.rule_meta[1].transition_base, 0);
        assert_eq!(packed.rule_meta[1].accept_base, 0);
        assert_eq!(packed.rule_meta[1].state_count, 1);
        assert_eq!(
            &packed.transitions[..ALPHABET_SIZE as usize],
            &vec![0; ALPHABET_SIZE as usize]
        );
        assert_eq!(packed.accept[0], 0);
    }
}

