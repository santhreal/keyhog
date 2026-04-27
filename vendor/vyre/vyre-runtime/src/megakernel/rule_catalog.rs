//! DFA rule catalog packing for batched megakernel dispatch.

use crate::PipelineError;

/// Dense byte alphabet used by the DFA transition table.
pub(crate) const ALPHABET_SIZE: u32 = 256;

/// Number of `u32` words per rule metadata entry.
pub(crate) const RULE_META_WORDS: usize = 3;

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

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
pub(crate) struct RuleMeta {
    pub(crate) transition_base: u32,
    pub(crate) accept_base: u32,
    pub(crate) state_count: u32,
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
pub(crate) struct PackedRuleCatalog {
    pub(crate) rule_meta: Vec<RuleMeta>,
    pub(crate) transitions: Vec<u32>,
    pub(crate) accept: Vec<u32>,
    pub(crate) rejected_rules: Vec<BatchRuleRejection>,
}

/// Fingerprints for the valid dense catalog entries.
#[must_use]
pub(crate) fn accepted_rule_fingerprints(
    rules: &[BatchRuleProgram],
) -> (Vec<[u8; 32]>, Vec<BatchRuleRejection>) {
    let mut fingerprints = vec![None; rules.len()];
    let mut rejections = Vec::new();
    let mut slots = DenseSlotTracker::new(rules.len());

    for rule in rules {
        slots.mark_addressed(rule.rule_idx);
        match validate_rule_shape(
            rule.rule_idx,
            &rule.transitions,
            &rule.accept,
            rule.state_count,
        ) {
            Ok(()) => match slots.claim_index(rule.rule_idx, rules.len()) {
                Ok(index) => fingerprints[index] = Some(rule_fingerprint(rule)),
                Err(rejection) => rejections.push(rejection),
            },
            Err(error) => rejections.push(BatchRuleRejection {
                rule_idx: Some(rule.rule_idx),
                reason: error.to_string(),
            }),
        }
    }

    rejections.extend(slots.missing_rejections());
    (
        fingerprints
            .into_iter()
            .flatten()
            .collect::<Vec<[u8; 32]>>(),
        rejections,
    )
}

/// Pack valid DFA rules into compact shared device tables.
///
/// Rules with identical `(transitions, accept, state_count)` share backing
/// transition and accept storage while retaining distinct dense metadata slots.
pub(crate) fn pack_rule_catalog(
    rules: &[BatchRuleProgram],
) -> Result<PackedRuleCatalog, PipelineError> {
    let mut unique = std::collections::BTreeMap::<[u8; 32], (u32, u32, u32)>::new();
    let mut transitions = vec![0; ALPHABET_SIZE as usize];
    let mut accept = vec![0];
    let mut rule_meta = vec![
        RuleMeta {
            transition_base: 0,
            accept_base: 0,
            state_count: 1,
        };
        rules.len()
    ];
    let mut rejections = Vec::new();
    let mut slots = DenseSlotTracker::new(rules.len());

    for rule in rules {
        slots.mark_addressed(rule.rule_idx);
        if let Err(error) = validate_rule_shape(
            rule.rule_idx,
            &rule.transitions,
            &rule.accept,
            rule.state_count,
        ) {
            rejections.push(BatchRuleRejection {
                rule_idx: Some(rule.rule_idx),
                reason: error.to_string(),
            });
            continue;
        }

        let meta_index = match slots.claim_index(rule.rule_idx, rule_meta.len()) {
            Ok(index) => index,
            Err(rejection) => {
                rejections.push(rejection);
                continue;
            }
        };

        let (transition_base, accept_base, state_count) = if let Some(layout) =
            unique.get(&dfa_storage_fingerprint(rule))
        {
            *layout
        } else {
            let transition_base =
                u32::try_from(transitions.len()).map_err(|_| PipelineError::QueueFull {
                    queue: "submission",
                    fix: "flattened transition table exceeds u32::MAX words; split the rule catalog into smaller groups",
                })?;
            let accept_base = u32::try_from(accept.len()).map_err(|_| PipelineError::QueueFull {
                queue: "submission",
                fix: "flattened accept table exceeds u32::MAX words; split the rule catalog into smaller groups",
            })?;
            transitions.extend_from_slice(&rule.transitions);
            accept.extend_from_slice(&rule.accept);
            unique.insert(
                dfa_storage_fingerprint(rule),
                (transition_base, accept_base, rule.state_count),
            );
            (transition_base, accept_base, rule.state_count)
        };
        rule_meta[meta_index] = RuleMeta {
            transition_base,
            accept_base,
            state_count,
        };
    }

    rejections.extend(slots.missing_rejections());
    Ok(PackedRuleCatalog {
        rule_meta,
        transitions,
        accept,
        rejected_rules: rejections,
    })
}

fn validate_rule_shape(
    rule_idx: u32,
    transitions: &[u32],
    accept: &[u32],
    state_count: u32,
) -> Result<(), PipelineError> {
    let expected_transitions = usize::try_from(state_count)
        .ok()
        .and_then(|count| count.checked_mul(ALPHABET_SIZE as usize))
        .ok_or_else(|| {
            PipelineError::Backend("rule transition table size overflowed usize".to_string())
        })?;
    if transitions.len() != expected_transitions {
        return Err(PipelineError::Backend(format!(
            "rule {rule_idx} transition table has {} words, expected {expected_transitions}. Fix: compile a dense state_count * 256 DFA table before batch dispatch.",
            transitions.len()
        )));
    }
    if accept.len() != state_count as usize {
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

struct DenseSlotTracker {
    occupied: Vec<bool>,
    addressed: Vec<bool>,
}

impl DenseSlotTracker {
    fn new(slot_count: usize) -> Self {
        Self {
            occupied: vec![false; slot_count],
            addressed: vec![false; slot_count],
        }
    }

    fn mark_addressed(&mut self, rule_idx: u32) {
        if let Some(index) = usize::try_from(rule_idx)
            .ok()
            .filter(|index| *index < self.addressed.len())
        {
            self.addressed[index] = true;
        }
    }

    fn claim_index(
        &mut self,
        rule_idx: u32,
        slot_count: usize,
    ) -> Result<usize, BatchRuleRejection> {
        let Some(meta_index) = usize::try_from(rule_idx).ok() else {
            return Err(BatchRuleRejection {
                rule_idx: Some(rule_idx),
                reason:
                    "rule_idx exceeds usize. Fix: rebuild the batch with a smaller rule catalog"
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
        if self.occupied[meta_index] {
            return Err(BatchRuleRejection {
                rule_idx: Some(rule_idx),
                reason: format!(
                    "duplicate rule_idx {rule_idx}. Fix: keep exactly one rule per dense rule-table slot"
                ),
            });
        }
        self.occupied[meta_index] = true;
        Ok(meta_index)
    }

    fn missing_rejections(self) -> Vec<BatchRuleRejection> {
        self.occupied
            .into_iter()
            .zip(self.addressed)
            .enumerate()
            .filter(|(_, (occupied, addressed))| !occupied && !addressed)
            .map(|(rule_idx, _)| BatchRuleRejection {
                    rule_idx: Some(rule_idx as u32),
                    reason: format!(
                        "rule_idx {rule_idx} has no valid catalog entry. Fix: provide a well-formed DFA for every dense rule slot before batch dispatch"
                    ),
            })
            .collect()
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
