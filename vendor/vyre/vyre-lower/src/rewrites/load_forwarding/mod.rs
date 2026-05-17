//! Store-to-load and load-to-load forwarding.
//!
//! When a `Load(slot, idx)` follows a `Store(slot, idx, val)` (or an
//! earlier `Load(slot, idx) -> r`) with no intervening op that could
//! invalidate `(slot, idx)`, the second load's result-id is rewritten
//! to point at the prior value-id. The Load op itself is left in place;
//! `descriptor_dce` removes it if it becomes unused.
//!
//! ## Invalidation
//!
//! Per-slot tracking. Any of these intervening ops invalidate ALL
//! entries for the relevant slot (or all slots, when scope is unknown):
//! - `Store*` to the same slot at a different index — may alias the
//!   tracked index, so the cached value is no longer guaranteed.
//! - `Atomic` — read-modify-writes can change the value.
//! - `Barrier` — re-publishes other threads' writes.
//! - `Async{Load,Store,Wait}` — staged writes may land asynchronously.
//! - Structured control flow (`If`/`ForLoop`/`Block`/`Region`) — body
//!   could write anywhere.
//! - `Trap`/`Resume`/`Return` — terminator.
//! - `Call`/`OpaqueExpr`/`OpaqueNode` — opaque side effects.
//!
//! ## Why two flavors at once
//!
//! Both store-to-load (`store; load → forward`) and load-to-load
//! (`load r1; load r2 → r2 := r1`) share the same per-slot cache; doing
//! one without the other would leave easy redundancy on the table.

use crate::{KernelBody, KernelDescriptor, KernelOpKind, LiteralValue};
use rustc_hash::FxHashMap;

#[must_use]
pub fn load_forwarding(desc: &KernelDescriptor) -> KernelDescriptor {
    load_forwarding_with_dataflow_facts(desc, None, None)
}

#[must_use]
pub fn load_forwarding_with_weir_alias_facts(
    desc: &KernelDescriptor,
    alias_facts: &crate::analyses::weir_alias::AliasFactSet,
) -> KernelDescriptor {
    load_forwarding_with_dataflow_facts(desc, Some(alias_facts), None)
}

#[must_use]
pub fn load_forwarding_with_weir_dataflow_facts(
    desc: &KernelDescriptor,
    alias_facts: &crate::analyses::weir_alias::AliasFactSet,
    reaching_defs: &crate::analyses::weir_reaching_def::ReachingDefFactSet,
) -> KernelDescriptor {
    load_forwarding_with_dataflow_facts(desc, Some(alias_facts), Some(reaching_defs))
}

fn load_forwarding_with_dataflow_facts(
    desc: &KernelDescriptor,
    alias_facts: Option<&crate::analyses::weir_alias::AliasFactSet>,
    reaching_defs: Option<&crate::analyses::weir_reaching_def::ReachingDefFactSet>,
) -> KernelDescriptor {
    let mut out = desc.clone();
    out.body = load_forwarding_body(out.body, alias_facts, reaching_defs);
    out
}

fn load_forwarding_body(
    mut body: KernelBody,
    alias_facts: Option<&crate::analyses::weir_alias::AliasFactSet>,
    reaching_defs: Option<&crate::analyses::weir_reaching_def::ReachingDefFactSet>,
) -> KernelBody {
    let literal_values = literal_u32_by_result(&body);
    // Per memory-space + slot map: (space, slot_id) → (address → val_id).
    let mut cache: FxHashMap<MemoryTarget, FxHashMap<AddressKey, CachedValue>> =
        FxHashMap::default();
    let mut id_remap: FxHashMap<u32, u32> = FxHashMap::default();

    for op in &body.ops {
        match &op.kind {
            KernelOpKind::StoreGlobal | KernelOpKind::StoreShared => {
                if op.operands.len() < 3 {
                    continue;
                }
                let target = match &op.kind {
                    KernelOpKind::StoreGlobal => MemoryTarget::new(MemorySpace::Global, op.operands[0]),
                    KernelOpKind::StoreShared => MemoryTarget::new(MemorySpace::Shared, op.operands[0]),
                    _ => continue,
                };
                let idx = resolve(op.operands[1], &id_remap, reaching_defs);
                let val = resolve(op.operands[2], &id_remap, reaching_defs);
                let address = address_key(idx, &literal_values);
                invalidate_cache_for_write(
                    &mut cache,
                    target,
                    idx,
                    address,
                    alias_facts,
                );
                cache.entry(target).or_default().insert(
                    address,
                    CachedValue {
                        index_operand: idx,
                        value_id: val,
                    },
                );
            }
            KernelOpKind::LoadGlobal | KernelOpKind::LoadShared => {
                if op.operands.len() < 2 {
                    continue;
                }
                let target = match &op.kind {
                    KernelOpKind::LoadGlobal => MemoryTarget::new(MemorySpace::Global, op.operands[0]),
                    KernelOpKind::LoadShared => MemoryTarget::new(MemorySpace::Shared, op.operands[0]),
                    _ => continue,
                };
                let idx = resolve(op.operands[1], &id_remap, reaching_defs);
                let address = address_key(idx, &literal_values);
                let Some(load_result) = op.result else {
                    continue;
                };
                let entry = cache.entry(target).or_default();
                if let Some(cached) = entry.get(&address) {
                    // Forward: rewrite this load's result-id refs to point
                    // at the cached value.
                    id_remap.insert(load_result, cached.value_id);
                    // Don't update the cache — the cached value is the
                    // canonical id; this load is now redundant.
                } else {
                    // First time seeing (slot, idx) at this point —
                    // remember THIS load as the canonical for any later
                    // duplicate.
                    entry.insert(
                        address,
                        CachedValue {
                            index_operand: idx,
                            value_id: load_result,
                        },
                    );
                }
            }
            KernelOpKind::LoadConstant => {
                // Constants are immutable — perfectly safe to forward.
                if op.operands.len() < 2 {
                    continue;
                }
                let target = MemoryTarget::new(MemorySpace::Constant, op.operands[0]);
                let idx = resolve(op.operands[1], &id_remap, reaching_defs);
                let address = address_key(idx, &literal_values);
                let Some(load_result) = op.result else {
                    continue;
                };
                let entry = cache.entry(target).or_default();
                if let Some(cached) = entry.get(&address) {
                    id_remap.insert(load_result, cached.value_id);
                } else {
                    entry.insert(
                        address,
                        CachedValue {
                            index_operand: idx,
                            value_id: load_result,
                        },
                    );
                }
            }
            KernelOpKind::Atomic { .. } => {
                if let (Some(&slot), Some(&idx)) = (op.operands.first(), op.operands.get(1)) {
                    let resolved_idx = resolve(idx, &id_remap, reaching_defs);
                    let address = address_key(resolved_idx, &literal_values);
                    invalidate_cache_for_write(
                        &mut cache,
                        MemoryTarget::new(MemorySpace::Global, slot),
                        resolved_idx,
                        address,
                        alias_facts,
                    );
                } else if let Some(&slot) = op.operands.first() {
                    cache.remove(&MemoryTarget::new(MemorySpace::Global, slot));
                } else {
                    cache.clear();
                }
            }
            KernelOpKind::Barrier { .. } => {
                // Barrier republishes other threads' writes — wipe everything.
                cache.clear();
            }
            KernelOpKind::AsyncLoad { .. }
            | KernelOpKind::AsyncStore { .. }
            | KernelOpKind::AsyncWait { .. } => {
                cache.clear();
            }
            KernelOpKind::StructuredIfThen
            | KernelOpKind::StructuredIfThenElse
            | KernelOpKind::StructuredForLoop { .. }
            | KernelOpKind::StructuredBlock
            | KernelOpKind::Region { .. } => {
                cache.clear();
            }
            KernelOpKind::Trap { .. } | KernelOpKind::Resume { .. } | KernelOpKind::Return => {
                cache.clear();
            }
            KernelOpKind::Call { .. }
            | KernelOpKind::OpaqueExpr(..)
            | KernelOpKind::OpaqueNode(..) => {
                cache.clear();
            }
            // Pure ops — no memory effect.
            _ => {}
        }
    }

    if !id_remap.is_empty() {
        for op in &mut body.ops {
            for pos in 0..op.operands.len() {
                if operand_is_result_reference(&op.kind, pos) {
                    if let Some(&new) = id_remap.get(&op.operands[pos]) {
                        op.operands[pos] = new;
                    }
                }
            }
        }
    }

    body.child_bodies = body
        .child_bodies
        .into_iter()
        .map(|child| load_forwarding_body(child, alias_facts, reaching_defs))
        .collect();
    body
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CachedValue {
    index_operand: u32,
    value_id: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct MemoryTarget {
    space: MemorySpace,
    slot: u32,
}

impl MemoryTarget {
    const fn new(space: MemorySpace, slot: u32) -> Self {
        Self { space, slot }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum MemorySpace {
    Global,
    Shared,
    Constant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum AddressKey {
    Const(u32),
    Result(u32),
}

fn resolve(
    id: u32,
    remap: &FxHashMap<u32, u32>,
    reaching_defs: Option<&crate::analyses::weir_reaching_def::ReachingDefFactSet>,
) -> u32 {
    let mut cur = id;
    let mut hops = 0usize;
    while let Some(&next) = remap.get(&cur) {
        if next == cur {
            break;
        }
        cur = next;
        hops += 1;
        if hops > remap.len() + 1 {
            break;
        }
    }
    if let Some(facts) = reaching_defs {
        let reaching = facts.reaching_defs(cur);
        if reaching.len() == 1 {
            return reaching[0];
        }
    }
    cur
}

fn address_key(index: u32, literal_values: &FxHashMap<u32, u32>) -> AddressKey {
    literal_values
        .get(&index)
        .copied()
        .map(AddressKey::Const)
        .unwrap_or(AddressKey::Result(index))
}

fn literal_u32_by_result(body: &KernelBody) -> FxHashMap<u32, u32> {
    let mut out = FxHashMap::default();
    for op in &body.ops {
        if !matches!(op.kind, KernelOpKind::Literal) {
            continue;
        }
        let Some(result) = op.result else {
            continue;
        };
        let Some(pool_index) = op.operands.first() else {
            continue;
        };
        let Some(LiteralValue::U32(value)) = body.literals.get(*pool_index as usize) else {
            continue;
        };
        out.insert(result, *value);
    }
    out
}

fn may_alias(
    left_target: MemoryTarget,
    left_index_operand: u32,
    left_address: AddressKey,
    right_target: MemoryTarget,
    right_index_operand: u32,
    right_address: AddressKey,
    alias_facts: Option<&crate::analyses::weir_alias::AliasFactSet>,
) -> bool {
    if left_target.space != right_target.space {
        return false;
    }
    if matches!(left_target.space, MemorySpace::Constant) {
        return false;
    }
    // Different binding slots in the same memory space are guaranteed
    // non-aliasing by the GPU memory model — each slot is a distinct
    // buffer allocation. A store to slot 1 cannot invalidate a cached
    // load from slot 0.
    if left_target.slot != right_target.slot {
        return false;
    }
    match (left_address, right_address) {
        (AddressKey::Const(left), AddressKey::Const(right)) if left_target.slot == right_target.slot => {
            return left == right;
        }
        (AddressKey::Result(left), AddressKey::Result(right))
            if left_target.slot == right_target.slot && left == right =>
        {
            return true;
        }
        _ => {}
    }
    !alias_facts.is_some_and(|facts| {
        facts.proves_no_alias(
            left_target.slot,
            left_index_operand,
            right_target.slot,
            right_index_operand,
        )
    })
}

fn invalidate_cache_for_write(
    cache: &mut FxHashMap<MemoryTarget, FxHashMap<AddressKey, CachedValue>>,
    write_target: MemoryTarget,
    write_index: u32,
    write_address: AddressKey,
    alias_facts: Option<&crate::analyses::weir_alias::AliasFactSet>,
) {
    cache.retain(|cached_target, entries| {
        entries.retain(|cached_address, cached| {
            !may_alias(
                *cached_target,
                cached.index_operand,
                *cached_address,
                write_target,
                write_index,
                write_address,
                alias_facts,
            )
        });
        !entries.is_empty()
    });
}

/// Mirror — must stay in sync with the others.
fn operand_is_result_reference(kind: &KernelOpKind, pos: usize) -> bool {
    use KernelOpKind::*;
    match kind {
        Literal => false,
        LocalInvocationId | GlobalInvocationId | WorkgroupId => false,
        SubgroupLocalId | SubgroupSize | LoopIndex { .. } => false,
        LoopCarrierInit { .. } | LoopCarrier { .. } | LoopCarrierEnd { .. } => pos == 0,
        LoadGlobal | LoadShared | LoadConstant => pos != 0,
        BufferLength => false,
        StoreGlobal | StoreShared => pos != 0,
        Copy | BinOpKind(_) | UnOpKind(_) | Fma | MatrixMma { .. } | Select | Cast { .. } => true,
        Atomic { .. } => pos != 0,
        SubgroupBallot | SubgroupShuffle | SubgroupAdd => true,
        StructuredIfThen | StructuredIfThenElse => pos == 0,
        StructuredForLoop { .. } => pos != 2,
        StructuredBlock | Region { .. } => false,
        Return | Barrier { .. } => false,
        AsyncLoad { .. } | AsyncStore { .. } => pos >= 2,
        AsyncWait { .. } => false,
        Trap { .. } => pos == 0,
        Resume { .. } => false,
        IndirectDispatch { .. } => false,
        Call { .. } => true,
        OpaqueExpr(..) | OpaqueNode(..) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BindingLayout, BindingSlot, BindingVisibility, Dispatch, KernelBody, KernelDescriptor,
        KernelOp, KernelOpKind, LiteralValue, MemoryClass,
    };
    use vyre_foundation::ir::DataType;

    fn rw_slot() -> BindingSlot {
        rw_slot_numbered(0)
    }

    fn rw_slot_numbered(slot: u32) -> BindingSlot {
        BindingSlot {
            slot,
            element_type: DataType::U32,
            element_count: None,
            memory_class: MemoryClass::Global,
            visibility: BindingVisibility::ReadWrite,
            name: format!("buf{slot}"),
        }
    }

    #[test]
    fn store_then_load_forwards_value() {
        // r0=Lit(0) (idx), r1=Lit(7) (val), Store(buf, r0, r1), r2=Load(buf, r0),
        // Store(buf, r0, r2). The Load should forward r2 := r1.
        let desc = KernelDescriptor {
            id: "stl".into(),
            bindings: BindingLayout {
                slots: vec![rw_slot()],
            },
            dispatch: Dispatch::new(1, 1, 1),
            body: KernelBody {
                ops: vec![
                    KernelOp {
                        kind: KernelOpKind::Literal,
                        operands: vec![0],
                        result: Some(0),
                    },
                    KernelOp {
                        kind: KernelOpKind::Literal,
                        operands: vec![1],
                        result: Some(1),
                    },
                    KernelOp {
                        kind: KernelOpKind::StoreGlobal,
                        operands: vec![0, 0, 1],
                        result: None,
                    },
                    KernelOp {
                        kind: KernelOpKind::LoadGlobal,
                        operands: vec![0, 0],
                        result: Some(2),
                    },
                    KernelOp {
                        kind: KernelOpKind::StoreGlobal,
                        operands: vec![0, 0, 2], // value should now resolve to r1
                        result: None,
                    },
                ],
                child_bodies: vec![],
                literals: vec![LiteralValue::U32(0), LiteralValue::U32(7)],
            },
        };
        let out = load_forwarding(&desc);
        // The trailing store's value-operand was 2 → should now be 1.
        assert_eq!(out.body.ops[4].operands, vec![0, 0, 1]);
    }

    #[test]
    fn weir_no_alias_fact_preserves_forwarding_across_unrelated_store() {
        let desc = KernelDescriptor {
            id: "alias_aware_stlf".into(),
            bindings: BindingLayout {
                slots: vec![rw_slot()],
            },
            dispatch: Dispatch::new(1, 1, 1),
            body: KernelBody {
                ops: vec![
                    KernelOp {
                        kind: KernelOpKind::LocalInvocationId,
                        operands: vec![0],
                        result: Some(0),
                    },
                    KernelOp {
                        kind: KernelOpKind::LocalInvocationId,
                        operands: vec![1],
                        result: Some(1),
                    },
                    KernelOp {
                        kind: KernelOpKind::Literal,
                        operands: vec![0],
                        result: Some(2),
                    },
                    KernelOp {
                        kind: KernelOpKind::Literal,
                        operands: vec![1],
                        result: Some(3),
                    },
                    KernelOp {
                        kind: KernelOpKind::StoreGlobal,
                        operands: vec![0, 0, 2],
                        result: None,
                    },
                    KernelOp {
                        kind: KernelOpKind::StoreGlobal,
                        operands: vec![0, 1, 3],
                        result: None,
                    },
                    KernelOp {
                        kind: KernelOpKind::LoadGlobal,
                        operands: vec![0, 0],
                        result: Some(4),
                    },
                    KernelOp {
                        kind: KernelOpKind::StoreGlobal,
                        operands: vec![0, 0, 4],
                        result: None,
                    },
                ],
                child_bodies: vec![],
                literals: vec![LiteralValue::U32(7), LiteralValue::U32(9)],
            },
        };
        let conservative = load_forwarding(&desc);
        assert_eq!(conservative.body.ops[7].operands, vec![0, 0, 4]);

        let mut facts = crate::analyses::weir_alias::AliasFactSet::default();
        facts.insert_no_alias(crate::analyses::weir_alias::NoAliasFact {
            left_binding: 0,
            left_index: 0,
            right_binding: 0,
            right_index: 1,
        });
        let alias_aware = load_forwarding_with_weir_alias_facts(&desc, &facts);
        assert_eq!(alias_aware.body.ops[7].operands, vec![0, 0, 2]);
    }

    #[test]
    fn different_binding_store_invalidates_forwarding_without_weir_no_alias_fact() {
        let desc = KernelDescriptor {
            id: "cross_binding_alias_conservative_stlf".into(),
            bindings: BindingLayout {
                slots: vec![rw_slot_numbered(0), rw_slot_numbered(1)],
            },
            dispatch: Dispatch::new(1, 1, 1),
            body: KernelBody {
                ops: vec![
                    KernelOp {
                        kind: KernelOpKind::Literal,
                        operands: vec![0],
                        result: Some(0),
                    },
                    KernelOp {
                        kind: KernelOpKind::Literal,
                        operands: vec![1],
                        result: Some(1),
                    },
                    KernelOp {
                        kind: KernelOpKind::Literal,
                        operands: vec![2],
                        result: Some(2),
                    },
                    KernelOp {
                        kind: KernelOpKind::LoadGlobal,
                        operands: vec![0, 0],
                        result: Some(3),
                    },
                    KernelOp {
                        kind: KernelOpKind::StoreGlobal,
                        operands: vec![1, 1, 2],
                        result: None,
                    },
                    KernelOp {
                        kind: KernelOpKind::LoadGlobal,
                        operands: vec![0, 0],
                        result: Some(4),
                    },
                    KernelOp {
                        kind: KernelOpKind::StoreGlobal,
                        operands: vec![0, 0, 4],
                        result: None,
                    },
                ],
                child_bodies: vec![],
                literals: vec![
                    LiteralValue::U32(0),
                    LiteralValue::U32(1),
                    LiteralValue::U32(9),
                ],
            },
        };

        // Slot 0 and slot 1 are distinct GPU buffer bindings — a store
        // to slot 1 cannot alias slot 0. The load at ops[5] (LoadGlobal
        // slot 0, idx 0) should forward to the earlier Load result r3,
        // making ops[6] use r3 instead of r4.
        let conservative = load_forwarding(&desc);
        assert_eq!(conservative.body.ops[6].operands, vec![0, 0, 3]);

        let mut facts = crate::analyses::weir_alias::AliasFactSet::default();
        facts.insert_no_alias(crate::analyses::weir_alias::NoAliasFact {
            left_binding: 0,
            left_index: 0,
            right_binding: 1,
            right_index: 1,
        });
        let alias_aware = load_forwarding_with_weir_alias_facts(&desc, &facts);
        assert_eq!(alias_aware.body.ops[6].operands, vec![0, 0, 3]);
    }

    #[test]
    fn global_and_shared_slots_do_not_forward_across_memory_spaces() {
        let desc = KernelDescriptor {
            id: "stlf_memory_space_separation".into(),
            bindings: BindingLayout {
                slots: vec![rw_slot()],
            },
            dispatch: Dispatch::new(1, 1, 1),
            body: KernelBody {
                ops: vec![
                    KernelOp {
                        kind: KernelOpKind::Literal,
                        operands: vec![0],
                        result: Some(0),
                    },
                    KernelOp {
                        kind: KernelOpKind::LoadGlobal,
                        operands: vec![0, 0],
                        result: Some(1),
                    },
                    KernelOp {
                        kind: KernelOpKind::LoadShared,
                        operands: vec![0, 0],
                        result: Some(2),
                    },
                    KernelOp {
                        kind: KernelOpKind::StoreShared,
                        operands: vec![0, 0, 2],
                        result: None,
                    },
                ],
                child_bodies: vec![],
                literals: vec![LiteralValue::U32(0)],
            },
        };

        let out = load_forwarding(&desc);
        assert_eq!(
            out.body.ops[3].operands,
            vec![0, 0, 2],
            "LoadShared must not forward from a same-slot LoadGlobal cache entry"
        );
    }

    #[test]
    fn load_then_load_same_idx_forwards() {
        let desc = KernelDescriptor {
            id: "ll".into(),
            bindings: BindingLayout {
                slots: vec![rw_slot()],
            },
            dispatch: Dispatch::new(1, 1, 1),
            body: KernelBody {
                ops: vec![
                    KernelOp {
                        kind: KernelOpKind::Literal,
                        operands: vec![0],
                        result: Some(0),
                    },
                    KernelOp {
                        kind: KernelOpKind::LoadGlobal,
                        operands: vec![0, 0],
                        result: Some(1),
                    },
                    KernelOp {
                        kind: KernelOpKind::LoadGlobal,
                        operands: vec![0, 0],
                        result: Some(2),
                    },
                    KernelOp {
                        kind: KernelOpKind::StoreGlobal,
                        operands: vec![0, 0, 2],
                        result: None,
                    },
                ],
                child_bodies: vec![],
                literals: vec![LiteralValue::U32(0)],
            },
        };
        let out = load_forwarding(&desc);
        // Store value should resolve to r1 (the first load), not r2.
        assert_eq!(out.body.ops[3].operands, vec![0, 0, 1]);
    }

    #[test]
    fn store_to_different_const_index_does_not_flush_forwardable_load() {
        let desc = KernelDescriptor {
            id: "different_const_store_keeps_load_cache".into(),
            bindings: BindingLayout {
                slots: vec![rw_slot()],
            },
            dispatch: Dispatch::new(1, 1, 1),
            body: KernelBody {
                ops: vec![
                    KernelOp {
                        kind: KernelOpKind::Literal,
                        operands: vec![0],
                        result: Some(0),
                    },
                    KernelOp {
                        kind: KernelOpKind::Literal,
                        operands: vec![1],
                        result: Some(1),
                    },
                    KernelOp {
                        kind: KernelOpKind::Literal,
                        operands: vec![2],
                        result: Some(2),
                    },
                    KernelOp {
                        kind: KernelOpKind::LoadGlobal,
                        operands: vec![0, 0],
                        result: Some(3),
                    },
                    KernelOp {
                        kind: KernelOpKind::StoreGlobal,
                        operands: vec![0, 1, 2],
                        result: None,
                    },
                    KernelOp {
                        kind: KernelOpKind::LoadGlobal,
                        operands: vec![0, 0],
                        result: Some(4),
                    },
                    KernelOp {
                        kind: KernelOpKind::StoreGlobal,
                        operands: vec![0, 1, 4],
                        result: None,
                    },
                ],
                child_bodies: vec![],
                literals: vec![
                    LiteralValue::U32(0),
                    LiteralValue::U32(1),
                    LiteralValue::U32(9),
                ],
            },
        };

        let out = load_forwarding(&desc);
        assert_eq!(out.body.ops[6].operands, vec![0, 1, 3]);
    }

    #[test]
    fn cache_keys_resolve_through_prior_load_forwarding() {
        let desc = KernelDescriptor {
            id: "resolved_idx".into(),
            bindings: BindingLayout {
                slots: vec![rw_slot()],
            },
            dispatch: Dispatch::new(1, 1, 1),
            body: KernelBody {
                ops: vec![
                    KernelOp {
                        kind: KernelOpKind::Literal,
                        operands: vec![0],
                        result: Some(0),
                    },
                    KernelOp {
                        kind: KernelOpKind::Literal,
                        operands: vec![1],
                        result: Some(3),
                    },
                    KernelOp {
                        kind: KernelOpKind::LoadGlobal,
                        operands: vec![0, 0],
                        result: Some(1),
                    },
                    KernelOp {
                        kind: KernelOpKind::LoadGlobal,
                        operands: vec![0, 0],
                        result: Some(2),
                    },
                    KernelOp {
                        kind: KernelOpKind::StoreGlobal,
                        operands: vec![0, 1, 3],
                        result: None,
                    },
                    KernelOp {
                        kind: KernelOpKind::LoadGlobal,
                        operands: vec![0, 2],
                        result: Some(4),
                    },
                    KernelOp {
                        kind: KernelOpKind::StoreGlobal,
                        operands: vec![0, 1, 4],
                        result: None,
                    },
                ],
                child_bodies: vec![],
                literals: vec![LiteralValue::U32(0), LiteralValue::U32(9)],
            },
        };

        let out = load_forwarding(&desc);
        assert_eq!(
            out.body.ops[6].operands,
            vec![0, 1, 3],
            "load at a remapped-equivalent index should forward from the earlier store"
        );
    }

    #[test]
    fn intervening_store_to_different_idx_invalidates_cache() {
        let desc = KernelDescriptor {
            id: "intervening".into(),
            bindings: BindingLayout {
                slots: vec![rw_slot()],
            },
            dispatch: Dispatch::new(1, 1, 1),
            body: KernelBody {
                ops: vec![
                    KernelOp {
                        kind: KernelOpKind::Literal,
                        operands: vec![0],
                        result: Some(0),
                    }, // idx_a
                    KernelOp {
                        kind: KernelOpKind::Literal,
                        operands: vec![1],
                        result: Some(1),
                    }, // val
                    KernelOp {
                        kind: KernelOpKind::LocalInvocationId,
                        operands: vec![0],
                        result: Some(2),
                    }, // idx_b is dynamic and may alias idx_a
                    KernelOp {
                        kind: KernelOpKind::Literal,
                        operands: vec![3],
                        result: Some(3),
                    }, // val_b
                    KernelOp {
                        kind: KernelOpKind::StoreGlobal,
                        operands: vec![0, 0, 1], // store val at idx_a
                        result: None,
                    },
                    KernelOp {
                        kind: KernelOpKind::StoreGlobal,
                        operands: vec![0, 2, 3], // dynamic idx_b may alias idx_a
                        result: None,
                    },
                    KernelOp {
                        kind: KernelOpKind::LoadGlobal,
                        operands: vec![0, 0], // load idx_a
                        result: Some(4),
                    },
                    KernelOp {
                        kind: KernelOpKind::StoreGlobal,
                        operands: vec![0, 0, 4],
                        result: None,
                    },
                ],
                child_bodies: vec![],
                literals: vec![
                    LiteralValue::U32(0),
                    LiteralValue::U32(7),
                    LiteralValue::U32(8),
                ],
            },
        };
        let out = load_forwarding(&desc);
        // The dynamic second store may alias idx_a, so it must wipe the cached idx_a load.
        // The load(idx_a) is no longer in cache → no forwarding → trailing store keeps r4.
        assert_eq!(out.body.ops[7].operands, vec![0, 0, 4]);
    }

    #[test]
    fn barrier_invalidates_cache() {
        let desc = KernelDescriptor {
            id: "barrier".into(),
            bindings: BindingLayout {
                slots: vec![rw_slot()],
            },
            dispatch: Dispatch::new(64, 1, 1),
            body: KernelBody {
                ops: vec![
                    KernelOp {
                        kind: KernelOpKind::Literal,
                        operands: vec![0],
                        result: Some(0),
                    },
                    KernelOp {
                        kind: KernelOpKind::Literal,
                        operands: vec![1],
                        result: Some(1),
                    },
                    KernelOp {
                        kind: KernelOpKind::StoreGlobal,
                        operands: vec![0, 0, 1],
                        result: None,
                    },
                    KernelOp {
                        kind: KernelOpKind::Barrier {
                            ordering:
                                vyre_foundation::runtime::memory_model::MemoryOrdering::SeqCst,
                        },
                        operands: vec![],
                        result: None,
                    },
                    KernelOp {
                        kind: KernelOpKind::LoadGlobal,
                        operands: vec![0, 0],
                        result: Some(2),
                    },
                    KernelOp {
                        kind: KernelOpKind::StoreGlobal,
                        operands: vec![0, 0, 2],
                        result: None,
                    },
                ],
                child_bodies: vec![],
                literals: vec![LiteralValue::U32(0), LiteralValue::U32(7)],
            },
        };
        let out = load_forwarding(&desc);
        // Barrier wiped cache; trailing store still references r2.
        assert_eq!(out.body.ops[5].operands, vec![0, 0, 2]);
    }

    #[test]
    fn different_slots_dont_interfere() {
        let mut s1 = rw_slot();
        s1.slot = 1;
        s1.name = "buf2".into();
        let desc = KernelDescriptor {
            id: "twoslots".into(),
            bindings: BindingLayout {
                slots: vec![rw_slot(), s1],
            },
            dispatch: Dispatch::new(1, 1, 1),
            body: KernelBody {
                ops: vec![
                    KernelOp {
                        kind: KernelOpKind::Literal,
                        operands: vec![0],
                        result: Some(0),
                    }, // idx
                    KernelOp {
                        kind: KernelOpKind::Literal,
                        operands: vec![1],
                        result: Some(1),
                    }, // val_a
                    KernelOp {
                        kind: KernelOpKind::Literal,
                        operands: vec![2],
                        result: Some(2),
                    }, // val_b
                    KernelOp {
                        kind: KernelOpKind::StoreGlobal,
                        operands: vec![0, 0, 1], // slot 0
                        result: None,
                    },
                    KernelOp {
                        kind: KernelOpKind::StoreGlobal,
                        operands: vec![1, 0, 2], // slot 1 — different slot, doesn't invalidate slot 0
                        result: None,
                    },
                    KernelOp {
                        kind: KernelOpKind::LoadGlobal,
                        operands: vec![0, 0], // slot 0, idx 0 — should forward to val_a (r1)
                        result: Some(3),
                    },
                    KernelOp {
                        kind: KernelOpKind::StoreGlobal,
                        operands: vec![0, 0, 3],
                        result: None,
                    },
                ],
                child_bodies: vec![],
                literals: vec![
                    LiteralValue::U32(0),
                    LiteralValue::U32(7),
                    LiteralValue::U32(99),
                ],
            },
        };
        let out = load_forwarding(&desc);
        assert_eq!(out.body.ops[6].operands, vec![0, 0, 1]);
    }

    #[test]
    fn atomic_invalidates_only_target_slot() {
        let desc = KernelDescriptor {
            id: "atomic_slot".into(),
            bindings: BindingLayout {
                slots: vec![rw_slot()],
            },
            dispatch: Dispatch::new(1, 1, 1),
            body: KernelBody {
                ops: vec![
                    KernelOp {
                        kind: KernelOpKind::Literal,
                        operands: vec![0],
                        result: Some(0),
                    },
                    KernelOp {
                        kind: KernelOpKind::Literal,
                        operands: vec![1],
                        result: Some(1),
                    },
                    KernelOp {
                        kind: KernelOpKind::StoreGlobal,
                        operands: vec![0, 0, 1],
                        result: None,
                    },
                    KernelOp {
                        kind: KernelOpKind::Atomic {
                            op: vyre_foundation::ir::AtomicOp::Add,
                            ordering:
                                vyre_foundation::runtime::memory_model::MemoryOrdering::SeqCst,
                        },
                        operands: vec![0, 0, 1], // slot 0
                        result: Some(2),
                    },
                    KernelOp {
                        kind: KernelOpKind::LoadGlobal,
                        operands: vec![0, 0],
                        result: Some(3),
                    },
                    KernelOp {
                        kind: KernelOpKind::StoreGlobal,
                        operands: vec![0, 0, 3],
                        result: None,
                    },
                ],
                child_bodies: vec![],
                literals: vec![LiteralValue::U32(0), LiteralValue::U32(7)],
            },
        };
        let out = load_forwarding(&desc);
        // Atomic on slot 0 invalidated cache; load can't forward.
        assert_eq!(out.body.ops[5].operands, vec![0, 0, 3]);
    }

    #[test]
    fn structured_if_invalidates_cache() {
        let desc = KernelDescriptor {
            id: "if_invalidates".into(),
            bindings: BindingLayout {
                slots: vec![rw_slot()],
            },
            dispatch: Dispatch::new(1, 1, 1),
            body: KernelBody {
                ops: vec![
                    KernelOp {
                        kind: KernelOpKind::Literal,
                        operands: vec![0],
                        result: Some(0),
                    },
                    KernelOp {
                        kind: KernelOpKind::Literal,
                        operands: vec![1],
                        result: Some(1),
                    },
                    KernelOp {
                        kind: KernelOpKind::StoreGlobal,
                        operands: vec![0, 0, 1],
                        result: None,
                    },
                    // condition operand
                    KernelOp {
                        kind: KernelOpKind::Literal,
                        operands: vec![0],
                        result: Some(2),
                    },
                    KernelOp {
                        kind: KernelOpKind::StructuredIfThen,
                        operands: vec![2, 0], // cond=r2, body-child-idx=0
                        result: None,
                    },
                    KernelOp {
                        kind: KernelOpKind::LoadGlobal,
                        operands: vec![0, 0],
                        result: Some(3),
                    },
                    KernelOp {
                        kind: KernelOpKind::StoreGlobal,
                        operands: vec![0, 0, 3],
                        result: None,
                    },
                ],
                child_bodies: vec![KernelBody {
                    ops: vec![],
                    child_bodies: vec![],
                    literals: vec![],
                }],
                literals: vec![LiteralValue::U32(0), LiteralValue::U32(7)],
            },
        };
        let out = load_forwarding(&desc);
        assert_eq!(out.body.ops[6].operands, vec![0, 0, 3]);
    }

    #[test]
    fn nothing_to_forward_is_noop() {
        let desc = KernelDescriptor {
            id: "noop".into(),
            bindings: BindingLayout {
                slots: vec![rw_slot()],
            },
            dispatch: Dispatch::new(1, 1, 1),
            body: KernelBody {
                ops: vec![
                    KernelOp {
                        kind: KernelOpKind::Literal,
                        operands: vec![0],
                        result: Some(0),
                    },
                    KernelOp {
                        kind: KernelOpKind::Literal,
                        operands: vec![1],
                        result: Some(1),
                    },
                    KernelOp {
                        kind: KernelOpKind::StoreGlobal,
                        operands: vec![0, 0, 1],
                        result: None,
                    },
                ],
                child_bodies: vec![],
                literals: vec![LiteralValue::U32(0), LiteralValue::U32(7)],
            },
        };
        let out = load_forwarding(&desc);
        assert_eq!(out.body.ops.len(), 3);
        assert_eq!(out.body.ops[2].operands, vec![0, 0, 1]);
    }

    #[test]
    fn loadconstant_is_forwardable_across_arbitrary_ops() {
        // LoadConstant points at immutable memory — even a Barrier shouldn't
        // wipe the cached entry. But our impl does (it's slot-keyed and
        // Barrier wipes everything). This test just documents current
        // conservative behavior.
        let desc = KernelDescriptor {
            id: "lc".into(),
            bindings: BindingLayout {
                slots: vec![rw_slot()],
            },
            dispatch: Dispatch::new(1, 1, 1),
            body: KernelBody {
                ops: vec![
                    KernelOp {
                        kind: KernelOpKind::Literal,
                        operands: vec![0],
                        result: Some(0),
                    },
                    KernelOp {
                        kind: KernelOpKind::LoadConstant,
                        operands: vec![0, 0],
                        result: Some(1),
                    },
                    KernelOp {
                        kind: KernelOpKind::LoadConstant,
                        operands: vec![0, 0], // same (slot, idx) — should forward
                        result: Some(2),
                    },
                    KernelOp {
                        kind: KernelOpKind::StoreGlobal,
                        operands: vec![0, 0, 2],
                        result: None,
                    },
                ],
                child_bodies: vec![],
                literals: vec![LiteralValue::U32(0)],
            },
        };
        let out = load_forwarding(&desc);
        assert_eq!(out.body.ops[3].operands, vec![0, 0, 1]);
    }

    #[test]
    fn idempotent() {
        let desc = KernelDescriptor {
            id: "idemp".into(),
            bindings: BindingLayout {
                slots: vec![rw_slot()],
            },
            dispatch: Dispatch::new(1, 1, 1),
            body: KernelBody {
                ops: vec![
                    KernelOp {
                        kind: KernelOpKind::Literal,
                        operands: vec![0],
                        result: Some(0),
                    },
                    KernelOp {
                        kind: KernelOpKind::Literal,
                        operands: vec![1],
                        result: Some(1),
                    },
                    KernelOp {
                        kind: KernelOpKind::StoreGlobal,
                        operands: vec![0, 0, 1],
                        result: None,
                    },
                    KernelOp {
                        kind: KernelOpKind::LoadGlobal,
                        operands: vec![0, 0],
                        result: Some(2),
                    },
                    KernelOp {
                        kind: KernelOpKind::StoreGlobal,
                        operands: vec![0, 0, 2],
                        result: None,
                    },
                ],
                child_bodies: vec![],
                literals: vec![LiteralValue::U32(0), LiteralValue::U32(7)],
            },
        };
        let once = load_forwarding(&desc);
        let twice = load_forwarding(&once);
        assert_eq!(once.body.ops, twice.body.ops);
    }

    #[test]
    fn empty_kernel_is_noop() {
        let desc = KernelDescriptor {
            id: "empty".into(),
            bindings: BindingLayout { slots: vec![] },
            dispatch: Dispatch::new(1, 1, 1),
            body: KernelBody {
                ops: vec![],
                child_bodies: vec![],
                literals: vec![],
            },
        };
        let out = load_forwarding(&desc);
        assert!(out.body.ops.is_empty());
    }

    #[test]
    fn reaching_def_facts_forward_equivalent_index_results() {
        let desc = KernelDescriptor {
            id: "reaching_def_forward".into(),
            bindings: BindingLayout {
                slots: vec![rw_slot()],
            },
            dispatch: Dispatch::new(1, 1, 1),
            body: KernelBody {
                ops: vec![
                    KernelOp {
                        kind: KernelOpKind::LocalInvocationId,
                        operands: vec![0],
                        result: Some(0),
                    },
                    KernelOp {
                        kind: KernelOpKind::Literal,
                        operands: vec![0],
                        result: Some(1),
                    },
                    KernelOp {
                        kind: KernelOpKind::Copy,
                        operands: vec![0],
                        result: Some(2),
                    },
                    KernelOp {
                        kind: KernelOpKind::StoreGlobal,
                        operands: vec![0, 0, 1],
                        result: None,
                    },
                    KernelOp {
                        kind: KernelOpKind::LoadGlobal,
                        operands: vec![0, 2],
                        result: Some(3),
                    },
                    KernelOp {
                        kind: KernelOpKind::StoreGlobal,
                        operands: vec![0, 0, 3],
                        result: None,
                    },
                ],
                child_bodies: vec![],
                literals: vec![LiteralValue::U32(7)],
            },
        };
        let mut reaching = crate::analyses::weir_reaching_def::ReachingDefFactSet::default();
        reaching.set_reaching_defs(2, vec![0]);
        let aliases = crate::analyses::weir_alias::AliasFactSet::default();
        let out = load_forwarding_with_weir_dataflow_facts(&desc, &aliases, &reaching);
        assert_eq!(out.body.ops[5].operands, vec![0, 0, 1]);
    }
}
