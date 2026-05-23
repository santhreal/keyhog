//! Shared fallible staging reservations for CUDA backend hot paths.

use std::hash::Hash;

use rustc_hash::{FxHashMap, FxHashSet};
use smallvec::{Array, SmallVec};
use vyre_driver::BackendError;

fn reserve_error(
    field: &'static str,
    capacity: usize,
    error: impl std::fmt::Display,
) -> BackendError {
    BackendError::InvalidProgram {
        fix: format!(
            "Fix: CUDA backend staging could not reserve {capacity} {field} slot(s): {error}. Split the dispatch batch or lower CUDA staging fan-out before retrying."
        ),
    }
}

pub(crate) fn reserve_vec<T>(
    vec: &mut Vec<T>,
    capacity: usize,
    field: &'static str,
) -> Result<(), BackendError> {
    if capacity > vec.capacity() {
        vec.try_reserve_exact(capacity - vec.capacity())
            .map_err(|error| reserve_error(field, capacity, error))?;
    }
    Ok(())
}

pub(crate) fn reserved_vec<T>(
    capacity: usize,
    field: &'static str,
) -> Result<Vec<T>, BackendError> {
    let mut vec = Vec::new();
    reserve_vec(&mut vec, capacity, field)?;
    Ok(vec)
}

pub(crate) fn ensure_vec_slots_at_least<T>(
    slots: &mut Vec<Vec<T>>,
    slot_count: usize,
    field: &'static str,
) -> Result<(), BackendError> {
    reserve_vec(slots, slot_count, field)?;
    if slots.len() < slot_count {
        slots.resize_with(slot_count, Vec::new);
    }
    Ok(())
}

pub(crate) fn resize_vec_slots<T>(
    slots: &mut Vec<Vec<T>>,
    slot_count: usize,
    field: &'static str,
) -> Result<(), BackendError> {
    ensure_vec_slots_at_least(slots, slot_count, field)?;
    if slots.len() > slot_count {
        slots.truncate(slot_count);
    }
    Ok(())
}

pub(crate) fn clear_vec_slots<T>(slots: &mut [Vec<T>]) {
    for slot in slots {
        slot.clear();
    }
}

pub(crate) fn reserve_smallvec<A>(
    vec: &mut SmallVec<A>,
    capacity: usize,
    field: &'static str,
) -> Result<(), BackendError>
where
    A: Array,
{
    if capacity > vec.capacity() {
        vec.try_reserve(capacity - vec.capacity())
            .map_err(|error| reserve_error(field, capacity, error))?;
    }
    Ok(())
}

pub(crate) fn reserve_hash_set<T>(
    set: &mut FxHashSet<T>,
    capacity: usize,
    field: &'static str,
) -> Result<(), BackendError>
where
    T: Eq + Hash,
{
    if capacity > set.capacity() {
        set.try_reserve(capacity - set.capacity())
            .map_err(|error| reserve_error(field, capacity, error))?;
    }
    Ok(())
}

pub(crate) fn reserve_hash_map<K, V>(
    map: &mut FxHashMap<K, V>,
    capacity: usize,
    field: &'static str,
) -> Result<(), BackendError>
where
    K: Eq + Hash,
{
    if capacity > map.capacity() {
        map.try_reserve(capacity - map.capacity())
            .map_err(|error| reserve_error(field, capacity, error))?;
    }
    Ok(())
}
