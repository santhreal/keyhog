//! Backend selection and acquisition policy.

use rustc_hash::FxHashMap;
use std::collections::HashSet;
use std::sync::OnceLock;
use vyre_foundation::ir::OpId;

use super::inventory_streams::{
    registered_backends, BackendCapability, BackendPrecedence, BackendRegistration,
};
use crate::allocation::{reserve_hash_map_to_capacity, reserve_vec_to_capacity};
use crate::backend::{default_supported_ops, BackendError, VyreBackend};

enum CacheState<T> {
    Ready(T),
    Failed(String),
}

fn cache_reservation_failed<T>(cache_name: &str, error: BackendError) -> CacheState<T> {
    CacheState::Failed(format!("{cache_name} initialization failed: {error}"))
}

fn cache_or_error<'a, T>(
    cache_name: &str,
    state: &'a CacheState<T>,
) -> Result<&'a T, BackendError> {
    match state {
        CacheState::Ready(value) => Ok(value),
        CacheState::Failed(message) => Err(BackendError::new(format!(
            "backend registry {cache_name} is unavailable: {message}. Fix: reduce linked backend inventory, increase available memory, or split registry initialization before acquiring a backend."
        ))),
    }
}

fn backend_dispatches_result(id: &str) -> Result<bool, BackendError> {
    static CACHE: OnceLock<CacheState<FxHashMap<&'static str, bool>>> = OnceLock::new();
    let table = cache_or_error(
        "dispatch capability cache",
        CACHE.get_or_init(|| {
            // HOT-PATH-OK: inventory::iter is consumed once to build the
            // immutable dispatch-capability cache; lookups use the frozen map.
            let entries = inventory::iter::<BackendCapability>.into_iter();
            let reserve = entries
                .size_hint()
                .1
                .unwrap_or_else(|| entries.size_hint().0);
            let mut table = FxHashMap::default();
            if let Err(error) = reserve_hash_map_to_capacity(
                &mut table,
                reserve,
                "Vyre backend registry",
                "dispatch capability slot",
                "reduce linked backend inventory or split registry initialization",
            ) {
                return cache_reservation_failed("dispatch capability cache", error);
            }
            for entry in entries {
                table.insert(entry.id, entry.dispatches);
            }
            CacheState::Ready(table)
        }),
    )?;
    Ok(table.get(id).copied().unwrap_or(false))
}

/// Return `true` when the named backend submitted `dispatches: true`.
#[must_use]
pub fn backend_dispatches(id: &str) -> bool {
    backend_dispatches_result(id).unwrap_or(false)
}

fn backend_precedence_result(id: &str) -> Result<u32, BackendError> {
    static CACHE: OnceLock<CacheState<FxHashMap<&'static str, u32>>> = OnceLock::new();
    let table = cache_or_error(
        "backend precedence cache",
        CACHE.get_or_init(|| {
            // HOT-PATH-OK: inventory::iter is consumed once to build the
            // immutable backend-precedence cache; lookups use the frozen map.
            let entries = inventory::iter::<BackendPrecedence>.into_iter();
            let reserve = entries
                .size_hint()
                .1
                .unwrap_or_else(|| entries.size_hint().0);
            let mut table = FxHashMap::default();
            if let Err(error) = reserve_hash_map_to_capacity(
                &mut table,
                reserve,
                "Vyre backend registry",
                "backend precedence slot",
                "reduce linked backend inventory or split registry initialization",
            ) {
                return cache_reservation_failed("backend precedence cache", error);
            }
            for entry in entries {
                table.insert(entry.id, entry.rank);
            }
            CacheState::Ready(table)
        }),
    )?;
    Ok(table.get(id).copied().unwrap_or(u32::MAX))
}

/// Look up a backend's submitted precedence. Returns `u32::MAX` for
/// backends that did not submit a `BackendPrecedence` entry.
#[must_use]
pub fn backend_precedence(id: &str) -> u32 {
    backend_precedence_result(id).unwrap_or(u32::MAX)
}

fn registered_backends_by_precedence_slice_result(
) -> Result<&'static [&'static BackendRegistration], BackendError> {
    static SORTED: OnceLock<CacheState<Box<[&'static BackendRegistration]>>> = OnceLock::new();
    let sorted = cache_or_error(
        "sorted backend precedence cache",
        SORTED.get_or_init(|| {
            let registrations = registered_backends();
            let mut keyed = Vec::new();
            if let Err(error) = reserve_vec_to_capacity(
                &mut keyed,
                registrations.len(),
                "Vyre backend registry",
                "precedence key slot",
                "reduce linked backend inventory or split registry initialization",
            ) {
                return cache_reservation_failed("sorted backend precedence cache", error);
            }
            for registration in registrations.iter().copied() {
                let precedence = match backend_precedence_result(registration.id) {
                    Ok(precedence) => precedence,
                    Err(error) => {
                        return cache_reservation_failed("sorted backend precedence cache", error);
                    }
                };
                keyed.push((precedence, registration.id, registration));
            }
            keyed.sort_unstable_by(|left, right| {
                left.0.cmp(&right.0).then_with(|| left.1.cmp(right.1))
            });
            let mut sorted = Vec::new();
            if let Err(error) = reserve_vec_to_capacity(
                &mut sorted,
                keyed.len(),
                "Vyre backend registry",
                "sorted backend slot",
                "reduce linked backend inventory or split registry initialization",
            ) {
                return cache_reservation_failed("sorted backend precedence cache", error);
            }
            sorted.extend(keyed.into_iter().map(|(_, _, registration)| registration));
            CacheState::Ready(sorted.into_boxed_slice())
        }),
    )?;
    Ok(sorted)
}

/// Return every registered backend sorted by precedence (low rank first).
#[must_use]
pub fn registered_backends_by_precedence_slice() -> &'static [&'static BackendRegistration] {
    registered_backends_by_precedence_slice_result().unwrap_or(&[])
}

/// Return every registered backend sorted by precedence (low rank first).
/// Prefer [`registered_backends_by_precedence_slice`] on hot paths.
#[must_use]
pub fn registered_backends_by_precedence() -> Vec<&'static BackendRegistration> {
    registered_backends_by_precedence_slice().to_vec()
}

fn registration_for_id(id: &str) -> Result<Option<&'static BackendRegistration>, BackendError> {
    static BY_ID: OnceLock<CacheState<FxHashMap<&'static str, &'static BackendRegistration>>> =
        OnceLock::new();
    let table = cache_or_error(
        "backend-id cache",
        BY_ID.get_or_init(|| {
            let registrations = registered_backends();
            let mut map: FxHashMap<&'static str, &'static BackendRegistration> =
                FxHashMap::default();
            if let Err(error) = reserve_hash_map_to_capacity(
                &mut map,
                registrations.len(),
                "Vyre backend registry",
                "backend-id slot",
                "reduce linked backend inventory or split registry initialization",
            ) {
                return cache_reservation_failed("backend-id cache", error);
            }
            for registration in registrations {
                map.entry(registration.id).or_insert(registration);
            }
            CacheState::Ready(map)
        }),
    )?;
    Ok(table.get(id).copied())
}

/// Construct the registered backend with the requested stable identifier.
///
/// # Errors
///
/// Returns [`BackendError`] when no linked backend registered `id`, or when
/// the selected backend factory cannot initialize on this host.
pub fn acquire(id: &str) -> Result<Box<dyn VyreBackend>, BackendError> {
    let Some(registration) = registration_for_id(id)? else {
        return Err(BackendError::new(format!(
            "backend `{id}` is not linked into this binary. Fix: link the concrete driver crate that registers this backend or choose one of the registered backend ids."
        )));
    };
    registration.acquire()
}

/// Construct the highest-precedence linked backend that declares live dispatch.
/// The preferred runtime path is GPU-only: CPU reference backends remain
/// available through [`acquire`] for explicit conformance/oracle use, but are
/// never selected implicitly.
///
/// # Errors
///
/// Returns [`BackendError`] when no dispatch-capable backend is linked or every
/// matching backend factory fails on this host.
pub fn acquire_preferred_dispatch_backend() -> Result<Box<dyn VyreBackend>, BackendError> {
    let registrations = registered_backends_by_precedence_slice_result()?;
    let mut failures = Vec::new();
    reserve_vec_to_capacity(
        &mut failures,
        registrations.len(),
        "preferred backend acquisition",
        "failure detail slot",
        "reduce linked backend inventory or request a backend by id",
    )?;
    let mut skipped_reference_oracles = Vec::new();
    reserve_vec_to_capacity(
        &mut skipped_reference_oracles,
        registrations.len(),
        "preferred backend acquisition",
        "reference-skip slot",
        "reduce linked backend inventory or request a backend by id",
    )?;
    for registration in registrations {
        if !backend_dispatches_result(registration.id)? {
            continue;
        }
        if is_reference_oracle_backend(registration.id) {
            skipped_reference_oracles.push(registration.id);
            continue;
        }
        match registration.acquire() {
            Ok(backend) => return Ok(backend),
            Err(error) => {
                tracing::trace!(
                    "acquire_preferred_dispatch_backend: failed to initialize backend `{}`: {}",
                    registration.id,
                    error
                );
                failures.push(format!("{}: {error}", registration.id))
            }
        }
    }
    let detail = if !failures.is_empty() {
        failures.join("; ")
    } else if !skipped_reference_oracles.is_empty() {
        format!(
            "only reference oracle backend(s) were available: {}",
            skipped_reference_oracles.join(", ")
        )
    } else {
        "no dispatch-capable backend is linked into this binary".to_string()
    };
    Err(BackendError::new(format!(
        "no usable GPU dispatch backend is available ({detail}). Fix: link a dispatch-capable GPU backend driver crate and repair the GPU driver probe; the CPU reference backend is explicit conformance-oracle infrastructure only."
    )))
}

fn is_reference_oracle_backend(id: &str) -> bool {
    matches!(id, "cpu-ref" | "reference")
}

/// Core operation support set used by backends during migration.
#[must_use]
pub fn core_supported_ops() -> &'static HashSet<OpId> {
    default_supported_ops()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_backend_registry_queries_return_absent_without_panicking() {
        let missing_id = "__vyre_missing_backend__";

        match backend_dispatches_result(missing_id) {
            Ok(dispatches) => assert!(!dispatches),
            Err(error) => panic!("registry dispatch query failed: {error}"),
        }

        match backend_precedence_result(missing_id) {
            Ok(precedence) => assert_eq!(precedence, u32::MAX),
            Err(error) => panic!("registry precedence query failed: {error}"),
        }

        match registration_for_id(missing_id) {
            Ok(registration) => assert!(registration.is_none()),
            Err(error) => panic!("registry id query failed: {error}"),
        }
    }
}
