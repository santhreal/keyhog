//! Backend selection and acquisition policy.

use rustc_hash::FxHashMap;
use std::collections::HashSet;
use std::sync::OnceLock;
use vyre_foundation::ir::OpId;

use super::inventory_streams::{
    registered_backends, BackendCapability, BackendPrecedence, BackendRegistration,
};
use crate::backend::{default_supported_ops, BackendError, VyreBackend};

/// Return `true` when the named backend submitted `dispatches: true`.
#[must_use]
pub fn backend_dispatches(id: &str) -> bool {
    static CACHE: OnceLock<FxHashMap<&'static str, bool>> = OnceLock::new();
    let table = CACHE.get_or_init(|| {
        inventory::iter::<BackendCapability>
            .into_iter()
            .map(|entry| (entry.id, entry.dispatches))
            .collect()
    });
    table.get(id).copied().unwrap_or(false)
}

/// Look up a backend's submitted precedence. Returns `u32::MAX` for
/// backends that did not submit a `BackendPrecedence` entry.
#[must_use]
pub fn backend_precedence(id: &str) -> u32 {
    static CACHE: OnceLock<FxHashMap<&'static str, u32>> = OnceLock::new();
    let table = CACHE.get_or_init(|| {
        inventory::iter::<BackendPrecedence>
            .into_iter()
            .map(|entry| (entry.id, entry.rank))
            .collect()
    });
    table.get(id).copied().unwrap_or(u32::MAX)
}

/// Return every registered backend sorted by precedence (low rank first).
#[must_use]
pub fn registered_backends_by_precedence_slice() -> &'static [&'static BackendRegistration] {
    static SORTED: OnceLock<Box<[&'static BackendRegistration]>> = OnceLock::new();
    SORTED.get_or_init(|| {
        let registrations = registered_backends();
        let mut keyed = Vec::with_capacity(registrations.len());
        keyed.extend(registrations.iter().copied().map(|registration| {
            (
                backend_precedence(registration.id),
                registration.id,
                registration,
            )
        }));
        keyed
            .sort_unstable_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(right.1)));
        let mut sorted = Vec::with_capacity(keyed.len());
        sorted.extend(keyed.into_iter().map(|(_, _, registration)| registration));
        sorted.into_boxed_slice()
    })
}

/// Return every registered backend sorted by precedence (low rank first).
/// Prefer [`registered_backends_by_precedence_slice`] on hot paths.
#[must_use]
pub fn registered_backends_by_precedence() -> Vec<&'static BackendRegistration> {
    registered_backends_by_precedence_slice().to_vec()
}

fn registration_for_id(id: &str) -> Option<&'static BackendRegistration> {
    static BY_ID: OnceLock<FxHashMap<&'static str, &'static BackendRegistration>> = OnceLock::new();
    let table = BY_ID.get_or_init(|| {
        let mut map: FxHashMap<&'static str, &'static BackendRegistration> =
            FxHashMap::with_capacity_and_hasher(registered_backends().len(), Default::default());
        for registration in registered_backends() {
            map.entry(registration.id).or_insert(registration);
        }
        map
    });
    table.get(id).copied()
}

/// Construct the registered backend with the requested stable identifier.
///
/// # Errors
///
/// Returns [`BackendError`] when no linked backend registered `id`, or when
/// the selected backend factory cannot initialize on this host.
pub fn acquire(id: &str) -> Result<Box<dyn VyreBackend>, BackendError> {
    let Some(registration) = registration_for_id(id) else {
        return Err(BackendError::new(format!(
            "backend `{id}` is not linked into this binary. Fix: link the concrete driver crate that registers this backend or choose one of the registered backend ids."
        )));
    };
    registration.acquire()
}

/// Construct the highest-precedence linked backend that declares live dispatch.
/// The preferred runtime path is GPU-only: CPU reference backends remain
/// available through [`acquire`] for explicit conformance/oracle use, but are
/// never selected as an implicit fallback.
///
/// # Errors
///
/// Returns [`BackendError`] when no dispatch-capable backend is linked or every
/// matching backend factory fails on this host.
pub fn acquire_preferred_dispatch_backend() -> Result<Box<dyn VyreBackend>, BackendError> {
    let registrations = registered_backends_by_precedence_slice();
    let mut failures = Vec::with_capacity(registrations.len());
    let mut skipped_reference_oracles = Vec::new();
    for registration in registrations {
        if !backend_dispatches(registration.id) {
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
        "no usable GPU dispatch backend is available ({detail}). Fix: link vyre-driver-cuda or vyre-driver-wgpu and repair the GPU driver probe; the CPU reference backend is an explicit conformance oracle, not a runtime fallback."
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
