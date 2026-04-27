//! Link-time backend registry.
//!
//! Backend crates submit a [`BackendRegistration`] with `inventory::submit!`.
//! Applications discover every linked backend through [`registered_backends`]
//! without hardcoding crate-specific constructors. Because the registry lives
//! in `vyre-core` and is populated by downstream crates at link time, this
//! crate's own test sees an empty registry — the forcing function for
//! substrate neutrality. Downstream crates assert their own presence.

use super::{default_supported_ops, BackendError, VyreBackend};
use std::collections::HashSet;
use std::sync::OnceLock;
use vyre_foundation::ir::OpId;

/// One backend constructor contributed by a linked backend crate.
///
/// Backend construction can fail (missing GPU adapter, unsupported driver),
/// so the factory returns a [`super::BackendError`] rather than panicking — callers
/// iterate [`registered_backends`] and skip backends whose factory fails on
/// this host.
pub struct BackendRegistration {
    /// Stable backend identifier, matching [`VyreBackend::id`].
    pub id: &'static str,
    /// Factory that constructs the backend implementation.
    ///
    /// Returns `Err(BackendError)` when the backend cannot initialize on
    /// this host (e.g. no GPU adapter, missing driver features). The error
    /// message must include a `Fix:` remediation section per the frozen
    /// `BackendError` contract.
    pub factory: fn() -> Result<Box<dyn VyreBackend>, BackendError>,
    /// Operation ids supported by this backend.
    pub supported_ops: fn() -> &'static HashSet<OpId>,
}

inventory::collect!(BackendRegistration);

/// V7-EXT-021: per-backend precedence rank registered alongside its
/// `BackendRegistration`. Lower rank wins in router selection.
///
/// Replaces the hardcoded `BACKEND_PRECEDENCE` static slice in
/// `vyre-driver-wgpu/src/runtime/router.rs`. New backend crates declare
/// their own rank via `inventory::submit!(BackendPrecedence { ... })`
/// — no router edits required to slot in. A backend that does not
/// submit a `BackendPrecedence` entry is treated as `u32::MAX`
/// (last-resort).
///
/// Conventional ranks (informal — backends are free to choose):
///
/// - `10` reserved for native PTX/CUDA when that backend lands.
/// - `20` SPIR-V (vendor-driver-agnostic next-best choice).
/// - `30` WGSL via wgpu (default substrate-neutral path).
/// - `50` photonic (live-hardware-only).
/// - `90` reference (CPU fallback, lowest precedence).
pub struct BackendPrecedence {
    /// Backend identifier — must match the corresponding `BackendRegistration::id`.
    pub id: &'static str,
    /// Sort key. Lower = higher priority.
    pub rank: u32,
}

inventory::collect!(BackendPrecedence);

/// Backend capability declaration — whether a backend owns a live
/// dispatch stack on this host.
///
/// Some backends (SPIR-V emission-only, photonic live-hardware target) register
/// themselves so consumers can target their wire format, but their
/// `dispatch` method returns an error because they don't own a device.
/// Tools that compare backend output against `vyre-reference`
/// (`vyre-conform prove`, corpus replay, shadow execution) must skip
/// those backends or they report false divergences on every op.
///
/// A backend that submits a `BackendCapability { dispatches: true, ... }`
/// alongside its `BackendRegistration` promises its `dispatch` method
/// can return real outputs on this host. A backend that does not submit
/// a capability entry is treated as non-dispatching.
///
/// This is a separate inventory stream from `BackendRegistration` so
/// that adding the capability signal doesn't break the registration
/// contract — existing backends compile unchanged.
pub struct BackendCapability {
    /// Backend identifier — must match the corresponding
    /// `BackendRegistration::id`.
    pub id: &'static str,
    /// `true` when this backend's `dispatch` can execute a Program and
    /// return real outputs; `false` (or absent) when dispatch always
    /// fails because the backend is emission-only.
    pub dispatches: bool,
}

inventory::collect!(BackendCapability);

/// Return `true` when the named backend has submitted a capability
/// declaration with `dispatches: true`. Emission-only backends and
/// backends that did not submit any capability return `false`.
#[must_use]
pub fn backend_dispatches(id: &str) -> bool {
    use std::sync::OnceLock;
    static CACHE: OnceLock<std::collections::HashMap<&'static str, bool>> = OnceLock::new();
    let table = CACHE.get_or_init(|| {
        inventory::iter::<BackendCapability>
            .into_iter()
            .map(|entry| (entry.id, entry.dispatches))
            .collect()
    });
    table.get(id).copied().unwrap_or(false)
}

/// Look up a backend's submitted precedence. Returns `u32::MAX` for
/// backends that did not submit a `BackendPrecedence` entry, so they
/// trail every backend that did.
#[must_use]
pub fn backend_precedence(id: &str) -> u32 {
    use std::sync::OnceLock;
    static CACHE: OnceLock<std::collections::HashMap<&'static str, u32>> = OnceLock::new();
    let table = CACHE.get_or_init(|| {
        inventory::iter::<BackendPrecedence>
            .into_iter()
            .map(|entry| (entry.id, entry.rank))
            .collect()
    });
    table.get(id).copied().unwrap_or(u32::MAX)
}

/// Return every registered backend sorted by precedence (low rank first).
/// Backends without a submitted `BackendPrecedence` trail those that have one.
/// Within the same rank, `id` is the secondary sort key for determinism.
#[must_use]
pub fn registered_backends_by_precedence_slice() -> &'static [&'static BackendRegistration] {
    static SORTED: OnceLock<Box<[&'static BackendRegistration]>> = OnceLock::new();
    SORTED.get_or_init(|| {
        let mut sorted: Vec<&'static BackendRegistration> = registered_backends().to_vec();
        sorted.sort_by(|a, b| {
            backend_precedence(a.id)
                .cmp(&backend_precedence(b.id))
                .then_with(|| a.id.cmp(b.id))
        });
        sorted.into_boxed_slice()
    })
}

/// Return every registered backend sorted by precedence (low rank first).
/// Prefer [`registered_backends_by_precedence_slice`] on hot paths.
#[must_use]
pub fn registered_backends_by_precedence() -> Vec<&'static BackendRegistration> {
    registered_backends_by_precedence_slice().to_vec()
}

/// Return all backend registrations linked into the current binary.
///
/// Iteration order is unspecified. Callers that need a specific backend
/// should look it up by [`BackendRegistration::id`].
///
/// # Runtime cost
///
/// First call walks the link-time inventory and freezes the result into a
/// process-wide `OnceLock<Box<[&'static BackendRegistration]>>`. Every
/// subsequent call is one atomic load and returns the frozen slice with
/// zero allocation. This is the dispatch hot path; the prior `Vec::from_iter`
/// allocated per call.
#[must_use]
pub fn registered_backends() -> &'static [&'static BackendRegistration] {
    static FROZEN: OnceLock<Box<[&'static BackendRegistration]>> = OnceLock::new();
    FROZEN.get_or_init(|| {
        // HOT-PATH-OK: inventory::iter runs once on first access; the result
        // is frozen into a 'static slice. See docs/inventory-contract.md.
        let registrations: Vec<&'static BackendRegistration> =
            inventory::iter::<BackendRegistration>.into_iter().collect();
        registrations.into_boxed_slice()
    })
}

/// Core operation support set used by backends during migration.
#[must_use]
pub fn core_supported_ops() -> &'static HashSet<OpId> {
    default_supported_ops()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::registered_backends;

    /// `vyre-core` has zero backend dependencies, so its in-crate view of the
    /// registry is empty. Downstream backend crates (e.g. `vyre-wgpu`) assert
    /// their own registration in their own test suites.
    #[test]
    fn vyre_core_alone_sees_no_backends() {
        assert!(
            registered_backends().is_empty(),
            "vyre-core has no backend deps; registry must be empty here. \
             Fix: if a backend crate was added as a dependency, move this \
             assertion into that crate's test suite."
        );
    }
}
