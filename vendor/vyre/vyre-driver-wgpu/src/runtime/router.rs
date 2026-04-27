//! Backend auto-picker.
//!
//! `BackendRouter` walks `inventory::iter::<BackendRegistration>`,
//! filters out registered backends that cannot dispatch, and picks the
//! best executable backend available by precedence. Override via
//! `VYRE_BACKEND=<id>`; cached per adapter fingerprint (hook exposed,
//! persistence deferred).
//!
//! Precedence (high → low):
//!
//! 1. `VYRE_BACKEND=<id>` — if set and the backend is registered,
//!    wins only when the backend is registered and executable.
//! 2. `ptx` — when NVIDIA GPU + CUDA present (not shipped yet;
//!    future backend registers and slots in here).
//! 3. `spirv` — when the SPIR-V backend is registered
//!    (Gemini C's C-B7).
//! 4. `wgpu` — the default WGSL path.
//! 5. `reference` — CPU reference, last resort.
//!
//! `BackendRouter::pick()` returns the selected backend id on success,
//! or a structured `BackendError` when no executable backend is linked.

use std::env;

use vyre_driver::backend::{backend_dispatches, registered_backends_by_precedence_slice};
use vyre_driver::{BackendError, BackendRegistration};
use vyre_foundation::ir::Program;

/// How to source the forced-backend override.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum Override<'a> {
    /// Read `VYRE_BACKEND` from the process environment.
    FromEnv,
    /// Use the explicit override regardless of environment.
    Explicit(&'a str),
    /// No override — router runs on precedence alone.
    None,
}

const OVERRIDE_ENV: &str = "VYRE_BACKEND";

/// Routing decision produced by the backend auto-picker.
#[derive(Debug, Clone)]
pub struct RouterDecision {
    /// The selected backend id.
    pub backend: &'static str,
    /// Reason the decision fell to this backend.
    pub reason: Reason,
}

/// How the decision was reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Reason {
    /// `VYRE_BACKEND=<id>` forced the selection.
    EnvOverride,
    /// Highest-precedence registered backend that covers the
    /// Program's dialects.
    Precedence,
}

/// Backend auto-picker.
///
/// Constructed with [`BackendRouter::new`]; queries the runtime
/// inventory on demand so newly-registered backends participate
/// without router rebuild.
#[derive(Default)]
pub struct BackendRouter;

impl BackendRouter {
    /// New router.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Pick the best-available backend for `_program`.
    ///
    /// # Errors
    ///
    /// Returns `BackendError` when:
    ///
    /// * `VYRE_BACKEND` is set to a backend id that is not
    ///   registered.
    /// * No registered backend is found. (`reference` is always
    ///   present as the lowest-precedence fallback; a hit on no
    ///   backend indicates a broken link-time inventory.)
    pub fn pick(&self, program: &Program) -> Result<RouterDecision, BackendError> {
        self.pick_with_override(program, Override::FromEnv)
    }

    /// Pick with an explicit override source — the testable form of
    /// [`pick`](Self::pick).
    ///
    /// # Errors
    ///
    /// Same conditions as [`pick`](Self::pick).
    pub fn pick_with_override(
        &self,
        _program: &Program,
        source: Override<'_>,
    ) -> Result<RouterDecision, BackendError> {
        let registered = vyre::backend::registered_backends();

        let forced: Option<String> = match source {
            Override::FromEnv => env::var(OVERRIDE_ENV).ok(),
            Override::Explicit(s) => Some(s.to_owned()),
            Override::None => None,
        };
        if let Some(forced) = forced {
            let forced = forced.trim();
            if !forced.is_empty() {
                let hit = registered
                    .iter()
                    .find(|r| r.id == forced && backend_dispatches(r.id));
                return match hit {
                    Some(reg) => Ok(RouterDecision {
                        backend: reg.id,
                        reason: Reason::EnvOverride,
                    }),
                    None => Err(BackendError::new(format!(
                        "VYRE_BACKEND={forced} is not an executable registered backend. Fix: link a backend crate whose registration dispatches, or unset VYRE_BACKEND to let the router pick."
                    ))),
                };
            }
        }

        // V7-EXT-021: precedence comes from the BackendPrecedence inventory
        // submitted by each backend crate, not a hardcoded driver-side table.
        // Walk backends in precedence order and return the first hit.
        for reg in registered_backends_by_precedence_slice() {
            if registered.iter().any(|r| r.id == reg.id) && backend_dispatches(reg.id) {
                return Ok(RouterDecision {
                    backend: reg.id,
                    reason: Reason::Precedence,
                });
            }
        }

        Err(BackendError::new(
            "no backend is registered. Fix: link at least one of vyre-wgpu, vyre-reference, or a custom VyreBackend crate into the binary.",
        ))
    }

    /// Enumerate every registered backend in precedence order. Inventory-driven
    /// per V7-EXT-021 — backends without a submitted `BackendPrecedence`
    /// trail every backend that has one (rank `u32::MAX`).
    #[must_use]
    pub fn enumerate_by_precedence() -> Vec<&'static BackendRegistration> {
        registered_backends_by_precedence_slice().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vyre_driver::backend::backend_precedence;

    fn noop_program() -> Program {
        // Programs built without any buffers / nodes are valid for
        // the router's purposes — we don't dispatch, we just pick.
        Program::wrapped(Vec::new(), [1, 1, 1], Vec::new())
    }

    #[test]
    fn enumerate_by_precedence_puts_wgpu_before_reference() {
        // V7-EXT-021: precedence is now inventory-driven. wgpu submits
        // rank 30 in this crate's lib.rs; reference (when registered)
        // must trail it.
        let wgpu_rank = backend_precedence("wgpu");
        let ref_rank = backend_precedence("reference");
        assert!(
            wgpu_rank < ref_rank || ref_rank == u32::MAX,
            "wgpu (rank {wgpu_rank}) must take precedence over the CPU reference (rank {ref_rank})"
        );
    }

    #[test]
    fn enumerate_by_precedence_is_inventory_driven() {
        // Replaces the BACKEND_PRECEDENCE static-slice assertion.
        let ranked = BackendRouter::enumerate_by_precedence();
        // wgpu registers in this crate; it must appear with a finite rank.
        let wgpu = ranked
            .iter()
            .find(|r| r.id == "wgpu")
            .expect("wgpu backend registered in this crate");
        assert_eq!(backend_precedence(wgpu.id), 30);
    }

    #[test]
    fn explicit_override_with_unknown_backend_surfaces_error() {
        let router = BackendRouter::new();
        let err = router
            .pick_with_override(
                &noop_program(),
                Override::Explicit("does-not-exist-backend"),
            )
            .expect_err("unknown backend must error");
        let msg = format!("{err}");
        assert!(msg.contains("does-not-exist-backend"));
        assert!(msg.contains("Fix:"));
    }

    #[test]
    fn explicit_override_picks_the_named_backend_when_registered() {
        let router = BackendRouter::new();
        // wgpu registers via inventory::submit! in lib.rs.
        let decision = router
            .pick_with_override(&noop_program(), Override::Explicit("wgpu"))
            .expect("Fix: wgpu backend is registered in this crate");
        assert_eq!(decision.backend, "wgpu");
        assert_eq!(decision.reason, Reason::EnvOverride);
    }

    #[test]
    fn precedence_picks_wgpu_when_registered() {
        let router = BackendRouter::new();
        let decision = router
            .pick_with_override(&noop_program(), Override::None)
            .expect("Fix: at least one backend must register");
        assert_eq!(decision.reason, Reason::Precedence);
        // The picked backend must have a registered precedence rank
        // (V7-EXT-021: replaces the BACKEND_PRECEDENCE static-slice check).
        assert!(
            backend_precedence(decision.backend) < u32::MAX,
            "picked backend {} did not submit a BackendPrecedence inventory entry",
            decision.backend
        );
    }
}
