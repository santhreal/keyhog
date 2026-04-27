use crate::ir::DataType;

/// Backend-specific validation hooks for capability-sensitive rules.
///
/// Foundation validation is backend-agnostic by default. Callers that know the
/// concrete lowering target can provide a capability implementation here so the
/// validator rejects IR shapes that would only fail later in a backend.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BackendCapabilities {
    /// The backend can lower `Expr::SubgroupAdd`, `Expr::SubgroupBallot`, and
    /// `Expr::SubgroupShuffle`.
    pub supports_subgroup_ops: bool,
    /// The backend can lower indirect dispatch paths.
    pub supports_indirect_dispatch: bool,
    /// The backend can compile specialization constants.
    pub supports_specialization_constants: bool,
}

/// Capability view supplied by a concrete backend during validation.
pub trait BackendValidationCapabilities {
    /// Stable backend name used in diagnostics.
    fn backend_name(&self) -> &'static str;

    /// Return true when the backend can lower a cast whose destination is
    /// `target`.
    fn supports_cast_target(&self, target: &DataType) -> bool;

    /// Return true when the backend supports subgroup operations.
    #[inline]
    fn supports_subgroup_ops(&self) -> bool {
        false
    }

    /// Return true when the backend supports indirect dispatch.
    #[inline]
    fn supports_indirect_dispatch(&self) -> bool {
        false
    }

    /// Return true when the backend supports specialization constants.
    #[inline]
    fn supports_specialization_constants(&self) -> bool {
        false
    }

    /// Export backend capabilities in a version-stable value object.
    #[must_use]
    #[inline]
    fn backend_capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            supports_subgroup_ops: self.supports_subgroup_ops(),
            supports_indirect_dispatch: self.supports_indirect_dispatch(),
            supports_specialization_constants: self.supports_specialization_constants(),
        }
    }
}

/// Configuration for one validation pass.
///
/// `ValidationOptions::default()` is a best-effort universal pass: it enforces
/// backend-independent invariants only. Provide `backend` when the caller knows
/// the concrete lowering target and wants capability-sensitive rejection.
#[derive(Clone, Copy, Default)]
pub struct ValidationOptions<'a> {
    /// Concrete backend capability surface to validate against.
    pub backend: Option<&'a dyn BackendValidationCapabilities>,
    /// Snapshot of backend capabilities for direct feature checks.
    pub backend_capabilities: Option<BackendCapabilities>,
    /// Allow nested-scope shadowing explicitly for this validation run.
    pub allow_shadowing: bool,
}

impl<'a> ValidationOptions<'a> {
    /// Build the default best-effort universal validator configuration.
    #[must_use]
    #[inline]
    pub fn universal() -> Self {
        Self::default()
    }

    /// Validate against the provided backend capability contract.
    #[must_use]
    #[inline]
    pub fn with_backend(mut self, backend: &'a dyn BackendValidationCapabilities) -> Self {
        self.backend = Some(backend);
        self.backend_capabilities = Some(backend.backend_capabilities());
        self
    }

    /// Validate against the provided backend capability snapshot.
    #[must_use]
    #[inline]
    pub fn with_backend_capabilities(mut self, backend_capabilities: BackendCapabilities) -> Self {
        self.backend_capabilities = Some(backend_capabilities);
        self
    }

    /// Explicitly allow nested-scope shadowing for this validation pass.
    #[must_use]
    #[inline]
    pub fn with_shadowing(mut self, allow_shadowing: bool) -> Self {
        self.allow_shadowing = allow_shadowing;
        self
    }

    /// Return the backend name carried by this configuration.
    #[must_use]
    #[inline]
    pub fn backend_name(&self) -> &'static str {
        self.backend
            .map(BackendValidationCapabilities::backend_name)
            .unwrap_or("best-effort universal")
    }

    /// Return true when this validation run accepts casts to `target`.
    #[must_use]
    #[inline]
    pub fn supports_cast_target(&self, target: &DataType) -> bool {
        self.backend
            .map(|backend| backend.supports_cast_target(target))
            .unwrap_or(true)
    }

    /// Return true when this validation run requires subgroup support.
    #[must_use]
    #[inline]
    pub fn requires_subgroup_ops(&self) -> bool {
        self.backend_capabilities
            .is_some_and(|caps| caps.supports_subgroup_ops)
    }
}
