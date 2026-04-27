//! Fixpoint optimizer pass framework for vyre IR.
//!
//! Passes are registered with [`vyre_macros::vyre_pass`] and discovered through
//! a process-wide registry. The scheduler applies registered passes until the
//! program reaches a fixed point or a safety cap rejects non-convergence.

use crate::ir_inner::model::program::Program;
use rustc_hash::FxHashSet;

pub mod ctx;
pub mod fusion_cert;

pub mod passes;
mod rewrite;
mod scheduler;
#[cfg(test)]
mod tests;

pub use ctx::{scheduling_error_to_diagnostic, AdapterCaps, AnalysisCache, PassCtx};
pub use fusion_cert::FusionCertificate;
use passes::{
    autotune::Autotune, const_fold::ConstFold, dead_buffer_elim::DeadBufferElim, fusion::Fusion,
    normalize_atomics::NormalizeAtomicsPass, spec_driven::SpecDriven,
    strength_reduce::StrengthReduce,
};
pub use scheduler::{schedule_passes, PassScheduler, PassSchedulingError};
pub use vyre_macros::vyre_pass;

/// Static metadata declared by an optimizer pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PassMetadata {
    /// Stable pass name.
    pub name: &'static str,
    /// Capabilities or prior passes required before this pass can run.
    pub requires: &'static [&'static str],
    /// Capabilities invalidated when this pass rewrites the program.
    pub invalidates: &'static [&'static str],
}

/// Lightweight pass analysis result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PassAnalysis {
    /// Whether the scheduler should invoke `transform`.
    pub should_run: bool,
}

impl PassAnalysis {
    /// Analysis result that asks the scheduler to run the pass.
    pub const RUN: Self = Self { should_run: true };

    /// Analysis result that asks the scheduler to skip the pass.
    pub const SKIP: Self = Self { should_run: false };
}

/// Result of one pass transformation.
#[derive(Debug, Clone, PartialEq)]
pub struct PassResult {
    /// Rewritten program.
    pub program: Program,
    /// Whether the program changed.
    pub changed: bool,
}

impl PassResult {
    /// Build a transformation result by comparing before and after programs.
    #[must_use]
    #[inline]
    pub fn from_programs(before: &Program, program: Program) -> Self {
        let changed = before != &program;
        Self { program, changed }
    }

    /// Declare the pass left the program unchanged. VYRE_IR_HOTSPOTS
    /// CRIT-2/CRIT-3: `from_programs(&program, program.clone())` pays
    /// a full `Program` clone + O(N) PartialEq comparison on every
    /// no-op call. When a pass has already proven it will not rewrite
    /// the program, it should `return PassResult::unchanged(program)`
    /// to move the input through without cloning or comparing.
    #[must_use]
    #[inline]
    pub fn unchanged(program: Program) -> Self {
        Self {
            program,
            changed: false,
        }
    }
}

/// Constructor and metadata submitted by each registered pass.
#[derive(Debug)]
pub struct PassRegistration {
    /// Pass metadata available without constructing the pass.
    pub metadata: PassMetadata,
    /// Construct a fresh pass instance.
    pub factory: fn() -> Box<dyn Pass>,
}

inventory::collect!(PassRegistration);

pub(crate) mod private {
    pub trait Sealed {}
}

/// One IR-to-IR optimizer pass.
pub trait Pass: private::Sealed + Send + Sync {
    /// Static metadata for scheduling and diagnostics.
    fn metadata(&self) -> PassMetadata;

    /// Unique pass identifier for diagnostics.
    ///
    /// Defaults to `metadata().name`, but external passes may override this
    /// to provide richer instance-level identity (e.g. a plugin crate name +
    /// pass name) that makes scheduler errors actionable in seconds.
    fn pass_id(&self) -> &'static str {
        self.metadata().name
    }

    /// Pre-transform analysis hook.
    fn analyze(&self, program: &Program) -> PassAnalysis;

    /// Transform a program.
    fn transform(&self, program: Program) -> PassResult;

    /// Fingerprint the pass-visible program state.
    fn fingerprint(&self, program: &Program) -> u64;
}

/// Devirtualized optimizer pass container.
#[non_exhaustive]
pub enum PassKind {
    /// Built-in workgroup autotuning.
    Autotune(Autotune),
    /// Built-in constant folding.
    ConstFold(ConstFold),
    /// Built-in dead-buffer elimination.
    DeadBufferElim(DeadBufferElim),
    /// Built-in scalar fusion.
    Fusion(Fusion),
    /// Built-in atomic normalization.
    NormalizeAtomics(NormalizeAtomicsPass),
    /// Built-in spec-driven rewrite pass.
    SpecDriven(SpecDriven),
    /// Built-in strength reduction.
    StrengthReduce(StrengthReduce),
    /// External inventory-registered pass fallback.
    External(Box<dyn Pass>),
}

impl PassKind {
    /// Static metadata for scheduling.
    #[must_use]
    #[inline(always)]
    pub fn metadata(&self) -> PassMetadata {
        match self {
            Self::Autotune(pass) => pass.metadata(),
            Self::ConstFold(pass) => pass.metadata(),
            Self::DeadBufferElim(pass) => pass.metadata(),
            Self::Fusion(pass) => pass.metadata(),
            Self::NormalizeAtomics(pass) => pass.metadata(),
            Self::SpecDriven(pass) => pass.metadata(),
            Self::StrengthReduce(pass) => pass.metadata(),
            Self::External(pass) => pass.metadata(),
        }
    }

    /// Instance-level pass identifier for diagnostics.
    #[must_use]
    #[inline(always)]
    pub fn pass_id(&self) -> &'static str {
        match self {
            Self::Autotune(pass) => pass.pass_id(),
            Self::ConstFold(pass) => pass.pass_id(),
            Self::DeadBufferElim(pass) => pass.pass_id(),
            Self::Fusion(pass) => pass.pass_id(),
            Self::NormalizeAtomics(pass) => pass.pass_id(),
            Self::SpecDriven(pass) => pass.pass_id(),
            Self::StrengthReduce(pass) => pass.pass_id(),
            Self::External(pass) => pass.pass_id(),
        }
    }

    /// Pre-transform analysis.
    #[must_use]
    #[inline(always)]
    pub fn analyze(&self, program: &Program) -> PassAnalysis {
        match self {
            Self::Autotune(pass) => pass.analyze(program),
            Self::ConstFold(pass) => pass.analyze(program),
            Self::DeadBufferElim(pass) => pass.analyze(program),
            Self::Fusion(pass) => pass.analyze(program),
            Self::NormalizeAtomics(pass) => pass.analyze(program),
            Self::SpecDriven(pass) => pass.analyze(program),
            Self::StrengthReduce(pass) => pass.analyze(program),
            Self::External(pass) => pass.analyze(program),
        }
    }

    /// Transform a program.
    #[must_use]
    #[inline(always)]
    pub fn transform(&self, program: Program) -> PassResult {
        match self {
            Self::Autotune(pass) => pass.transform(program),
            Self::ConstFold(pass) => pass.transform(program),
            Self::DeadBufferElim(pass) => pass.transform(program),
            Self::Fusion(pass) => pass.transform(program),
            Self::NormalizeAtomics(pass) => pass.transform(program),
            Self::SpecDriven(pass) => pass.transform(program),
            Self::StrengthReduce(pass) => pass.transform(program),
            Self::External(pass) => pass.transform(program),
        }
    }
}

/// Error returned by the pass scheduler.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum OptimizerError {
    /// The scheduler hit its safety cap before reaching a fixed point.
    #[error(
        "optimizer did not reach a fixpoint after {max_iterations} iterations. Fix: inspect pass `{last_pass}` for oscillating rewrites or raise the cap only with a convergence proof."
    )]
    MaxIterations {
        /// Iteration cap that was reached.
        max_iterations: usize,
        /// Last pass that changed the program.
        last_pass: &'static str,
    },
    /// At least one pass could not run because its requirements were missing.
    #[error(
        "optimizer pass `{pass}` requires `{missing}` but no prior pass provides it. Fix: register the required analysis pass or remove the stale requirement."
    )]
    UnsatisfiedRequirement {
        /// Pass that could not run.
        pass: &'static str,
        /// First missing requirement.
        missing: &'static str,
    },
    /// Registered passes contain an invalid dependency graph.
    #[error("{0}")]
    Scheduling(#[from] PassSchedulingError),
}

/// Return pass instances from the global registry.
#[must_use]
pub fn registered_passes() -> Result<Vec<PassKind>, OptimizerError> {
    let mut passes = vec![
        PassKind::Autotune(Autotune),
        PassKind::ConstFold(ConstFold),
        PassKind::DeadBufferElim(DeadBufferElim),
        PassKind::Fusion(Fusion),
        PassKind::NormalizeAtomics(NormalizeAtomicsPass),
        PassKind::SpecDriven(SpecDriven),
        PassKind::StrengthReduce(StrengthReduce),
    ];
    passes.extend(
        registered_pass_registrations()?
            .into_iter()
            .filter(|registration| !is_builtin_pass(registration.metadata.name))
            .map(|registration| PassKind::External((registration.factory)())),
    );
    Ok(passes)
}

fn is_builtin_pass(name: &str) -> bool {
    matches!(
        name,
        "autotune"
            | "const_fold"
            | "dead_buffer_elim"
            | "fusion"
            | "normalize_atomics"
            | "spec_driven"
            | "strength_reduce"
    )
}

/// Return registered pass metadata in scheduled execution order.
///
/// # Errors
///
/// Returns [`OptimizerError::Scheduling`] when a linked pass declares an
/// unknown requirement or a cyclic requirement graph.
#[must_use]
pub fn registered_pass_registrations() -> Result<Vec<&'static PassRegistration>, OptimizerError> {
    let registrations = inventory::iter::<PassRegistration>
        .into_iter()
        .collect::<Vec<_>>();
    Ok(schedule_passes(&registrations)?)
}

/// Run the globally registered optimizer passes to a fixed point.
///
/// # Errors
///
/// Returns [`OptimizerError`] when requirements cannot be satisfied or when
/// the pass pipeline oscillates past the configured iteration cap.
pub fn optimize(program: Program) -> Result<Program, OptimizerError> {
    PassScheduler::default().run(program)
}

/// Stable, content-addressed fingerprint of a program.
///
/// Uses blake3 over the canonical wire-format bytes, not the `Debug`
/// representation, so the fingerprint is:
///   - **deterministic across compiler versions** (plain `Debug` output
///     is not a language-stable contract),
///   - **~10× faster** than the prior `format!("{program:?}")` + SipHasher
///     combination on programs with dense IR,
///   - **allocation-light** — no intermediate `String`.
///
/// Collisions are practically impossible for the program sizes vyre ever
/// sees; the returned `u64` is the first 8 bytes of the 256-bit digest.
/// Callers that need the full digest should call `blake3::hash` directly
/// on `program.to_wire()?`.
#[must_use]
pub fn fingerprint_program(program: &Program) -> u64 {
    // Pre-AUDIT_2026-04-24 F-OPT-04: this was `unwrap_or_default()`
    // which caused every unserializable program to collide to the
    // same zero-bytes fingerprint. Hashing a dedicated error-digest
    // domain-separator instead preserves distinguishability while
    // keeping the signature infallible for callers.
    const FINGERPRINT_ERROR_SENTINEL: &[u8] =
        b"vyre-foundation::fingerprint_program::to_wire_failed";
    let wire = program.to_wire();
    let digest = match &wire {
        Ok(bytes) => blake3::hash(bytes),
        Err(err) => {
            // Domain-separated error digest includes the concrete
            // error string, so two distinct unserializable programs
            // produce distinct fingerprints instead of colliding.
            let mut hasher = blake3::Hasher::new();
            hasher.update(FINGERPRINT_ERROR_SENTINEL);
            hasher.update(err.to_string().as_bytes());
            hasher.finalize()
        }
    };
    let first8 = digest.as_bytes();
    u64::from_le_bytes([
        first8[0], first8[1], first8[2], first8[3], first8[4], first8[5], first8[6], first8[7],
    ])
}

#[inline]
fn requirements_satisfied(metadata: PassMetadata, available: &FxHashSet<&'static str>) -> bool {
    metadata
        .requires
        .iter()
        .all(|requirement| available.contains(requirement))
}
