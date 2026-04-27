//! Universal Cat-A op harness registry + Region builder.
//!
//! Every Cat-A composition that participates in automated harness
//! checks registers one `OpEntry` through `inventory::submit!`. The
//! conform integration test at `tests/universal_harness.rs` discovers
//! every entry and validates: program validity, wire round-trip, CSE
//! stability, and (when available) CPU-oracle parity.
//!
//! The crate also re-exports the Region builder used by every Cat-A
//! library to wrap its produced `Vec<Node>` so optimizer passes treat
//! the library call as an opaque unit by default. See
//! [`region`](self::region) for `wrap`, `wrap_anonymous`, `wrap_child`,
//! `tag_program`.

pub mod region;

pub use region::{reparent_program_children, tag_program, wrap, wrap_anonymous, wrap_child};

use vyre::ir::Program;

/// Deterministic fixture input cases.
pub type InputsFn = fn() -> Vec<Vec<Vec<u8>>>;
/// Deterministic expected-output fixtures.
pub type ExpectedFn = fn() -> Vec<Vec<Vec<u8>>>;

/// Shared migration-compatible fixture descriptor for registered Cat-A programs.
///
/// At migration time, new entries may still rely on the
/// [`OpEntry::expected_output`] field while legacy entries that only
/// set `expected_output` and omit an oracle are skipped from oracle
/// comparison. Once all entries migrate, `expected_output` is
/// deprecated but kept for back-compat until that migration completes.
//
// The struct is intentionally NOT `#[non_exhaustive]` so the dozens of
// in-tree vyre-libs registrations (graph/, parsing/, security/, …) can
// continue to use struct-literal syntax. External consumers should still
// prefer `OpEntry::new(...)` to keep their code resilient to future
// fields, but every cross-crate field addition will be accompanied by
// either a bump or a defaulted helper.
pub struct OpEntry {
    /// Stable operation identifier.
    pub id: &'static str,

    /// Construct the [`Program`] under test.
    pub build: fn() -> Program,

    /// Deterministic fixture input bytes in declaration order.
    ///
    /// The harness passes this into both `vyre_reference::reference_eval` and the
    /// legacy `expected_output` oracle when they are both provided.
    pub test_inputs: Option<InputsFn>,

    /// Legacy fixture oracle output bytes.
    ///
    /// Kept during migration so existing registrations in
    /// `src/{math,nn,crypto,matching}` remain buildable without edits.
    pub expected_output: Option<ExpectedFn>,
}

impl OpEntry {
    /// Construct an `OpEntry` with all required fields set. Exists so
    /// community Cat-A crates can `inventory::submit!(OpEntry::new(...))`
    /// despite the struct being `#[non_exhaustive]` (V7-EXT-004).
    #[must_use]
    pub const fn new(
        id: &'static str,
        build: fn() -> Program,
        test_inputs: Option<InputsFn>,
        expected_output: Option<ExpectedFn>,
    ) -> Self {
        Self {
            id,
            build,
            test_inputs,
            expected_output,
        }
    }

    /// Allowed output drift in ULPs for f32-producing backends.
    ///
    /// `0` means byte-identity is required. Non-zero tolerances are used only
    /// for ops whose contract already permits backend-defined transcendental
    /// drift.
    #[must_use]
    pub fn tolerance(&self) -> u32 {
        match self.id {
            "vyre-libs::nn::softmax" => 1,
            "vyre-libs::nn::attention" => 4,
            "vyre-libs::nn::layer_norm" => 1,
            "vyre-libs::nn::silu" => 1,
            "vyre-libs::nn::rms_norm" => 2,
            "vyre-libs::nn::rms_norm_linear" => 2,
            _ => 0,
        }
    }
}

inventory::collect!(OpEntry);

/// Return all registered operation entries.
pub fn all_entries() -> impl Iterator<Item = &'static OpEntry> {
    inventory::iter::<OpEntry>()
}

/// Fixpoint contract for dataflow ops whose GPU body performs one
/// iteration per dispatch.
///
/// Submitting a `FixpointRegistration` alongside an `OpEntry` tells the
/// conform harness to call `backend.dispatch` in a loop until the
/// `converged_flag_buffer` reads zero before comparing against the CPU
/// reference. Without this registration such ops would always diverge
/// in a single-dispatch byte-identity test even though their lowering
/// is correct.
#[derive(Clone, Debug)]
pub struct FixpointContract {
    /// Name of the RW buffer whose bytes-interpreted-as-`u32` must
    /// equal zero for the fixpoint loop to terminate. Semantics: the
    /// GPU body writes `1` whenever any lane updated shared state;
    /// the driver clears it between iterations.
    pub converged_flag_buffer: &'static str,
    /// Hard cap on driver iterations before the loop bails out. Every
    /// fixpoint op MUST reach its answer in a known-bounded number of
    /// steps so the harness cannot hang.
    pub max_iterations: u32,
}

/// Link-time registration binding a fixpoint contract to an op id.
pub struct FixpointRegistration {
    /// Stable op id (`OpEntry::id`) this contract applies to.
    pub op_id: &'static str,
    /// Fixpoint contract parameters.
    pub contract: FixpointContract,
}

inventory::collect!(FixpointRegistration);

/// Look up the fixpoint contract registered for `op_id`, if any.
#[must_use]
pub fn fixpoint_contract(op_id: &str) -> Option<&'static FixpointContract> {
    inventory::iter::<FixpointRegistration>()
        .find(|registration| registration.op_id == op_id)
        .map(|registration| &registration.contract)
}

/// Convergence contract for ops whose GPU body performs one
/// iteration per dispatch and needs an external driver loop to
/// reach fixpoint before byte-identity comparison.
///
/// Submitting a `ConvergenceContract` alongside an `OpEntry` tells
/// the conform harness to dispatch the backend in a loop (transfer
/// step + `bitset_fixpoint` convergence check) until the changed
/// flag clears or the iteration budget is exhausted.
#[derive(Clone, Debug)]
pub struct ConvergenceContract {
    /// Stable op id (`OpEntry::id`) this contract applies to.
    pub op_id: &'static str,
    /// Hard cap on driver iterations before the loop bails out.
    pub max_iterations: u32,
}

inventory::collect!(ConvergenceContract);

/// Look up the convergence contract registered for `op_id`, if any.
#[must_use]
pub fn convergence_contract(op_id: &str) -> Option<&'static ConvergenceContract> {
    inventory::iter::<ConvergenceContract>().find(|contract| contract.op_id == op_id)
}

/// Declares an op is exempt from the workspace-wide universal byte-identity
/// GPU-differential sweep, with a reason recorded at registration site.
///
/// Replaces the hardcoded `is_universal_diff_exempt` match inside the wgpu
/// differential test. Each exempt op lives next to the op that needs it,
/// which means (a) adding a new op automatically causes the diff test to
/// run (LAW 9 evasion harder to sneak in), (b) the reason is self-
/// documenting, and (c) removing the exemption is one local edit instead
/// of a cross-crate test patch.
pub struct UniversalDiffExemption {
    /// Stable op id this exemption applies to (`OpEntry::id`).
    pub op_id: &'static str,
    /// Why this op is exempt. Must be specific — e.g. "fixpoint op, needs
    /// driver convergence loop", "approximate intrinsic with declared
    /// tolerance", not "broken on GPU".
    pub reason: &'static str,
}

inventory::collect!(UniversalDiffExemption);

/// Return the recorded exemption reason for `op_id`, if any.
#[must_use]
pub fn universal_diff_exemption(op_id: &str) -> Option<&'static str> {
    inventory::iter::<UniversalDiffExemption>()
        .find(|exempt| exempt.op_id == op_id)
        .map(|exempt| exempt.reason)
}

/// One record in the universal byte-identity diff matrix.
///
/// Pairs an `OpEntry` with any structured reason it should be skipped.
/// Conform lenses iterate this instead of iterating raw `all_entries()`
/// and re-implementing the skip logic, which kept drifting.
pub struct DiffCandidate {
    /// The registered op entry.
    pub entry: &'static OpEntry,
    /// If `Some`, the harness must skip this entry and record the string
    /// as the reason. Includes both registered exemptions (from
    /// [`universal_diff_exemption`]) and ops missing `test_inputs`.
    pub skip_reason: Option<String>,
}

/// Iterate every registered `OpEntry`, pairing each with its skip reason.
///
/// This is the single source of truth for "which ops participate in the
/// universal byte-identity GPU differential sweep". Replaces ad-hoc
/// iteration and per-test hardcoded skip lists so adding a new exempt op
/// is one registration next to the op body, not a cross-crate patch.
pub fn universal_diff_candidates() -> impl Iterator<Item = DiffCandidate> {
    all_entries().map(|entry| {
        let skip_reason = if entry.test_inputs.is_none() {
            Some("no test_inputs — nothing to differentiate.".to_string())
        } else {
            universal_diff_exemption(entry.id).map(|reason| reason.to_string())
        };
        DiffCandidate { entry, skip_reason }
    })
}
