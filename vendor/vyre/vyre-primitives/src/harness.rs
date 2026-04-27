//! Tier 2.5 LEGO primitive registry.
//!
//! Mirrors `vyre_libs::harness::OpEntry` so that the universal
//! conform harness, `cargo xtask print-composition`, and the
//! cross-backend parity matrix discover primitives via the same
//! `inventory::iter::<OpEntry>` walk they already use for Tier-3
//! dialects. The Tier-2.5 bucket is a separate `inventory::collect!`
//! slot so consumers (and audits) can scan just the LEGO substrate
//! without sweeping the entire library surface.
//!
//! ## Gating
//!
//! The module is compiled only when `inventory-registry` is enabled
//! (which pulls in `inventory` + `vyre-foundation`). Production
//! builds that only want the `fn(...) -> Program` builders without
//! the registry overhead leave the feature off — the primitives
//! still work, they just aren't listed in the inventory walk.

// The enclosing `pub mod harness` in `lib.rs` already carries a
// `#[cfg(feature = "inventory-registry")]` gate, so no inner
// `#![cfg]` attribute is needed here.

use vyre_foundation::ir::Program;

/// Deterministic fixture input cases. One `Vec<Vec<u8>>` per input
/// set, one `Vec<u8>` per declared buffer.
pub type InputsFn = fn() -> Vec<Vec<Vec<u8>>>;

/// Deterministic expected-output fixtures. Same shape as [`InputsFn`].
pub type ExpectedFn = fn() -> Vec<Vec<Vec<u8>>>;

/// One registered Tier-2.5 primitive. Every `pub fn <name>(...) ->
/// Program` in `vyre-primitives` submits one of these.
#[non_exhaustive]
pub struct OpEntry {
    /// Stable op id. Convention:
    /// `"vyre-primitives::<domain>::<name>"` — a grep tells any
    /// reader the op lives at Tier 2.5.
    pub id: &'static str,

    /// Construct the `Program` under test.
    pub build: fn() -> Program,

    /// Deterministic fixture input bytes in declaration order.
    pub test_inputs: Option<InputsFn>,

    /// Deterministic expected-output bytes the universal harness
    /// compares against the reference + every backend.
    pub expected_output: Option<ExpectedFn>,
}

impl OpEntry {
    /// Construct an `OpEntry`. Required because the struct is
    /// `#[non_exhaustive]`; callers cannot use literal construction.
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
}

inventory::collect!(OpEntry);

/// Iterate every Tier-2.5 primitive that ships its registration via
/// `inventory::submit!(OpEntry { ... })`.
pub fn all_entries() -> impl Iterator<Item = &'static OpEntry> {
    inventory::iter::<OpEntry>()
}
