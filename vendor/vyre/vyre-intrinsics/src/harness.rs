//! Inventory-backed OpEntry registry for the intrinsic-differential harness.
//!
//! Every Cat-C intrinsic registers one `OpEntry` via `inventory::submit!`.
//! The test `tests/hardware_conform.rs` iterates the inventory and
//! asserts each op's CPU reference matches the declared
//! `expected_output` bit-for-bit.

use vyre_foundation::ir::Program;

pub type Fixture = Vec<Vec<u8>>;
pub type Fixtures = Vec<Fixture>;
pub type InputsFn = fn() -> Fixtures;
pub type ExpectedFn = fn() -> Fixtures;

#[non_exhaustive]
pub struct OpEntry {
    pub id: &'static str,
    pub build: fn() -> Program,
    pub test_inputs: Option<InputsFn>,
    pub expected_output: Option<ExpectedFn>,
}

impl OpEntry {
    /// Construct an `OpEntry` with all required fields set. Exists so
    /// external intrinsic packs can `inventory::submit!(OpEntry::new(...))`
    /// despite the struct being `#[non_exhaustive]` (V7-EXT-003).
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

pub fn all_entries() -> impl Iterator<Item = &'static OpEntry> {
    inventory::iter::<OpEntry>()
}
