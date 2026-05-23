//! Inventory-backed OpEntry registry for the intrinsic-differential harness.
//!
//! **Registry Layering**: This file defines the `OpEntry` registry for Tier-2 hardware intrinsics.
//! It operates in parallel with the Cat-A registry (`vyre-harness::OpEntry`) and the Tier-2.5 primitives registry (`vyre-primitives::harness::OpEntry`).
//! For an architectural overview of this three-registry split, see `vyre-harness/README.md`.
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
    /// Coarse-grained taxonomy tag (T028 / SEPARATION_AUDIT S2 prep).
    /// Examples: `"hardware"`, `"math"`, `"crypto"`, `"graph"`,
    /// `"matching"`. `None` means uncategorised — equivalent to the
    /// pre-T028 behaviour. Use `OpEntry::with_category` to set it
    /// without losing the const-fn `new` constructor.
    pub category: Option<&'static str>,
}

impl OpEntry {
    /// Construct an `OpEntry` with all required fields set. Exists so
    /// external intrinsic packs can `inventory::submit!(OpEntry::new(...))`
    /// despite the struct being `#[non_exhaustive]` (V7-EXT-003).
    /// `category` initialises to `None`; chain `with_category` if a
    /// category is required at submission time.
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
            category: None,
        }
    }

    /// Set the category and return `self`. `const`-friendly so callers
    /// can write `OpEntry::new(...).with_category("hardware")` inside
    /// `inventory::submit!`.
    #[must_use]
    pub const fn with_category(mut self, category: &'static str) -> Self {
        self.category = Some(category);
        self
    }

    /// Return the registered coarse-grained taxonomy tag, if any.
    #[must_use]
    pub const fn category(&self) -> Option<&'static str> {
        self.category
    }
}

inventory::collect!(OpEntry);

pub fn all_entries() -> impl Iterator<Item = &'static OpEntry> {
    inventory::iter::<OpEntry>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use vyre_foundation::ir::Program;

    fn empty_build() -> Program {
        Program::default()
    }

    #[test]
    fn new_initialises_category_to_none() {
        let entry = OpEntry::new("test::id", empty_build, None, None);
        assert_eq!(entry.category(), None);
    }

    #[test]
    fn with_category_sets_and_returns_self() {
        let entry = OpEntry::new("test::id", empty_build, None, None).with_category("hardware");
        assert_eq!(entry.category(), Some("hardware"));
    }

    #[test]
    fn registered_hardware_entries_carry_hardware_category() {
        // Every inventory::submit! site under hardware/ must declare
        // category = Some("hardware") — the T028 contract for vyre-
        // intrinsics. If a future hardware op forgets the field this
        // test fires.
        let mut hardware_count = 0;
        let mut categorised = 0;
        for entry in all_entries() {
            if entry.id.starts_with("vyre-intrinsics::hardware::") {
                hardware_count += 1;
                if entry.category() == Some("hardware") {
                    categorised += 1;
                }
            }
        }
        assert_eq!(
            categorised, hardware_count,
            "every vyre-intrinsics::hardware::* op must declare category=Some(\"hardware\") — counted {hardware_count} hardware ops, {categorised} carry the category"
        );
        assert!(
            hardware_count > 0,
            "expected at least one registered vyre-intrinsics::hardware:: op"
        );
    }
}
