//! Runtime category-classification consistency check (F-IR-34).
//!
//! Complements the build-time scanner in `build.rs` by walking the linked
//! `inventory::iter::<OpDefRegistration>` and asserting every entry obeys the
//! A/B/C invariant.
//!
//! Invariant (machine-checked):
//! * `Category::Composite` (A) **must** have `lowerings.naga_wgsl == None`.
//! * `Category::Intrinsic` (B/C) may have `naga_wgsl` present or absent.
//! * `naga_wgsl: Some(...)` **must not** appear on a `Category::Composite` op.

use vyre_driver::registry::{Category, OpDefRegistration};
use vyre_foundation::dialect_lookup::NagaBuilder;

/// Assert that a single op's declared category matches its lowering table.
///
/// # Panics
///
/// Panics with an actionable `Fix:` message when a Category-A op carries a
/// dedicated Naga arm — the exact drift shape that F-IR-34 exists to catch.
pub fn check_opdef(id: &str, category: Category, naga_wgsl: Option<NagaBuilder>) {
    if category == Category::Composite && naga_wgsl.is_some() {
        panic!(
            "category classification mismatch for op `{id}`: declared Composite (Category A) but lowering table says Some(NagaBuilder). Fix: Category A ops must be pure IR composition with no dedicated Naga arm."
        );
    }
}

/// Walk every linked `OpDefRegistration` and assert the invariant.
///
/// # Panics
///
/// Panics on the first violating entry.
pub fn check_all_inventory_opdefs() {
    for reg in inventory::iter::<OpDefRegistration>() {
        let def = (reg.op)();
        check_opdef(def.id, def.category, def.lowerings.naga_wgsl);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vyre_driver::registry::Category;

    fn dummy_naga(_: &vyre_foundation::dialect_lookup::LoweringCtx<'_>) -> Result<(), String> {
        Ok(())
    }

    #[test]
    fn composite_without_naga_passes() {
        // Category A, pure IR composition — no Naga arm.  This is the
        // canonical correct shape.
        check_opdef("test.cat_a_ok", Category::Composite, None);
    }

    #[test]
    fn intrinsic_without_naga_passes() {
        // Category C runtime-only op (e.g. core.indirect_dispatch) —
        // Intrinsic category but no WGSL arm yet.
        check_opdef("test.cat_c_ok", Category::Intrinsic, None);
    }

    #[test]
    fn intrinsic_with_naga_passes() {
        // Category B op with a dedicated Naga arm.
        check_opdef("test.cat_b_ok", Category::Intrinsic, Some(dummy_naga));
    }

    #[test]
    #[should_panic(
        expected = "category classification mismatch for op `test.cat_a_bad`: declared Composite (Category A) but lowering table says Some(NagaBuilder). Fix: Category A ops must be pure IR composition with no dedicated Naga arm."
    )]
    fn composite_with_naga_panics() {
        // This is the drift shape: an op claims to be pure composition but
        // secretly requires a backend-specific Naga arm.
        check_opdef("test.cat_a_bad", Category::Composite, Some(dummy_naga));
    }

    #[test]
    fn inventory_walk_does_not_panic() {
        // Exercises every OpDefRegistration linked into the current test
        // binary (vyre-driver core + io ops, plus any dev-dependencies).
        check_all_inventory_opdefs();
    }
}
