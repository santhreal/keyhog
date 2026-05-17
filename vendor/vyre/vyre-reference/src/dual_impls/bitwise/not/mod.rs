//! Dual CPU references for `primitive.bitwise.not`.

use crate::dual::DualReference;

/// Operation ID for the NOT primitive.
pub const OP_ID: &str = "primitive.bitwise.not";

/// docs
pub mod reference_a;
/// docs
pub mod reference_b;

/// Dual-reference marker for the NOT primitive.
pub struct NotDualReference;

impl DualReference for NotDualReference {
    fn reference_a(input: &[u8]) -> Vec<u8> {
        reference_a::reference(input)
    }

    fn reference_b(input: &[u8]) -> Vec<u8> {
        reference_b::reference(input)
    }
}
