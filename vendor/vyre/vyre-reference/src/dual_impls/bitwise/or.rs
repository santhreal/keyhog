//! Dual CPU references for `primitive.bitwise.or`.

use crate::dual::DualReference;

/// Operation ID for the OR primitive.
pub const OP_ID: &str = "primitive.bitwise.or";

/// Direct word-oriented OR reference.
pub mod reference_a;
/// Bit-by-bit OR reference.
pub mod reference_b;

/// Dual-reference marker for the OR primitive.
pub struct OrDualReference;

impl DualReference for OrDualReference {
    fn reference_a(input: &[u8]) -> Vec<u8> {
        reference_a::reference(input)
    }

    fn reference_b(input: &[u8]) -> Vec<u8> {
        reference_b::reference(input)
    }
}
