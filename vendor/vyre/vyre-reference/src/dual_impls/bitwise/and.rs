//! Dual CPU references for `primitive.bitwise.and`.

use crate::dual::DualReference;

/// Operation ID for the AND primitive.
pub const OP_ID: &str = "primitive.bitwise.and";

/// Direct word-oriented AND reference.
pub mod reference_a;
/// Bit-by-bit AND reference.
pub mod reference_b;

/// Dual-reference marker for the AND primitive.
pub struct AndDualReference;

impl DualReference for AndDualReference {
    fn reference_a(input: &[u8]) -> Vec<u8> {
        reference_a::reference(input)
    }

    fn reference_b(input: &[u8]) -> Vec<u8> {
        reference_b::reference(input)
    }
}
