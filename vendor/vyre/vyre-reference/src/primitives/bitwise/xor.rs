//! Dual CPU references for `primitive.bitwise.xor`.

use crate::dual::DualReference;

/// Operation ID for the XOR primitive.
pub const OP_ID: &str = "primitive.bitwise.xor";

/// Direct word-oriented XOR reference.
pub mod reference_a;
/// Bit-by-bit XOR reference.
pub mod reference_b;

/// Dual-reference marker for the XOR primitive.
pub struct XorDualReference;

impl DualReference for XorDualReference {
    fn reference_a(input: &[u8]) -> Vec<u8> {
        reference_a::reference(input)
    }

    fn reference_b(input: &[u8]) -> Vec<u8> {
        reference_b::reference(input)
    }
}
