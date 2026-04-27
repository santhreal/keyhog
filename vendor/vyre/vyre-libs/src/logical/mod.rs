//! Elementwise logical operations (and, or, xor, nand, nor).
//! Ported from the legacy WGSL implementations in vyre-ops.

/// Bitwise AND
pub mod and;
/// Bitwise NAND
pub mod nand;
/// Bitwise NOR
pub mod nor;
/// Bitwise OR
pub mod or;
/// Bitwise XOR
pub mod xor;

pub use and::and;
pub use nand::nand;
pub use nor::nor;
pub use or::or;
pub use xor::xor;
