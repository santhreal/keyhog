//! IEEE 754 float rules enforced by the parity engine.
//!
//! Until vyre IR gains full float variants, this module acts as a strict guard:
//! any code path that would require float semantics returns a deterministic error
//! rather than falling back to undefined or driver-dependent behavior. When float
//! support lands, this module will become the source of truth for rounding mode,
//! NaN propagation, and subnormal handling that the conform gate checks.

use vyre::Error;

/// Deterministic f32 sine used by the CPU parity oracle.
///
/// # Examples
///
/// ```
/// let y = vyre_reference::ieee754::canonical_sin(0.0);
/// assert_eq!(y.to_bits(), 0.0f32.to_bits());
/// ```
#[must_use]
#[inline]
pub fn canonical_sin(x: f32) -> f32 {
    libm::sinf(x)
}

/// Deterministic f32 cosine used by the CPU parity oracle.
///
/// # Examples
///
/// ```
/// let y = vyre_reference::ieee754::canonical_cos(0.0);
/// assert_eq!(y.to_bits(), 1.0f32.to_bits());
/// ```
#[must_use]
#[inline]
pub fn canonical_cos(x: f32) -> f32 {
    libm::cosf(x)
}

/// Deterministic f32 square root used by the CPU parity oracle.
///
/// # Examples
///
/// ```
/// let y = vyre_reference::ieee754::canonical_sqrt(4.0);
/// assert_eq!(y.to_bits(), 2.0f32.to_bits());
/// ```
#[must_use]
#[inline]
pub fn canonical_sqrt(x: f32) -> f32 {
    libm::sqrtf(x)
}

/// Deterministic f32 exponential used by the CPU parity oracle.
///
/// # Examples
///
/// ```
/// let y = vyre_reference::ieee754::canonical_exp(0.0);
/// assert_eq!(y.to_bits(), 1.0f32.to_bits());
/// ```
#[must_use]
#[inline]
pub fn canonical_exp(x: f32) -> f32 {
    libm::expf(x)
}

/// Deterministic f32 natural logarithm used by the CPU parity oracle.
///
/// # Examples
///
/// ```
/// let y = vyre_reference::ieee754::canonical_log(1.0);
/// assert_eq!(y.to_bits(), 0.0f32.to_bits());
/// ```
#[must_use]
#[inline]
pub fn canonical_log(x: f32) -> f32 {
    libm::logf(x)
}

/// Return the canonical float-pending error.
///
/// This function exists to make the reference interpreter intentionally fail on
/// float operations until the parity engine has a complete, testable IEEE 754
/// CPU reference to compare against GPU output.
///
/// # Examples
///
/// ```rust,ignore
/// let err = vyre::reference::ieee754::pending_float_types();
/// ```
pub fn pending_float_types() -> Error {
    Error::interp(
        "pending upstream float variants in vyre::ir; reference interpreter is integer-only until those variants land",
    )
}
