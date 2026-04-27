//! Tier 2.5 bitset primitives — `and`/`or`/`not`/`xor`/`popcount`/
//! `any`/`contains` over packed u32 bitsets. These are the LEGO
//! blocks every higher-level graph/taint composition reaches for
//! when combining two NodeSets.
//!
//! All primitives operate on the same bitset shape: a u32 buffer
//! with `word_count` slots, where bit `i` of word `w` represents
//! element `w * 32 + i`. Sizes are declared at `Program` build
//! time so the backend can allocate + validate layout up front.

pub mod and;
pub mod and_into;
pub mod and_not;
pub mod and_not_into;
pub mod any;
pub mod clear_bit;
pub mod contains;
pub mod equal;
pub mod four_russians;
pub mod not;
pub mod or;
pub mod or_into;
pub mod popcount;
pub mod set_bit;
pub mod subset_of;
pub mod test_bit;
pub mod xor;
pub mod xor_into;

/// Words needed to hold a bitset over `n` elements.
///
/// Overflow-safe — `(n + 31) / 32` wraps to 0 for `n > u32::MAX - 31`;
/// `div_ceil` handles the overflow correctly. Per AUDIT_2026-04-24
/// F-CT-01 / F-LBL-01 (kimi).
#[must_use]
pub const fn bitset_words(n: u32) -> u32 {
    n.div_ceil(32)
}
