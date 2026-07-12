pub mod ssrf_engine;

/// Deterministic 32-bit linear congruential generator (Numerical Recipes
/// constants). Same seed → same stream on every run, so a failing case in any
/// property sweep is byte-for-byte reproducible from its seed. This is the ONE
/// canonical RNG for every `tests/property/*_proptest.rs`; do not re-inline a
/// copy (ONE PLACE).
pub fn lcg(state: &mut u32) -> u32 {
    *state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
    *state
}

/// A random DNS label: 1..=12 lowercase ASCII letters. Never empty, never
/// contains a dot — so composing labels with `.` yields well-formed hostnames.
pub fn rand_label(state: &mut u32) -> String {
    let len = 1 + (lcg(state) % 12) as usize;
    (0..len)
        .map(|_| (b'a' + (lcg(state) % 26) as u8) as char)
        .collect()
}

/// A random two-label domain (`foo.bar`). Not a shared-tenant suffix (those are
/// specific real brands); random lowercase labels collide with that small set
/// with negligible probability.
pub fn rand_domain(state: &mut u32) -> String {
    format!("{}.{}", rand_label(state), rand_label(state))
}
