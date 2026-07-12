//! Re-homed from the inline `body_capacity_tests` in
//! `crates/verifier/src/verify/response.rs` (the `no_inline_tests_in_verifier_src`
//! gate forbids inline `#[cfg(test)]`). Pins the response-body preallocation
//! DoS guard: `body_capacity_hint` honours an honest Content-Length but CLAMPS a
//! hostile/huge one to `MAX_RESPONSE_BODY_BYTES` (never reserves wholesale, and
//! `u64::MAX` must not wrap the usize cast). Exercised through the `testing`
//! facade so `body_capacity_hint`/`MAX_RESPONSE_BODY_BYTES` stay `pub(crate)`.

use keyhog_verifier::testing::{body_capacity_hint, MAX_RESPONSE_BODY_BYTES};

#[test]
fn honors_honest_content_length_but_clamps_hostile_headers() {
    // No header => no speculative preallocation.
    assert_eq!(body_capacity_hint(None), 0);
    assert_eq!(body_capacity_hint(Some(0)), 0);
    // An honest small length preallocates exactly that.
    assert_eq!(body_capacity_hint(Some(1024)), 1024);
    // At the cap => the cap.
    assert_eq!(
        body_capacity_hint(Some(MAX_RESPONSE_BODY_BYTES as u64)),
        MAX_RESPONSE_BODY_BYTES
    );
    // A hostile/huge Content-Length must be CLAMPED to the cap, never
    // reserved wholesale (a memory-exhaustion DoS on a lying header), and
    // u64::MAX must not wrap through the usize cast.
    assert_eq!(body_capacity_hint(Some(u64::MAX)), MAX_RESPONSE_BODY_BYTES);
    assert_eq!(
        body_capacity_hint(Some(MAX_RESPONSE_BODY_BYTES as u64 + 1)),
        MAX_RESPONSE_BODY_BYTES
    );
}
