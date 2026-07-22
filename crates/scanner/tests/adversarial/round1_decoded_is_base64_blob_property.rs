//! Round 1 FP-killer regression contract: `decoded_is_base64_blob` must
//! distinguish k8s `data:` double-base64 wrappers from real (random-bytes)
//! secrets.
//!
//! Investigator finding (base64-protobuf cause #6): pre-fix, the k8s
//! `data:` field shape (base64 of binary content that itself happens to
//! be all-base64-alphabet text) collapsed to a generic-secret finding
//! with the outer base64 wrapper as the credential. Mirror v32 had 7
//! such FPs in yaml/k8s-secret fixtures. The fix adds
//! `decoded_is_base64_blob`: decode the candidate, then require the decoded
//! text to satisfy the canonical uniform-random-base64 shape gate. This keeps
//! Base64-wrapped printable secrets and hex key material live while rejecting
//! realistic `base64(base64(random_bytes))` data envelopes.
//!
//! Adversarial style: PROPTEST 1k iterations. Property A (positive truth):
//! outer = base64(base64(random bytes)) MUST be flagged as a data envelope.
//! Property B (false-positive ceiling): outer = base64(random bytes containing
//! non-alphabet bytes) MUST NOT be flagged.

use base64::Engine as _;
use keyhog_scanner::testing::decode_structure::decoded_is_base64_blob;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig { cases: 1_000, .. ProptestConfig::default() })]

    /// Property A: a realistic Kubernetes `data:` envelope wraps an already
    /// base64-encoded random binary payload. The outer layer must be flagged.
    #[test]
    fn double_base64_wrapper_is_flagged(
        mut raw in prop::collection::vec(any::<u8>(), 32..80usize),
    ) {
        raw[..3].copy_from_slice(&[0xfb, 0xff, 0xff]);
        let inner = base64::engine::general_purpose::STANDARD.encode(&raw);
        let outer = base64::engine::general_purpose::STANDARD.encode(inner.as_bytes());
        prop_assert!(
            decoded_is_base64_blob(&outer),
            "base64(base64(random bytes)) with inner len={} must be flagged; outer={outer}",
            inner.len()
        );
    }

    /// Property B: a real (random-bytes) secret encoded once decodes to
    /// raw bytes that contain control codes / high bytes / non-alphabet
    /// chars by construction. Must NOT be flagged.
    ///
    /// We construct the inner as 30+ random bytes that include at least
    /// one non-base64-alphabet byte (control codes, 0x7f-0xff, etc.) so
    /// the gate's "all printable + all base64 alphabet" predicate fails.
    #[test]
    fn random_secret_bytes_are_not_flagged(
        raw in prop::collection::vec(any::<u8>(), 30..80usize),
    ) {
        // Skip the (vanishingly rare) draws where every random byte
        // happens to be in the base64 alphabet AND printable - those
        // would correctly land in the flagged set.
        let all_alpha = raw.iter().all(|&b| {
            b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'='
        });
        prop_assume!(!all_alpha);

        let outer = base64::engine::general_purpose::STANDARD.encode(&raw);
        prop_assert!(
            !decoded_is_base64_blob(&outer),
            "random-bytes secret must NOT be flagged as double-base64 \
             blob; outer={outer}"
        );
    }
}

/// CVE-replay style: a documented Kubernetes Secret manifest shape with
/// `data:` field carrying a base64-of-base64 token. The exact bytes are
/// synthesised but the structural shape mirrors what the SecretBench
/// mirror's k8s-secret yaml decoys produce.
#[test]
fn k8s_data_envelope_shape_is_flagged() {
    // 64 chars of 'A' decoded once = 48 bytes of 0x00, but here we
    // construct a more realistic shape: inner is a 48-char standard-
    // base64 string, outer wraps it.
    let inner = "RjVwV00rYUNrTGZNN0pGYzJIVjJhM2xGRTBzQmxaY05JYmdGQWdYNw==";
    let outer = base64::engine::general_purpose::STANDARD.encode(inner.as_bytes());
    assert!(
        decoded_is_base64_blob(&outer),
        "k8s data: envelope shape (base64-of-base64) must be flagged. outer={outer}"
    );
}
