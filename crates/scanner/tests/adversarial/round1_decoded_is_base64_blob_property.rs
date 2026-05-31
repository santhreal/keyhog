//! Round 1 FP-killer regression contract: `decoded_is_base64_blob` must
//! distinguish k8s `data:` double-base64 wrappers from real (random-bytes)
//! secrets.
//!
//! Investigator finding (base64-protobuf cause #6): pre-fix, the k8s
//! `data:` field shape (base64 of binary content that itself happens to
//! be all-base64-alphabet text) collapsed to a generic-secret finding
//! with the outer base64 wrapper as the credential. Mirror v32 had 7
//! such FPs in yaml/k8s-secret fixtures. The fix adds
//! `decoded_is_base64_blob`: decode the candidate, check whether the
//! decoded bytes are all printable AND all base64-alphabet AND length
//! >= 32. If so, the candidate is a binary-data envelope, not a
//! credential.
//!
//! Adversarial style: PROPTEST 1k iterations. Property A (positive truth
//! soundness): outer = base64(inner) where inner is itself any
//! all-base64-alphabet string of length >= 32 MUST be flagged
//! `decoded_is_base64_blob`. Property B (false-positive ceiling): outer =
//! base64(random_bytes_with_non_alphabet_bytes) MUST NOT be flagged.

use base64::Engine as _;
use keyhog_scanner::decode_structure::decoded_is_base64_blob;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig { cases: 1_000, .. ProptestConfig::default() })]

    /// Property A: outer = base64(<inner all-base64-alphabet, len >= 32>)
    /// MUST be flagged. Covers the entire k8s `data:` wrapper shape.
    #[test]
    fn double_base64_wrapper_is_flagged(
        inner in "[A-Za-z0-9+/]{32,80}",
    ) {
        let outer = base64::engine::general_purpose::STANDARD
            .encode(inner.as_bytes());
        prop_assert!(
            decoded_is_base64_blob(&outer),
            "base64-of-base64 (inner len={}) must be flagged as a blob; \
             outer={outer}",
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
