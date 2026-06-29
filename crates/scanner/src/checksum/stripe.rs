use super::{ChecksumResult, ChecksumValidator};

/// Validates Stripe API key structure.
///
/// Stripe keys follow the format: `{prefix}_{mode}_{24+ alphanumeric chars}`
/// where prefix is sk/pk/rk and mode is live/test.
/// No public checksum algorithm, so valid Stripe-shaped tokens are structural
/// matches only. They must not receive the embedded-checksum confidence floor.
pub(crate) struct StripeTokenValidator;

/// Inclusive length window for the post-prefix payload of a Stripe key. The
/// lower bound is the documented "24+ alphanumeric chars" of the key format;
/// the upper bound is a sanity ceiling that rejects an over-long run the
/// boundary extender may have grabbed. A payload outside `[MIN, MAX]` is
/// `Invalid` (wrong family shape), not merely unverifiable.
const MIN_STRIPE_PAYLOAD_LEN: usize = 24;
const MAX_STRIPE_PAYLOAD_LEN: usize = 128;

impl ChecksumValidator for StripeTokenValidator {
    fn validate(&self, credential: &str) -> ChecksumResult {
        let prefixes = [
            "sk_live_", "sk_test_", "pk_live_", "pk_test_", "rk_live_", "rk_test_",
        ];
        let Some(payload) = prefixes.iter().find_map(|p| credential.strip_prefix(p)) else {
            return ChecksumResult::NotApplicable;
        };
        // Stripe does not publish a checksum. Keep this validator aligned
        // with the detector contract: enforce the family and alphabet, but
        // do not claim checksum proof for long live keys that satisfy the regex.
        if payload.len() < MIN_STRIPE_PAYLOAD_LEN || payload.len() > MAX_STRIPE_PAYLOAD_LEN {
            return ChecksumResult::Invalid;
        }
        if !payload.chars().all(|c| c.is_ascii_alphanumeric()) {
            return ChecksumResult::Invalid;
        }
        ChecksumResult::StructurallyValid
    }
}
