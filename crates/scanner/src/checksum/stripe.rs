use super::{ChecksumResult, ChecksumValidator};

/// Validates Stripe API key structure.
///
/// Stripe keys follow the format: `{prefix}_{mode}_{24+ alphanumeric chars}`
/// where prefix is sk/pk/rk and mode is live/test.
/// No public checksum algorithm, so valid Stripe-shaped tokens are structural
/// matches only. They must not receive the embedded-checksum confidence floor.
pub(crate) struct StripeTokenValidator;

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
        if payload.len() < 24 || payload.len() > 128 {
            return ChecksumResult::Invalid;
        }
        if !payload.chars().all(|c| c.is_ascii_alphanumeric()) {
            return ChecksumResult::Invalid;
        }
        ChecksumResult::StructurallyValid
    }
}
