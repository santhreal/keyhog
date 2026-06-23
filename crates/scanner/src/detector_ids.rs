//! Canonical detector-id strings and family predicates used by scanner logic.

pub(crate) const GENERIC_PREFIX: &str = "generic-";
pub(crate) const ENTROPY_PREFIX: &str = "entropy-";

pub(crate) const GENERIC_SECRET: &str = "generic-secret";
pub(crate) const GENERIC_KEYWORD_SECRET: &str = "generic-keyword-secret";
pub(crate) const GENERIC_API_KEY: &str = "generic-api-key";
pub(crate) const GENERIC_PASSWORD: &str = "generic-password";
pub(crate) const GENERIC_DATABASE_URL: &str = "generic-database-url";
pub(crate) const GENERIC_PRIVATE_KEY: &str = "generic-private-key";

pub(crate) const ENTROPY: &str = "entropy";
#[cfg(feature = "entropy")]
pub(crate) const ENTROPY_GENERIC: &str = "entropy-generic";
#[cfg(feature = "entropy")]
pub(crate) const ENTROPY_PASSWORD: &str = "entropy-password";
#[cfg(feature = "entropy")]
pub(crate) const ENTROPY_TOKEN: &str = "entropy-token";
#[cfg(feature = "entropy")]
pub(crate) const ENTROPY_API_KEY: &str = "entropy-api-key";

pub(crate) const PRIVATE_KEY: &str = "private-key";
pub(crate) const SSH_PRIVATE_KEY: &str = "ssh-private-key";
pub(crate) const GITHUB_APP_PRIVATE_KEY: &str = "github-app-private-key";

pub(crate) const AWS_ACCESS_KEY: &str = "aws-access-key";
pub(crate) const GITHUB_CLASSIC_PAT: &str = "github-classic-pat";
pub(crate) const GITHUB_FINE_GRAINED_PAT: &str = "github-fine-grained-pat";
pub(crate) const GITLAB_TOKEN: &str = "gitlab-token";
pub(crate) const NPM_ACCESS_TOKEN: &str = "npm-access-token";
pub(crate) const PYPI_API_TOKEN: &str = "pypi-api-token";
#[cfg(feature = "simdsieve")]
pub(crate) const OPENAI_API_KEY: &str = "openai-api-key";
#[cfg(feature = "simdsieve")]
pub(crate) const SENDGRID_API_KEY: &str = "sendgrid-api-key";
#[cfg(feature = "simdsieve")]
pub(crate) const SLACK_BOT_TOKEN: &str = "slack-bot-token";
pub(crate) const SLACK_TOKEN: &str = "slack-token";
#[cfg(feature = "simdsieve")]
pub(crate) const SLACK_USER_TOKEN: &str = "slack-user-token";
#[cfg(feature = "simdsieve")]
pub(crate) const SQUARE_ACCESS_TOKEN: &str = "square-access-token";
pub(crate) const STRIPE_API_KEY: &str = "stripe-api-key";
pub(crate) const STRIPE_SECRET_KEY: &str = "stripe-secret-key";

#[inline]
pub(crate) fn is_generic_detector(detector_id: &str) -> bool {
    detector_id.starts_with(GENERIC_PREFIX)
}

#[inline]
pub(crate) fn is_entropy_detector(detector_id: &str) -> bool {
    detector_id == ENTROPY || detector_id.starts_with(ENTROPY_PREFIX)
}

#[inline]
pub(crate) fn is_private_key_fallback(detector_id: &str) -> bool {
    detector_id == PRIVATE_KEY
}

#[inline]
pub(crate) fn is_generic_or_private_key_detector(detector_id: &str) -> bool {
    is_generic_detector(detector_id) || is_private_key_fallback(detector_id)
}

#[inline]
pub(crate) fn is_generic_or_entropy_detector(detector_id: &str) -> bool {
    is_generic_detector(detector_id) || is_entropy_detector(detector_id)
}

#[inline]
pub(crate) fn is_service_anchored_detector(detector_id: &str) -> bool {
    !is_generic_detector(detector_id)
        && !is_entropy_detector(detector_id)
        && !is_private_key_fallback(detector_id)
}

#[inline]
pub(crate) fn is_private_key_block_detector(detector_id: &str) -> bool {
    matches!(
        detector_id,
        PRIVATE_KEY | SSH_PRIVATE_KEY | GITHUB_APP_PRIVATE_KEY
    )
}
