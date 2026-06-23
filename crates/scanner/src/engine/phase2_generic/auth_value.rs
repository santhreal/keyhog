//! Bare `auth = ...` value allowance for the generic assignment bridge.

use crate::entropy::plausibility::{passes_secret_strength_checks, PlausibilityContext};

pub(super) fn bare_auth_value_allowed(value: &str) -> bool {
    let context = PlausibilityContext::new(true, false);
    crate::suppression::shape::is_structured_dotted_token(value)
        || (!value.contains('.')
            && value.bytes().any(|byte| !byte.is_ascii_alphanumeric())
            && passes_secret_strength_checks(value, context))
}
