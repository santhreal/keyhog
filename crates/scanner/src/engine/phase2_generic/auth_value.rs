//! Bare `auth = ...` value allowance for the generic assignment bridge.

use super::shape_helpers::is_structured_dotted_token;

pub(super) fn bare_auth_value_allowed(value: &str) -> bool {
    let context = crate::entropy::keywords::PlausibilityContext::new(true, false);
    is_structured_dotted_token(value)
        || (!value.contains('.')
            && value.bytes().any(|byte| !byte.is_ascii_alphanumeric())
            && crate::entropy::keywords::passes_secret_strength_checks(value, context))
}
