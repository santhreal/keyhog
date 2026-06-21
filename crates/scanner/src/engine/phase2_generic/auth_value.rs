//! Bare `auth = ...` value allowance for the generic assignment bridge.

use super::shape_helpers::is_structured_dotted_token;
use crate::entropy::plausibility::{passes_secret_strength_checks, PlausibilityContext};

pub(super) fn bare_auth_value_allowed(value: &str) -> bool {
    let context = PlausibilityContext::new(true, false);
    is_structured_dotted_token(value)
        || (!value.contains('.')
            && value.bytes().any(|byte| !byte.is_ascii_alphanumeric())
            && passes_secret_strength_checks(value, context))
}
