pub use super::depth::{DEFAULT_MAX_CALL_DEPTH, DEFAULT_MAX_NESTING_DEPTH, DEFAULT_MAX_NODE_COUNT};
use super::ValidationError;
use std::borrow::Cow;

#[inline]
pub(crate) fn err(message: impl Into<Cow<'static, str>>) -> ValidationError {
    ValidationError {
        message: message.into(),
    }
}
