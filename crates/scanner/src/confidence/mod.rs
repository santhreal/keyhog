//! Confidence scoring: combines multiple signals into a 0.0–1.0 score.
//! Higher confidence means more likely to be a real secret.

pub(crate) mod penalties;
pub(crate) mod policy;
mod prefixes;
mod signals;

pub use prefixes::KNOWN_PREFIXES;
pub(crate) use prefixes::{known_prefix_body, known_prefix_confidence_floor};
pub(crate) use signals::ConfidenceSignals;

pub(crate) use penalties::apply_calibration_multiplier;
pub(crate) use penalties::apply_path_confidence_penalties;
pub(crate) use penalties::apply_post_ml_penalties_with_encoded_text_lift;
#[cfg(feature = "entropy")]
pub(crate) use penalties::contains_placeholder_word;
pub(crate) use signals::is_sensitive_path;

const CONFIDENCE_MIN: f64 = 0.0;
const CONFIDENCE_MAX: f64 = 1.0;
