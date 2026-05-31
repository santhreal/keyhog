//! Property-based (proptest) suite as its OWN bounded test binary.
//! Was silently orphaned (empty property/mod.rs). Every property/*.rs is a
//! module here; the all-wired guard enforces it.

#[path = "property/parse_byte_size_rejects_bare_number.rs"]
mod parse_byte_size_rejects_bare_number;
#[path = "property/parse_byte_size_rejects_unknown_suffix.rs"]
mod parse_byte_size_rejects_unknown_suffix;
#[path = "property/parse_byte_size_valid_suffix_roundtrip.rs"]
mod parse_byte_size_valid_suffix_roundtrip;
#[path = "property/parse_decode_depth_rejects_zero.rs"]
mod parse_decode_depth_rejects_zero;
#[path = "property/parse_decode_depth_valid_range.rs"]
mod parse_decode_depth_valid_range;
#[path = "property/parse_min_confidence_invariant.rs"]
mod parse_min_confidence_invariant;
#[path = "property/parse_min_confidence_rejects_nan.rs"]
mod parse_min_confidence_rejects_nan;
#[path = "property/parse_ml_threshold_finite_unit_interval.rs"]
mod parse_ml_threshold_finite_unit_interval;
#[path = "property/parse_ml_threshold_rejects_nan.rs"]
mod parse_ml_threshold_rejects_nan;
#[path = "property/parse_verify_rate_finite_positive.rs"]
mod parse_verify_rate_finite_positive;
#[path = "property/parse_verify_rate_rejects_nonpositive.rs"]
mod parse_verify_rate_rejects_nonpositive;
#[path = "property/r5t_parse_byte_size_empty_string_is_zero.rs"]
mod r5t_parse_byte_size_empty_string_is_zero;
#[path = "property/r5t_parse_byte_size_fractional_megabytes.rs"]
mod r5t_parse_byte_size_fractional_megabytes;
#[path = "property/r5t_parse_byte_size_rejects_negative_number.rs"]
mod r5t_parse_byte_size_rejects_negative_number;
#[path = "property/r5t_parse_decode_depth_rejects_eleven.rs"]
mod r5t_parse_decode_depth_rejects_eleven;
#[path = "property/r5t_parse_min_confidence_rejects_infinity.rs"]
mod r5t_parse_min_confidence_rejects_infinity;
#[path = "property/r5t_parse_ml_threshold_rejects_infinity.rs"]
mod r5t_parse_ml_threshold_rejects_infinity;
#[path = "property/r5t_parse_verify_rate_accepts_ten_thousand_boundary.rs"]
mod r5t_parse_verify_rate_accepts_ten_thousand_boundary;
#[path = "property/r5t_parse_verify_rate_rejects_above_cap.rs"]
mod r5t_parse_verify_rate_rejects_above_cap;
#[path = "property/r5t_parse_verify_rate_rejects_infinity.rs"]
mod r5t_parse_verify_rate_rejects_infinity;
#[path = "property/r5t_parse_verify_rate_rejects_nan.rs"]
mod r5t_parse_verify_rate_rejects_nan;
