//! Suppression module: placeholder-credential and shape-gate suppression.

pub(crate) mod api;
pub(crate) mod decision;
pub(crate) mod decode;
pub(crate) mod doc_markers;
pub(crate) mod path_filter;
pub(crate) mod shape;
pub(crate) mod shape_gates;
pub(crate) mod token_randomness;

// Only the simdsieve hot-pattern fast path consumes this through the
// `suppression::` alias; the direct callers in this crate go through
// `path_filter::`. Gate to keep the lean build warning-free.
#[cfg(feature = "simdsieve")]
pub(crate) use path_filter::looks_like_secret_scanner_source;
pub(crate) use path_filter::looks_like_vendored_minified_path;
#[cfg(feature = "entropy")]
pub(crate) use shape::{contains_uuid_v4_substring, looks_like_email_address};
pub(crate) use shape::{
    looks_like_punctuation_decorated_identifier, looks_like_pure_identifier,
    looks_like_regex_literal_tail, looks_like_scheme_prefixed_uri, looks_like_url_or_path_segment,
    looks_like_word_separated_identifier,
};

#[cfg(any(feature = "entropy", feature = "simdsieve", test))]
pub(crate) use api::should_suppress_known_example_credential_with_source;
pub(crate) use api::{detector_weak_anchor, should_suppress_named_detector_finding_weak};
#[cfg(test)]
pub(crate) use api::{
    should_suppress_known_example_credential, should_suppress_named_detector_finding,
};
