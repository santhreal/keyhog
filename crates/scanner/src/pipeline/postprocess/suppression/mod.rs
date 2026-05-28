//! Placeholder-credential suppression. Decides whether a regex-matched
//! candidate is a real leak or a known example, mask, placeholder,
//! identifier, vendored-bundle artefact, or one of ~20 other FP shapes.
//!
//! The decision is split across focused submodules so no single file
//! grows past the 500-line cap:
//!
//!   * [`api`]          - the three public entry points the scanner calls.
//!   * [`shape`]        - value-shape predicates (`looks_like_*`).
//!   * [`path_filter`]  - path-based predicates (vendored, scanner source).
//!   * [`doc_markers`]  - universal doc/placeholder/marker substring scans.
//!   * [`decision`]     - the unified `should_suppress_inner` decision tree.
//!   * [`decode`]       - base64-then-recheck helper.

mod api;
mod decision;
mod decode;
mod doc_markers;
mod path_filter;
mod shape;

pub(crate) use path_filter::looks_like_secret_scanner_source;
pub(crate) use path_filter::looks_like_vendored_minified_path;
pub(crate) use shape::{
    contains_uuid_v4_substring, looks_like_email_address,
    looks_like_punctuation_decorated_identifier, looks_like_pure_identifier,
    looks_like_regex_literal_tail, looks_like_scheme_prefixed_uri, looks_like_url_or_path_segment,
    looks_like_word_separated_identifier,
};

pub use api::{
    should_suppress_known_example_credential, should_suppress_known_example_credential_with_source,
    should_suppress_named_detector_finding,
};
