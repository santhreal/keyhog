//! Suppression module: placeholder-credential and shape-gate suppression.

pub(crate) mod api;
pub(crate) mod decision;
pub(crate) mod decode;
pub(crate) mod doc_markers;
pub(crate) mod path_filter;
pub(crate) mod shape;
pub(crate) mod token_randomness;

#[cfg(test)]
pub(crate) use api::should_suppress_known_example_credential_with_source;
pub(crate) use api::{
    detector_weak_anchor, suppress_named_detector_finding, NamedDetectorSuppressionCtx,
};
#[cfg(test)]
pub(crate) use api::{
    should_suppress_known_example_credential, should_suppress_named_detector_finding,
};
