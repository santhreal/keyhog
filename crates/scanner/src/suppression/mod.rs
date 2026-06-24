//! Suppression module: placeholder-credential and shape-gate suppression.

pub(crate) mod api;
pub(crate) mod decision;
pub(crate) mod decode;
pub(crate) mod doc_markers;
pub(crate) mod path_filter;
pub(crate) mod shape;
pub(crate) mod token_randomness;

pub(crate) use api::{
    NamedDetectorSuppressionCtx, detector_weak_anchor, suppress_named_detector_finding_stage,
};
