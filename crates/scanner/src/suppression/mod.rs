//! Suppression module: placeholder-credential and shape-gate suppression.

pub(crate) mod api;
pub(crate) mod decision;
pub(crate) mod decode;
mod detector_policy;
pub(crate) mod doc_markers;
pub(crate) mod path_filter;
pub(crate) mod shape;
pub(crate) mod token_randomness;

pub(crate) use api::{
    detector_weak_anchor, detector_weak_anchor_base, suppress_named_detector_finding_stage,
    NamedDetectorSuppressionCtx, WeakAnchorBase,
};
pub(crate) use detector_policy::DetectorSuppressionPolicy;
