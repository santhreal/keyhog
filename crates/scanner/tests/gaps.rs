//! Aggregated coverage-gap + multi-OS dogfood tests (generated).
//! One binary so the many gap modules link once, isolated from all_tests.
#![allow(clippy::all)]
#[path = "gaps/checksum_github.rs"]
mod checksum_github;
#[path = "gaps/checksum_gitlab_npm_slack_stripe.rs"]
mod checksum_gitlab_npm_slack_stripe;
#[path = "gaps/confidence_floor_policy.rs"]
mod confidence_floor_policy;
#[path = "gaps/decode_pipeline_layers.rs"]
mod decode_pipeline_layers;
#[path = "gaps/detector_precision_decoys.rs"]
mod detector_precision_decoys;
#[path = "gaps/detector_recall_prefixes.rs"]
mod detector_recall_prefixes;
#[path = "gaps/engine_backend_parity.rs"]
mod engine_backend_parity;
#[path = "gaps/multiline_reassembly.rs"]
mod multiline_reassembly;
#[path = "gaps/scan_filters_grouped.rs"]
mod scan_filters_grouped;
#[path = "gaps/unicode_homoglyph_matrix.rs"]
mod unicode_homoglyph_matrix;
