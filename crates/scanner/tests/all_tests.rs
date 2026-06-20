#![allow(clippy::needless_borrow, clippy::needless_update, clippy::useless_vec)]

pub mod concurrent;
pub mod contract;
pub mod integration;
pub mod regression;
#[path = "regression_creddata_hex_key_recall.rs"]
pub mod regression_creddata_hex_key_recall;
#[path = "regression_encoded_benign_text_suppression.rs"]
pub mod regression_encoded_benign_text_suppression;
#[path = "regression_reverse_integrity_decoy_suppression.rs"]
pub mod regression_reverse_integrity_decoy_suppression;
#[path = "regression_structured_hcl_generic_recall.rs"]
pub mod regression_structured_hcl_generic_recall;
