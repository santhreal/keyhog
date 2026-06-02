//! Aggregated coverage-gap + multi-OS dogfood tests (generated).
//! One binary so the many gap modules link once, isolated from all_tests.
#![allow(clippy::all)]
#[path = "gaps/redaction_dedup.rs"]
mod redaction_dedup;
#[path = "gaps/report_html_xss.rs"]
mod report_html_xss;
#[path = "gaps/report_json_sarif.rs"]
mod report_json_sarif;
#[path = "gaps/report_text_csv_injection.rs"]
mod report_text_csv_injection;
#[path = "gaps/spec_validate_merkle.rs"]
mod spec_validate_merkle;
