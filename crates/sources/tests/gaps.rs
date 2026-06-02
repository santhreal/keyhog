//! Aggregated coverage-gap + multi-OS dogfood tests (generated).
//! One binary so the many gap modules link once, isolated from all_tests.
#![allow(clippy::all)]
#[path = "gaps/filesystem_source.rs"]
mod filesystem_source;
#[path = "gaps/git_source.rs"]
mod git_source;
