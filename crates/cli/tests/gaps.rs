//! Aggregated coverage-gap + multi-OS dogfood tests (generated).
//! One binary so the many gap modules link once, isolated from all_tests.
#![allow(clippy::all)]
#[path = "gaps/exit_codes_lockdown.rs"]
mod exit_codes_lockdown;
#[path = "gaps/flag_surface.rs"]
mod flag_surface;
#[path = "gaps/format_surface.rs"]
mod format_surface;
