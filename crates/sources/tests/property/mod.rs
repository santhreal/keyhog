//! Property-based fuzz tests for source backends.
//!
//! Random file content + random extensions should never crash the
//! source iteration. This catches the class of bugs where a corrupt
//! `.gz` / `.zst` / weird-extension file shape panics inside
//! ziftsieve / mmap / gix.

mod archive_entry_name_traversal_proptest;
mod binary_strings_extraction_proptest;
mod default_excludes_rule_validation_proptest;
mod filesystem_fuzz;
#[cfg(feature = "github")]
mod hosted_git_validator_adversarial_proptest;
#[cfg(any(feature = "web", feature = "github", feature = "s3"))]
mod http_fuzz;
mod magic_byte_signatures_proptest;
#[cfg(feature = "web")]
mod url_redaction_no_leak_proptest;
mod window_slicer_proptest;
