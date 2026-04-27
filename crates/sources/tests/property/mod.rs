//! Property-based fuzz tests for source backends.
//!
//! Random file content + random extensions should never crash the
//! source iteration. This catches the class of bugs where a corrupt
//! `.gz` / `.zst` / weird-extension file shape panics inside
//! ziftsieve / mmap / gix.

mod filesystem_fuzz;
