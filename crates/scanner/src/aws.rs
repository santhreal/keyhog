//! Offline AWS account-ID recovery + canary-token classification.
//!
//! The implementation is the fleet-canonical one in [`keyhog_core::aws`] — it
//! lives in `keyhog-core` because BOTH the scanner (which attaches the decoded
//! account / canary flag as finding metadata with no verify) and the verifier
//! (which refuses to send a live STS probe for a canary key) need it, and
//! `keyhog-core` is the one crate both depend on. Keeping the decode + canary
//! list in a single place means there is exactly one implementation, never a
//! fork (the same single-source-of-truth contract the `bogon` SSRF classifier
//! follows).
//!
//! This module re-exports the canonical API so existing
//! `keyhog_scanner::aws::…` call sites keep working unchanged.
//!
//! Algorithm + canary-list provenance: see [`keyhog_core::aws`] and
//! <https://trufflesecurity.com/blog/research-uncovers-aws-account-numbers-hidden-in-access-keys>
//! / <https://trufflesecurity.com/blog/canaries>.

pub use keyhog_core::finding_metadata;

// No tests here on purpose: this module only re-exports `keyhog_core::aws`, and
// `core/src` must stay free of inline test modules (KH-GAP-004). The decode /
// canary behaviour is covered once, at the source of truth, in
// `crates/core/tests/unit/aws.rs`.
