//! Adversarial coverage for source backends — bomb-prevention,
//! malformed inputs, evasions.
//!
//! Mirrors the audit release-2026-04-26 hardening: gzip/zstd 4× budget,
//! per-archive-entry size cap, dropped io_uring single-op path, etc.

mod gzip_bomb_caps;
