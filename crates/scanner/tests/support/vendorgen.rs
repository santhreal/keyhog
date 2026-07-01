//! Canonical seeded-random generators + scan helpers for vendor recall-lock
//! runners.
//!
//! The per-vendor recall locks (email, observability/CI, edge-platform, AI/LLM,
//! messaging, …) each need the same three things: (1) a deterministic way to
//! synthesize a credential body of an exact length and alphabet — so a test
//! never embeds a real secret and always reproduces byte-for-byte — (2) a scan
//! wrapper that returns `(detector_id, credential)` pairs, and (3) predicates
//! that ask whether a value surfaces under a specific detector / any of a set /
//! at all. Those helpers were previously copy-pasted into every runner; this
//! module is the single owner.
//!
//! The generator is a deterministic LCG (the SplitMix64 seed-mix feeding a PCG
//! multiplier), NOT a cryptographic RNG — its only job is to produce a stable,
//! high-alphabet-coverage string per `(n, seed, charset)`. `Math`/`rand`-free so
//! it works identically on every host and never varies a fixture.

use keyhog_core::Chunk;
use keyhog_scanner::CompiledScanner;

use super::contracts::{make_chunk, scanner};

/// Deterministic string of `n` characters drawn from `charset`. The same
/// `(n, seed, charset)` always yields the same string; different seeds yield
/// independent strings. `charset` must be non-empty.
pub fn gen(n: usize, seed: u64, charset: &[u8]) -> String {
    assert!(!charset.is_empty(), "gen charset must be non-empty");
    let m = charset.len() as u64;
    // SplitMix64-style seed mix so nearby seeds start far apart in the stream.
    let mut s = seed
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(0x2545_F491_4F6C_DD1D);
    (0..n)
        .map(|_| {
            s = s
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            charset[((s >> 33) % m) as usize] as char
        })
        .collect()
}

pub const HEX: &[u8] = b"0123456789abcdef";
pub const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
pub const LCNUM: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
pub const UPPERNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
pub const DIGITS: &[u8] = b"0123456789";

/// `n` lowercase hex characters (`[0-9a-f]`).
pub fn hex(n: usize, seed: u64) -> String {
    gen(n, seed, HEX)
}
/// `n` mixed-case alphanumerics (`[A-Za-z0-9]`).
pub fn alnum(n: usize, seed: u64) -> String {
    gen(n, seed, ALNUM)
}
/// `n` lowercase alphanumerics (`[a-z0-9]`).
pub fn lcnum(n: usize, seed: u64) -> String {
    gen(n, seed, LCNUM)
}
/// `n` uppercase alphanumerics (`[A-Z0-9]`).
pub fn uppernum(n: usize, seed: u64) -> String {
    gen(n, seed, UPPERNUM)
}
/// `n` decimal digits (`[0-9]`).
pub fn digits(n: usize, seed: u64) -> String {
    gen(n, seed, DIGITS)
}

/// A canonical `8-4-4-4-12` lowercase-hex UUID string.
pub fn uuid(seed: u64) -> String {
    format!(
        "{}-{}-{}-{}-{}",
        hex(8, seed),
        hex(4, seed.wrapping_add(1)),
        hex(4, seed.wrapping_add(2)),
        hex(4, seed.wrapping_add(3)),
        hex(12, seed.wrapping_add(4))
    )
}

/// Scan `text` as a synthetic `.env`-style source and return every match as an
/// `(detector_id, credential)` pair. Compiles a fresh scanner per call to match
/// the parallel-safe pattern of [`super::contracts::scanner`].
pub fn scan_ids(text: &str) -> Vec<(String, String)> {
    let s: CompiledScanner = scanner();
    let chunk: Chunk = make_chunk(text, "source", "vendor.env");
    s.clear_fragment_cache();
    s.scan(&chunk)
        .into_iter()
        .map(|m| (m.detector_id.to_string(), m.credential.to_string()))
        .collect()
}

/// True when `needle` surfaces under exactly the named `detector`.
pub fn surfaces_under(text: &str, detector: &str, needle: &str) -> bool {
    scan_ids(text)
        .iter()
        .any(|(id, cred)| id == detector && cred.contains(needle))
}

/// True when `needle` surfaces under any detector in `detectors` — used where a
/// value is validly detected by one of several overlapping vendor labels.
pub fn surfaces_under_any(text: &str, detectors: &[&str], needle: &str) -> bool {
    scan_ids(text)
        .iter()
        .any(|(id, cred)| detectors.contains(&id.as_str()) && cred.contains(needle))
}

/// True when the named `detector` produces any match for `text`.
pub fn fires(text: &str, detector: &str) -> bool {
    scan_ids(text).iter().any(|(id, _)| id == detector)
}

/// True when any detector in `detectors` produces a match for `text`.
pub fn fires_any(text: &str, detectors: &[&str]) -> bool {
    scan_ids(text)
        .iter()
        .any(|(id, _)| detectors.contains(&id.as_str()))
}

/// Recall predicate: `needle` is detected under *some* detector, regardless of
/// which label wins value-dedup. Use for generic-shape secrets whose vendor
/// label collides with a generic detector (see the vendor-label-collision note).
pub fn detected(text: &str, needle: &str) -> bool {
    scan_ids(text).iter().any(|(_, cred)| cred.contains(needle))
}
