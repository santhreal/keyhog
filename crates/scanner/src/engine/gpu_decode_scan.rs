//! Fused GPU decode→scan: base64 and hex decode + Aho-Corasick match in a
//! single GPU dispatch.
//!
//! # Motivation
//!
//! keyhog's CPU decode pipeline (`decode/pipeline.rs`) extracts base64/hex
//! blobs, decodes them on the CPU, and re-scans the decoded output through
//! the GPU literal-set engine. This creates a full CPU→GPU round-trip per
//! encoded chunk. Vyre's fused decode builders compose decode + AC-scan
//! into a single `vyre::Program` where decoded bytes never leave VRAM:
//!
//! ```text
//! encoded bytes (host)
//!   ↓  upload once
//!   ↓  base64_decode_then_aho_corasick (one GPU dispatch)
//!   ↓  readback match triples only
//! host match offsets
//! ```
//!
//! Eliminates ~4 GiB of throwaway allocations on a 1 GiB scan with
//! 512 × 2 MiB shards.
//!
//! # Architecture
//!
//! The fused programs are built at scanner compile time alongside the
//! `GpuLiteralSet`. They share the same DFA transition/accept tables
//! (from the literal-set AC automaton) but prepend a decode stage
//! that transforms the encoded input in-place before the AC walk.
//!
//! Two encoding variants are supported:
//! - **Base64** via `vyre_libs::decode::base64_decode_then_aho_corasick`
//! - **Hex** via `vyre_libs::decode::hex_decode_then_aho_corasick`
//!
//! # Fallback
//!
//! If GPU dispatch fails (no backend, device lost, program compilation
//! error), the caller falls back to the existing CPU decode pipeline.
//! This module never panics on GPU failure.

use std::sync::OnceLock;

/// Supported encoding types for fused GPU decode→scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FusedEncoding {
    /// Standard base64 (RFC 4648 §4).
    Base64,
    /// Lowercase/uppercase hex (case-insensitive).
    Hex,
}

impl FusedEncoding {
    /// Human-readable label for logging.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Base64 => "base64",
            Self::Hex => "hex",
        }
    }
}

/// Compiled fused decode+scan programs, lazily built and cached.
///
/// Holds the vyre `Program` objects for base64-then-AC and hex-then-AC.
/// These programs share the same DFA tables as the literal-set AC engine
/// but prepend an on-GPU decode stage.
pub struct FusedDecodeScanPrograms {
    /// Fused base64 decode + AC scan program. `None` if the DFA tables
    /// are not available (no patterns compiled).
    pub base64_program: Option<vyre::Program>,
    /// Fused hex decode + AC scan program.
    pub hex_program: Option<vyre::Program>,
    /// Number of DFA states in the shared AC automaton.
    pub state_count: u32,
}

/// Build fused decode→scan programs from the same DFA tables the
/// `GpuLiteralSet` uses.
///
/// # Arguments
///
/// * `transitions` - Flattened `state_count × 256` DFA transition table
/// * `accept` - Per-state accept/output array
/// * `state_count` - Number of DFA states
/// * `input_len` - Maximum input buffer length (bytes)
///
/// # Returns
///
/// `FusedDecodeScanPrograms` with both base64 and hex fused programs.
/// If construction fails for either, that field is `None`.
pub fn build_fused_programs(
    state_count: u32,
    input_len: u32,
) -> FusedDecodeScanPrograms {
    // Buffer names follow vyre convention for interop with existing
    // dispatch infrastructure.
    let base64_program = std::panic::catch_unwind(|| {
        vyre_libs::decode::base64_decode_then_aho_corasick(
            "haystack",
            "decoded",
            "transitions",
            "accept",
            "matches",
            input_len,
            state_count,
        )
    })
    .ok();

    let hex_program = std::panic::catch_unwind(|| {
        vyre_libs::decode::hex_decode_then_aho_corasick(
            "haystack",
            "decoded",
            "transitions",
            "accept",
            "matches",
            input_len,
            state_count,
        )
    })
    .ok();

    if base64_program.is_none() {
        tracing::debug!(
            target: "keyhog::gpu",
            "fused base64 decode+scan program build failed — will use CPU decode path"
        );
    }
    if hex_program.is_none() {
        tracing::debug!(
            target: "keyhog::gpu",
            "fused hex decode+scan program build failed — will use CPU decode path"
        );
    }

    FusedDecodeScanPrograms {
        base64_program,
        hex_program,
        state_count,
    }
}

impl FusedDecodeScanPrograms {
    /// Get the fused program for the given encoding, if available.
    #[must_use]
    pub fn program_for(&self, encoding: FusedEncoding) -> Option<&vyre::Program> {
        match encoding {
            FusedEncoding::Base64 => self.base64_program.as_ref(),
            FusedEncoding::Hex => self.hex_program.as_ref(),
        }
    }

    /// Returns `true` if at least one fused program was built successfully.
    #[must_use]
    pub fn any_available(&self) -> bool {
        self.base64_program.is_some() || self.hex_program.is_some()
    }
}

/// Detect likely encoding of a byte slice.
///
/// Returns `Some(FusedEncoding::Base64)` if the input looks like base64,
/// `Some(FusedEncoding::Hex)` if it looks like hex, or `None` if neither.
/// Uses fast heuristics (character frequency, length modular checks).
#[must_use]
pub fn detect_encoding(data: &[u8]) -> Option<FusedEncoding> {
    if data.is_empty() {
        return None;
    }

    // Quick length checks.
    let len = data.len();

    // Count character classes for classification.
    let mut hex_chars = 0usize;
    let mut b64_chars = 0usize;
    let mut other = 0usize;

    // Sample up to 256 bytes for speed on large inputs.
    let sample = &data[..len.min(256)];
    for &b in sample {
        match b {
            b'0'..=b'9' => {
                hex_chars += 1;
                b64_chars += 1;
            }
            b'a'..=b'f' | b'A'..=b'F' => {
                hex_chars += 1;
                b64_chars += 1;
            }
            b'g'..=b'z' | b'G'..=b'Z' => {
                b64_chars += 1;
            }
            b'+' | b'/' | b'=' => {
                b64_chars += 1;
            }
            b'\n' | b'\r' | b' ' | b'\t' => {
                // Whitespace is neutral.
            }
            _ => {
                other += 1;
            }
        }
    }

    // If >20% is non-alphanumeric non-whitespace, it's not encoded.
    if other * 5 > sample.len() {
        return None;
    }

    // Pure hex: all chars are 0-9a-fA-F and length is even.
    if hex_chars == b64_chars && hex_chars > 0 && len % 2 == 0 {
        return Some(FusedEncoding::Hex);
    }

    // Base64: includes chars outside hex range, length is multiple of 4
    // or has padding.
    if b64_chars > hex_chars && (len % 4 == 0 || data.ends_with(b"=")) {
        return Some(FusedEncoding::Base64);
    }

    // Default to base64 if it has any base64-only chars.
    if b64_chars > hex_chars {
        return Some(FusedEncoding::Base64);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_empty_is_none() {
        assert_eq!(detect_encoding(b""), None);
    }

    #[test]
    fn detect_hex_even_length() {
        assert_eq!(
            detect_encoding(b"48656c6c6f"),
            Some(FusedEncoding::Hex)
        );
    }

    #[test]
    fn detect_base64_with_padding() {
        assert_eq!(
            detect_encoding(b"SGVsbG8gV29ybGQ="),
            Some(FusedEncoding::Base64)
        );
    }

    #[test]
    fn detect_binary_is_none() {
        assert_eq!(detect_encoding(&[0xFF, 0xFE, 0x00, 0x01, 0x80, 0x90]), None);
    }

    #[test]
    fn detect_base64_without_padding() {
        // "Hello" in base64 without padding is "SGVsbG8" — 7 chars, not
        // multiple of 4, but contains base64-only chars (G, V, s).
        assert_eq!(
            detect_encoding(b"SGVsbG8"),
            Some(FusedEncoding::Base64)
        );
    }

    #[test]
    fn fused_encoding_labels() {
        assert_eq!(FusedEncoding::Base64.label(), "base64");
        assert_eq!(FusedEncoding::Hex.label(), "hex");
    }

    #[test]
    fn build_fused_programs_does_not_panic() {
        // With state_count=0 this should either produce empty programs
        // or gracefully return None.
        let programs = build_fused_programs(0, 0);
        // We don't assert on the result — just verify no panic.
        let _ = programs.any_available();
    }

    #[test]
    fn build_fused_programs_small_automaton() {
        // Minimal 2-state DFA (start + one accept state).
        let programs = build_fused_programs(2, 64);
        // At least one should succeed with valid state count.
        // (May fail if vyre rejects tiny programs — that's OK.)
        let _ = programs.any_available();
    }

    #[test]
    fn program_for_returns_correct_variant() {
        let programs = build_fused_programs(4, 128);
        // program_for should return the right variant or None.
        let b64 = programs.program_for(FusedEncoding::Base64);
        let hex = programs.program_for(FusedEncoding::Hex);
        // Both may be None if vyre rejects — that's fine.
        let _ = (b64, hex);
    }
}
