//! BPE "rare-not-random" precision gate for the entropy fallback.
//!
//! The entropy detectors (`entropy-token`, `entropy-api-key`, `entropy-password`)
//! flag high-entropy tokens. Their dominant false positives on real corpora are
//! NOT random noise but WORD-LIKE structured identifiers, dotted API paths like
//! `PInvoke.User32.WindowMessage.WM_SYSCOLORCHANGE`, XML/HTML fragments, camelCase
//! symbol names. These are high-entropy (mixed case, punctuation) yet compress
//! into a handful of common subword tokens, whereas a real secret (`ghp_a8Xk…`,
//! a base64 key) has no common merges and tokenizes into many short pieces.
//!
//! tiktoken `cl100k_base` bytes-per-token measures exactly that compressibility:
//! word-like text ≈ 3–5 bytes/token, random secrets ≈ 1.1–1.5 bytes/token. This
//! is the same broad signal Betterleaks exposes as `failsTokenEfficiency` using
//! its embedded `cl100k_base` tokenizer. Betterleaks combines byte-length/token
//! thresholds with word-list and short-value branches; KeyHog deliberately uses
//! a bytes/token score whose ceiling is detector-owned TOML policy.
//! Suppressing entropy candidates ABOVE the threshold is a large CredData precision win (offline A/B
//! on a real scan, scored by the bench: F1 0.3684 → 0.4236, FP 8185 → 4260 for
//! only −55 TP at the 2.2 peak). The heuristic word-like gates that already exist
//! (English-prose, pure-identifier, word-separated) miss the dotted API-path and
//! XML classes; this principled measure catches them.
//!
//! Gated on `feature = "entropy"` (the tokenizer dep rides that feature).

use std::sync::LazyLock;

use tiktoken_rs::{cl100k_base, CoreBPE};

/// The compiled default bytes-per-token suppression bound. A candidate whose
/// `cl100k_base` bytes-per-token is STRICTLY GREATER than the ACTIVE bound is
/// treated as word-like (non-secret) and suppressed. 2.2 is the empirical
/// CredData F1 peak (see the module doc A/B); values 2.0–2.5 are all strong
/// (F1 ≈ 0.421–0.424).
///
/// The VALUE has exactly one owner, [`keyhog_core::DEFAULT_ENTROPY_BPE_MAX_BYTES_PER_TOKEN`]
/// it lives in the lower `keyhog-core` crate so `ScanConfig` can default to it
/// without a scanner↔core cycle. This is the historical name re-bound to that one
/// owner for the gate's compiled default and the tests below; a per-scan override
/// (`ScanConfig::entropy_bpe_max_bytes_per_token`, Tier-A TOML + CLI) is threaded
/// into [`is_word_like_low_bpe`] at the two call sites, so operators trade
/// precision for recall per corpus without a code change.
#[cfg(test)]
pub(crate) const ENTROPY_BPE_MAX_BYTES_PER_TOKEN: f64 =
    keyhog_core::DEFAULT_ENTROPY_BPE_MAX_BYTES_PER_TOKEN;

/// Lazily-built cl100k_base tokenizer. The ranks are embedded in the crate, so
/// this is a pure decode with no I/O; built once on first entropy candidate that
/// survives the cheaper shape gates.
static CL100K: LazyLock<CoreBPE> =
    LazyLock::new(|| cl100k_base().expect("tiktoken cl100k_base ranks are embedded in the crate"));

/// UTF-8 bytes per BPE token for `s` under cl100k_base. Higher = more
/// compressible = more word-like. `cl100k_base` is byte-level, so using Unicode
/// scalar counts would artificially lower non-ASCII text and let ordinary
/// localized prose bypass the gate. Returns `0.0` for empty input.
pub(crate) fn bytes_per_token(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let tokens = CL100K.encode_ordinary(s).len();
    if tokens == 0 {
        return 0.0;
    }
    s.len() as f64 / tokens as f64
}

/// True iff `s` is word-like (compresses into few common subwords) under the
/// given `max_bytes_per_token` bound, i.e. a probable entropy false positive
/// that should be suppressed. The bound is the per-scan
/// `ScanConfig::entropy_bpe_max_bytes_per_token` (Tier-A), which defaults to
/// `keyhog_core::DEFAULT_ENTROPY_BPE_MAX_BYTES_PER_TOKEN`; the predicate itself owns no threshold so
/// the config value is the single runtime authority.
pub(crate) fn is_word_like_low_bpe(s: &str, max_bytes_per_token: f64) -> bool {
    bytes_per_token(s) > max_bytes_per_token
}

#[cfg(test)]
#[path = "../../tests/unit/entropy_bpe.rs"]
mod tests;
