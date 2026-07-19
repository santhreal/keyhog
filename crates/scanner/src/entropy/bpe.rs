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

use std::cell::RefCell;
use std::num::NonZeroUsize;
use std::sync::LazyLock;

use lru::LruCache;
use tiktoken_rs::{cl100k_base, CoreBPE};
use zeroize::Zeroizing;

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

/// Bound retained candidate material to at most 64 KiB per scanner worker.
/// Longer values still tokenize exactly but do not remain resident.
const TOKEN_CACHE_ENTRIES: usize = 256;
const TOKEN_CACHE_MAX_VALUE_BYTES: usize = 256;

struct TokenCountCacheEntry {
    /// Exact bytes make an FNV collision a miss rather than a recall-affecting
    /// cached verdict. `Zeroizing` scrubs candidate material on replacement,
    /// eviction, thread exit, and explicit test reset.
    value: Zeroizing<Box<[u8]>>,
    tokens: usize,
}

thread_local! {
    static TOKEN_COUNT_CACHE: RefCell<LruCache<u64, TokenCountCacheEntry>> = RefCell::new(
        LruCache::new(
            NonZeroUsize::new(TOKEN_CACHE_ENTRIES).unwrap_or(NonZeroUsize::MIN)
        )
    );
    #[cfg(test)]
    static TOKENIZER_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn token_count_uncached(s: &str) -> usize {
    #[cfg(test)]
    TOKENIZER_CALLS.with(|calls| calls.set(calls.get().saturating_add(1)));
    CL100K.encode_ordinary(s).len()
}

fn token_count_with_key(s: &str, key: u64) -> usize {
    if s.len() > TOKEN_CACHE_MAX_VALUE_BYTES {
        return token_count_uncached(s);
    }
    if let Some(tokens) = TOKEN_COUNT_CACHE.with(|cache| {
        cache.borrow_mut().get(&key).and_then(|entry| {
            let cached: &[u8] = entry.value.as_ref().as_ref();
            (cached == s.as_bytes()).then_some(entry.tokens)
        })
    }) {
        return tokens;
    }

    let tokens = token_count_uncached(s);
    TOKEN_COUNT_CACHE.with(|cache| {
        cache.borrow_mut().put(
            key,
            TokenCountCacheEntry {
                value: Zeroizing::new(s.as_bytes().to_vec().into_boxed_slice()),
                tokens,
            },
        );
    });
    tokens
}

fn token_count(s: &str) -> usize {
    token_count_with_key(s, crate::util_hash::hash_fast(s.as_bytes()))
}

/// UTF-8 bytes per BPE token for `s` under cl100k_base. Higher = more
/// compressible = more word-like. `cl100k_base` is byte-level, so using Unicode
/// scalar counts would artificially lower non-ASCII text and let ordinary
/// localized prose bypass the gate. Returns `0.0` for empty input.
pub(crate) fn bytes_per_token(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let tokens = token_count(s);
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
fn reset_token_cache_for_test() {
    TOKEN_COUNT_CACHE.with(|cache| cache.borrow_mut().clear());
    TOKENIZER_CALLS.with(|calls| calls.set(0));
}

#[cfg(test)]
fn tokenizer_calls_for_test() -> usize {
    TOKENIZER_CALLS.with(std::cell::Cell::get)
}

#[cfg(test)]
#[path = "../../tests/unit/entropy_bpe.rs"]
mod tests;
