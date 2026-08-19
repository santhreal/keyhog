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
use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::num::NonZeroUsize;
use std::sync::LazyLock;

use lru::LruCache;
use zeroize::Zeroizing;

#[cfg(test)]
pub(crate) const ENTROPY_BPE_MAX_BYTES_PER_TOKEN: f64 =
    keyhog_core::DEFAULT_ENTROPY_BPE_MAX_BYTES_PER_TOKEN;

const CL100K_PATTERN: &str = "'(?i:[sdmt]|ll|ve|re)|[^\\r\\n\\p{L}\\p{N}]?+\\p{L}++|\\p{N}{1,3}+| ?[^\\s\\p{L}\\p{N}]++[\\r\\n]*+|\\s++$|\\s*[\\r\\n]|\\s+(?!\\S)|\\s";
static CL100K_REGEX: LazyLock<fancy_regex::Regex> = LazyLock::new(|| {
    fancy_regex::Regex::new(CL100K_PATTERN)
        .expect("cl100k split regex is a validated compile-time constant")
});
static CL100K_TOKEN_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/cl100k_token_bytes.bin"));
static CL100K_OFFSETS: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/cl100k_offsets.bin"));
static CL100K_RANKS: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/cl100k_ranks.bin"));
static CL100K_PREFIXES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/cl100k_prefixes.bin"));

#[inline]
fn packed_u32(bytes: &[u8], index: usize) -> u32 {
    let start = index * std::mem::size_of::<u32>();
    u32::from_le_bytes(
        bytes[start..start + std::mem::size_of::<u32>()]
            .try_into()
            .expect("build-generated cl100k table has complete u32 rows"),
    )
}

fn token_rank(token: &[u8]) -> Option<u32> {
    let first = *token.first()? as usize;
    let mut low = packed_u32(CL100K_PREFIXES, first) as usize;
    let mut high = packed_u32(CL100K_PREFIXES, first + 1) as usize;
    while low < high {
        let middle = low + (high - low) / 2;
        let start = packed_u32(CL100K_OFFSETS, middle) as usize;
        let end = packed_u32(CL100K_OFFSETS, middle + 1) as usize;
        match CL100K_TOKEN_BYTES[start..end].cmp(token) {
            Ordering::Less => low = middle + 1,
            Ordering::Greater => high = middle,
            Ordering::Equal => return Some(packed_u32(CL100K_RANKS, middle)),
        }
    }
    None
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct Merge {
    start: usize,
    rank: u32,
}

impl Ord for Merge {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .rank
            .cmp(&self.rank)
            .then_with(|| other.start.cmp(&self.start))
    }
}

impl PartialOrd for Merge {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

struct MergeState {
    prev: usize,
    end: usize,
    next_end: usize,
    next_rank: u32,
}

fn byte_pair_count_large(piece: &[u8]) -> usize {
    let mut state = Vec::with_capacity(piece.len());
    state.push(MergeState {
        prev: usize::MAX,
        end: 1,
        next_end: 2,
        next_rank: u32::MAX,
    });
    let mut heap = BinaryHeap::with_capacity(piece.len());
    for index in 0..piece.len() - 1 {
        if let Some(rank) = token_rank(&piece[index..index + 2]) {
            heap.push(Merge { start: index, rank });
            state[index].next_rank = rank;
        }
        state.push(MergeState {
            prev: index,
            end: index + 2,
            next_end: index + 3,
            next_rank: u32::MAX,
        });
    }

    let potential_merge = |state: &mut Vec<MergeState>,
                           heap: &mut BinaryHeap<Merge>,
                           start: usize,
                           next_end: usize| {
        state[start].next_end = next_end;
        state[start].next_rank = u32::MAX;
        if next_end <= piece.len() {
            if let Some(rank) = token_rank(&piece[start..next_end]) {
                heap.push(Merge { start, rank });
                state[start].next_rank = rank;
            }
        }
    };
    while let Some(left) = heap.pop() {
        if left.rank != state[left.start].next_rank {
            continue;
        }
        let left_start = left.start;
        let right_start = state[left_start].end;
        let right_end = state[left_start].next_end;
        let right_next_end = state[right_start].next_end;
        state[left_start].end = right_end;
        potential_merge(&mut state, &mut heap, left_start, right_next_end);
        if right_end < state.len() {
            state[right_end].prev = left_start;
        }
        if left_start > 0 {
            let previous_start = state[left_start].prev;
            potential_merge(&mut state, &mut heap, previous_start, right_end);
        }
        state[right_start].next_rank = u32::MAX;
    }

    let mut count = 0usize;
    let mut index = 0usize;
    while index < state.len() {
        count += 1;
        index = state[index].end;
    }
    count
}

fn byte_pair_count_small(piece: &[u8]) -> usize {
    let mut parts = Vec::with_capacity(piece.len() + 1);
    let mut minimum = (u32::MAX, usize::MAX);
    for index in 0..piece.len() - 1 {
        // LAW10: an absent BPE rank is the algorithm's u32::MAX no-merge sentinel, not a degraded tokenizer path.
        let rank = token_rank(&piece[index..index + 2]).unwrap_or(u32::MAX);
        if rank < minimum.0 {
            minimum = (rank, index);
        }
        parts.push((index, rank));
    }
    parts.push((piece.len() - 1, u32::MAX));
    parts.push((piece.len(), u32::MAX));

    while minimum.0 != u32::MAX {
        let index = minimum.1;
        if index > 0 {
            parts[index - 1].1 = if index + 2 < parts.len() {
                // LAW10: an absent BPE rank is the algorithm's u32::MAX no-merge sentinel.
                token_rank(&piece[parts[index - 1].0..parts[index + 2].0]).unwrap_or(u32::MAX)
            } else {
                u32::MAX
            };
        }
        parts[index].1 = if index + 3 < parts.len() {
            // LAW10: an absent BPE rank is the algorithm's u32::MAX no-merge sentinel.
            token_rank(&piece[parts[index].0..parts[index + 3].0]).unwrap_or(u32::MAX)
        } else {
            u32::MAX
        };
        parts.remove(index + 1);
        minimum = parts[..parts.len() - 1]
            .iter()
            .enumerate()
            .map(|(index, &(_, rank))| (rank, index))
            .min()
            // LAW10: an empty candidate range terminates with the documented no-merge sentinel.
            .unwrap_or((u32::MAX, usize::MAX));
    }
    parts.len() - 1
}

fn byte_pair_count(piece: &[u8]) -> usize {
    if piece.len() == 1 || token_rank(piece).is_some() {
        1
    } else if piece.len() < 100 {
        byte_pair_count_small(piece)
    } else {
        byte_pair_count_large(piece)
    }
}

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
        LruCache::new(NonZeroUsize::MIN)
    );
    #[cfg(test)]
    static TOKENIZER_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn token_count_uncached(s: &str) -> usize {
    #[cfg(test)]
    TOKENIZER_CALLS.with(|calls| calls.set(calls.get().saturating_add(1)));
    CL100K_REGEX
        .find_iter(s)
        .map(|result| {
            let piece = result
                .expect("cl100k split regex cannot fail after successful construction")
                .as_str()
                .as_bytes();
            byte_pair_count(piece)
        })
        .sum()
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
        let mut cache = cache.borrow_mut();
        crate::fragment_cache::grow_lru_for_workload(&mut cache, TOKEN_CACHE_ENTRIES);
        cache.put(
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
