//! Value-pinning tests for the shared bounded-cache eviction primitives
//! (`cache::oldest_eviction_batch` + `cache::evict_oldest_dashmap_entries`) that
//! back the DNS-resolution and pinned-client caches. Before this the only
//! coverage was `error_path/ssrf_dns_cache_ttl_boundary.rs`'s
//! `ssrf_dns_cache_max_entries_cap_exists`, which re-declared a LOCAL
//! `const DNS_CACHE_MAX_ENTRIES = 4096` and asserted `> 0`: a tautology that
//! shadows the real owner and proves nothing about the eviction ALGORITHM (which
//! oldest entries go, how many, whether the batch can be zero). These pin the
//! actual behavior: evict the OLDEST `count`, keep the newest, and never compute
//! a zero batch (which would make a cap-hit eviction a silent no-op and let the
//! cache grow past its bound forever (an unbounded-memory bug)).

use keyhog_verifier::testing::{
    evict_oldest_dashmap_survivors_for_test as survivors, oldest_eviction_batch,
};

// ── oldest_eviction_batch: 1/8 of cap, floored at 1 ──────────────────────────

#[test]
fn oldest_eviction_batch_is_one_eighth_of_cap() {
    assert_eq!(oldest_eviction_batch(4096), 512);
    assert_eq!(oldest_eviction_batch(16), 2);
    assert_eq!(oldest_eviction_batch(8), 1);
}

/// The `.max(1)` floor is load-bearing: a batch of 0 would make a cap-hit
/// eviction a silent no-op, so a cache stuck exactly at its cap would grow one
/// entry per insert forever (unbounded memory). Every sub-8 cap, including the
/// degenerate 0 and 1 (must still evict at least one entry).
#[test]
fn oldest_eviction_batch_never_returns_zero() {
    assert_eq!(oldest_eviction_batch(7), 1);
    assert_eq!(oldest_eviction_batch(1), 1);
    assert_eq!(oldest_eviction_batch(0), 1);
}

// ── evict_oldest_dashmap_entries: removes exactly the `count` OLDEST ──────────

/// Entry key `k` is stamped `base + k`s, so key `0` is the oldest. Evicting the
/// 4 oldest from ages `0..16` must remove keys `0,1,2,3` and keep `4..16`: this
/// is the whole point of the primitive (drop oldest, not newest, not wholesale).
#[test]
fn evict_oldest_removes_the_count_oldest_and_keeps_the_newest() {
    let ages: Vec<u64> = (0..16).collect();
    assert_eq!(survivors(&ages, 4), (4..16).collect::<Vec<u64>>());
}

/// A zero count is a no-op, nothing is evicted (guards the early return and
/// mirrors the `oldest_eviction_batch(…) == 0`-can't-happen contract above).
#[test]
fn evict_oldest_count_zero_is_a_noop() {
    assert_eq!(survivors(&[5, 1, 3], 0), vec![1, 3, 5]);
}

/// When the requested count meets or exceeds the map size the whole map is
/// evicted (the `count < len` partition guard is skipped and every entry drops).
#[test]
fn evict_oldest_count_at_or_above_len_evicts_everything() {
    assert_eq!(survivors(&[5, 1, 3], 3), Vec::<u64>::new());
    assert_eq!(survivors(&[5, 1, 3], 9), Vec::<u64>::new());
}

/// The two primitives compose to the real bounded-cache contract: at a 4096 cap
/// the batch is 512, so evicting a full-cap map leaves exactly `4096 - 512`
/// entries (the oldest 512 keys (`0..512`) gone, the newest retained).
#[test]
fn batch_and_evict_compose_to_the_bounded_cache_contract() {
    let cap = 4096usize;
    let batch = oldest_eviction_batch(cap);
    let ages: Vec<u64> = (0..cap as u64).collect();
    let remaining = survivors(&ages, batch);
    assert_eq!(remaining.len(), cap - batch);
    assert_eq!(remaining.first().copied(), Some(batch as u64));
    assert_eq!(remaining.last().copied(), Some(cap as u64 - 1));
}
