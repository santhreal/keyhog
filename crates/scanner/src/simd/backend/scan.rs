use super::HsScanner;
use hyperscan::{Matching, Scratch};
use std::cell::RefCell;
use std::collections::HashMap;
use std::mem::MaybeUninit;
use std::sync::{Arc, Weak};

struct CachedScratch {
    owner: Weak<()>,
    scratch: Scratch,
}

const SCRATCH_TLS_PRUNE_THRESHOLD: usize = 32;

thread_local! {
    static SCRATCH_TLS: RefCell<HashMap<(u64, usize), CachedScratch>> =
        RefCell::new(HashMap::new());
}

#[cfg(test)]
thread_local! {
    static FAIL_NEXT_SCRATCH_ALLOCATION: std::cell::Cell<Option<usize>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn fail_next_scratch_allocation_for_test(shard_idx: usize) {
    FAIL_NEXT_SCRATCH_ALLOCATION.with(|target| target.set(Some(shard_idx)));
}

#[cfg(test)]
fn take_injected_scratch_failure(shard_idx: usize) -> bool {
    FAIL_NEXT_SCRATCH_ALLOCATION.with(|target| {
        if target.get() == Some(shard_idx) {
            target.set(None);
            true
        } else {
            false
        }
    })
}

fn allocate_scratch(
    scanner_id: u64,
    shard_idx: usize,
    shard: &super::Shard,
) -> Result<Scratch, String> {
    #[cfg(test)]
    if take_injected_scratch_failure(shard_idx) {
        return Err(format!(
            "hyperscan scratch on-demand growth failed for scanner {scanner_id} \
             shard {shard_idx}: injected allocation failure"
        ));
    }

    shard.db.alloc_scratch().map_err(|error| {
        format!(
            "hyperscan scratch on-demand growth failed for scanner {scanner_id} \
             shard {shard_idx}: {error}"
        )
    })
}

fn take_scratch(
    scanner_id: u64,
    shard_idx: usize,
    shard: &super::Shard,
    owner: &Arc<()>,
) -> Result<Scratch, String> {
    let key = (scanner_id, shard_idx);
    if let Some(cached) = SCRATCH_TLS.with(|tls| tls.borrow_mut().remove(&key)) {
        // The monotonic scanner id is the fast cache key. Checking the Arc
        // address as well makes a wrapped/reused id fail safe instead of
        // handing Hyperscan scratch to a different database.
        if std::ptr::eq(cached.owner.as_ptr(), Arc::as_ptr(owner)) {
            return Ok(cached.scratch);
        }
    }
    debug_assert!(Arc::strong_count(owner) > 0);
    SCRATCH_TLS.with(|tls| prune_dead_scanner_scratch(&mut tls.borrow_mut()));
    // The first scan on this thread for this (scanner, shard) allocates a
    // scratch lazily. The scratch is bound to this shard's database and is
    // returned to thread-local storage after the scan, so every later request
    // on this thread reuses it lock-free. If more distinct threads scan a
    // shard than the executor width (`--batch-pipeline` reader + fused-dispatch
    // threads on top of rayon), each new thread pays the one-time allocation
    // exactly once and then caches its own scratch. This is the same precise
    // full-chunk scan; there is no silent partial or over-marked degrade.
    allocate_scratch(scanner_id, shard_idx, shard)
}

fn put_scratch(scanner_id: u64, shard_idx: usize, owner: &Arc<()>, scratch: Scratch) {
    let key = (scanner_id, shard_idx);
    SCRATCH_TLS.with(|tls| {
        let mut tls = tls.borrow_mut();
        if tls.len() >= SCRATCH_TLS_PRUNE_THRESHOLD {
            prune_dead_scanner_scratch(&mut tls);
        }
        tls.insert(
            key,
            CachedScratch {
                owner: Arc::downgrade(owner),
                scratch,
            },
        );
    });
}

fn prune_dead_scanner_scratch(tls: &mut HashMap<(u64, usize), CachedScratch>) {
    tls.retain(|_, cached| cached.owner.strong_count() > 0);
}

pub(super) fn purge_scanner_scratch(scanner_id: u64) {
    SCRATCH_TLS.with(|tls| {
        tls.borrow_mut()
            .retain(|(cached_scanner_id, _), _| *cached_scanner_id != scanner_id);
    });
}

/// A call's complete set of per-shard scratches, acquired before the first
/// Hyperscan callback can become observable.
///
/// Keeping the fixed-size storage on the stack preserves the callback hot
/// path's no-allocation contract. If any lazy allocation fails, `Drop` returns
/// the already-acquired scratches to TLS and the caller receives an error
/// before any finding state has been mutated.
struct ScratchBatch<'a> {
    scanner_id: u64,
    owner: &'a Arc<()>,
    initialized: usize,
    slots: [MaybeUninit<Scratch>; super::MAX_COMPILE_SHARDS],
}

impl<'a> ScratchBatch<'a> {
    fn acquire(scanner: &'a HsScanner) -> Result<Self, String> {
        if scanner.shards.len() > super::MAX_COMPILE_SHARDS {
            return Err(format!(
                "hyperscan scanner has {} shards, exceeding scratch batch capacity {}",
                scanner.shards.len(),
                super::MAX_COMPILE_SHARDS
            ));
        }

        let mut batch = Self {
            scanner_id: scanner.scanner_id,
            owner: &scanner.scratch_owner,
            initialized: 0,
            slots: std::array::from_fn(|_| MaybeUninit::uninit()),
        };
        for (shard_idx, shard) in scanner.shards.iter().enumerate() {
            let scratch =
                take_scratch(scanner.scanner_id, shard_idx, shard, &scanner.scratch_owner)?;
            batch.slots[shard_idx].write(scratch);
            batch.initialized += 1;
        }
        Ok(batch)
    }

    #[inline]
    fn scratch(&self, shard_idx: usize) -> &Scratch {
        assert!(
            shard_idx < self.initialized,
            "shard_idx {shard_idx} out of range (initialized {})",
            self.initialized
        );
        // SAFETY: `acquire` initializes slots contiguously and returns `Ok`
        // only after every scanner shard has a scratch. Scan loops use shard
        // indices from that same scanner.
        unsafe { self.slots.get_unchecked(shard_idx).assume_init_ref() }
    }
}

impl Drop for ScratchBatch<'_> {
    fn drop(&mut self) {
        for shard_idx in 0..self.initialized {
            // SAFETY: the prefix `0..initialized` contains exactly the slots
            // written by `acquire`, and each is read only here during Drop.
            let scratch = unsafe { self.slots.get_unchecked(shard_idx).assume_init_read() };
            put_scratch(self.scanner_id, shard_idx, self.owner, scratch);
        }
    }
}

#[cfg(test)]
fn current_thread_scratch_count_for_test(scanner_id: u64) -> usize {
    SCRATCH_TLS.with(|tls| {
        tls.borrow()
            .keys()
            .filter(|(cached_scanner_id, _)| *cached_scanner_id == scanner_id)
            .count()
    })
}

impl HsScanner {
    /// Scan `text`, streaming global pattern ids and byte offsets to `on_match`.
    ///
    /// All shard scratches are acquired before the callback can run, so lazy
    /// scratch allocation failure has no partial callback side effects. A
    /// Hyperscan execution error can occur after callbacks; on `Err`, callers
    /// must discard all callback-derived state from this call.
    pub(crate) fn scan_matches_result(
        &self,
        text: &[u8],
        mut on_match: impl FnMut(usize, usize, usize),
    ) -> Result<(), String> {
        // The match callback exposes the GLOBAL pattern id (set on
        // `Pattern.id` at compile), so the union over shards is identical
        // to a single all-patterns database's output - offsets are in the
        // original byte space, no remapping.
        let scratches = ScratchBatch::acquire(self)?;
        for (shard_idx, shard) in self.shards.iter().enumerate() {
            if let Err(error) = shard.db.scan(
                text,
                scratches.scratch(shard_idx),
                |id, from, to, _flags| {
                    on_match(id as usize, from as usize, to as usize);
                    Matching::Continue
                },
            ) {
                return Err(format!(
                    "hyperscan scan failed while executing shard {shard_idx} of {}; \
                     callback output from this call is incomplete and must be discarded: {error}",
                    self.shards.len()
                ));
            }
        }
        Ok(())
    }

    /// Scan `text`, invoking `on_match(hs_id)` for each matching pattern id,
    /// with no per-call heap allocation. All shard scratches are acquired
    /// before `on_match` runs. If execution itself returns `Err`, callback
    /// state from the call is incomplete and must be discarded.
    ///
    /// This is the set-membership hot path: on tiny chunks the match triple
    /// allocation dominates, while a prefilter only needs "which pattern ids
    /// matched". Paired with a single-shard build
    /// (`HsCompileOpts::shard_target = Some(usize::MAX)`) and `SINGLEMATCH`,
    /// this is ~20x faster per call on ~150-byte inputs.
    pub(crate) fn scan_each_result(
        &self,
        text: &[u8],
        mut on_match: impl FnMut(usize),
    ) -> Result<(), String> {
        let scratches = ScratchBatch::acquire(self)?;
        for (shard_idx, shard) in self.shards.iter().enumerate() {
            if let Err(error) = shard.db.scan(
                text,
                scratches.scratch(shard_idx),
                |id, _from, _to, _flags| {
                    on_match(id as usize);
                    Matching::Continue
                },
            ) {
                return Err(format!(
                    "hyperscan scan_each failed while executing shard {shard_idx} of {}; \
                     callback output from this call is incomplete and must be discarded: {error}",
                    self.shards.len()
                ));
            }
        }
        Ok(())
    }

    /// Scan several independently-addressed texts while holding one scratch
    /// batch for the entire lane. Callers must discard callback state if this
    /// returns `Err`.
    pub(crate) fn scan_many_each_result<'a>(
        &self,
        texts: impl IntoIterator<Item = (usize, &'a [u8])>,
        mut on_match: impl FnMut(usize, usize),
    ) -> Result<(), String> {
        let scratches = ScratchBatch::acquire(self)?;
        for (text_index, text) in texts {
            for (shard_idx, shard) in self.shards.iter().enumerate() {
                if let Err(error) = shard.db.scan(
                    text,
                    scratches.scratch(shard_idx),
                    |id, _from, _to, _flags| {
                        on_match(text_index, id as usize);
                        Matching::Continue
                    },
                ) {
                    return Err(format!(
                        "hyperscan batch scan failed for text {text_index} while executing shard {shard_idx} of {}; callback output from this lane is incomplete and must be discarded: {error}",
                        self.shards.len()
                    ));
                }
            }
        }
        Ok(())
    }

    /// True iff ANY compiled pattern matches `text`. The BOOLEAN companion
    /// to [`scan_each_result`](Self::scan_each_result): the match callback returns
    /// `Matching::Terminate` on the first hit, so HS aborts the scan
    /// (`HS_SCAN_TERMINATED`) instead of enumerating every match. On a chunk
    /// that has an active pattern this returns after the first one - the
    /// admission gate (`has_active_phase2_patterns_for_chunk`) needs only
    /// "is anything active?", never the full marked set, and building that
    /// set is the measured #1 scan cost (`phase2:prefilter`).
    pub(crate) fn any_match_result(&self, text: &[u8]) -> Result<bool, String> {
        let scratches = ScratchBatch::acquire(self)?;
        for (shard_idx, shard) in self.shards.iter().enumerate() {
            let mut hit = false;
            if let Err(error) = shard.db.scan(
                text,
                scratches.scratch(shard_idx),
                |_id, _from, _to, _flags| {
                    hit = true;
                    Matching::Terminate
                },
            ) {
                if !hit {
                    return Err(format!(
                        "hyperscan any_match failed before a match was observed while executing \
                         shard {shard_idx} of {}: {error}",
                        self.shards.len()
                    ));
                }
            }
            if hit {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Look up detector and pattern metadata for a Hyperscan pattern id.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use keyhog_scanner::simd::backend::HsScanner;
    ///
    /// let (scanner, _) = HsScanner::compile(&[(0, 0, "demo_[A-Z0-9]{8}", false)])?;
    /// assert!(scanner.pattern_info(0).is_some());
    /// ```
    pub(crate) fn pattern_info(&self, hs_id: usize) -> Option<(usize, usize, bool)> {
        self.pattern_map
            .get(hs_id)
            .map(|&(_, det_idx, pat_idx, has_group)| (det_idx, pat_idx, has_group))
    }

    /// Return the number of patterns compiled into the SIMD database.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use keyhog_scanner::simd::backend::HsScanner;
    ///
    /// let (scanner, _) = HsScanner::compile(&[(0, 0, "demo_[A-Z0-9]{8}", false)])?;
    /// assert_eq!(scanner.pattern_count(), 1);
    /// ```
    pub(crate) fn pattern_count(&self) -> usize {
        self.pattern_map.len()
    }

    /// Number of compiled shard databases. Each shard owns one lazy,
    /// per-thread Hyperscan scratch after the first scan on that thread.
    #[cfg(test)]
    pub(crate) fn shard_count(&self) -> usize {
        self.shards.len()
    }
}

// The scratch-lifetime suite lives in `tests/unit/simd_scratch_lifetime.rs`.
// It was 434 lines against 333 of implementation, so the file read as a test
// file that happened to contain a backend. The `#[path]` include keeps it
// compiled with the crate, which it needs: it exercises the private scratch
// buffers directly.
#[cfg(test)]
#[path = "../../../tests/unit/simd_scratch_lifetime.rs"]
mod scratch_lifetime;
