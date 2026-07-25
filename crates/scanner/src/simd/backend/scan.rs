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
    if let Some(cached) =
        SCRATCH_TLS.with(|tls| tls.borrow_mut().remove(&key))
    {
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
            let scratch = take_scratch(
                scanner.scanner_id,
                shard_idx,
                shard,
                &scanner.scratch_owner,
            )?;
            batch.slots[shard_idx].write(scratch);
            batch.initialized += 1;
        }
        Ok(batch)
    }

    #[inline]
    fn scratch(&self, shard_idx: usize) -> &Scratch {
        debug_assert!(shard_idx < self.initialized);
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
            if let Err(error) =
                shard
                    .db
                    .scan(text, scratches.scratch(shard_idx), |id, from, to, _flags| {
                        on_match(id as usize, from as usize, to as usize);
                        Matching::Continue
                    })
            {
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
            if let Err(error) =
                shard
                    .db
                    .scan(text, scratches.scratch(shard_idx), |id, _from, _to, _flags| {
                        on_match(id as usize);
                        Matching::Continue
                    })
            {
                return Err(format!(
                    "hyperscan scan_each failed while executing shard {shard_idx} of {}; \
                     callback output from this call is incomplete and must be discarded: {error}",
                    self.shards.len()
                ));
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
            if let Err(error) =
                shard
                    .db
                    .scan(text, scratches.scratch(shard_idx), |_id, _from, _to, _flags| {
                        hit = true;
                        Matching::Terminate
                    })
            {
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

#[cfg(test)]
mod scratch_lifetime {
    use super::super::{HsCompileOpts, HsScanner};

    /// Regression: dropping a scanner must not strand database-bound scratch
    /// on the thread that performed its last scan.
    #[test]
    fn dropping_scanner_purges_current_thread_tls_scratch() {
        let patterns = [(0usize, 0usize, "KHDROP_[A-Z0-9]{8}", false)];
        let (scanner, unsupported) = HsScanner::compile(&patterns).expect("probe pattern compiles");
        assert!(
            unsupported.is_empty(),
            "probe pattern must be Hyperscan-supported, got unsupported={unsupported:?}"
        );
        let scanner_id = scanner.scanner_id;

        let mut ids = Vec::new();
        scanner
            .scan_matches_result(b"KHDROP_AB12CD34", |id, _start, _end| ids.push(id))
            .expect("scan succeeds and retains scratch in this thread");
        assert_eq!(ids, vec![0]);
        assert!(
            super::current_thread_scratch_count_for_test(scanner_id) > 0,
            "scan should retain at least one scratch for the live scanner"
        );

        drop(scanner);

        assert_eq!(
            super::current_thread_scratch_count_for_test(scanner_id),
            0,
            "dropping a scanner must evict its thread-local Hyperscan scratches"
        );
    }

    /// Regression: pruning one scanner's cache must not evict another live
    /// scanner interleaved on the same worker.
    #[test]
    fn interleaved_live_scanners_keep_thread_local_scratches() {
        let patterns_a = [(0usize, 0usize, "KHA_[A-Z0-9]{8}", false)];
        let patterns_b = [(0usize, 0usize, "KHB_[A-Z0-9]{8}", false)];
        let (scanner_a, unsupported_a) =
            HsScanner::compile(&patterns_a).expect("scanner A pattern compiles");
        let (scanner_b, unsupported_b) =
            HsScanner::compile(&patterns_b).expect("scanner B pattern compiles");
        assert!(
            unsupported_a.is_empty() && unsupported_b.is_empty(),
            "probe patterns must be Hyperscan-supported"
        );

        scanner_a
            .scan_matches_result(b"KHA_AB12CD34", |_, _, _| {})
            .expect("scanner A scan succeeds");
        assert!(
            super::current_thread_scratch_count_for_test(scanner_a.scanner_id) > 0,
            "scanner A should retain its current-thread scratch"
        );

        scanner_b
            .scan_matches_result(b"KHB_AB12CD34", |_, _, _| {})
            .expect("scanner B scan succeeds");

        assert!(
            super::current_thread_scratch_count_for_test(scanner_a.scanner_id) > 0,
            "interleaving scanner B must not evict live scanner A scratch"
        );
        assert!(
            super::current_thread_scratch_count_for_test(scanner_b.scanner_id) > 0,
            "scanner B should retain its own current-thread scratch"
        );
    }

    /// Regression: persistent workers must reclaim stale scratch after the
    /// owning scanner is dropped on a different thread.
    #[test]
    fn dead_scanner_scratch_is_pruned_on_worker_next_cache_touch() {
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (continue_tx, continue_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let patterns_a = [(0usize, 0usize, "KHSTALE_[A-Z0-9]{8}", false)];
            let (scanner_a, unsupported_a) =
                HsScanner::compile(&patterns_a).expect("scanner A pattern compiles");
            assert!(
                unsupported_a.is_empty(),
                "scanner A pattern must be Hyperscan-supported"
            );
            let scanner_a_id = scanner_a.scanner_id;
            scanner_a
                .scan_matches_result(b"KHSTALE_AB12CD34", |_, _, _| {})
                .expect("scanner A scan succeeds");
            ready_tx
                .send((
                    scanner_a_id,
                    super::current_thread_scratch_count_for_test(scanner_a_id),
                    scanner_a,
                ))
                .expect("send scanner A cache count");
            continue_rx.recv().expect("wait for prune command");

            let patterns_b = [(0usize, 0usize, "KHFRESH_[A-Z0-9]{8}", false)];
            let (scanner_b, unsupported_b) =
                HsScanner::compile(&patterns_b).expect("scanner B pattern compiles");
            assert!(
                unsupported_b.is_empty(),
                "scanner B pattern must be Hyperscan-supported"
            );
            scanner_b
                .scan_matches_result(b"KHFRESH_AB12CD34", |_, _, _| {})
                .expect("scanner B scan succeeds and prunes stale entries on miss");
            (
                super::current_thread_scratch_count_for_test(scanner_a_id),
                super::current_thread_scratch_count_for_test(scanner_b.scanner_id),
            )
        });

        let (_scanner_a_id, cached_before_drop, scanner_a) =
            ready_rx.recv().expect("receive scanner A cache count");
        assert!(
            cached_before_drop > 0,
            "worker should retain scanner A scratch before scanner A is dropped"
        );
        drop(scanner_a);
        continue_tx.send(()).expect("release worker");
        let (stale_after_touch, fresh_after_touch) = worker.join().expect("worker joins");

        assert_eq!(
            stale_after_touch, 0,
            "dead scanner A scratch must be pruned on the worker's next cache touch"
        );
        assert!(
            fresh_after_touch > 0,
            "worker should retain scanner B scratch after pruning stale scanner A"
        );
    }

    /// Regression: lazy scratch construction keeps compile free of
    /// executor-width-dependent scratch allocation and failure.
    #[test]
    fn compile_does_not_allocate_thread_local_scratch() {
        let patterns = [(0usize, 0usize, "KHDROP_[A-Z0-9]{8}", false)];
        let (scanner, unsupported) = HsScanner::compile(&patterns).expect("probe pattern compiles");
        assert!(unsupported.is_empty(), "probe pattern must be Hyperscan-supported");

        assert_eq!(
            super::current_thread_scratch_count_for_test(scanner.scanner_id),
            0,
            "compile must not allocate any thread-local Hyperscan scratch"
        );
    }

    /// Regression: the first cold scan must populate the complete per-shard
    /// cache and subsequent scans must reuse it without growth.
    #[test]
    fn first_scan_lazily_warms_then_reuses_scratch() {
        let patterns = [(0usize, 0usize, "KHLAZY_[A-Z0-9]{8}", false)];
        let (scanner, unsupported) = HsScanner::compile(&patterns).expect("probe pattern compiles");
        assert!(unsupported.is_empty(), "probe pattern must be Hyperscan-supported");

        let mut ids = Vec::new();
        scanner
            .scan_matches_result(b"KHLAZY_AB12CD34", |id, _start, _end| ids.push(id))
            .expect("first scan lazily allocates scratch");
        assert_eq!(ids, vec![0]);

        let after_first = super::current_thread_scratch_count_for_test(scanner.scanner_id);
        assert_eq!(
            after_first,
            scanner.shard_count(),
            "first scan must allocate exactly one scratch per shard"
        );

        scanner
            .scan_matches_result(b"KHLAZY_AB12CD34", |_, _, _| {})
            .expect("second scan reuses warm scratch");

        let after_second = super::current_thread_scratch_count_for_test(scanner.scanner_id);
        assert_eq!(
            after_second, after_first,
            "post-warm scan must not allocate additional scratch"
        );
    }

    /// Regression: explicit warm-up must seed every Rayon worker so normal
    /// request traffic does not allocate Hyperscan scratch.
    #[test]
    fn warm_broadcast_seeds_one_scratch_per_shard_on_every_worker() {
        let patterns = [
            (0usize, 0usize, "KHWORKER_[A-Z0-9]{8}", false),
            (1usize, 0usize, "ZZWORKER_[a-z0-9]{6}", false),
        ];
        let (scanner, unsupported) = HsScanner::compile(&patterns).expect("probe patterns compile");
        assert!(unsupported.is_empty(), "probe patterns must be Hyperscan-supported");

        scanner.warm().expect("warm must seed worker thread-local scratch");

        let shard_count = scanner.shard_count();
        let warm_counts: Vec<usize> = rayon::broadcast(|_| {
            super::current_thread_scratch_count_for_test(scanner.scanner_id)
        });
        for (i, count) in warm_counts.iter().enumerate() {
            assert_eq!(
                *count, shard_count,
                "worker {i} must have one scratch per shard after warm, got {count}"
            );
        }

        let probe = b"x KHWORKER_AB12CD34 y ZZWORKER_xy99zz z";
        let post_scan_counts: Vec<usize> = rayon::broadcast(|_| {
            let mut ids = Vec::new();
            scanner
                .scan_matches_result(probe, |id, _, _| ids.push(id))
                .expect("post-warm scan succeeds");
            ids.sort_unstable();
            ids.dedup();
            assert_eq!(ids, vec![0, 1], "post-warm scan must preserve exact parity");
            super::current_thread_scratch_count_for_test(scanner.scanner_id)
        });
        for (i, count) in post_scan_counts.iter().enumerate() {
            assert_eq!(
                *count, shard_count,
                "worker {i} must not allocate additional scratch after warm, got {count}"
            );
        }
    }

    /// Regression: concurrency beyond the Rayon executor width must grow
    /// exact per-thread scratch instead of skipping shards or over-marking.
    #[test]
    fn oversubscribed_threads_allocate_once_and_keep_exact_parity() {
        let patterns = [
            (0usize, 0usize, "KHSCRATCH_[A-Z0-9]{8}", false),
            (1usize, 0usize, "ZZTOK_[a-z0-9]{6}", false),
        ];
        let (scanner, unsupported) = HsScanner::compile(&patterns).expect("probe patterns compile");
        assert!(unsupported.is_empty(), "probe patterns must be Hyperscan-supported");

        let probe = b"x KHSCRATCH_AB12CD34 y ZZTOK_xy99zz z";
        let mut expected = Vec::new();
        scanner
            .scan_matches_result(probe, |id, _, _| expected.push(id))
            .expect("reference scan succeeds");
        expected.sort_unstable();
        expected.dedup();

        let extra_threads = 3;
        let n_threads = rayon::current_num_threads().saturating_add(extra_threads).max(2);
        std::thread::scope(|scope| {
            let handles: Vec<_> = (0..n_threads)
                .map(|_| {
                    scope.spawn(|| {
                        let mut ids = Vec::new();
                        scanner
                            .scan_matches_result(probe, |id, _, _| ids.push(id))
                            .expect("oversubscribed scan succeeds");
                        ids.sort_unstable();
                        ids.dedup();
                        (
                            ids,
                            super::current_thread_scratch_count_for_test(scanner.scanner_id),
                        )
                    })
                })
                .collect();

            for (i, (ids, count)) in handles
                .into_iter()
                .map(|h| h.join().expect("scan thread joins"))
                .enumerate()
            {
                assert_eq!(
                    ids, expected,
                    "thread {i} must match exact reference parity"
                );
                assert_eq!(
                    count,
                    scanner.shard_count(),
                    "thread {i} must retain exactly one scratch per shard"
                );
            }
        });
    }

    /// Regression: a later-shard scratch allocation failure previously made
    /// earlier shard callbacks observable before returning an error. The
    /// one-shot failure also proves retained scratch can recover cleanly.
    #[test]
    fn scratch_failure_precedes_callbacks_and_next_scan_recovers_all_findings() {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(2)
            .build()
            .expect("two-thread compile pool builds");
        let patterns = [
            (0usize, 0usize, "KHFAIL_[A-Z0-9]{8}", false),
            (1usize, 0usize, "ZZFAIL_[a-z0-9]{6}", false),
        ];
        let (scanner, unsupported) = pool
            .install(|| {
                HsScanner::compile_with_opts(
                    &patterns,
                    HsCompileOpts {
                        shard_target: Some(1),
                        ..Default::default()
                    },
                )
            })
            .expect("two-shard probe compiles");
        assert!(unsupported.is_empty(), "probe patterns must be Hyperscan-supported");
        assert_eq!(scanner.shard_count(), 2, "failure probe requires two shards");

        super::fail_next_scratch_allocation_for_test(1);
        let mut callbacks = Vec::new();
        let error = scanner
            .scan_matches_result(
                b"x KHFAIL_AB12CD34 y ZZFAIL_xy99zz z",
                |id, _, _| callbacks.push(id),
            )
            .expect_err("second shard scratch allocation must fail");
        assert!(
            error.contains("scratch on-demand growth failed")
                && error.contains("shard 1")
                && error.contains("injected allocation failure"),
            "allocation failure must retain actionable scanner/shard context: {error}"
        );
        assert!(
            callbacks.is_empty(),
            "scratch acquisition must complete for every shard before callbacks run"
        );
        assert_eq!(
            super::current_thread_scratch_count_for_test(scanner.scanner_id),
            1,
            "scratch acquired before failure must be returned to TLS for recovery"
        );

        let mut recovered = Vec::new();
        scanner
            .scan_matches_result(
                b"x KHFAIL_AB12CD34 y ZZFAIL_xy99zz z",
                |id, _, _| recovered.push(id),
            )
            .expect("one-shot allocation failure must recover on the next scan");
        recovered.sort_unstable();
        recovered.dedup();
        assert_eq!(
            recovered,
            vec![0, 1],
            "recovery scan must report the complete cross-shard finding set"
        );

        super::purge_scanner_scratch(scanner.scanner_id);
        super::fail_next_scratch_allocation_for_test(1);
        let mut each_callbacks = Vec::new();
        scanner
            .scan_each_result(
                b"x KHFAIL_AB12CD34 y ZZFAIL_xy99zz z",
                |id| each_callbacks.push(id),
            )
            .expect_err("scan_each must propagate scratch allocation failure");
        assert!(
            each_callbacks.is_empty(),
            "scan_each scratch failure must precede every callback"
        );

        super::purge_scanner_scratch(scanner.scanner_id);
        super::fail_next_scratch_allocation_for_test(1);
        scanner
            .any_match_result(b"x KHFAIL_AB12CD34 y ZZFAIL_xy99zz z")
            .expect_err("any_match must propagate scratch allocation failure");
        assert!(
            scanner
                .any_match_result(b"x KHFAIL_AB12CD34 y ZZFAIL_xy99zz z")
                .expect("any_match must recover after one-shot allocation failure"),
            "any_match recovery must observe the cross-shard finding set"
        );
    }

    /// Regression: a wrapped/reused numeric scanner id must never retrieve
    /// scratch bound to another scanner's database; owner identity is the
    /// adversarial backstop against incompatible scratch reuse.
    #[test]
    fn scanner_id_collision_rejects_foreign_scratch_and_both_scanners_recover() {
        let patterns_a = [(0usize, 0usize, "KHCOLLIDEA_[A-Z0-9]{8}", false)];
        let patterns_b = [(0usize, 0usize, "KHCOLLIDEB_[a-z0-9]{6}", false)];
        let (scanner_a, unsupported_a) =
            HsScanner::compile(&patterns_a).expect("scanner A pattern compiles");
        let (mut scanner_b, unsupported_b) =
            HsScanner::compile(&patterns_b).expect("scanner B pattern compiles");
        assert!(
            unsupported_a.is_empty() && unsupported_b.is_empty(),
            "collision probes must be Hyperscan-supported"
        );

        scanner_a
            .scan_matches_result(b"KHCOLLIDEA_AB12CD34", |_, _, _| {})
            .expect("scanner A seeds its scratch");
        scanner_b.scanner_id = scanner_a.scanner_id;

        let mut b_hits = 0;
        scanner_b
            .scan_matches_result(b"KHCOLLIDEB_xy99zz", |_, _, _| b_hits += 1)
            .expect("scanner B must reject and replace scanner A scratch");
        assert_eq!(b_hits, 1, "scanner B must retain exact findings after collision");

        let mut a_hits = 0;
        scanner_a
            .scan_matches_result(b"KHCOLLIDEA_AB12CD34", |_, _, _| a_hits += 1)
            .expect("scanner A must replace scanner B scratch on reuse");
        assert_eq!(a_hits, 1, "scanner A must recover exact findings after collision");
    }
}
