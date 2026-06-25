use super::HsScanner;
use hyperscan::{Matching, Scratch};
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::{Arc, Weak};

struct CachedScratch {
    owner: Weak<()>,
    scratch: Scratch,
}

thread_local! {
    static SCRATCH_TLS: RefCell<HashMap<(u64, usize), CachedScratch>> =
        RefCell::new(HashMap::new());
}

fn take_scratch(
    scanner_id: u64,
    shard_idx: usize,
    shard: &super::Shard,
    owner: &Arc<()>,
) -> Result<Scratch, String> {
    let key = (scanner_id, shard_idx);
    if let Some(scratch) = SCRATCH_TLS.with(|tls| {
        let mut tls = tls.borrow_mut();
        prune_dead_scanner_scratch(&mut tls);
        tls.remove(&key).map(|cached| cached.scratch)
    }) {
        return Ok(scratch);
    }
    debug_assert!(Arc::strong_count(owner) > 0);
    if let Some(scratch) = shard.scratch_pool.lock().pop() {
        return Ok(scratch);
    }
    // Pool drained: MORE distinct threads are scanning this shard than the
    // compile-time preallocation seeded (the pool is sized to the host core
    // count, but `--batch-pipeline` stacks a reader pool + the fused dispatch
    // threads ON TOP of rayon, so one shard can see more live threads than
    // cores). Grow on demand with a fresh scratch bound to THIS shard's
    // database. This is NOT a fallback and NOT a partial scan: it runs the
    // identical precise Hyperscan path over the full chunk, so recall and
    // precision are unchanged. It is the seed pool growing to true concurrency
    // — at most once per (thread, scanner, shard), because the scratch then
    // lives in this thread's TLS and is reused lock-free on every later scan
    // (alloc cost amortizes to zero, Law 7). The old hard error here was the
    // real defect: it forced callers into the over-marking degrade, which is
    // non-deterministic (it depends on which chunk loses the scratch race) and
    // is what made `autoroute` calibration's reference-consistency check abort
    // on high-core hosts.
    shard.db.alloc_scratch().map_err(|error| {
        format!(
            "hyperscan scratch on-demand growth failed for scanner {scanner_id} \
             shard {shard_idx}: {error}"
        )
    })
}

fn put_scratch(scanner_id: u64, shard_idx: usize, owner: &Arc<()>, scratch: Scratch) {
    let key = (scanner_id, shard_idx);
    SCRATCH_TLS.with(|tls| {
        let mut tls = tls.borrow_mut();
        prune_dead_scanner_scratch(&mut tls);
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
    pub(crate) fn scan_matches_result(
        &self,
        text: &[u8],
        mut on_match: impl FnMut(usize, usize, usize),
    ) -> Result<(), String> {
        // The match callback exposes the GLOBAL pattern id (set on
        // `Pattern.id` at compile), so the union over shards is identical
        // to a single all-patterns database's output - offsets are in the
        // original byte space, no remapping.
        for (shard_idx, shard) in self.shards.iter().enumerate() {
            let scratch = take_scratch(self.scanner_id, shard_idx, shard, &self.scratch_owner)?;

            if let Err(error) = shard.db.scan(text, &scratch, |id, from, to, _flags| {
                on_match(id as usize, from as usize, to as usize);
                Matching::Continue
            }) {
                put_scratch(self.scanner_id, shard_idx, &self.scratch_owner, scratch);
                return Err(format!(
                    "hyperscan scan failed for shard {shard_idx}: {error}"
                ));
            }

            put_scratch(self.scanner_id, shard_idx, &self.scratch_owner, scratch);
        }
        Ok(())
    }

    /// Scan `text`, invoking `on_match(hs_id)` for each matching pattern id,
    /// with NO per-call heap allocation. This is the set-membership hot
    /// path: on tiny chunks the match triple allocation dominates, while a
    /// prefilter only needs "which pattern ids matched". Paired with a single-shard build
    /// (`HsCompileOpts::shard_target = Some(usize::MAX)`) and `SINGLEMATCH`,
    /// this is ~20x faster per call on ~150-byte inputs.
    pub(crate) fn scan_each_result(
        &self,
        text: &[u8],
        mut on_match: impl FnMut(usize),
    ) -> Result<(), String> {
        for (shard_idx, shard) in self.shards.iter().enumerate() {
            let scratch = take_scratch(self.scanner_id, shard_idx, shard, &self.scratch_owner)?;
            if let Err(error) = shard.db.scan(text, &scratch, |id, _from, _to, _flags| {
                on_match(id as usize);
                Matching::Continue
            }) {
                put_scratch(self.scanner_id, shard_idx, &self.scratch_owner, scratch);
                return Err(format!(
                    "hyperscan scan_each failed for shard {shard_idx}: {error}"
                ));
            }
            put_scratch(self.scanner_id, shard_idx, &self.scratch_owner, scratch);
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
        for (shard_idx, shard) in self.shards.iter().enumerate() {
            let scratch = take_scratch(self.scanner_id, shard_idx, shard, &self.scratch_owner)?;
            let mut hit = false;
            if let Err(error) = shard.db.scan(text, &scratch, |_id, _from, _to, _flags| {
                hit = true;
                Matching::Terminate
            }) {
                if !hit {
                    put_scratch(self.scanner_id, shard_idx, &self.scratch_owner, scratch);
                    return Err(format!(
                        "hyperscan any_match failed before a match was observed for shard {shard_idx}: {error}"
                    ));
                }
            }
            put_scratch(self.scanner_id, shard_idx, &self.scratch_owner, scratch);
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
}

#[cfg(test)]
mod scratch_lifetime {
    use super::super::HsScanner;

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
}
