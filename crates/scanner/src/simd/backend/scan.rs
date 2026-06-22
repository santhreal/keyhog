use super::HsScanner;
use hyperscan::{Matching, Scratch};
use std::cell::RefCell;
use std::collections::HashMap;

thread_local! {
    static SCRATCH_TLS: RefCell<HashMap<(u64, usize), Scratch>> =
        RefCell::new(HashMap::new());
}

fn take_scratch(
    scanner_id: u64,
    shard_idx: usize,
    shard: &super::Shard,
) -> Result<Scratch, String> {
    let key = (scanner_id, shard_idx);
    if let Some(scratch) = SCRATCH_TLS.with(|tls| tls.borrow_mut().remove(&key)) {
        return Ok(scratch);
    }
    if let Some(scratch) = shard.scratch_pool.lock().pop() {
        return Ok(scratch);
    }
    shard.db.alloc_scratch().map_err(|error| {
        format!("hyperscan scratch allocation failed for shard {shard_idx}: {error}")
    })
}

fn put_scratch(scanner_id: u64, shard_idx: usize, scratch: Scratch) {
    let key = (scanner_id, shard_idx);
    SCRATCH_TLS.with(|tls| {
        tls.borrow_mut().insert(key, scratch);
    });
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
            let scratch = take_scratch(self.scanner_id, shard_idx, shard)?;

            if let Err(error) = shard.db.scan(text, &scratch, |id, from, to, _flags| {
                on_match(id as usize, from as usize, to as usize);
                Matching::Continue
            }) {
                put_scratch(self.scanner_id, shard_idx, scratch);
                return Err(format!(
                    "hyperscan scan failed for shard {shard_idx}: {error}"
                ));
            }

            put_scratch(self.scanner_id, shard_idx, scratch);
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
            let scratch = take_scratch(self.scanner_id, shard_idx, shard)?;
            if let Err(error) = shard.db.scan(text, &scratch, |id, _from, _to, _flags| {
                on_match(id as usize);
                Matching::Continue
            }) {
                put_scratch(self.scanner_id, shard_idx, scratch);
                return Err(format!(
                    "hyperscan scan_each failed for shard {shard_idx}: {error}"
                ));
            }
            put_scratch(self.scanner_id, shard_idx, scratch);
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
            let scratch = take_scratch(self.scanner_id, shard_idx, shard)?;
            let mut hit = false;
            if let Err(error) = shard.db.scan(text, &scratch, |_id, _from, _to, _flags| {
                hit = true;
                Matching::Terminate
            }) {
                if !hit {
                    put_scratch(self.scanner_id, shard_idx, scratch);
                    return Err(format!(
                        "hyperscan any_match failed before a match was observed for shard {shard_idx}: {error}"
                    ));
                }
            }
            put_scratch(self.scanner_id, shard_idx, scratch);
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
        self.pattern_map.get(hs_id).copied()
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
