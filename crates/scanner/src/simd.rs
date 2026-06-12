//! Vectorscan/Hyperscan SIMD regex backend for high-throughput scanning.
//!
//! When the `simd` feature is enabled, this replaces the AC+fallback approach
//! with Hyperscan's simultaneous multi-pattern matching using SIMD instructions.
//! Gives 3-5x throughput improvement. Accuracy is identical - same patterns, faster engine.

#[cfg(feature = "simd")]
pub(crate) mod backend {
    use hyperscan::{
        Block as BlockMode, BlockDatabase, Builder, Matching, Pattern, PatternFlags, Patterns,
        Scratch,
    };
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Target number of patterns per compile shard. The cold compile is a
    /// single serial C-side NFA/DFA build whose wall-clock scales ~linearly
    /// with the pattern count, so the shard COUNT is sized to keep each shard
    /// near this many patterns: `shards = ceil(n / TARGET_PATTERNS_PER_SHARD)`,
    /// capped at the core count. Sizing by patterns-per-shard (rather than a
    /// fixed shard count) is what flattens the build's scaling: as the corpus
    /// grows, the number of shards grows while each shard's serial build stays
    /// ~constant, so on a many-core box "double the patterns" is absorbed by
    /// spinning up more parallel shards instead of doubling each shard's work.
    /// ~80 was chosen empirically: on the ~900-detector corpus (~1.7k compiled
    /// patterns) it lands the full set at ~21 shards and a half set at ~11, so
    /// BOTH sit comfortably under a 32-core box's one-wave budget AND carry a
    /// near-equal per-shard pattern count - which flattens the full/half
    /// cold-compile ratio to ~1.3x (vs ~1.9-2.0x serial). A smaller target
    /// (e.g. 40) pushes the full set up against the core count, making its
    /// per-shard size diverge from the half set's and the ratio worse; a much
    /// larger target gives up parallelism. Per-shard builds stay ~150-190ms
    /// (vs ~1600ms for the serial all-patterns build). Each shard is
    /// disk-cached independently (keyed by the SHA-256 of its own pattern
    /// list), so the warm path stays a deserialize-only load. Overridable at
    /// runtime via `KEYHOG_SHARD_TARGET` for hardware-specific tuning.
    const TARGET_PATTERNS_PER_SHARD: usize = 80;

    /// Hard ceiling on shard count, so a pathologically large detector set on a
    /// 128-core box cannot spawn an unbounded number of databases (each costs a
    /// scan-time dispatch). At this cap the per-shard size grows again, but the
    /// real corpus (~900 patterns) sits at ~23 shards, well under it.
    const MAX_COMPILE_SHARDS: usize = 64;

    /// Monotonic per-process id source so each `HsScanner` instance gets a
    /// distinct key for its thread-local scratch cache (below). Multiple
    /// scanners in one process must not hand each other a scratch allocated
    /// against a different database.
    static SCANNER_ID_SEQ: AtomicU64 = AtomicU64::new(0);

    /// One compiled shard: its database plus a Mutex-guarded scratch pool. Each
    /// `Scratch` is tied to exactly one `BlockDatabase`, so the pools are
    /// per-shard.
    struct Shard {
        db: BlockDatabase,
        scratch_pool: parking_lot::Mutex<Vec<Scratch>>,
    }

    /// Compiled Hyperscan databases for all detector patterns, sharded across
    /// cores at compile time.
    ///
    /// Thread-safe: every database is immutable after compilation and the
    /// scratch pools are Mutex-guarded. The public scan/lookup surface is
    /// unchanged from the single-database version - `pattern_info`/
    /// `pattern_count` still index a single global `pattern_map` keyed by the
    /// HS pattern id, because each shard's patterns carry their ORIGINAL global
    /// id, so a match from any shard maps back through the same table and the
    /// scan output is the union of all shards in original-byte space.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use keyhog_scanner::simd::backend::HsScanner;
    ///
    /// let _scanner = HsScanner::compile(&[(0, 0, "demo_[A-Z0-9]{8}", false)])?;
    /// ```
    pub struct HsScanner {
        /// Independently-compiled shard databases. Their union over a scan is
        /// exactly the set of matches a single all-patterns database would
        /// produce (Hyperscan match ids are the global pattern ids, which are
        /// disjoint across shards).
        shards: Vec<Shard>,
        /// Map from HS pattern ID to (detector_index, pattern_index, has_group).
        /// Global and shared across shards - unchanged from the single-db build.
        pattern_map: Vec<(usize, usize, bool)>,
        /// Distinct id for this scanner instance, used to key the thread-local
        /// per-shard scratch cache so two scanners never share scratches.
        scanner_id: u64,
    }

    // SAFETY: BlockDatabase is immutable after compilation and safe to share.
    // Scratch pools are Mutex-guarded. Individual Scratch objects are only used
    // by one thread at a time (taken from pool/thread-local, returned after use).
    unsafe impl Send for HsScanner {}
    unsafe impl Sync for HsScanner {}

    /// Per-pattern compilation options for [`HsScanner::compile_with_opts`].
    ///
    /// The legacy phase-1 [`HsScanner::compile`] path compiles every pattern
    /// `CASELESS` and reports every match (no `SINGLEMATCH`). The always-active
    /// fallback PREFILTER wants the opposite on both axes: it needs each
    /// pattern's OWN case sensitivity (a plain homoglyph variant is
    /// case-sensitive; a detector regex is not) so the marked set matches the
    /// `regex` reference exactly, and it only needs to know "did pattern P match
    /// at all" — so `SINGLEMATCH` fires each pattern once and stops, removing the
    /// broad-pattern callback storm that is why the fallback never used HS.
    #[derive(Clone, Copy, Default)]
    pub struct HsCompileOpts<'a> {
        /// Set `HS_FLAG_SINGLEMATCH` on every pattern (fire once, then retire).
        pub singlematch: bool,
        /// Per-input-pattern caseless flags, parallel to `patterns`. `None` =
        /// every pattern `CASELESS` (legacy behavior). A missing/short entry
        /// defaults to caseless.
        pub caseless: Option<&'a [bool]>,
        /// Override the patterns-per-shard target (else `KEYHOG_SHARD_TARGET` /
        /// the default). The sharded scan must hit EVERY shard per call, so the
        /// per-shard fixed overhead is paid `shard_count` times — fine for the
        /// phase-1 position scan, but it dominates the set-membership PREFILTER
        /// on tiny chunks. Pass `Some(usize::MAX)` to force a single database so
        /// `scan_each` pays the per-scan overhead exactly once.
        pub shard_target: Option<usize>,
        /// Set `HS_FLAG_UTF8`. The `regex` crate matches unicode classes as
        /// CODEPOINTS; the homoglyph fallback variants (`[sѕｓ]…`) are unicode.
        /// Without this flag HS treats the pattern as BYTES, expanding every
        /// unicode class into a byte-alternation — a much larger, slower
        /// automaton AND byte- (not codepoint-) match semantics. UTF8 mode
        /// matches the `regex` reference and keeps the automaton small.
        pub utf8: bool,
    }

    impl HsScanner {
        /// Compile patterns into a Hyperscan database (legacy: all `CASELESS`,
        /// no `SINGLEMATCH`).
        ///
        /// # Examples
        ///
        /// ```rust,ignore
        /// use keyhog_scanner::simd::backend::HsScanner;
        ///
        /// let _scanner = HsScanner::compile(&[(0, 0, "demo_[A-Z0-9]{8}", false)])?;
        /// ```
        pub fn compile(
            patterns: &[(usize, usize, &str, bool)],
        ) -> Result<(Self, Vec<usize>), String> {
            Self::compile_with_opts(patterns, HsCompileOpts::default())
        }

        /// Compile patterns with explicit per-pattern flags. See [`HsCompileOpts`].
        ///
        /// # Examples
        ///
        /// ```rust,ignore
        /// use keyhog_scanner::simd::backend::{HsScanner, HsCompileOpts};
        ///
        /// let opts = HsCompileOpts { singlematch: true, caseless: Some(&[false]) };
        /// let _ = HsScanner::compile_with_opts(&[(0, 0, "demo_[A-Z0-9]{8}", false)], opts)?;
        /// ```
        pub fn compile_with_opts(
            patterns: &[(usize, usize, &str, bool)],
            opts: HsCompileOpts<'_>,
        ) -> Result<(Self, Vec<usize>), String> {
            let mut hs_pats = Vec::new();
            let mut pattern_map = Vec::new();
            let mut unsupported = Vec::new();

            for (i, &(det_idx, pat_idx, regex, has_group)) in patterns.iter().enumerate() {
                // Skip patterns that are too long for Hyperscan (>500 chars)
                if regex.len() > 500 {
                    unsupported.push(i);
                    continue;
                }
                // No SOM_LEFTMOST - it causes "Pattern too large" on complex
                // regexes; match positions are extracted by the regex crate.
                // CASELESS is per-pattern (legacy callers get all-caseless);
                // SINGLEMATCH is opt-in for the set-membership prefilter.
                let mut flags = PatternFlags::empty();
                if opts.caseless.map_or(true, |c| c.get(i).copied().unwrap_or(true)) {
                    flags |= PatternFlags::CASELESS;
                }
                if opts.singlematch {
                    flags |= PatternFlags::SINGLEMATCH;
                }
                if opts.utf8 {
                    flags |= PatternFlags::UTF8;
                }
                match Pattern::with_flags(regex, flags) {
                    Ok(mut p) => {
                        p.id = Some(pattern_map.len());
                        hs_pats.push(p);
                        pattern_map.push((det_idx, pat_idx, has_group));
                    }
                    Err(_) => {
                        unsupported.push(i);
                    }
                }
            }

            if hs_pats.is_empty() {
                return Err("no patterns compiled".into());
            }

            // Task 1c: Cache directory validation
            let cache_dir = {
                let dir = if let Ok(custom) = std::env::var("KEYHOG_CACHE_DIR") {
                    let path = PathBuf::from(custom);
                    let home = dirs::home_dir().ok_or("Fix: Could not determine HOME directory")?;
                    // SAFETY: geteuid() is a trivial syscall with no memory
                    // safety preconditions and always succeeds on Linux/macOS.
                    let uid = unsafe { libc::geteuid() };
                    let tmp_user_dir = PathBuf::from(format!("/tmp/keyhog-cache-{}", uid));

                    if !path.starts_with(&home) && !path.starts_with(&tmp_user_dir) {
                        return Err(format!(
                            "Fix: KEYHOG_CACHE_DIR must be under {} or {}",
                            home.display(),
                            tmp_user_dir.display()
                        ));
                    }
                    path
                } else {
                    // Persistent per-user cache so the ~1.7 s Hyperscan compile
                    // is paid once per (machine, pattern-set, hyperscan version,
                    // CPU features) - NOT once per reboot. The previous default
                    // lived under /tmp, which most distros mount on tmpfs or
                    // sweep on boot, so every reboot discarded the compiled DB
                    // and the next scan ate the full cold-start again.
                    // ~/.cache/keyhog (XDG_CACHE_HOME) survives reboots. Falls
                    // back to the /tmp dir only when no home/cache directory is
                    // resolvable (minimal containers, locked-down sandboxes).
                    // SAFETY: see geteuid() above - trivial syscall.
                    let uid = unsafe { libc::geteuid() };
                    match dirs::cache_dir() {
                        Some(cache) => cache.join("keyhog"),
                        None => PathBuf::from(format!("/tmp/keyhog-cache-{}", uid)),
                    }
                };

                if dir.exists() {
                    let meta = std::fs::symlink_metadata(&dir)
                        .map_err(|e| format!("Fix: Could not read cache dir metadata: {}", e))?;
                    if meta.is_symlink() {
                        return Err("Fix: KEYHOG_CACHE_DIR cannot be a symlink".into());
                    }
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::{MetadataExt, PermissionsExt};
                        // SAFETY: `geteuid` is a thread-safe read-only
                        // syscall that takes no arguments and cannot
                        // fail. The Rust binding is `unsafe` only
                        // because it crosses an FFI boundary.
                        let uid = unsafe { libc::geteuid() };
                        if meta.uid() != uid {
                            return Err(
                                "Fix: Cache directory is not owned by the current user".into()
                            );
                        }
                        if meta.permissions().mode() & 0o777 != 0o700 {
                            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                                .map_err(|e| {
                                    format!("Fix: Could not set cache dir permissions: {}", e)
                                })?;
                        }
                    }
                } else {
                    std::fs::create_dir_all(&dir)
                        .map_err(|e| format!("Fix: Could not create cache dir: {}", e))?;
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                            .map_err(|e| {
                                format!("Fix: Could not set cache dir permissions: {}", e)
                            })?;
                    }
                }
                dir
            };

            // Cache key: SHA-256 of all pattern strings + environment metadata.
            let cache_key = {
                use sha2::{Digest, Sha256};
                let mut h = Sha256::new();
                for p in &hs_pats {
                    h.update(p.expression.as_bytes());
                    h.update([0]);
                }

                // Task 1a: include hyperscan library version, CPU features, target arch
                h.update(hyperscan::version().to_string().as_bytes());
                h.update(b"0.3.2"); // Pin hyperscan crate version

                #[cfg(target_arch = "x86_64")]
                {
                    if is_x86_feature_detected!("avx512f") {
                        h.update(b"avx512f");
                    }
                    if is_x86_feature_detected!("avx2") {
                        h.update(b"avx2");
                    }
                    if is_x86_feature_detected!("sse4.2") {
                        h.update(b"sse4.2");
                    }
                }
                #[cfg(target_arch = "aarch64")]
                {
                    h.update(b"neon");
                }
                h.update(std::env::consts::ARCH.as_bytes());

                // Flags are baked into the serialized DB, so the cache key must
                // distinguish a caseless-all/no-singlematch build from a
                // per-pattern/singlematch one — otherwise a phase-1 cache entry
                // could be loaded for a prefilter request (or vice versa).
                h.update(if opts.singlematch { b"SM1" } else { b"SM0" });
                h.update(if opts.utf8 { b"U81" } else { b"U80" });
                match opts.caseless {
                    None => h.update(b"CLall"),
                    Some(cl) => {
                        h.update(b"CLper");
                        for &b in cl {
                            h.update([b as u8]);
                        }
                    }
                }

                hex::encode(h.finalize())
            };
            // ── Shard the pattern set and compile each shard in parallel ──
            //
            // The single serial `Builder::build` over the whole pattern set is
            // the entire cold-compile cost (~99.7% of it; the rayon regex-
            // validate phase upstream is ~5ms) and it scales ~linearly with the
            // pattern count while every core but one idles. Splitting the
            // patterns into K independent shards and building them on the rayon
            // pool lets the idle cores absorb the work, so doubling the pattern
            // count is bounded by the largest shard, not the sum. Each
            // `Builder::build` is fully independent and CPU-bound; the match ids
            // are the GLOBAL pattern ids (set on `Pattern.id` above), so a match
            // from any shard maps back through the same `pattern_map` and the
            // union of all shards' matches is exactly what a single all-patterns
            // database would have produced - no recall change, only WHERE each
            // pattern compiles.
            let cores = std::thread::available_parallelism()
                .map(|c| c.get())
                .unwrap_or(1);
            // Shard count: aim for ~TARGET patterns per shard, but cap at the
            // core count so every shard runs in a SINGLE parallel wave. Two
            // boundary behaviours matter for the full/half cold-compile ratio:
            //
            //   * Below the cap (small/medium corpus): shard COUNT scales with n
            //     at a fixed per-shard size, so each `Builder::build` costs the
            //     same and doubling the corpus is fully absorbed by spinning up
            //     more parallel shards (flat).
            //   * At the cap (large corpus, n > cores*TARGET): per-shard size
            //     grows as n/cores. With TARGET tuned so the full corpus sits
            //     right at the cap, a half-size corpus lands just below it at a
            //     similar per-shard size, so the two stay within a small factor
            //     and the ratio tracks the (sub-linear) per-shard build growth
            //     rather than the pattern count.
            //
            // Letting shards exceed cores was measured to be WORSE: the build
            // then runs ceil(shards/cores) work-stealing waves and the wall-clock
            // quantizes at the core boundary (a corpus needing 42 shards on 32
            // cores pays ~1.7x vs a half needing 21), so we stay within one wave.
            let target = opts
                .shard_target
                .filter(|&v| v >= 1)
                .or_else(|| {
                    std::env::var("KEYHOG_SHARD_TARGET")
                        .ok()
                        .and_then(|v| v.parse::<usize>().ok())
                        .filter(|&v| v >= 1)
                })
                .unwrap_or(TARGET_PATTERNS_PER_SHARD);
            let cap = cores.min(MAX_COMPILE_SHARDS).max(1);
            let shard_count = hs_pats
                .len()
                .div_ceil(target)
                .clamp(1, cap)
                .min(hs_pats.len())
                .max(1);

            // LPT (longest-processing-time-first) bin-packing partition. The
            // Hyperscan build time of a shard is dominated by its heaviest
            // regexes (DFA state blow-up is super-linear in pattern length), so a
            // naive round-robin that happens to land several long regexes in one
            // shard makes that shard the wall-clock-determining straggler. Sort
            // patterns by a cost proxy (expression length) descending and place
            // each on the currently-lightest shard. This minimizes the MAX shard
            // cost, so wall-clock ~ mean shard cost, which scales smoothly with
            // patterns-per-shard - the property the full/half ratio test checks.
            // Each shard keeps the patterns' original GLOBAL ids (set on
            // `Pattern.id` above), so the union semantics are unchanged.
            let mut order: Vec<usize> = (0..hs_pats.len()).collect();
            order.sort_unstable_by_key(|&i| std::cmp::Reverse(hs_pats[i].expression.len()));
            let mut shard_pats: Vec<Vec<Pattern>> = (0..shard_count).map(|_| Vec::new()).collect();
            let mut shard_cost: Vec<u64> = vec![0; shard_count];
            for &i in &order {
                // Index of the lightest shard so far. `shard_count` is
                // `.clamp(1, cap).max(1)` above, so `shard_cost` is never empty
                // and `min_by_key` always yields `Some`; `unwrap_or(0)` keeps the
                // path panic-free (shard 0 always exists) without a production
                // `.expect`.
                let lightest = shard_cost
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, &c)| c)
                    .map(|(idx, _)| idx)
                    .unwrap_or(0);
                // Cost proxy: length plus a fixed per-pattern overhead so a shard
                // with many short patterns is not treated as free.
                shard_cost[lightest] += hs_pats[i].expression.len() as u64 + 16;
                shard_pats[lightest].push(hs_pats[i].clone());
            }

            const CACHE_MAGIC: &[u8; 4] = b"KHHS";
            const CACHE_VERSION: u32 = 1;

            // Compile (or cache-load) every shard concurrently. Returns the
            // built database and the global ids the shard had to drop (over-long
            // / unsupported constructs) for the keyword-fallback reroute.
            use rayon::prelude::*;
            let shard_results: Vec<Result<(BlockDatabase, Vec<usize>), String>> = shard_pats
                .into_par_iter()
                .enumerate()
                .map(|(shard_idx, pats)| {
                    // Per-shard cache key: the shared env-metadata digest plus
                    // this shard's own pattern strings, so each shard file is
                    // independent and the warm path is a deserialize-only load.
                    // The partition is deterministic for a given (pattern set,
                    // shard_count), so the keys are stable across runs; a host
                    // with a different shard_count simply produces different
                    // per-shard keys (no stale-read collision).
                    let shard_key = {
                        use sha2::{Digest, Sha256};
                        let mut h = Sha256::new();
                        h.update(cache_key.as_bytes());
                        h.update((shard_count as u64).to_le_bytes());
                        h.update((shard_idx as u64).to_le_bytes());
                        for p in &pats {
                            h.update(p.expression.as_bytes());
                            h.update([0]);
                        }
                        hex::encode(h.finalize())
                    };
                    let cache_path = cache_dir.join(format!("hs-{shard_key}.db"));

                    // Try the per-shard disk cache first.
                    if let Ok(bytes) = std::fs::read(&cache_path) {
                        if bytes.len() > 8
                            && &bytes[0..4] == CACHE_MAGIC
                            && bytes[4..8].try_into().map(u32::from_le_bytes).unwrap_or(0)
                                == CACHE_VERSION
                        {
                            use hyperscan::Serialized;
                            let payload: &[u8] = &bytes[8..];
                            if let Ok(db) = payload.deserialize::<BlockMode>() {
                                tracing::info!(
                                    cache = %cache_path.display(),
                                    shard = shard_idx,
                                    patterns = pats.len(),
                                    "HS shard loaded from cache"
                                );
                                return Ok((db, Vec::new()));
                            }
                        }
                    }

                    // Cold: build this shard, then atomically persist it.
                    let (db, dropped) = Self::compile_hs_db(&pats)?;
                    if let Ok(ser) = db.serialize() {
                        let mut data = Vec::with_capacity(ser.as_ref().len() + 8);
                        data.extend_from_slice(CACHE_MAGIC);
                        data.extend_from_slice(&CACHE_VERSION.to_le_bytes());
                        data.extend_from_slice(ser.as_ref());
                        let parent = cache_path
                            .parent()
                            .unwrap_or_else(|| std::path::Path::new("."));
                        if let Ok(mut tmp) = tempfile::NamedTempFile::new_in(parent) {
                            if std::io::Write::write_all(&mut tmp, &data).is_ok()
                                && tmp.as_file().sync_all().is_ok()
                            {
                                if let Err(error) = tmp.persist(&cache_path) {
                                    tracing::debug!(
                                        cache = %cache_path.display(),
                                        error = %error,
                                        "HS shard cache persist failed; next run will recompile"
                                    );
                                }
                            }
                        }
                        tracing::info!(cache = %cache_path.display(), shard = shard_idx, "HS shard cached");
                    }
                    Ok((db, dropped))
                })
                .collect();

            // Assemble the shards; any single shard's compile error fails the
            // whole build (matches the previous all-or-nothing contract).
            let mut shards = Vec::with_capacity(shard_count);
            for result in shard_results {
                let (db, dropped) = result?;
                unsupported.extend(dropped);
                // Verify scratch allocation works once per shard; further
                // scratches are allocated lazily per-thread on first scan.
                let test_scratch = db
                    .alloc_scratch()
                    .map_err(|e| format!("hyperscan scratch: {e}"))?;
                shards.push(Shard {
                    db,
                    scratch_pool: parking_lot::Mutex::new(vec![test_scratch]),
                });
            }

            // The caller (`build_simd_scanner`) already logs
            // `unsupported.len()` via tracing::info!, and consumers that
            // need the count get the Vec returned alongside. No need to
            // store a redundant copy on the scanner itself.
            Ok((
                Self {
                    shards,
                    pattern_map,
                    scanner_id: SCANNER_ID_SEQ.fetch_add(1, Ordering::Relaxed),
                },
                unsupported,
            ))
        }

        /// Build one shard's `BlockDatabase`, returning the database and the
        /// GLOBAL pattern ids it had to drop (over-long or an unsupported
        /// construct Hyperscan rejects only at build time). The dropped ids are
        /// rerouted into the keyword fallback by the caller so the pattern is
        /// never silently lost. Because sharding makes each shard far smaller
        /// than the old single combined database, the size-limit retry below
        /// almost never fires now - which strictly REDUCES the set of patterns
        /// dropped for "Pattern too large", improving recall, never hurting it.
        fn compile_hs_db(hs_pats: &[Pattern]) -> Result<(BlockDatabase, Vec<usize>), String> {
            let mut attempts = hs_pats.to_vec();
            let mut dropped: Vec<usize> = Vec::new();
            let started = std::time::Instant::now();
            let db: BlockDatabase = loop {
                let patterns_obj = Patterns(std::mem::take(&mut attempts));
                match Builder::build::<BlockMode>(&patterns_obj) {
                    Ok(db) => break db,
                    Err(_) if patterns_obj.0.len() > 100 => {
                        // Reclaim ownership for the next attempt.
                        attempts = patterns_obj.0;
                        attempts.sort_by_key(|p| std::cmp::Reverse(p.expression.len()));
                        let remove_count = attempts.len() / 10;
                        for _ in 0..remove_count {
                            if let Some(removed) = attempts.pop() {
                                dropped.push(removed.id.unwrap_or(0));
                            }
                        }
                        attempts.sort_by_key(|p| p.id.unwrap_or(0));
                    }
                    Err(e) => return Err(format!("hyperscan compile: {e}")),
                }
            };
            tracing::info!(
                patterns = hs_pats.len() - dropped.len(),
                compile_ms = started.elapsed().as_millis(),
                "HS shard compiled"
            );
            Ok((db, dropped))
        }

        /// Scan text and return `(hs_pattern_id, match_start, match_end)`.
        /// Uses a scratch pool for thread-safety without per-call allocation.
        ///
        /// # Examples
        ///
        /// ```rust,ignore
        /// use keyhog_scanner::simd::backend::HsScanner;
        ///
        /// let (scanner, _) = HsScanner::compile(&[(0, 0, "demo_[A-Z0-9]{8}", false)])?;
        /// let _matches = scanner.scan(b"demo_ABC12345");
        /// ```
        pub fn scan(&self, text: &[u8]) -> Vec<(usize, usize, usize)> {
            // Thread-local per-(scanner, shard) scratch: zero mutex contention
            // on parallel scans. Each rayon thread keeps one scratch per shard,
            // reused across all files it processes. Keyed by `scanner_id` so two
            // scanners in one process never hand each other a scratch allocated
            // against a different database; keyed by shard so each shard's
            // immutable database gets its own. No lock, no allocation after
            // first touch.
            thread_local! {
                static TLS: std::cell::RefCell<
                    std::collections::HashMap<(u64, usize), Scratch>,
                > = std::cell::RefCell::new(std::collections::HashMap::new());
            }

            // The match callback pushes the GLOBAL pattern id (set on
            // `Pattern.id` at compile), so the union over shards is identical
            // to a single all-patterns database's output - offsets are in the
            // original byte space, no remapping. Reserve once for the common
            // case; the union is typically small.
            let mut matches = Vec::with_capacity(32);

            for (shard_idx, shard) in self.shards.iter().enumerate() {
                let key = (self.scanner_id, shard_idx);
                // Take this thread's scratch for the shard (or allocate one):
                // pool first to reuse the compile-time test scratch, else a
                // fresh alloc tied to the shard's db.
                let scratch = TLS
                    .with(|tls| tls.borrow_mut().remove(&key))
                    .or_else(|| shard.scratch_pool.lock().pop())
                    .or_else(|| shard.db.alloc_scratch().ok());

                let Some(scratch) = scratch else {
                    continue;
                };

                let _ = shard.db.scan(text, &scratch, |id, from, to, _flags| {
                    matches.push((id as usize, from as usize, to as usize));
                    Matching::Continue
                });

                TLS.with(|tls| {
                    tls.borrow_mut().insert(key, scratch);
                });
            }
            matches
        }

        /// Scan `text`, invoking `on_match(hs_id)` for each matching pattern id,
        /// with NO per-call heap allocation (unlike [`scan`](Self::scan), which
        /// collects every match into a `Vec`). This is the set-membership hot
        /// path: on tiny chunks the `Vec::with_capacity(32)` allocation and the
        /// `(from,to)` triples `scan` builds dominate, while a prefilter only
        /// needs "which pattern ids matched". Paired with a single-shard build
        /// (`HsCompileOpts::shard_target = Some(usize::MAX)`) and `SINGLEMATCH`,
        /// this is ~20x faster per call than `scan` on ~150-byte inputs.
        pub fn scan_each(&self, text: &[u8], mut on_match: impl FnMut(usize)) {
            thread_local! {
                static TLS_EACH: std::cell::RefCell<
                    std::collections::HashMap<(u64, usize), Scratch>,
                > = std::cell::RefCell::new(std::collections::HashMap::new());
            }
            for (shard_idx, shard) in self.shards.iter().enumerate() {
                let key = (self.scanner_id, shard_idx);
                let scratch = TLS_EACH
                    .with(|tls| tls.borrow_mut().remove(&key))
                    .or_else(|| shard.scratch_pool.lock().pop())
                    .or_else(|| shard.db.alloc_scratch().ok());
                let Some(scratch) = scratch else {
                    continue;
                };
                let _ = shard.db.scan(text, &scratch, |id, _from, _to, _flags| {
                    on_match(id as usize);
                    Matching::Continue
                });
                TLS_EACH.with(|tls| {
                    tls.borrow_mut().insert(key, scratch);
                });
            }
        }

        /// True iff ANY compiled pattern matches `text`. The BOOLEAN companion
        /// to [`scan_each`](Self::scan_each): the match callback returns
        /// `Matching::Terminate` on the first hit, so HS aborts the scan
        /// (`HS_SCAN_TERMINATED`) instead of enumerating every match. On a chunk
        /// that has an active pattern this returns after the first one — the
        /// admission gate (`has_active_fallback_patterns_for_chunk`) needs only
        /// "is anything active?", never the full marked set, and building that
        /// set is the measured #1 scan cost (`fb:prefilter`).
        ///
        /// Returns the same boolean as `!scan_each(text).is_empty()` — same
        /// database, same haystack — but short-circuits.
        pub fn any_match(&self, text: &[u8]) -> bool {
            thread_local! {
                static TLS_ANY: std::cell::RefCell<
                    std::collections::HashMap<(u64, usize), Scratch>,
                > = std::cell::RefCell::new(std::collections::HashMap::new());
            }
            for (shard_idx, shard) in self.shards.iter().enumerate() {
                let key = (self.scanner_id, shard_idx);
                let scratch = TLS_ANY
                    .with(|tls| tls.borrow_mut().remove(&key))
                    .or_else(|| shard.scratch_pool.lock().pop())
                    .or_else(|| shard.db.alloc_scratch().ok());
                let Some(scratch) = scratch else {
                    continue;
                };
                let mut hit = false;
                let _ = shard.db.scan(text, &scratch, |_id, _from, _to, _flags| {
                    hit = true;
                    Matching::Terminate
                });
                TLS_ANY.with(|tls| {
                    tls.borrow_mut().insert(key, scratch);
                });
                if hit {
                    return true;
                }
            }
            false
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
        pub fn pattern_info(&self, hs_id: usize) -> Option<(usize, usize, bool)> {
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
        pub fn pattern_count(&self) -> usize {
            self.pattern_map.len()
        }
    }
}
