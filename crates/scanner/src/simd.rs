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

    /// Compiled Hyperscan database for all detector patterns.
    /// Thread-safe: the database is immutable and scratch is pooled per-instance.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use keyhog_scanner::simd::backend::HsScanner;
    ///
    /// let _scanner = HsScanner::compile(&[(0, 0, "demo_[A-Z0-9]{8}", false)])?;
    /// ```
    pub struct HsScanner {
        db: BlockDatabase,
        /// Map from HS pattern ID to (detector_index, pattern_index, has_group)
        pattern_map: Vec<(usize, usize, bool)>,
        /// Per-instance scratch pool (each scratch is tied to this db)
        scratch_pool: parking_lot::Mutex<Vec<Scratch>>,
    }

    // SAFETY: BlockDatabase is immutable after compilation and safe to share.
    // Scratch pool is Mutex-guarded. Individual Scratch objects are only used
    // by one thread at a time (taken from pool, returned after use).
    unsafe impl Send for HsScanner {}
    unsafe impl Sync for HsScanner {}

    impl HsScanner {
        /// Compile patterns into a Hyperscan database.
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
            let mut hs_pats = Vec::new();
            let mut pattern_map = Vec::new();
            let mut unsupported = Vec::new();

            for (i, &(det_idx, pat_idx, regex, has_group)) in patterns.iter().enumerate() {
                // Skip patterns that are too long for Hyperscan (>500 chars)
                if regex.len() > 500 {
                    unsupported.push(i);
                    continue;
                }
                // CASELESS only. No SOM_LEFTMOST - it causes "Pattern too large"
                // on complex regexes. Match positions extracted by regex crate.
                let flags = PatternFlags::CASELESS;
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

                hex::encode(h.finalize())
            };
            let cache_path = cache_dir.join(format!("hs-{cache_key}.db"));

            const CACHE_MAGIC: &[u8; 4] = b"KHHS";
            const CACHE_VERSION: u32 = 1;

            // Try loading from cache first.
            let db: BlockDatabase = if let Ok(bytes) = std::fs::read(&cache_path) {
                if bytes.len() > 8 && &bytes[0..4] == CACHE_MAGIC {
                    let version = bytes[4..8].try_into().map(u32::from_le_bytes).unwrap_or(0);
                    if version == CACHE_VERSION {
                        use hyperscan::Serialized;
                        let payload: Vec<u8> = bytes[8..].to_vec();
                        match payload.as_slice().deserialize::<BlockMode>() {
                            Ok(db) => {
                                tracing::info!(cache = %cache_path.display(), patterns = hs_pats.len(), "HS loaded from cache");
                                db
                            }
                            Err(_) => {
                                Self::compile_hs_db(&hs_pats, &mut unsupported, &pattern_map)?
                            }
                        }
                    } else {
                        Self::compile_hs_db(&hs_pats, &mut unsupported, &pattern_map)?
                    }
                } else {
                    Self::compile_hs_db(&hs_pats, &mut unsupported, &pattern_map)?
                }
            } else {
                let db = Self::compile_hs_db(&hs_pats, &mut unsupported, &pattern_map)?;
                // Task 1b: Atomic write with magic + version
                if let Ok(ser) = db.serialize() {
                    let mut data = Vec::with_capacity(ser.as_ref().len() + 8);
                    data.extend_from_slice(CACHE_MAGIC);
                    data.extend_from_slice(&CACHE_VERSION.to_le_bytes());
                    data.extend_from_slice(ser.as_ref());

                    // NamedTempFile + persist for atomic write - same
                    // rationale as `merkle_index::save`. The previous
                    // pid-suffixed tmp leaked on panic between write
                    // and rename; the Drop impl on NamedTempFile
                    // cleans it up automatically.
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
                                    "HS DB cache persist failed; next run will recompile"
                                );
                            }
                        }
                    }
                    tracing::info!(cache = %cache_path.display(), "HS cached");
                }
                db
            };

            // Verify scratch allocation works with a single test allocation.
            // Further scratches are allocated lazily per-thread on first scan.
            let test_scratch = db
                .alloc_scratch()
                .map_err(|e| format!("hyperscan scratch: {e}"))?;
            let initial_pool = vec![test_scratch];

            // The caller (`build_simd_scanner`) already logs
            // `unsupported.len()` via tracing::info!, and consumers that
            // need the count get the Vec returned alongside. No need to
            // store a redundant copy on the scanner itself.
            Ok((
                Self {
                    db,
                    pattern_map,
                    scratch_pool: parking_lot::Mutex::new(initial_pool),
                },
                unsupported,
            ))
        }

        fn compile_hs_db(
            hs_pats: &[Pattern],
            unsupported: &mut Vec<usize>,
            pattern_map: &[(usize, usize, bool)],
        ) -> Result<BlockDatabase, String> {
            let mut attempts = hs_pats.to_vec();
            let started = std::time::Instant::now();
            let db: BlockDatabase = loop {
                let patterns_obj = Patterns(attempts.clone());
                match Builder::build::<BlockMode>(&patterns_obj) {
                    Ok(db) => break db,
                    Err(_) if attempts.len() > 100 => {
                        attempts.sort_by_key(|p| std::cmp::Reverse(p.expression.len()));
                        let remove_count = attempts.len() / 10;
                        for _ in 0..remove_count {
                            if let Some(removed) = attempts.pop() {
                                let idx = removed.id.unwrap_or(0);
                                if idx < pattern_map.len() {
                                    unsupported.push(idx);
                                }
                            }
                        }
                        attempts.sort_by_key(|p| p.id.unwrap_or(0));
                    }
                    Err(e) => return Err(format!("hyperscan compile: {e}")),
                }
            };
            tracing::info!(
                patterns = attempts.len(),
                compile_ms = started.elapsed().as_millis(),
                "HS compiled"
            );
            Ok(db)
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
            // Thread-local scratch: zero mutex contention on parallel scans.
            // Each rayon thread gets its own scratch, reused across all files
            // that thread processes. No lock, no allocation after first use.
            thread_local! {
                static TLS: std::cell::RefCell<Option<Scratch>> = const { std::cell::RefCell::new(None) };
            }

            let scratch = TLS
                .with(|tls| tls.borrow_mut().take())
                .or_else(|| self.scratch_pool.lock().pop())
                .or_else(|| self.db.alloc_scratch().ok());

            let Some(scratch) = scratch else {
                return Vec::new();
            };

            let mut matches = Vec::with_capacity(32);
            let _ = self.db.scan(text, &scratch, |id, from, to, _flags| {
                matches.push((id as usize, from as usize, to as usize));
                Matching::Continue
            });

            TLS.with(|tls| {
                *tls.borrow_mut() = Some(scratch);
            });
            matches
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

    // Regression gate for the silent-pattern-drop class of bug.
    //
    // Two engines compile every detector pattern in production:
    // `HsScanner::compile` (Hyperscan, simd path) and
    // `regex::RegexBuilder` (used by the fallback + companion paths
    // via `compiler.rs::shared_regex`). Each has its own ~1 MiB
    // per-pattern DFA budget; both can silently drop a pattern when
    // a bounded repetition over a wide character class blows the
    // budget.
    //
    // Hyperscan logs `unsupported.len()` at `tracing::info!`
    // (silenced by default). The regex crate raises a
    // `CompiledTooBig` error inside `CompiledScanner::compile` -
    // but that fails LATE, only when keyhog binds a real scanner
    // at runtime, NOT in any unit test that compiles individual
    // patterns in isolation. Together the two engines let a
    // regression land silently until either a `contracts_runner`
    // fixture-text test misses a credential (Hyperscan path) or a
    // real `keyhog scan` invocation exits 2 with the runtime error
    // (regex-crate path).
    //
    // Both classes regressed on 2026-05-24:
    //   - aws-ecr-token   `{50,4096}` over 64-char alphabet
    //                     -> Hyperscan rejection
    //   - supabase-realtime `[^\s"']{1,2048}` over ~250-char class
    //                     -> regex-crate `CompiledTooBig`
    //
    // This gate runs every embedded detector pattern through BOTH
    // engines with the same size limits the production paths use,
    // and fails with the offending regex string the moment either
    // engine rejects it - catching the silent-drop class at PR time.
    #[cfg(test)]
    mod silent_drop_gate {
        use super::HsScanner;

        /// Compile `pattern` through the regex crate with the EXACT flags the
        /// production fallback path uses (`compiler_compile::shared_regex_compile`):
        /// `case_insensitive(true)`, `crlf(true)`, and the same size + DFA
        /// budgets. Returns the regex-crate error if the pattern is rejected.
        fn regex_crate_rejects(pattern: &str) -> Option<regex::Error> {
            regex::RegexBuilder::new(pattern)
                .case_insensitive(true)
                .size_limit(crate::types::REGEX_SIZE_LIMIT_BYTES)
                .dfa_size_limit(crate::types::regex_dfa_limit())
                .crlf(true)
                .build()
                .err()
        }

        /// Every embedded detector pattern must compile in BOTH the Hyperscan
        /// (simd) engine and the regex crate (fallback engine). A pattern that
        /// either engine silently drops is a live credential keyhog cannot
        /// detect on the corresponding platform - exactly the 2026-05-24
        /// aws-ecr-token / supabase-realtime regression. This drives the real
        /// embedded detector set through both real compile paths and names the
        /// offending detector + regex the moment one is dropped.
        #[test]
        fn every_embedded_pattern_compiles_in_both_engines() {
            // Route Hyperscan's compiled-DB cache into a throwaway dir so the
            // batched compile below does not write into the user's real
            // ~/.cache/keyhog (and so a stale cache cannot mask a regression).
            // `compile()` only accepts a `KEYHOG_CACHE_DIR` under $HOME or
            // `/tmp/keyhog-cache-<uid>`, so nest under the latter to pass that
            // validation. SAFETY: geteuid/getpid are trivial, infallible,
            // read-only syscalls.
            let (uid, pid) = unsafe { (libc::geteuid(), libc::getpid()) };
            let tmp = std::path::PathBuf::from(format!("/tmp/keyhog-cache-{uid}"))
                .join(format!("silentgate-{pid}"));
            std::fs::create_dir_all(&tmp).expect("create temp cache dir");
            std::env::set_var("KEYHOG_CACHE_DIR", &tmp);

            let tomls = keyhog_core::embedded_detector_tomls();
            assert!(
                tomls.len() >= 100,
                "expected the full embedded detector set, got {} (build dropped detectors?)",
                tomls.len()
            );

            // (detector_id, regex) for every in-budget embedded pattern, in a
            // stable order so the Hyperscan `unsupported` indices map straight
            // back to the offending detector.
            let mut hs_inputs: Vec<(String, String)> = Vec::new();
            let mut checked = 0usize;

            for (file, toml) in tomls {
                let detectors = keyhog_core::load_detectors_from_str(toml)
                    .unwrap_or_else(|e| panic!("embedded detector {file} failed to parse: {e}"));

                for detector in &detectors {
                    for pat in &detector.patterns {
                        checked += 1;
                        let regex = pat.regex.as_str();

                        // Engine A: regex crate (fallback path). A rejection here
                        // is the `CompiledTooBig`-class failure that surfaces as a
                        // late runtime error in a real `keyhog scan`.
                        if let Some(err) = regex_crate_rejects(regex) {
                            panic!(
                                "regex-crate engine dropped detector {} (file {file}): {err}\n  regex: {regex}",
                                detector.id
                            );
                        }

                        // Patterns over Hyperscan's 500-char ceiling are a known,
                        // explicit skip (the `compile()` guard reroutes them to
                        // the keyword fallback), so only the simd engine is
                        // asserted for in-budget regexes.
                        if regex.len() <= 500 {
                            hs_inputs.push((detector.id.clone(), regex.to_string()));
                        }
                    }
                }
            }

            assert!(
                checked >= 100,
                "expected to check >=100 embedded patterns, only checked {checked}"
            );

            // Engine B: Hyperscan (simd path), compiled in ONE batch exactly as
            // production does. `compile` returns the input indices it could not
            // compile in `unsupported`; any index there is a pattern the simd
            // engine would silently never match.
            let pattern_refs: Vec<(usize, usize, &str, bool)> = hs_inputs
                .iter()
                .enumerate()
                .map(|(i, (_id, regex))| (i, i, regex.as_str(), false))
                .collect();

            let (_scanner, unsupported) = HsScanner::compile(&pattern_refs)
                .expect("Hyperscan failed to compile the embedded detector set");

            if let Some(&idx) = unsupported.first() {
                let (id, regex) = &hs_inputs[idx];
                panic!(
                    "Hyperscan engine dropped {} embedded pattern(s); first is detector {id}\n  regex: {regex}",
                    unsupported.len()
                );
            }
        }
    }
}
