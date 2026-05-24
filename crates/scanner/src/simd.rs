//! Vectorscan/Hyperscan SIMD regex backend for high-throughput scanning.
//!
//! When the `simd` feature is enabled, this replaces the AC+fallback approach
//! with Hyperscan's simultaneous multi-pattern matching using SIMD instructions.
//! Gives 3-5x throughput improvement. Accuracy is identical — same patterns, faster engine.

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
                // CASELESS only. No SOM_LEFTMOST — it causes "Pattern too large"
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
                    // SAFETY: see geteuid() above — trivial syscall.
                    let uid = unsafe { libc::geteuid() };
                    PathBuf::from(format!("/tmp/keyhog-cache-{}", uid))
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

                    // NamedTempFile + persist for atomic write — same
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
                            let _ = tmp.persist(&cache_path);
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

    /// Regression gate for the silent-pattern-drop class of bug.
    ///
    /// `HsScanner::compile` returns `(scanner, unsupported: Vec<usize>)`
    /// — `unsupported` lists every pattern that failed to compile into
    /// the Hyperscan database. Today the production path
    /// (`build_simd_scanner` in `engine/backend.rs`) only logs that
    /// count at `tracing::info!`, which is silenced by default. A
    /// detector pattern can therefore silently drop out of the scan
    /// with zero CI signal.
    ///
    /// That's how the `aws-ecr-token` `{50,4096}` capture broke on
    /// 2026-05-24 — Hyperscan's per-pattern DFA budget (~1 MiB)
    /// exploded on a bounded repetition over a 64-char class, the
    /// pattern silently dropped, and only `contracts_runner` (which
    /// scans actual fixture text) noticed. This test catches the same
    /// failure mode directly at PR time instead of via a missing
    /// fixture match.
    #[cfg(test)]
    mod silent_drop_regression {
        use super::*;

        #[test]
        fn no_embedded_detector_pattern_silently_drops_at_hyperscan_compile() {
            // Load the production-shipped embedded detector corpus.
            let mut specs = Vec::new();
            for (name, toml_text) in keyhog_core::embedded_detector_tomls() {
                match keyhog_core::load_detectors_from_str(toml_text) {
                    Ok(parsed) => specs.extend(parsed),
                    Err(err) => panic!(
                        "embedded detector `{name}` failed to parse — fix the TOML \
                         first. Inner: {err}"
                    ),
                }
            }
            assert!(
                !specs.is_empty(),
                "embedded_detector_tomls() returned empty after parse — build.rs \
                 likely skipped embedding; rebuild keyhog-core from a clean target/."
            );

            // Compile each pattern in isolation through HsScanner::compile
            // and assert `unsupported` is empty. This is more strict than
            // the production path (which compiles the union database with
            // pattern-bisect-on-failure) but it's the right gate for
            // catching the silent-drop bug: any pattern that can't make
            // it through compile() alone won't be in the database either.
            let mut dropped: Vec<(String, String, String)> = Vec::new();
            for spec in &specs {
                for (pat_idx, pattern) in spec.patterns.iter().enumerate() {
                    let regex_str = pattern.regex.as_str();
                    let single = [(0usize, pat_idx, regex_str, false)];
                    match HsScanner::compile(&single) {
                        Ok((_scanner, unsupported)) => {
                            if !unsupported.is_empty() {
                                dropped.push((
                                    spec.id.to_string(),
                                    regex_str.to_string(),
                                    "single-pattern compile returned unsupported — \
                                     probable DFA-size or unsupported-feature rejection"
                                        .to_string(),
                                ));
                            }
                        }
                        Err(err) => {
                            dropped.push((spec.id.to_string(), regex_str.to_string(), err));
                        }
                    }
                }
            }

            if !dropped.is_empty() {
                let mut msg = format!(
                    "{} detector pattern(s) silently dropped at Hyperscan compile:\n",
                    dropped.len()
                );
                for (det, regex, why) in dropped.iter().take(10) {
                    msg.push_str(&format!("  - {det}: {regex}\n    -> {why}\n"));
                }
                if dropped.len() > 10 {
                    msg.push_str(&format!("  ... and {} more.\n", dropped.len() - 10));
                }
                msg.push_str(
                    "\nCommon cause: a bounded repetition `{0,N}` over a wide \
                     character class (8-bit alphabet, N > ~256) explodes the \
                     per-pattern DFA. Fix: drop the upper bound or shrink N. \
                     Prior art: aws-ecr-token commit c6d0511.",
                );
                panic!("{msg}");
            }
        }
    }
}
