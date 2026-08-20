use hyperscan::{Block as BlockMode, BlockDatabase, Builder, Pattern, PatternFlags, Patterns};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

mod scan;

/// Target number of patterns per compile shard. The cold compile is a
/// single serial C-side NFA/DFA build whose wall-clock scales ~linearly
/// with the pattern count, so the shard COUNT is sized to keep each shard
/// near this many patterns: `shards = ceil(n / TARGET_PATTERNS_PER_SHARD)`,
/// capped at the active Rayon executor width. Sizing by patterns-per-shard
/// (rather than a fixed shard count) is what flattens the build's scaling: as
/// the corpus grows, the number of shards grows while each shard's serial
/// build stays ~constant, so on a many-core box "double the patterns" is
/// absorbed by adding parallel shards instead of doubling work per shard.
/// ~320 was chosen empirically: on the ~900-detector corpus (~2.2k compiled
/// patterns) it keeps the full and half corpora in a small number of similarly
/// heavy shards. That gives the ratio gate stable margin (about 1.25x on the
/// 22-core dev box) while avoiding the tiny-shard regime where cache
/// serialization, temp-file persistence, and scan-time fanout dominate. A much
/// smaller target makes the half corpus artificially fast and the ratio flakes;
/// a much larger target gives up parallelism. Per-shard builds stay sub-second
/// (vs ~1600ms for the serial all-patterns build). Each shard is
/// disk-cached independently (keyed by the SHA-256 of its own pattern
/// list), so the warm path stays a deserialize-only load. Overridable through
/// explicit scanner compile tuning (`[tuning].hs_shard_target` in the CLI).
// ONE-PLACE: the shard-target default has a single literal owner in
// `ScannerTuningConfig::HS_SHARD_TARGET_DEFAULT` (the value the CLI's
// `[tuning].hs_shard_target` knob defaults to). Deriving it here keeps the
// SIMD backend's absent-tuning fallback (line ~519) from silently diverging
// from the config layer's fallback if the default is ever retuned.
const TARGET_PATTERNS_PER_SHARD: usize =
    crate::scanner_config::ScannerTuningConfig::HS_SHARD_TARGET_DEFAULT;

/// Hard ceiling on shard count, so a pathologically large detector set on a
/// 128-core box cannot spawn an unbounded number of databases (each costs a
/// scan-time dispatch). At this cap the per-shard size grows again, but the
/// real corpus (~900 patterns) sits at ~23 shards, well under it.
const MAX_COMPILE_SHARDS: usize = 64;
const MAX_HS_PATTERN_LEN: usize = 500;
const BASE_PATTERN_COST: u64 = 16;
const RETRY_DROP_DIVISOR: usize = 10;
const HS_CRATE_CACHE_VERSION: &[u8] = b"0.3.2";

pub(crate) fn contains_ucp_semantic_escape(regex: &str) -> bool {
    let mut escaped = false;
    for byte in regex.bytes() {
        if byte == b'\\' {
            escaped = !escaped;
            continue;
        }
        if escaped
            && matches!(
                byte,
                b'b' | b'B' | b'd' | b'D' | b'p' | b'P' | b's' | b'S' | b'w' | b'W'
            )
        {
            return true;
        }
        escaped = false;
    }
    false
}

/// Effective user id for cache-dir namespacing and ownership checks. On Unix
/// this is `geteuid()`; on non-Unix (Windows) there is no euid, and per-user
/// isolation comes from the ACL'd user profile dir (`dirs::cache_dir()` →
/// LocalAppData) instead, so a constant namespace is correct. Gating the FFI
/// here keeps the whole `simd` backend buildable on the default Windows target
/// (the prior unconditional `libc::geteuid()` failed to compile there).
#[cfg(unix)]
fn current_uid() -> u32 {
    // SAFETY: `geteuid` is a thread-safe read-only syscall taking no arguments
    // that cannot fail; the binding is `unsafe` only because it crosses FFI.
    unsafe { libc::geteuid() }
}

#[cfg(not(unix))]
fn current_uid() -> u32 {
    0
}

/// Whether an operator-supplied Hyperscan cache dir is under an allowed root:
/// the user's home, or a per-uid dir under the system temp root. Pure (no env,
/// no syscalls) so the allowlist policy is unit-testable without mutating
/// process-global env. `temp_root` is `std::env::temp_dir()` at the call site,
/// so `$TMPDIR` (else `/tmp`) is honored rather than a hardcoded `/tmp`.
///
/// `pub` only for re-export through the `#[doc(hidden)] crate::testing` facade
/// (scanner src forbids inline test modules, KH-GAP-004); `mod simd` is
/// `pub(crate)`, so it is not otherwise reachable.
pub(crate) fn cache_dir_under_allowed_root(
    path: &std::path::Path,
    home: &std::path::Path,
    temp_root: &std::path::Path,
    uid: u32,
) -> bool {
    let tmp_user_dir = temp_root.join(format!("keyhog-cache-{uid}"));
    path.starts_with(home) || path.starts_with(&tmp_user_dir)
}

static CONFIGURED_CACHE_DIR: OnceLock<parking_lot::RwLock<Option<PathBuf>>> = OnceLock::new();

fn configured_cache_dir_cell() -> &'static parking_lot::RwLock<Option<PathBuf>> {
    CONFIGURED_CACHE_DIR.get_or_init(|| parking_lot::RwLock::new(None))
}

pub(crate) fn set_configured_cache_dir(path: Option<PathBuf>) {
    *configured_cache_dir_cell().write() = path;
}

fn configured_cache_dir() -> Option<PathBuf> {
    configured_cache_dir_cell().read().clone()
}

pub(crate) fn validate_configured_cache_dir(path: &std::path::Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err(format!(
            "Fix: configured Hyperscan cache dir '{}' must be absolute",
            path.display()
        ));
    }
    let home = dirs::home_dir().ok_or("Fix: Could not determine HOME directory")?;
    let uid = current_uid();
    let temp_root = std::env::temp_dir();
    if !cache_dir_under_allowed_root(path, &home, &temp_root, uid) {
        return Err(format!(
            "Fix: configured Hyperscan cache dir must be under {} or {}",
            home.display(),
            temp_root.join(format!("keyhog-cache-{uid}")).display()
        ));
    }
    if path.exists() {
        let meta = std::fs::symlink_metadata(path)
            .map_err(|e| format!("Fix: Could not read cache dir metadata: {}", e))?;
        if meta.is_symlink() {
            return Err("Fix: configured Hyperscan cache dir cannot be a symlink".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if meta.uid() != uid {
                return Err("Fix: cache directory is not owned by the current user".into());
            }
        }
    }
    Ok(())
}

fn default_cache_dir() -> PathBuf {
    let uid = current_uid();
    match dirs::cache_dir() {
        Some(cache) => cache.join("keyhog"),
        // Last-resort fallback honors `$TMPDIR` (else `/tmp`), matching
        // the validation allowlist root below.
        None => std::env::temp_dir().join(format!("keyhog-cache-{}", uid)),
    }
}

fn resolve_cache_dir() -> Result<PathBuf, String> {
    let dir = if let Some(path) = configured_cache_dir() {
        validate_configured_cache_dir(&path)?;
        path
    } else {
        // Persistent per-user cache so cold Hyperscan compilation is paid once
        // per (machine, pattern-set, hyperscan version, CPU features), then
        // warm scans reload serialized shards instead of recompiling. Falls
        // back to the per-uid temp cache only when no platform cache directory
        // is resolvable.
        default_cache_dir()
    };

    if dir.exists() {
        let meta = std::fs::symlink_metadata(&dir)
            .map_err(|e| format!("Fix: Could not read cache dir metadata: {}", e))?;
        if meta.is_symlink() {
            return Err("Fix: configured Hyperscan cache dir cannot be a symlink".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let uid = current_uid();
            if meta.uid() != uid {
                return Err("Fix: cache directory is not owned by the current user".into());
            }
            if meta.permissions().mode() & 0o777 != 0o700 {
                std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                    .map_err(|e| format!("Fix: Could not set cache dir permissions: {}", e))?;
            }
        }
    } else {
        std::fs::create_dir_all(&dir)
            .map_err(|e| format!("Fix: Could not create cache dir: {}", e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| format!("Fix: Could not set cache dir permissions: {}", e))?;
        }
    }
    Ok(dir)
}

fn read_hs_cache_file(path: &std::path::Path) -> std::io::Result<Option<Vec<u8>>> {
    use std::io::Read;

    let file = std::fs::File::open(path)?;
    let metadata = file.metadata()?;
    if metadata.len() > keyhog_core::HYPERSCAN_CACHE_FILE_BYTES {
        tracing::warn!(
            cache = %path.display(),
            size = metadata.len(),
            cap = keyhog_core::HYPERSCAN_CACHE_FILE_BYTES,
            "HS shard cache file exceeds cap; compiling from patterns"
        );
        return Ok(None);
    }

    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    let mut limited = file.take(keyhog_core::HYPERSCAN_CACHE_FILE_BYTES.saturating_add(1));
    limited.read_to_end(&mut bytes)?;
    if bytes.len() as u64 > keyhog_core::HYPERSCAN_CACHE_FILE_BYTES {
        tracing::warn!(
            cache = %path.display(),
            cap = keyhog_core::HYPERSCAN_CACHE_FILE_BYTES,
            "HS shard cache grew beyond cap while reading; compiling from patterns"
        );
        return Ok(None);
    }
    Ok(Some(bytes))
}

/// Monotonic per-process id source so each `HsScanner` instance gets a
/// distinct key for its thread-local scratch cache (below). Multiple
/// scanners in one process must not hand each other a scratch allocated
/// against a different database.
static SCANNER_ID_SEQ: AtomicU64 = AtomicU64::new(0);
static COMPILE_WITH_OPTS_INVOCATIONS: AtomicUsize = AtomicUsize::new(0);

/// One compiled shard: its Hyperscan database. Scratch space is allocated
/// lazily, bound to this database, and retained per-thread / per-scanner in
/// the thread-local cache (see `simd/backend/scan.rs`). Removing the
/// compile-time pool means `compile` pays only for the immutable database,
/// not `executor_width` scratches per shard.
struct Shard {
    db: BlockDatabase,
}

/// Compiled Hyperscan databases for all detector patterns, sharded across
/// cores at compile time.
///
/// Thread-safe: every database is immutable after compilation. Scratch state
/// is held in the thread-local cache (`scan::SCRATCH_TLS`) keyed by scanner
/// identity, so a dropped scanner cannot leak or be aliased by another.
/// `pattern_info`/`pattern_count` index one global `pattern_map` keyed by
/// dense Hyperscan database ID. If shard building rejects patterns, the
/// supported patterns and mapping rows are compacted together, IDs are
/// reassigned, and every shard is rebuilt. Mapping rows retain their original
/// caller IDs for canonical recovery while matches from every shard use the
/// same dense database-ID space.
///
/// # Examples
///
/// ```rust,ignore
/// use keyhog_scanner::simd::backend::HsScanner;
///
/// let _scanner = HsScanner::compile(&[(0, 0, "demo_[A-Z0-9]{8}", false)])?;
/// ```
pub(crate) struct HsScanner {
    /// Independently-compiled shard databases. Their union over a scan is
    /// exactly the set of supported matches a single all-patterns database
    /// would produce. Hyperscan match IDs are dense global database IDs,
    /// disjoint across shards.
    shards: Vec<Shard>,
    /// Dense map from Hyperscan database ID to
    /// (original input index, detector index, pattern index, has_group).
    pattern_map: Vec<(usize, usize, usize, bool)>,
    /// Distinct id for this scanner instance, used to key the thread-local
    /// per-shard scratch cache so two scanners never share scratches.
    scanner_id: u64,
    /// Liveness token for thread-local scratch entries. Drop purges scratches
    /// on the current thread; Rayon and other persistent worker threads prune
    /// stale entries on later Hyperscan cache touches without evicting live
    /// scanners that are interleaved on the same thread.
    scratch_owner: Arc<()>,
}

// SAFETY: BlockDatabase is immutable after compilation and safe to share.
// Scratch objects are held one-at-a-time by the scanning thread and then
// returned to thread-local storage keyed by the live scanner, so `Send` and
// `Sync` hold.
unsafe impl Send for HsScanner {}
unsafe impl Sync for HsScanner {}

impl Drop for HsScanner {
    fn drop(&mut self) {
        let scanner_id = self.scanner_id;
        scan::purge_scanner_scratch(scanner_id);
    }
}

/// Per-pattern compilation options for [`HsScanner::compile_with_opts`].
///
/// The legacy phase-1 [`HsScanner::compile`] path compiles every pattern
/// `CASELESS` and reports every match (no `SINGLEMATCH`). The always-active
/// phase-2 prefilter wants the opposite on both axes: it needs each
/// pattern's OWN case sensitivity (a plain homoglyph variant is
/// case-sensitive; a detector regex is not) so the marked set matches the
/// `regex` reference exactly, and it only needs to know "did pattern P match
/// at all", so `SINGLEMATCH` fires each pattern once and stops, removing the
/// broad-pattern callback storm that is why the phase-2 prefilter never used HS.
#[derive(Clone, Copy)]
pub(crate) struct HsCompileOpts<'a> {
    /// Set `HS_FLAG_SINGLEMATCH` on every pattern (fire once, then retire).
    pub(crate) singlematch: bool,
    /// Per-input-pattern caseless flags, parallel to `patterns`. `None` =
    /// every pattern `CASELESS` (legacy behavior). `Some` must have exactly
    /// one flag per input pattern; length drift is a compile-configuration
    /// error, not permission to silently broaden missing entries to caseless.
    pub(crate) caseless: Option<&'a [bool]>,
    /// Override the patterns-per-shard target (else the compiled default). The
    /// sharded scan must hit EVERY shard per call, so the per-shard fixed
    /// overhead is paid `shard_count` times, fine for the phase-1 position
    /// scan, but it dominates the set-membership PREFILTER on tiny chunks.
    /// Pass `Some(usize::MAX)` to force a single database so `scan_each` pays
    /// the per-scan overhead exactly once.
    pub(crate) shard_target: Option<usize>,
    pub(crate) utf8: bool,
    pub(crate) ucp: bool,
}

impl Default for HsCompileOpts<'_> {
    fn default() -> Self {
        Self {
            singlematch: false,
            caseless: None,
            shard_target: None,
            utf8: false,
            ucp: false,
        }
    }
}

struct PreparedPatterns {
    hs_pats: Vec<Pattern>,
    pattern_map: Vec<(usize, usize, usize, bool)>,
    unsupported: Vec<usize>,
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
    #[cfg(test)]
    pub(crate) fn compile(
        patterns: &[(usize, usize, &str, bool)],
    ) -> Result<(Self, Vec<usize>), String> {
        Self::compile_with_opts(patterns, HsCompileOpts::default())
    }

    fn prepare_patterns(
        patterns: &[(usize, usize, &str, bool)],
        opts: HsCompileOpts<'_>,
    ) -> PreparedPatterns {
        enum PrepResult {
            Pattern {
                input_index: usize,
                det_idx: usize,
                pat_idx: usize,
                has_group: bool,
                pattern: Pattern,
            },
            Unsupported {
                index: usize,
            },
            Rejected {
                index: usize,
                error: String,
            },
        }

        let prepare =
            |(i, &(det_idx, pat_idx, regex, has_group)): (usize, &(usize, usize, &str, bool))| {
                if regex.len() > MAX_HS_PATTERN_LEN {
                    return PrepResult::Unsupported { index: i };
                }
                if opts.ucp && contains_ucp_semantic_escape(regex) {
                    return PrepResult::Unsupported { index: i };
                }
                match Pattern::with_flags(regex, Self::pattern_flags(i, opts)) {
                    Ok(pattern) => PrepResult::Pattern {
                        input_index: i,
                        det_idx,
                        pat_idx,
                        has_group,
                        pattern,
                    },
                    Err(error) => PrepResult::Rejected {
                        index: i,
                        error: error.to_string(),
                    },
                }
            };
        let prepared: Vec<PrepResult> = patterns.iter().enumerate().map(prepare).collect();

        let mut hs_pats = Vec::new();
        let mut pattern_map = Vec::new();
        let mut unsupported = Vec::new();

        for result in prepared {
            match result {
                PrepResult::Pattern {
                    input_index,
                    det_idx,
                    pat_idx,
                    has_group,
                    mut pattern,
                } => {
                    pattern.id = Some(pattern_map.len());
                    hs_pats.push(pattern);
                    pattern_map.push((input_index, det_idx, pat_idx, has_group));
                }
                PrepResult::Unsupported { index } => unsupported.push(index),
                PrepResult::Rejected { index, error } => {
                    // Unsupported IDs return to the caller for exact literal recovery.
                    tracing::debug!(
                        error,
                        pattern_index = index,
                        "pattern rejected by hyperscan; caller retains its canonical literal route"
                    );
                    unsupported.push(index);
                }
            }
        }

        PreparedPatterns {
            hs_pats,
            pattern_map,
            unsupported,
        }
    }

    fn pattern_flags(index: usize, opts: HsCompileOpts<'_>) -> PatternFlags {
        // No SOM_LEFTMOST - it causes "Pattern too large" on complex regexes;
        // match positions are extracted by the regex crate. CASELESS is
        // per-pattern (legacy callers get all-caseless); SINGLEMATCH is opt-in
        // for the set-membership prefilter.
        let mut flags = PatternFlags::empty();
        let caseless = match opts.caseless {
            Some(flags) => flags[index],
            None => true,
        };
        if caseless {
            flags |= PatternFlags::CASELESS;
        }
        if opts.singlematch {
            flags |= PatternFlags::SINGLEMATCH;
        }
        if opts.utf8 {
            flags |= PatternFlags::UTF8;
        }
        if opts.ucp {
            flags |= PatternFlags::UCP;
        }
        flags
    }

    fn validate_compile_opts(pattern_count: usize, opts: HsCompileOpts<'_>) -> Result<(), String> {
        if let Some(caseless) = opts.caseless {
            if caseless.len() != pattern_count {
                return Err(format!(
                    "hyperscan compile option mismatch: caseless flags length {} does not match pattern count {}; refusing silent CASELESS default",
                    caseless.len(),
                    pattern_count
                ));
            }
        }
        Ok(())
    }

    fn compile_cache_key(hs_pats: &[Pattern], opts: HsCompileOpts<'_>) -> String {
        use sha2::{Digest, Sha256};
        let HsCompileOpts {
            singlematch,
            caseless,
            shard_target: _,
            utf8,
            ucp,
        } = opts;
        let mut h = Sha256::new();
        for p in hs_pats {
            h.update(p.expression.as_bytes());
            h.update([0]);
        }

        h.update(hyperscan::version().to_string().as_bytes());
        h.update(HS_CRATE_CACHE_VERSION);

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
        // per-pattern/singlematch one.
        h.update(if singlematch { b"SM1" } else { b"SM0" });
        h.update(if utf8 { b"U81" } else { b"U80" });
        h.update(if ucp { b"UP1" } else { b"UP0" });
        match caseless {
            None => h.update(b"CLall"),
            Some(cl) => {
                h.update(b"CLper");
                for &b in cl {
                    h.update([b as u8]);
                }
            }
        }

        hex::encode(h.finalize())
    }

    fn compile_shard_count(pattern_count: usize, opts: HsCompileOpts<'_>) -> usize {
        let target = opts
            .shard_target
            .filter(|&v| v >= 1)
            .unwrap_or(TARGET_PATTERNS_PER_SHARD); // LAW10: absent shard-target compile tuning => documented default; sharding only changes WHERE patterns compile, never the finding set.
        let cap = Self::executor_width();
        pattern_count
            .div_ceil(target)
            .clamp(1, cap)
            .min(pattern_count)
            .max(1)
    }

    fn partition_patterns_lpt(hs_pats: &[Pattern], shard_count: usize) -> Vec<Vec<Pattern>> {
        let mut order: Vec<usize> = (0..hs_pats.len()).collect();
        let costs: Vec<u64> = hs_pats
            .iter()
            .map(|pattern| hs_partition_cost(&pattern.expression))
            .collect();
        order.sort_unstable_by(|&a, &b| {
            costs[b]
                .cmp(&costs[a])
                .then_with(|| hs_pats[a].id.cmp(&hs_pats[b].id))
                .then_with(|| a.cmp(&b))
        });
        let mut shard_pats: Vec<Vec<Pattern>> = (0..shard_count).map(|_| Vec::new()).collect();
        let mut shard_cost: Vec<u64> = vec![0; shard_count];
        for &i in &order {
            let lightest = shard_cost
                .iter()
                .enumerate()
                .min_by_key(|(_, &c)| c)
                .map(|(idx, _)| idx)
                .unwrap_or(0); // LAW10: shard_count is clamped to >=1 above; fallback is unreachable and preserves shard 0.
            shard_cost[lightest] = shard_cost[lightest].saturating_add(costs[i]);
            shard_pats[lightest].push(hs_pats[i].clone());
        }
        shard_pats
    }

    fn compile_cached_shards(
        shard_pats: Vec<Vec<Pattern>>,
        shard_count: usize,
        cache_key: &str,
        cache_dir: &std::path::Path,
    ) -> Vec<Result<(Option<BlockDatabase>, Vec<usize>), String>> {
        // Lazy phase-2 compilation can begin while a Rayon scan worker holds
        // thread-local active-pattern scratch. Nested parallel compilation
        // lets that worker steal another scan job and re-enter the scratch
        // borrow. Compile inline on workers; cold startup keeps parallel shard
        // compilation when entered from a non-worker coordinator thread.
        shard_pats
            .into_iter()
            .enumerate()
            .map(|(shard_idx, pats)| {
                Self::compile_cached_shard(pats, shard_count, shard_idx, cache_key, cache_dir)
            })
            .collect()
    }
    fn compile_cached_shard(
        pats: Vec<Pattern>,
        shard_count: usize,
        shard_idx: usize,
        cache_key: &str,
        cache_dir: &std::path::Path,
    ) -> Result<(Option<BlockDatabase>, Vec<usize>), String> {
        let shard_key = Self::shard_cache_key(cache_key, shard_count, shard_idx, &pats);
        let cache_path = cache_dir.join(keyhog_core::hyperscan_cache_filename(&shard_key));

        if let Some((db, dropped)) = Self::load_cached_shard(&cache_path, shard_idx, pats.len()) {
            return Ok((Some(db), dropped));
        }

        let (db, dropped) = Self::compile_hs_db(&pats)?;
        if let Some(db) = db.as_ref() {
            Self::persist_cached_shard(db, &dropped, &cache_path, shard_idx);
        }
        Ok((db, dropped))
    }

    fn shard_cache_key(
        cache_key: &str,
        shard_count: usize,
        shard_idx: usize,
        pats: &[Pattern],
    ) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(cache_key.as_bytes());
        h.update((shard_count as u64).to_le_bytes());
        h.update((shard_idx as u64).to_le_bytes());
        for p in pats {
            h.update(p.expression.as_bytes());
            h.update([0]);
        }
        hex::encode(h.finalize())
    }

    fn load_cached_shard(
        cache_path: &std::path::Path,
        shard_idx: usize,
        pattern_count: usize,
    ) -> Option<(BlockDatabase, Vec<usize>)> {
        match read_hs_cache_file(cache_path) {
            Ok(Some(bytes)) => {
                if bytes.len() > keyhog_core::HYPERSCAN_CACHE_HEADER_LEN
                    && keyhog_core::hyperscan_cache_header_is_valid(
                        &bytes[..keyhog_core::HYPERSCAN_CACHE_HEADER_LEN],
                    )
                {
                    use hyperscan::Serialized;
                    let Some((dropped, payload)) = read_cached_dropped_ids(&bytes) else {
                        tracing::warn!(
                            cache = %cache_path.display(),
                            shard = shard_idx,
                            "HS shard cache metadata is not usable; compiling from patterns"
                        );
                        return None;
                    };
                    match payload.deserialize::<BlockMode>() {
                        Ok(db) => {
                            tracing::info!(
                                cache = %cache_path.display(),
                                shard = shard_idx,
                                patterns = pattern_count,
                                dropped = dropped.len(),
                                "HS shard loaded from cache"
                            );
                            keyhog_profile::record_cache_hit(
                                keyhog_profile::CacheId::HyperscanShard,
                            );
                            return Some((db, dropped));
                        }
                        Err(error) => {
                            tracing::warn!(
                                cache = %cache_path.display(),
                                shard = shard_idx,
                                %error,
                                "HS shard cache DB deserialization failed; compiling from patterns"
                            );
                        }
                    }
                } else {
                    tracing::warn!(
                        cache = %cache_path.display(),
                        shard = shard_idx,
                        bytes = bytes.len(),
                        "HS shard cache header is invalid or truncated; compiling from patterns"
                    );
                }
            }
            Ok(None) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                tracing::warn!(
                    cache = %cache_path.display(),
                    error = %error,
                    "HS shard cache file is not usable; compiling from patterns"
                );
            }
        }
        keyhog_profile::record_cache_miss(keyhog_profile::CacheId::HyperscanShard);
        None
    }

    fn persist_cached_shard(
        db: &BlockDatabase,
        dropped: &[usize],
        cache_path: &std::path::Path,
        shard_idx: usize,
    ) {
        let ser = match db.serialize() {
            Ok(ser) => ser,
            Err(error) => {
                tracing::warn!(
                    cache = %cache_path.display(),
                    shard = shard_idx,
                    %error,
                    "HS shard cache serialization failed; not persisting cache artifact"
                );
                return;
            }
        };
        let dropped_bytes = 8usize.saturating_add(dropped.len().saturating_mul(8));
        let mut data = Vec::with_capacity(
            ser.as_ref().len() + keyhog_core::HYPERSCAN_CACHE_HEADER_LEN + dropped_bytes,
        );
        keyhog_core::write_hyperscan_cache_header(&mut data);
        write_cached_dropped_ids(&mut data, dropped);
        data.extend_from_slice(ser.as_ref());
        if data.len() as u64 > keyhog_core::HYPERSCAN_CACHE_FILE_BYTES {
            tracing::warn!(
                cache = %cache_path.display(),
                shard = shard_idx,
                size = data.len(),
                cap = keyhog_core::HYPERSCAN_CACHE_FILE_BYTES,
                "HS shard cache serialization exceeds cap; not persisting oversized cache artifact"
            );
            return;
        }
        let parent = cache_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new(".")); // LAW10: cache_path is constructed with a parent; fallback only disables atomic cache locality, not scanning.
        match tempfile::NamedTempFile::new_in(parent) {
            Ok(mut tmp) => {
                if let Err(error) = std::io::Write::write_all(&mut tmp, &data) {
                    tracing::warn!(
                        cache = %cache_path.display(),
                        %error,
                        "HS shard cache write failed; next run will recompile"
                    );
                    return;
                }
                if let Err(error) = tmp.persist(cache_path) {
                    tracing::warn!(
                        cache = %cache_path.display(),
                        %error,
                        "HS shard cache persist failed; next run will recompile"
                    );
                    return;
                }
            }
            Err(error) => {
                tracing::warn!(
                    cache = %cache_path.display(),
                    %error,
                    "HS shard cache tempfile creation failed; next run will recompile"
                );
                return;
            }
        }
        tracing::info!(
            cache = %cache_path.display(),
            shard = shard_idx,
            dropped = dropped.len(),
            "HS shard cached"
        );
        crate::cache_eviction::evict_cache_dir_with_policy(
            parent,
            keyhog_core::CacheKind::HyperscanShards,
            keyhog_core::CacheKind::HyperscanShards.default_policy(),
        );
    }

    fn assemble_scanner_shards(
        shard_count: usize,
        shard_results: Vec<Result<(Option<BlockDatabase>, Vec<usize>), String>>,
    ) -> Result<(Vec<Shard>, Vec<usize>), String> {
        let mut shards = Vec::with_capacity(shard_count);
        let mut dropped_ids = Vec::new();
        for result in shard_results {
            let (db, dropped) = result?;
            dropped_ids.extend(dropped);
            if let Some(db) = db {
                shards.push(Shard { db });
            }
        }
        Ok((shards, dropped_ids))
    }

    fn compact_after_build_drops(
        hs_pats: &mut Vec<Pattern>,
        pattern_map: &mut Vec<(usize, usize, usize, bool)>,
        dropped_ids: &[usize],
    ) -> Result<Vec<usize>, String> {
        if hs_pats.len() != pattern_map.len() {
            return Err(format!(
                "hyperscan pattern/map length mismatch before compaction: {} patterns for {} mapping rows",
                hs_pats.len(),
                pattern_map.len()
            ));
        }

        let mut dropped = vec![false; pattern_map.len()];
        for &database_id in dropped_ids {
            let Some(slot) = dropped.get_mut(database_id) else {
                return Err(format!(
                    "hyperscan returned dropped pattern id {database_id} outside pattern map len {}",
                    pattern_map.len()
                ));
            };
            if std::mem::replace(slot, true) {
                return Err(format!(
                    "hyperscan returned duplicate dropped pattern id {database_id}"
                ));
            }
        }

        let old_patterns = std::mem::take(hs_pats);
        let old_map = std::mem::take(pattern_map);
        let mut unsupported = Vec::with_capacity(dropped_ids.len());
        hs_pats.reserve(old_patterns.len().saturating_sub(dropped_ids.len()));
        pattern_map.reserve(old_map.len().saturating_sub(dropped_ids.len()));
        for (old_database_id, (mut pattern, mapping)) in
            old_patterns.into_iter().zip(old_map).enumerate()
        {
            if pattern.id != Some(old_database_id) {
                return Err(format!(
                    "hyperscan pattern id mismatch before compaction: row {old_database_id} carries {:?}",
                    pattern.id
                ));
            }
            if dropped[old_database_id] {
                unsupported.push(mapping.0);
                continue;
            }
            pattern.id = Some(pattern_map.len());
            hs_pats.push(pattern);
            pattern_map.push(mapping);
        }
        Ok(unsupported)
    }

    /// Width of the current Rayon executor. It caps compile sharding and
    /// determines how many persistent workers explicit warm-up seeds; callers
    /// outside Rayon can still allocate their own exact TLS scratch lazily.
    fn executor_width() -> usize {
        keyhog_profile::logical_cpu_count().clamp(1, MAX_COMPILE_SHARDS)
    }

    /// Warm the scanner for steady-state execution: allocate one
    /// Hyperscan scratch per shard on the current thread and retain
    /// it in thread-local storage keyed by this scanner's identity.
    pub(crate) fn warm(&self) -> Result<(), String> {
        self.scan_matches_result(b"", |_, _, _| {})?;
        Ok(())
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
    pub(crate) fn compile_with_opts(
        patterns: &[(usize, usize, &str, bool)],
        opts: HsCompileOpts<'_>,
    ) -> Result<(Self, Vec<usize>), String> {
        COMPILE_WITH_OPTS_INVOCATIONS.fetch_add(1, Ordering::Relaxed);
        Self::compile_with_opts_inner(patterns, opts, None)
    }

    #[cfg(test)]
    fn compile_with_forced_build_drop(
        patterns: &[(usize, usize, &str, bool)],
        opts: HsCompileOpts<'_>,
        database_id: usize,
    ) -> Result<(Self, Vec<usize>), String> {
        Self::compile_with_opts_inner(patterns, opts, Some((database_id, false)))
    }
    #[cfg(test)]
    fn compile_with_forced_retryable_build_drop(
        patterns: &[(usize, usize, &str, bool)],
        opts: HsCompileOpts<'_>,
        database_id: usize,
    ) -> Result<(Self, Vec<usize>), String> {
        Self::compile_with_opts_inner(patterns, opts, Some((database_id, true)))
    }

    fn compile_with_opts_inner(
        patterns: &[(usize, usize, &str, bool)],
        opts: HsCompileOpts<'_>,
        mut forced_build_drop: Option<(usize, bool)>,
    ) -> Result<(Self, Vec<usize>), String> {
        Self::validate_compile_opts(patterns.len(), opts)?;
        let PreparedPatterns {
            mut hs_pats,
            mut pattern_map,
            mut unsupported,
        } = Self::prepare_patterns(patterns, opts);

        if hs_pats.is_empty() {
            return Ok((
                Self {
                    shards: Vec::new(),
                    pattern_map,
                    scanner_id: SCANNER_ID_SEQ.fetch_add(1, Ordering::Relaxed),
                    scratch_owner: Arc::new(()),
                },
                unsupported,
            ));
        }

        let cache_dir = resolve_cache_dir()?;
        let mut minimum_shard_count = 1usize;
        loop {
            let cache_key = Self::compile_cache_key(&hs_pats, opts);
            let max_shard_count = Self::executor_width().min(hs_pats.len());
            let shard_count = Self::compile_shard_count(hs_pats.len(), opts)
                .max(minimum_shard_count)
                .min(max_shard_count);
            let shard_pats = Self::partition_patterns_lpt(&hs_pats, shard_count);
            let shard_results =
                Self::compile_cached_shards(shard_pats, shard_count, &cache_key, &cache_dir);
            let (shards, mut dropped_ids) =
                Self::assemble_scanner_shards(shard_count, shard_results)?;
            let forced_drop = forced_build_drop.take();
            if let Some((database_id, _)) = forced_drop {
                dropped_ids.push(database_id);
            }

            if dropped_ids.is_empty() {
                unsupported.sort_unstable();
                if unsupported.windows(2).any(|ids| ids[0] == ids[1]) {
                    return Err(
                        "hyperscan produced duplicate unsupported canonical pattern ids".into(),
                    );
                }
                return Ok((
                    Self {
                        shards,
                        pattern_map,
                        scanner_id: SCANNER_ID_SEQ.fetch_add(1, Ordering::Relaxed),
                        scratch_owner: Arc::new(()),
                    },
                    unsupported,
                ));
            }

            // A combined database may exceed Hyperscan's internal limits even
            // though every pattern is supported independently. Repartition
            // before declaring any row unsupported so exact scalar recovery is
            // reserved for patterns that still fail in the narrowest shards.
            // The non-retryable forced-drop seam reaches compaction directly.
            let retryable_drop = forced_drop.map_or(true, |(_, retryable)| retryable);
            if retryable_drop && shard_count < max_shard_count {
                minimum_shard_count = shard_count.saturating_mul(2).min(max_shard_count);
                continue;
            }

            unsupported.extend(Self::compact_after_build_drops(
                &mut hs_pats,
                &mut pattern_map,
                &dropped_ids,
            )?);
            if hs_pats.is_empty() {
                unsupported.sort_unstable();
                if unsupported.windows(2).any(|ids| ids[0] == ids[1]) {
                    return Err(
                        "hyperscan produced duplicate unsupported canonical pattern ids".into(),
                    );
                }
                return Ok((
                    Self {
                        shards: Vec::new(),
                        pattern_map,
                        scanner_id: SCANNER_ID_SEQ.fetch_add(1, Ordering::Relaxed),
                        scratch_owner: Arc::new(()),
                    },
                    unsupported,
                ));
            }
        }
    }

    /// Validate authenticated native shard headers against this Hyperscan
    /// runtime without constructing their much larger database allocations.
    pub(crate) fn validate_serialized_database_shards(
        serialized_shards: &[crate::execution_pack::simd_program::SerializedHyperscanShard],
    ) -> Result<(), String> {
        use hyperscan::Serialized;

        for (index, bytes) in serialized_shards.iter().enumerate() {
            let validation = bytes.size().map_err(|error| {
                format!(
                    "packed Hyperscan shard {index} is incompatible or corrupt; reinstall and recalibrate: {error}"
                )
            });
            bytes
                .release_resident_pages()
                .map_err(|error| format!("releasing packed Hyperscan shard {index}: {error}"))?;
            validation?;
        }
        Ok(())
    }

    /// Recreates an immutable scanner from authenticated execution-pack shards.
    ///
    /// This path is deliberately strict: serialized native databases never fall
    /// back to pattern compilation, and their global IDs must use the canonical
    /// execution-program ordering.
    pub(crate) fn from_serialized_database_shards(
        serialized_shards: &[crate::execution_pack::simd_program::SerializedHyperscanShard],
        pattern_map: Vec<(usize, usize, usize, bool)>,
    ) -> Result<Self, String> {
        use hyperscan::Serialized;

        if serialized_shards.is_empty() != pattern_map.is_empty() {
            return Err(format!(
                "packed Hyperscan shard/mapping mismatch: {} shard(s) for {} mapped pattern(s)",
                serialized_shards.len(),
                pattern_map.len()
            ));
        }
        let mut previous_canonical_id = None;
        for (database_id, &(input_index, _, canonical_id, _)) in pattern_map.iter().enumerate() {
            if input_index != canonical_id {
                return Err(format!(
                    "packed Hyperscan mapping row {database_id} has input id {input_index} but canonical id {canonical_id}"
                ));
            }
            if previous_canonical_id.is_some_and(|previous| canonical_id <= previous) {
                return Err(format!(
                    "packed Hyperscan mapping row {database_id} has non-increasing canonical id {canonical_id}"
                ));
            }
            previous_canonical_id = Some(canonical_id);
        }

        let shards = serialized_shards
            .iter()
            .enumerate()
            .map(|(index, bytes)| {
                let database = bytes
                    .as_ref()
                    .deserialize::<BlockMode>()
                    .map_err(|error| {
                        format!(
                            "packed Hyperscan shard {index} is incompatible or corrupt; reinstall and recalibrate: {error}"
                        )
                    });
                bytes
                    .release_resident_pages()
                    .map_err(|error| format!("releasing packed Hyperscan shard {index}: {error}"))?;
                database.map(|db| Shard { db })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            shards,
            pattern_map,
            scanner_id: SCANNER_ID_SEQ.fetch_add(1, Ordering::Relaxed),
            scratch_owner: Arc::new(()),
        })
    }

    pub(crate) fn compile_with_opts_invocations() -> usize {
        COMPILE_WITH_OPTS_INVOCATIONS.load(Ordering::Relaxed)
    }

    /// Serializes every compiled database shard for immutable execution-pack publication.
    pub(crate) fn serialize_database_shards(&self) -> Result<Vec<Vec<u8>>, String> {
        self.shards
            .iter()
            .enumerate()
            .map(|(index, shard)| {
                shard
                    .db
                    .serialize()
                    .map(|serialized| serialized.as_ref().to_vec())
                    .map_err(|error| {
                        format!("Hyperscan shard {index} serialization failed: {error}")
                    })
            })
            .collect()
    }

    /// Returns the stable Hyperscan id mapping embedded beside serialized shards.
    pub(crate) fn execution_pattern_map(&self) -> &[(usize, usize, usize, bool)] {
        &self.pattern_map
    }

    /// Build one shard's `BlockDatabase`, returning the database and the
    /// GLOBAL pattern ids it had to drop (over-long or an unsupported
    /// construct Hyperscan rejects only at build time). A shard that rejects
    /// its final pattern returns no database and routes that pattern through
    /// caller-owned scalar recovery.
    fn compile_hs_db(hs_pats: &[Pattern]) -> Result<(Option<BlockDatabase>, Vec<usize>), String> {
        let mut attempts = hs_pats.to_vec();
        let mut dropped: Vec<usize> = Vec::new();
        let started = std::time::Instant::now();
        let db = loop {
            let patterns_obj = Patterns(std::mem::take(&mut attempts));
            match Builder::build::<BlockMode>(&patterns_obj) {
                Ok(db) => break Some(db),
                Err(error) => {
                    attempts = patterns_obj.0;
                    if attempts.len() == 1 {
                        let Some(removed) = attempts.pop() else {
                            return Err(
                                "hyperscan singleton retry lost its only pattern".to_owned()
                            );
                        };
                        let database_id = removed.id.ok_or_else(|| {
                            "hyperscan singleton pattern is missing its database id".to_owned()
                        })?;
                        dropped.push(database_id);
                        tracing::debug!(
                            %error,
                            database_id,
                            "pattern rejected while building hyperscan shard; caller retains scalar recovery"
                        );
                        break None;
                    }

                    // Remove the longest/most expensive expressions first.
                    attempts.sort_by_key(|p| p.expression.len());
                    let remove_count = (attempts.len() / RETRY_DROP_DIVISOR).max(1);
                    for _ in 0..remove_count {
                        if let Some(removed) = attempts.pop() {
                            let database_id = removed.id.ok_or_else(|| {
                                "hyperscan retry pattern is missing its database id".to_owned()
                            })?;
                            dropped.push(database_id);
                        }
                    }
                    attempts.sort_by_key(|p| p.id);
                }
            }
        };
        tracing::info!(
            patterns = hs_pats.len() - dropped.len(),
            compile_ms = started.elapsed().as_millis(),
            "HS shard compiled"
        );
        Ok((db, dropped))
    }
}

fn write_cached_dropped_ids(data: &mut Vec<u8>, dropped: &[usize]) {
    data.extend_from_slice(&(dropped.len() as u64).to_le_bytes());
    for &id in dropped {
        data.extend_from_slice(&(id as u64).to_le_bytes());
    }
}

fn read_cached_dropped_ids(bytes: &[u8]) -> Option<(Vec<usize>, &[u8])> {
    let mut offset = keyhog_core::HYPERSCAN_CACHE_HEADER_LEN;
    let count = read_u64_le_at(bytes, offset)?;
    offset = offset.checked_add(8)?;
    let Ok(count) = usize::try_from(count) else {
        return None;
    };
    let total_id_bytes = count.checked_mul(8)?;
    let payload_offset = offset.checked_add(total_id_bytes)?;
    if payload_offset > bytes.len() {
        return None;
    }
    let mut dropped = Vec::with_capacity(count);
    for _ in 0..count {
        let id = read_u64_le_at(bytes, offset)?;
        let Ok(id) = usize::try_from(id) else {
            return None;
        };
        dropped.push(id);
        offset = offset.checked_add(8)?;
    }
    Some((dropped, &bytes[payload_offset..]))
}

fn read_u64_le_at(bytes: &[u8], offset: usize) -> Option<u64> {
    let end = offset.checked_add(8)?;
    let slice = bytes.get(offset..end)?;
    let mut raw = [0u8; 8];
    raw.copy_from_slice(slice);
    Some(u64::from_le_bytes(raw))
}

fn hs_partition_cost(regex: &str) -> u64 {
    let bytes = regex.as_bytes();
    let mut cost = BASE_PATTERN_COST.saturating_add(bytes.len() as u64);
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'|' => cost = cost.saturating_add(400),
            b'[' => {
                let start = i;
                i += 1;
                while i < bytes.len() {
                    if bytes[i] == b'\\' {
                        i = i.saturating_add(2);
                        continue;
                    }
                    if bytes[i] == b']' {
                        break;
                    }
                    i += 1;
                }
                let class_len = i.saturating_sub(start);
                if class_len >= 20 {
                    cost = cost.saturating_add(200);
                }
            }
            b'{' => {
                if let Some((upper, end)) = counted_repeat_upper_bound(bytes, i) {
                    cost = cost.saturating_add(upper.min(10_000).saturating_mul(20));
                    i = end;
                }
            }
            _ => {}
        }
        i += 1;
    }
    cost
}

fn counted_repeat_upper_bound(bytes: &[u8], open: usize) -> Option<(u64, usize)> {
    let mut i = open + 1;
    let first_start = i;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        i += 1;
    }
    if i == first_start {
        return None;
    }
    let Ok(lower_str) = std::str::from_utf8(&bytes[first_start..i]) else {
        return None;
    };
    let Ok(lower) = lower_str.parse::<u64>() else {
        return None;
    };
    match bytes.get(i).copied() {
        Some(b'}') => Some((lower, i)),
        Some(b',') => {
            i += 1;
            let upper_start = i;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            if bytes.get(i).copied() != Some(b'}') {
                return None;
            }
            let upper = if i == upper_start {
                lower.saturating_add(100)
            } else {
                let Ok(upper_str) = std::str::from_utf8(&bytes[upper_start..i]) else {
                    return None;
                };
                let Ok(upper) = upper_str.parse::<u64>() else {
                    return None;
                };
                upper
            };
            Some((upper, i))
        }
        _ => None,
    }
}

#[cfg(test)]
#[path = "../../tests/unit/simd_build_drop_compaction.rs"]
mod build_drop_compaction_tests;
