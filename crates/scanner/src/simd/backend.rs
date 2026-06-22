use hyperscan::{
    Block as BlockMode, BlockDatabase, Builder, Pattern, PatternFlags, Patterns, Scratch,
};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

mod scan;

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
/// list), so the warm path stays a deserialize-only load. Overridable through
/// explicit scanner compile tuning (`[tuning].hs_shard_target` in the CLI).
const TARGET_PATTERNS_PER_SHARD: usize = 80;

/// Hard ceiling on shard count, so a pathologically large detector set on a
/// 128-core box cannot spawn an unbounded number of databases (each costs a
/// scan-time dispatch). At this cap the per-shard size grows again, but the
/// real corpus (~900 patterns) sits at ~23 shards, well under it.
const MAX_COMPILE_SHARDS: usize = 64;

/// Hard cap for one serialized Hyperscan shard cache file. Cache files are
/// performance artifacts, not source input; refusing an oversized cache and
/// compiling the shard from detector patterns preserves findings while closing
/// the unbounded `std::fs::read` allocation path.
const HS_CACHE_FILE_BYTES: u64 = 64 * 1024 * 1024;

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
        // Persistent per-user cache so the ~1.7 s Hyperscan compile is paid
        // once per (machine, pattern-set, hyperscan version, CPU features) -
        // NOT once per reboot. Falls back to the per-uid temp cache only when
        // no platform cache directory is resolvable.
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
    if metadata.len() > HS_CACHE_FILE_BYTES {
        tracing::warn!(
            cache = %path.display(),
            size = metadata.len(),
            cap = HS_CACHE_FILE_BYTES,
            "HS shard cache file exceeds cap; compiling from patterns"
        );
        return Ok(None);
    }

    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    let mut limited = file.take(HS_CACHE_FILE_BYTES.saturating_add(1));
    limited.read_to_end(&mut bytes)?;
    if bytes.len() as u64 > HS_CACHE_FILE_BYTES {
        tracing::warn!(
            cache = %path.display(),
            cap = HS_CACHE_FILE_BYTES,
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
pub(crate) struct HsScanner {
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
/// phase-2 prefilter wants the opposite on both axes: it needs each
/// pattern's OWN case sensitivity (a plain homoglyph variant is
/// case-sensitive; a detector regex is not) so the marked set matches the
/// `regex` reference exactly, and it only needs to know "did pattern P match
/// at all" — so `SINGLEMATCH` fires each pattern once and stops, removing the
/// broad-pattern callback storm that is why the phase-2 prefilter never used HS.
#[derive(Clone, Copy, Default)]
pub(crate) struct HsCompileOpts<'a> {
    /// Set `HS_FLAG_SINGLEMATCH` on every pattern (fire once, then retire).
    pub(crate) singlematch: bool,
    /// Per-input-pattern caseless flags, parallel to `patterns`. `None` =
    /// every pattern `CASELESS` (legacy behavior). A missing/short entry
    /// defaults to caseless.
    pub(crate) caseless: Option<&'a [bool]>,
    /// Override the patterns-per-shard target (else the compiled default). The
    /// sharded scan must hit EVERY shard per call, so the per-shard fixed
    /// overhead is paid `shard_count` times — fine for the phase-1 position
    /// scan, but it dominates the set-membership PREFILTER on tiny chunks.
    /// Pass `Some(usize::MAX)` to force a single database so `scan_each` pays
    /// the per-scan overhead exactly once.
    pub(crate) shard_target: Option<usize>,
    /// Set `HS_FLAG_UTF8`. The `regex` crate matches unicode classes as
    /// CODEPOINTS; the homoglyph fallback variants (`[sѕｓ]…`) are unicode.
    /// Without this flag HS treats the pattern as BYTES, expanding every
    /// unicode class into a byte-alternation — a much larger, slower
    /// automaton AND byte- (not codepoint-) match semantics. UTF8 mode
    /// matches the `regex` reference and keeps the automaton small.
    pub(crate) utf8: bool,
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
            let caseless = match opts.caseless {
                Some(flags) => match flags.get(i) {
                    Some(value) => *value,
                    None => true,
                },
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
            match Pattern::with_flags(regex, flags) {
                Ok(mut p) => {
                    p.id = Some(pattern_map.len());
                    hs_pats.push(p);
                    pattern_map.push((det_idx, pat_idx, has_group));
                }
                Err(error) => {
                    tracing::debug!(
                        %error,
                        pattern_index = i,
                        "pattern rejected by hyperscan; caller reroutes it through keyword phase-2 path"
                    );
                    // Law 10: unsupported HS pattern id is returned to the caller and rerouted through the phase-2 keyword lane.
                    unsupported.push(i);
                }
            }
        }

        if hs_pats.is_empty() {
            return Err("no patterns compiled".into());
        }

        let cache_dir = resolve_cache_dir()?;

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
            .unwrap_or(1); // LAW10: host core-count probe failure only selects the one-shard compile path; findings are unchanged.
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
            .unwrap_or(TARGET_PATTERNS_PER_SHARD); // LAW10: absent shard-target compile tuning => documented default; sharding only changes WHERE patterns compile, never the finding set (recall-unchanged, per the comment above).
        let cap = cores.clamp(1, MAX_COMPILE_SHARDS);
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
                .unwrap_or(0); // LAW10: shard_count is clamped to >=1 above; fallback is unreachable and preserves shard 0.
                               // Cost proxy: length plus a fixed per-pattern overhead so a shard
                               // with many short patterns is not treated as free.
            shard_cost[lightest] += hs_pats[i].expression.len() as u64 + 16;
            shard_pats[lightest].push(hs_pats[i].clone());
        }

        const CACHE_MAGIC: &[u8; 4] = b"KHHS";
        const CACHE_VERSION: u32 = 1;

        // Compile (or cache-load) every shard concurrently. Returns the
        // built database and the global ids the shard had to drop (over-long
        // / unsupported constructs) for the phase-2 keyword reroute.
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
                match read_hs_cache_file(&cache_path) {
                    Ok(Some(bytes)) => {
                        if bytes.len() > 8 && &bytes[0..4] == CACHE_MAGIC {
                            let cache_version = bytes[4..8]
                                .try_into()
                                .map(u32::from_le_bytes)
                                .unwrap_or(0); // LAW10: invalid cache header misses cache and recompiles the same patterns.
                            if cache_version == CACHE_VERSION {
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

                // Cold: build this shard, then atomically persist it.
                let (db, dropped) = Self::compile_hs_db(&pats)?;
                if let Ok(ser) = db.serialize() {
                    let mut data = Vec::with_capacity(ser.as_ref().len() + 8);
                    data.extend_from_slice(CACHE_MAGIC);
                    data.extend_from_slice(&CACHE_VERSION.to_le_bytes());
                    data.extend_from_slice(ser.as_ref());
                    let parent = cache_path
                        .parent()
                        .unwrap_or_else(|| std::path::Path::new(".")); // LAW10: cache_path is constructed with a parent; fallback only disables atomic cache locality, not scanning.
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
            let scratch_count = scratch_pool_size();
            let mut scratch_pool = Vec::with_capacity(scratch_count);
            for _ in 0..scratch_count {
                scratch_pool.push(
                    db.alloc_scratch()
                        .map_err(|e| format!("hyperscan scratch: {e}"))?,
                );
            }
            shards.push(Shard {
                db,
                scratch_pool: parking_lot::Mutex::new(scratch_pool),
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
    /// rerouted into the phase-2 keyword lane by the caller so the pattern is
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
                    // Law 10: compile retry records dropped ids and caller reroutes them to the phase-2 keyword lane.
                    // Reclaim ownership for the next attempt.
                    attempts = patterns_obj.0;
                    attempts.sort_by_key(|p| std::cmp::Reverse(p.expression.len()));
                    let remove_count = attempts.len() / 10;
                    for _ in 0..remove_count {
                        if let Some(removed) = attempts.pop() {
                            dropped.push(removed.id.unwrap_or(0)); // LAW10: ids are assigned above; fallback id is unreachable and only affects the returned reroute list.
                        }
                    }
                    attempts.sort_by_key(|p| p.id.unwrap_or(0)); // LAW10: ids are assigned above; fallback id is unreachable and preserves deterministic retry order.
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
}

fn scratch_pool_size() -> usize {
    rayon::current_num_threads()
        .max(
            std::thread::available_parallelism()
                .map(usize::from)
                .unwrap_or(1), // LAW10: host parallelism probe failure ⇒ 1 (then max'd with rayon's count, clamped 1..64); scratch-pool size is perf-only, recall-unchanged.
        )
        .clamp(1, 64)
}
