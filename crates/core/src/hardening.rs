//! Process-level memory protections.
//!
//! Two tiers:
//!
//! 1. **Always on** (`apply_protections(false)`): zero-cost runtime
//!    settings that disable debugging features. No throughput impact, so
//!    they live outside the `lockdown` feature gate. Examples:
//!    - Linux: `prctl(PR_SET_DUMPABLE, 0)` - no core dumps, no
//!      `/proc/<pid>/mem` read, no `ptrace` attach from non-root.
//!    - macOS: `ptrace(PT_DENY_ATTACH, …)` - same intent.
//!    - Windows: best-effort process mitigation policy.
//!
//! 2. **Lockdown-only** (`apply_protections(true)`): protections that
//!    have a real cost or change runtime behavior. Examples:
//!    - `mlockall(MCL_CURRENT | MCL_FUTURE)` - pin all current and
//!      future allocations into RAM. Slows allocator paths and can be
//!      blocked by ulimits.
//!    - Refuse to run if `/proc/self/coredump_filter` allows anonymous
//!      pages (Linux).
//!    - Refuse to run if any persistence cache exists on disk.
//!
//! Callers that embed keyhog in security-critical contexts (EnvSeal,
//! lockdown-mode UIs) should call both. Callers using keyhog as a normal
//! triage tool only get the always-on tier.

#![allow(missing_docs)]

use std::ffi::OsStr;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::hyperscan_cache::{HYPERSCAN_CACHE_PREFIX, HYPERSCAN_CACHE_SUFFIX};

/// Outcome of a hardening attempt - collected so callers can log which
/// protections actually took.
#[derive(Debug, Default, Clone)]
pub struct HardeningReport {
    pub no_core_dumps: bool,
    pub no_ptrace: bool,
    pub mlocked: bool,
    pub coredump_filter_safe: bool,
    pub failures: Vec<String>,
}

/// Apply the process protections for the requested security mode.
///
/// When `lockdown` is true, this also fails closed on persisted keyhog cache
/// artifacts that could expose past findings.
#[must_use]
pub fn apply_protections(lockdown: bool) -> HardeningReport {
    apply_protections_with_persistence_paths(lockdown, std::iter::empty::<PathBuf>())
}

/// Apply process protections and, in lockdown mode, fail closed on known
/// persistence artifacts outside the default keyhog cache root.
#[must_use]
pub fn apply_protections_with_persistence_paths<I, P>(
    lockdown: bool,
    persistence_paths: I,
) -> HardeningReport
where
    I: IntoIterator<Item = P>,
    P: AsRef<Path>,
{
    if !lockdown {
        return apply_default_protections();
    }

    let mut report = apply_lockdown_protections();
    for path in lockdown_disk_cache_violations_for_paths(persistence_paths) {
        report.failures.push(format!(
            "lockdown disk cache exists at {} and could expose past findings. \
             Fix: remove it and rerun.",
            path.display()
        ));
    }
    report
}

/// Apply zero-cost process protections that should always be on for a
/// secret-scanning binary. Returns a report of what took.
///
/// Always safe to call - failures are logged and tallied but do not
/// abort. The same bits set twice are idempotent.
fn apply_default_protections() -> HardeningReport {
    let mut report = HardeningReport::default();

    #[cfg(target_os = "linux")]
    {
        // PR_SET_DUMPABLE = 0 disables: core dumps, ptrace, /proc/<pid>/mem
        // read by other processes, and the kernel's coredump_filter. This
        // is what every credential manager (gpg-agent, ssh-agent, etc) does
        // and it costs nothing - the kernel just sets a flag.
        // SAFETY: prctl is a documented syscall; failure is non-fatal.
        let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
        if rc == 0 {
            report.no_core_dumps = true;
            report.no_ptrace = true;
        } else {
            let err = std::io::Error::last_os_error();
            report
                .failures
                .push(format!("prctl(PR_SET_DUMPABLE): {err}"));
        }
    }

    #[cfg(target_os = "macos")]
    {
        // PT_DENY_ATTACH on macOS prevents the calling process from being
        // attached by ptrace (lldb, dtrace). Same intent as Linux's
        // PR_SET_DUMPABLE. Best-effort.
        const PT_DENY_ATTACH: libc::c_int = 31;
        // SAFETY: documented sysctl; failure non-fatal.
        let rc = unsafe { libc::ptrace(PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) };
        if rc == 0 {
            report.no_ptrace = true;
            // macOS doesn't surface a separate "no core" knob; PT_DENY_ATTACH
            // implicitly disables that as well in practice.
            report.no_core_dumps = true;
        } else {
            let err = std::io::Error::last_os_error();
            report
                .failures
                .push(format!("ptrace(PT_DENY_ATTACH): {err}"));
        }
    }

    #[cfg(target_os = "windows")]
    {
        // No syscall is wired here: SetProcessMitigationPolicy and WER
        // dump-suppression need Win32 FFI this crate does not link. DEP/CFG are
        // default-on for 64-bit images, but core-dump (WER) suppression and the
        // ptrace-equivalent denial are NOT applied. Leave both flags false (their
        // default) and record the gap so a caller logging the process posture is
        // never told a protection took that didn't (Law 10).
        report.failures.push(
            "process mitigation policy not applied on Windows \
             (SetProcessMitigationPolicy unwired); WER may still write a crash dump"
                .to_string(),
        );
    }

    report
}

/// Apply protections that have a real cost or operational impact. Only
/// call from `lockdown` mode - these protections trade throughput and
/// flexibility for additional defense in depth.
///
/// Returns a report of what took. Callers should treat any `failures`
/// entry as a hard error in lockdown - it means a protection the user
/// asked for did not engage.
fn apply_lockdown_protections() -> HardeningReport {
    let mut report = apply_default_protections();

    #[cfg(target_os = "linux")]
    {
        // mlockall(MCL_CURRENT | MCL_FUTURE) pins every page of this
        // process - current heap + every future allocation - to RAM.
        // No swap to disk. Costs ~30% on allocator-heavy workloads but
        // guarantees credentials never hit a swap partition.
        // SAFETY: documented syscall; failure non-fatal.
        let rc = unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) };
        if rc == 0 {
            report.mlocked = true;
        } else {
            let err = std::io::Error::last_os_error();
            report.failures.push(format!("mlockall: {err}"));
        }

        // Hard-kill any core dump regardless of coredump_filter by
        // setting RLIMIT_CORE to 0. The kernel refuses to write a core
        // file at all when the soft limit is 0, so anonymous pages can
        // never reach disk via the dump path. This makes lockdown a
        // true one-flag toggle: the user no longer has to pre-set the
        // coredump filter outside keyhog.
        // SAFETY: documented syscall; failure non-fatal (we still try
        // PR_SET_DUMPABLE in apply_default_protections).
        let rlim_zero = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        let rc = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &rlim_zero) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            report
                .failures
                .push(format!("setrlimit(RLIMIT_CORE, 0): {err}"));
        }

        // With RLIMIT_CORE=0 set above the kernel cannot write any core
        // file, so coredump_filter is moot. We still record what was
        // configured for observability, but a non-zero filter is no
        // longer a fatal failure - the rlimit covers it. Only escalate
        // when *both* RLIMIT_CORE could not be set AND the filter is
        // open, which is the only scenario where credentials could
        // actually reach disk.
        // A read/parse failure here yields `None`, and the `match filter` below
        // escalates `None` to a `report.failures` entry (surfaced to the lockdown
        // caller, which treats any `failures` entry as a hard error) UNLESS
        // RLIMIT_CORE=0 already blocks any dump. The failure is recorded, never
        // swallowed.
        let filter = std::fs::read_to_string("/proc/self/coredump_filter")
            .ok() // LAW10: None -> report.failures entry below; recorded, not swallowed
            .and_then(|s| u32::from_str_radix(s.trim(), 16).ok()); // LAW10: parse failure -> report.failures below
        let rlimit_blocked = rc == 0;
        match filter {
            Some(0) => report.coredump_filter_safe = true,
            Some(_other) if rlimit_blocked => {
                // Filter is open but RLIMIT_CORE=0 prevents any dump.
                report.coredump_filter_safe = true;
            }
            Some(other) => report.failures.push(format!(
                "/proc/self/coredump_filter = 0x{other:x} - anonymous pages would be dumped; \
                 RLIMIT_CORE could not be set to 0 either. Set ulimit -c 0 in the parent shell."
            )),
            None => {
                if rlimit_blocked {
                    report.coredump_filter_safe = true;
                } else {
                    report
                        .failures
                        .push("could not read /proc/self/coredump_filter".into());
                }
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        // Lockdown's swap guarantee (credentials never reach a swap partition) is
        // implemented via mlockall, which is Linux-only: macOS lacks mlockall and
        // Windows needs per-region VirtualLock with a raised working-set quota,
        // neither of which is wired. Fail closed (Law 10) instead of reporting a
        // lock that never happened — push a failures entry so the lockdown caller
        // (which treats any failure as hard) surfaces that memory pinning is
        // unavailable on this platform rather than silently claiming success.
        report.mlocked = false;
        report.failures.push(format!(
            "memory locking (mlockall) is unavailable on {}; lockdown cannot \
             keep credentials out of swap on this platform",
            std::env::consts::OS
        ));
    }

    report
}

/// In lockdown mode, the engine refuses to start if a keyhog cache that could
/// expose PAST FINDINGS exists on disk - such caches survive across runs and
/// are exactly the "credentials accidentally written to disk" exfil vector
/// lockdown is supposed to prevent. Returns the offending paths, empty if clean.
///
/// NOT every file under `<cache>/keyhog` qualifies. The compiled Hyperscan
/// pattern database is the only thing keyhog writes there by default; it holds
/// the compiled DETECTOR AUTOMATON - regex shapes - with zero scan findings or
/// credentials, and keyhog (re)creates it early in startup. Treating it as a
/// violation made `--lockdown` self-defeating: the gate tripped on keyhog's own
/// freshly-compiled pattern DB on every machine, so the flag could never run.
/// Only files with keyhog's exact `hs-<sha256>.db` shard name and `KHHS` cache
/// header are trusted as compiled-pattern caches; everything else is a
/// potential findings-bearing cache and therefore a lockdown violation.
#[must_use]
pub(crate) fn lockdown_disk_cache_violations() -> Vec<PathBuf> {
    lockdown_disk_cache_violations_for_paths(std::iter::empty::<PathBuf>())
}

/// Return persisted keyhog cache artifacts that violate lockdown mode.
///
/// The default keyhog cache root is always checked. `persistence_paths` lets
/// callers pass resolved custom Merkle/incremental cache paths that may live
/// outside the default root.
#[must_use]
pub(crate) fn lockdown_disk_cache_violations_for_paths<I, P>(persistence_paths: I) -> Vec<PathBuf>
where
    I: IntoIterator<Item = P>,
    P: AsRef<Path>,
{
    let mut hits = Vec::new();
    if let Some(keyhog_root) = crate::keyhog_cache_root() {
        let has_findings_cache = match std::fs::read_dir(&keyhog_root) {
            Ok(entries) => keyhog_cache_contains_findings(&keyhog_root, entries),
            // The cache dir simply not existing is the genuinely-clean case:
            // there is no past-findings artifact to leak.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            // Law 10 / fail-closed for a SECURITY gate: any OTHER error (e.g. a
            // permission denial on a directory that DOES exist) must NOT be read
            // as "clean" — that would let `--lockdown` start with an unaudited
            // cache present. Surface it LOUDLY and treat the path as a violation
            // so lockdown refuses to start rather than silently passing.
            Err(e) => {
                eprintln!(
                    "keyhog: cannot inspect cache dir '{}' for past-findings artifacts: {e}; \
                     refusing lockdown (fail-closed)",
                    keyhog_root.display()
                );
                true
            }
        };
        if has_findings_cache {
            hits.push(keyhog_root);
        }
    }
    for path in persistence_paths {
        let path = path.as_ref();
        if explicit_persistence_path_is_violation(path) {
            push_unique_path(&mut hits, path.to_path_buf());
        }
    }
    hits
}

fn explicit_persistence_path_is_violation(path: &Path) -> bool {
    match std::fs::metadata(path) {
        Ok(metadata) if metadata.is_dir() => match std::fs::read_dir(path) {
            Ok(entries) => keyhog_cache_contains_findings(path, entries),
            Err(error) => {
                eprintln!(
                    "keyhog: cannot inspect configured cache dir '{}' for past-findings \
                     artifacts: {error}; refusing lockdown (fail-closed)",
                    path.display()
                );
                true
            }
        },
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => {
            eprintln!(
                "keyhog: cannot inspect configured cache path '{}' for past-findings artifacts: \
                 {error}; refusing lockdown (fail-closed)",
                path.display()
            );
            true
        }
    }
}

fn push_unique_path(hits: &mut Vec<PathBuf>, path: PathBuf) {
    if !hits.iter().any(|hit| hit == &path) {
        hits.push(path);
    }
}

fn keyhog_cache_contains_findings<I>(keyhog_root: &Path, entries: I) -> bool
where
    I: IntoIterator<Item = std::io::Result<std::fs::DirEntry>>,
{
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                eprintln!(
                    "keyhog: cannot inspect an entry in cache dir '{}' for past-findings \
                     artifacts: {error}; refusing lockdown (fail-closed)",
                    keyhog_root.display()
                );
                return true;
            }
        };
        match trusted_compiled_pattern_cache_entry(&entry) {
            Ok(true) => {}
            Ok(false) => return true,
            Err(error) => {
                eprintln!(
                    "keyhog: cannot inspect candidate compiled-pattern cache entry '{}' in '{}' \
                     for past-findings artifacts: {error}; refusing lockdown (fail-closed)",
                    entry.file_name().to_string_lossy(),
                    keyhog_root.display()
                );
                return true;
            }
        }
    }
    false
}

fn trusted_compiled_pattern_cache_entry(entry: &std::fs::DirEntry) -> std::io::Result<bool> {
    if !compiled_pattern_cache_filename(&entry.file_name()) {
        return Ok(false);
    }
    if !entry.file_type()?.is_file() {
        return Ok(false);
    }
    compiled_pattern_cache_header_is_valid(&entry.path())
}

fn compiled_pattern_cache_filename(name: &OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    let Some(digest) = name
        .strip_prefix(HYPERSCAN_CACHE_PREFIX)
        .and_then(|s| s.strip_suffix(HYPERSCAN_CACHE_SUFFIX))
    else {
        return false;
    };
    digest.len() == crate::git_lfs::SHA256_HEX_LEN
        && digest
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn compiled_pattern_cache_header_is_valid(path: &Path) -> std::io::Result<bool> {
    let mut file = std::fs::File::open(path)?;
    let mut header = [0_u8; crate::HYPERSCAN_CACHE_HEADER_LEN];
    match file.read_exact(&mut header) {
        Ok(()) => Ok(crate::hyperscan_cache_header_is_valid(&header)),
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => Ok(false),
        Err(error) => Err(error),
    }
}

pub(crate) fn lockdown_cache_entry_error_is_violation_for_test() -> bool {
    let entries = std::iter::once(Err::<std::fs::DirEntry, std::io::Error>(
        std::io::Error::new(std::io::ErrorKind::PermissionDenied, "entry denied"),
    ));
    keyhog_cache_contains_findings(Path::new("<test-cache>"), entries)
}

// Tests live in `tests/unit/hardening_sha256_len_single_owner.rs` (KH-GAP-004:
// no inline test modules in `src/`).
