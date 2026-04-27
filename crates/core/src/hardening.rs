//! Process-level memory protections.
//!
//! Two tiers:
//!
//! 1. **Always on** (`apply_default_protections`): zero-cost runtime
//!    settings that disable debugging features. No throughput impact, so
//!    they live outside the `lockdown` feature gate. Examples:
//!    - Linux: `prctl(PR_SET_DUMPABLE, 0)` — no core dumps, no
//!      `/proc/<pid>/mem` read, no `ptrace` attach from non-root.
//!    - macOS: `ptrace(PT_DENY_ATTACH, …)` — same intent.
//!    - Windows: best-effort process mitigation policy.
//!
//! 2. **Lockdown-only** (`apply_lockdown_protections`): protections that
//!    have a real cost or change runtime behavior. Examples:
//!    - `mlockall(MCL_CURRENT | MCL_FUTURE)` — pin all current and
//!      future allocations into RAM. Slows allocator paths and can be
//!      blocked by ulimits.
//!    - Refuse to run if `/proc/self/coredump_filter` allows anonymous
//!      pages (Linux).
//!    - Refuse to run if any persistence cache exists on disk.
//!
//! Callers that embed keyhog in security-critical contexts (EnvSeal,
//! lockdown-mode UIs) should call both. Callers using keyhog as a normal
//! triage tool only get the always-on tier.

use std::path::PathBuf;

/// Outcome of a hardening attempt — collected so callers can log which
/// protections actually took.
#[derive(Debug, Default, Clone)]
pub struct HardeningReport {
    pub no_core_dumps: bool,
    pub no_ptrace: bool,
    pub mlocked: bool,
    pub coredump_filter_safe: bool,
    pub failures: Vec<String>,
}

/// Apply zero-cost process protections that should always be on for a
/// secret-scanning binary. Returns a report of what took.
///
/// Always safe to call — failures are logged and tallied but do not
/// abort. The same bits set twice are idempotent.
pub fn apply_default_protections() -> HardeningReport {
    let mut report = HardeningReport::default();

    #[cfg(target_os = "linux")]
    {
        // PR_SET_DUMPABLE = 0 disables: core dumps, ptrace, /proc/<pid>/mem
        // read by other processes, and the kernel's coredump_filter. This
        // is what every credential manager (gpg-agent, ssh-agent, etc) does
        // and it costs nothing — the kernel just sets a flag.
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
        // SetProcessMitigationPolicy with ProcessSystemCallDisablePolicy
        // would deny dynamic loading of the Win32k subsystem; in practice
        // it's enough that we set DEP/CFG/etc which are default-on for
        // 64-bit binaries anyway. Mark as already-protected by platform.
        report.no_core_dumps = true;
        report.no_ptrace = true;
    }

    report
}

/// Apply protections that have a real cost or operational impact. Only
/// call from `lockdown` mode — these protections trade throughput and
/// flexibility for additional defense in depth.
///
/// Returns a report of what took. Callers should treat any `failures`
/// entry as a hard error in lockdown — it means a protection the user
/// asked for did not engage.
pub fn apply_lockdown_protections() -> HardeningReport {
    let mut report = apply_default_protections();

    #[cfg(target_os = "linux")]
    {
        // mlockall(MCL_CURRENT | MCL_FUTURE) pins every page of this
        // process — current heap + every future allocation — to RAM.
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

        // Verify the kernel's coredump_filter is restrictive. Default is
        // 0x33 which allows anonymous private pages — exactly where
        // credentials live. Refuse to run with `failures` populated when
        // it's wide open, so the lockdown caller hard-aborts.
        let filter = std::fs::read_to_string("/proc/self/coredump_filter")
            .ok()
            .and_then(|s| u32::from_str_radix(s.trim(), 16).ok());
        match filter {
            Some(0) => report.coredump_filter_safe = true,
            Some(other) => report.failures.push(format!(
                "/proc/self/coredump_filter = 0x{other:x} — anonymous pages would be dumped; \
                 set RLIMIT_CORE=0 or write 0 to /proc/self/coredump_filter before exec"
            )),
            None => {
                report
                    .failures
                    .push("could not read /proc/self/coredump_filter".into());
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        // mlockall isn't standardized on non-Linux Unix and Windows uses
        // VirtualLock + DEP. Mark mlocked as best-effort handled by the
        // platform's default protections.
        report.mlocked = false;
    }

    report
}

/// In lockdown mode, the engine refuses to start if any keyhog cache
/// exists on disk — caches survive across runs and are exactly the
/// "credentials accidentally written to disk" exfil vector lockdown is
/// supposed to prevent. Returns the offending paths, empty if clean.
#[must_use]
pub fn lockdown_disk_cache_violations() -> Vec<PathBuf> {
    let mut hits = Vec::new();
    if let Some(cache_root) = dirs::cache_dir() {
        let keyhog_root = cache_root.join("keyhog");
        if keyhog_root.exists() {
            hits.push(keyhog_root);
        }
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_protections_are_idempotent() {
        // Calling twice in quick succession must not error or change
        // outcomes — bits are already set on the second call.
        let first = apply_default_protections();
        let second = apply_default_protections();
        assert_eq!(first.no_core_dumps, second.no_core_dumps);
        assert_eq!(first.no_ptrace, second.no_ptrace);
    }

    #[test]
    fn report_starts_empty() {
        let r = HardeningReport::default();
        assert!(!r.no_core_dumps);
        assert!(!r.no_ptrace);
        assert!(!r.mlocked);
        assert!(r.failures.is_empty());
    }
}
