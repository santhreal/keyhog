//! Per-OS hardware detection helpers: physical core count, total
//! memory, io_uring availability. Each helper has Linux / macOS /
//! Windows arms; the dispatch fns route based on `cfg!(target_os = …)`.

#[cfg(any(target_os = "macos", target_os = "windows"))]
use std::str::FromStr;

pub(super) fn physical_core_count() -> Option<usize> {
    #[cfg(target_os = "linux")]
    {
        linux_physical_cores()
    }
    #[cfg(target_os = "macos")]
    {
        macos_physical_cores()
    }
    #[cfg(target_os = "windows")]
    {
        windows_physical_cores()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        None
    }
}

#[cfg(target_os = "linux")]
fn linux_physical_cores() -> Option<usize> {
    let content = std::fs::read_to_string("/proc/cpuinfo").ok()?; // LAW10: host/OS hardware probe parse failure => None/conservative default; perf-only, recall-irrelevant
    linux_physical_cores_from_cpuinfo(&content)
}

#[cfg(target_os = "linux")]
pub(crate) fn linux_physical_cores_from_cpuinfo(content: &str) -> Option<usize> {
    let mut pairs = std::collections::HashSet::new();
    let mut physical_id = None::<usize>;
    let mut core_id = None::<usize>;
    for line in content.lines() {
        if line.starts_with("physical id") {
            physical_id = parse_proc_usize_field(line);
        } else if line.starts_with("core id") {
            core_id = parse_proc_usize_field(line);
        } else if line.trim().is_empty() {
            if let (Some(p), Some(c)) = (physical_id, core_id) {
                pairs.insert((p, c));
            }
            physical_id = None;
            core_id = None;
        }
    }
    if let (Some(p), Some(c)) = (physical_id, core_id) {
        pairs.insert((p, c));
    }
    if pairs.is_empty() {
        None
    } else {
        Some(pairs.len())
    }
}

#[cfg(target_os = "linux")]
fn parse_proc_usize_field(line: &str) -> Option<usize> {
    let Some((_, value)) = line.split_once(':') else {
        return None;
    };
    match value.trim().parse() {
        Ok(parsed) => Some(parsed),
        Err(_) => None, // LAW10: malformed trusted /proc hardware probe field skipped; perf-only core-count sizing, recall-irrelevant
    }
}

#[cfg(target_os = "macos")]
fn macos_physical_cores() -> Option<usize> {
    // SECURITY: kimi-wave1 audit finding 3.PATH-sysctl. Resolve only from
    // trusted absolute system dirs; a missing probe tool means unknown cores,
    // not execution of an arbitrary PATH binary.
    run_probe_command("sysctl", &["-n", "hw.physicalcpu"])
        .and_then(|stdout| parse_trimmed_probe_value(&stdout))
}

#[cfg(target_os = "windows")]
fn windows_physical_cores() -> Option<usize> {
    // SECURITY: kimi-wave1 audit finding 3.PATH-powershell/wmic. Resolve each
    // binary against trusted absolute dirs; fall through to None if neither is
    // found there. Refuses unconditional PATH lookup.
    let core_count = run_probe_command(
        "powershell",
        &[
            "-NoProfile",
            "-Command",
            "(Get-CimInstance Win32_Processor).NumberOfCores",
        ],
    )
    .and_then(|stdout| parse_trimmed_probe_value(&stdout));
    if core_count.is_some() {
        return core_count;
    }
    run_probe_command("wmic", &["cpu", "get", "NumberOfCores", "/value"]).and_then(|stdout| {
        stdout
            .lines()
            .find_map(|line| parse_wmic_value::<usize>(line, "NumberOfCores"))
    })
}

pub(super) fn detect_total_memory_mb() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let content = std::fs::read_to_string("/proc/meminfo").ok()?; // LAW10: host/OS hardware probe parse failure => None/conservative default; perf-only, recall-irrelevant
        linux_total_memory_mb_from_meminfo(&content)
    }
    #[cfg(target_os = "macos")]
    {
        run_probe_command("sysctl", &["-n", "hw.memsize"])
            .and_then(|stdout| parse_trimmed_probe_value::<u64>(&stdout))
            .map(|bytes| bytes / 1024 / 1024)
    }
    #[cfg(target_os = "windows")]
    {
        let memory = run_probe_command(
            "powershell",
            &[
                "-NoProfile",
                "-Command",
                "(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory",
            ],
        )
        .and_then(|stdout| parse_trimmed_probe_value::<u64>(&stdout))
        .map(|bytes| bytes / 1024 / 1024);
        if memory.is_some() {
            return memory;
        }
        run_probe_command(
            "wmic",
            &["computersystem", "get", "TotalPhysicalMemory", "/value"],
        )
        .and_then(|stdout| {
            stdout
                .lines()
                .find_map(|line| parse_wmic_value::<u64>(line, "TotalPhysicalMemory"))
        })
        .map(|bytes| bytes / 1024 / 1024)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        None
    }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn run_probe_command(bin_name: &str, args: &[&str]) -> Option<String> {
    let bin = keyhog_core::resolve_safe_bin(bin_name)?;
    let output = match std::process::Command::new(&bin).args(args).output() {
        Ok(output) => output,
        Err(_) => return None, // LAW10: host/OS hardware probe command failure => None/conservative default; perf-only, recall-irrelevant
    };
    Some(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn parse_trimmed_probe_value<T>(stdout: &str) -> Option<T>
where
    T: FromStr,
{
    match stdout.trim().parse() {
        Ok(value) => Some(value),
        Err(_) => None, // LAW10: host/OS hardware probe parse failure => None/conservative default; perf-only, recall-irrelevant
    }
}

#[cfg(target_os = "windows")]
fn parse_wmic_value<T>(line: &str, key: &str) -> Option<T>
where
    T: FromStr,
{
    let (field, raw_value) = line.split_once('=')?;
    if field != key {
        return None;
    }
    parse_trimmed_probe_value(raw_value)
}

#[cfg(target_os = "linux")]
pub(crate) fn linux_total_memory_mb_from_meminfo(content: &str) -> Option<u64> {
    for line in content.lines() {
        if line.starts_with("MemTotal:") {
            let Some(kb_text) = line.split_whitespace().nth(1) else {
                continue;
            };
            let Ok(kb) = kb_text.parse::<u64>() else {
                continue;
            };
            return Some(kb / 1024);
        }
    }
    None
}

/// Whether a `/proc/sys/kernel/osrelease` string reports a kernel new enough for
/// io_uring (5.1+, when `IORING_OP`/the syscall surface landed). Pure parse of
/// the version string so it is testable without a kernel: trims, splits on `.`,
/// and is conservative, any shape it cannot parse (fewer than two dotted
/// components, a non-numeric major/minor) returns `false`, matching the original
/// `.ok()? … .unwrap_or(false)` fail-closed chain.
#[cfg(target_os = "linux")]
pub(crate) fn kernel_supports_io_uring(osrelease: &str) -> bool {
    let parts: Vec<&str> = osrelease.trim().split('.').collect();
    if parts.len() < 2 {
        return false;
    }
    let (Ok(major), Ok(minor)) = (parts[0].parse::<u32>(), parts[1].parse::<u32>()) else {
        return false; // LAW10: malformed osrelease => conservative false; perf-only, recall-irrelevant
    };
    major > 5 || (major == 5 && minor >= 1)
}

pub(super) fn detect_io_uring() -> bool {
    #[cfg(target_os = "linux")]
    {
        let kernel_ok = std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .ok() // LAW10: host/OS hardware probe parse failure => None/conservative default; perf-only, recall-irrelevant
            .map(|s| kernel_supports_io_uring(&s))
            .unwrap_or(false); // LAW10: host/OS hardware probe parse failure => None/conservative default; perf-only, recall-irrelevant
        if !kernel_ok {
            return false;
        }
        io_uring::IoUring::new(1).is_ok()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}
