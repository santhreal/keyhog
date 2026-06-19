//! Per-OS hardware detection helpers: physical core count, total
//! memory, io_uring availability. Each helper has Linux / macOS /
//! Windows arms; the dispatch fns route based on `cfg!(target_os = …)`.

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
    let mut pairs = std::collections::HashSet::new();
    let mut physical_id = None::<usize>;
    let mut core_id = None::<usize>;
    for line in content.lines() {
        if line.starts_with("physical id") {
            physical_id = line.split(':').nth(1)?.trim().parse().ok(); // LAW10: host/OS hardware probe parse failure => None/conservative default; perf-only, recall-irrelevant
        } else if line.starts_with("core id") {
            core_id = line.split(':').nth(1)?.trim().parse().ok(); // LAW10: host/OS hardware probe parse failure => None/conservative default; perf-only, recall-irrelevant
        } else if line.trim().is_empty() {
            if let (Some(p), Some(c)) = (physical_id, core_id) {
                pairs.insert((p, c));
            }
            physical_id = None;
            core_id = None;
        }
    }
    if pairs.is_empty() {
        None
    } else {
        Some(pairs.len())
    }
}

#[cfg(target_os = "macos")]
fn macos_physical_cores() -> Option<usize> {
    // SECURITY: kimi-wave1 audit finding 3.PATH-sysctl. Resolve only from
    // trusted absolute system dirs; a missing probe tool means unknown cores,
    // not execution of an arbitrary PATH binary.
    let bin = keyhog_core::resolve_safe_bin("sysctl")?;
    std::process::Command::new(&bin)
        .args(["-n", "hw.physicalcpu"])
        .output()
        .ok() // LAW10: host/OS hardware probe parse failure => None/conservative default; perf-only, recall-irrelevant
        .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse().ok()) // LAW10: host/OS hardware probe parse failure => None/conservative default; perf-only, recall-irrelevant
}

#[cfg(target_os = "windows")]
fn windows_physical_cores() -> Option<usize> {
    // SECURITY: kimi-wave1 audit finding 3.PATH-powershell/wmic. Resolve each
    // binary against trusted absolute dirs; fall through to None if neither is
    // found there. Refuses unconditional PATH lookup.
    let core_count = keyhog_core::resolve_safe_bin("powershell").and_then(|ps| {
        std::process::Command::new(&ps)
            .args([
                "-NoProfile",
                "-Command",
                "(Get-CimInstance Win32_Processor).NumberOfCores",
            ])
            .output()
            .ok() // LAW10: host/OS hardware probe parse failure => None/conservative default; perf-only, recall-irrelevant
            .and_then(|o| {
                String::from_utf8_lossy(&o.stdout).trim().parse().ok() // LAW10: host/OS hardware probe parse failure => None/conservative default; perf-only, recall-irrelevant
            })
    });
    if core_count.is_some() {
        return core_count;
    }
    let wmic = keyhog_core::resolve_safe_bin("wmic")?;
    std::process::Command::new(&wmic)
        .args(["cpu", "get", "NumberOfCores", "/value"])
        .output()
        .ok() // LAW10: host/OS hardware probe parse failure => None/conservative default; perf-only, recall-irrelevant
        .and_then(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .find(|l| l.starts_with("NumberOfCores="))
                .and_then(|l| l.split('=').nth(1))
                .and_then(|v| v.trim().parse().ok()) // LAW10: host/OS hardware probe parse failure => None/conservative default; perf-only, recall-irrelevant
        })
}

pub(super) fn detect_total_memory_mb() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let content = std::fs::read_to_string("/proc/meminfo").ok()?; // LAW10: host/OS hardware probe parse failure => None/conservative default; perf-only, recall-irrelevant
        for line in content.lines() {
            if line.starts_with("MemTotal:") {
                let kb: u64 = line.split_whitespace().nth(1)?.parse().ok()?; // LAW10: host/OS hardware probe parse failure => None/conservative default; perf-only, recall-irrelevant
                return Some(kb / 1024);
            }
        }
        None
    }
    #[cfg(target_os = "macos")]
    {
        let bin = keyhog_core::resolve_safe_bin("sysctl")?;
        std::process::Command::new(&bin)
            .args(["-n", "hw.memsize"])
            .output()
            .ok() // LAW10: host/OS hardware probe parse failure => None/conservative default; perf-only, recall-irrelevant
            .and_then(|o| {
                let bytes: u64 = String::from_utf8_lossy(&o.stdout).trim().parse().ok()?; // LAW10: host/OS hardware probe parse failure => None/conservative default; perf-only, recall-irrelevant
                Some(bytes / 1024 / 1024)
            })
    }
    #[cfg(target_os = "windows")]
    {
        let memory = keyhog_core::resolve_safe_bin("powershell").and_then(|ps| {
            std::process::Command::new(&ps)
                .args([
                    "-NoProfile",
                    "-Command",
                    "(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory",
                ])
                .output()
                .ok() // LAW10: host/OS hardware probe parse failure => None/conservative default; perf-only, recall-irrelevant
                .and_then(|o| {
                    let bytes: u64 = String::from_utf8_lossy(&o.stdout).trim().parse().ok()?; // LAW10: host/OS hardware probe parse failure => None/conservative default; perf-only, recall-irrelevant
                    Some(bytes / 1024 / 1024)
                })
        });
        if memory.is_some() {
            return memory;
        }
        let wmic = keyhog_core::resolve_safe_bin("wmic")?;
        std::process::Command::new(&wmic)
            .args(["computersystem", "get", "TotalPhysicalMemory", "/value"])
            .output()
            .ok() // LAW10: host/OS hardware probe parse failure => None/conservative default; perf-only, recall-irrelevant
            .and_then(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .find(|l| l.starts_with("TotalPhysicalMemory="))
                    .and_then(|l| l.split('=').nth(1))
                    .and_then(|v| v.trim().parse::<u64>().ok()) // LAW10: host/OS hardware probe parse failure => None/conservative default; perf-only, recall-irrelevant
                    .map(|bytes| bytes / 1024 / 1024)
            })
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        None
    }
}

pub(super) fn detect_io_uring() -> bool {
    #[cfg(target_os = "linux")]
    {
        let kernel_ok = std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .ok() // LAW10: host/OS hardware probe parse failure => None/conservative default; perf-only, recall-irrelevant
            .and_then(|s| {
                let parts: Vec<&str> = s.trim().split('.').collect();
                if parts.len() >= 2 {
                    let major = parts[0].parse::<u32>().ok()?; // LAW10: host/OS hardware probe parse failure => None/conservative default; perf-only, recall-irrelevant
                    let minor = parts[1].parse::<u32>().ok()?; // LAW10: host/OS hardware probe parse failure => None/conservative default; perf-only, recall-irrelevant
                    Some(major > 5 || (major == 5 && minor >= 1))
                } else {
                    None
                }
            })
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
