//! Tier-B contract for the scan-system mount filters.
//!
//! `keyhog scan-system` no longer hardcodes which filesystems/paths to skip; it
//! loads them from `data/scan_system/mount_filters.toml` (the shipped baseline,
//! optionally extended by a user file). This test pins that baseline: it must be
//! present, parse, and carry the lists the mount enumerator depends on. A
//! regression here (dropped entry, renamed key, malformed TOML) would silently
//! change which mounts get scanned, exactly the kind of invisible behavior
//! shift the Tier-B move was meant to make reviewable.

use std::collections::BTreeSet;

#[derive(serde::Deserialize)]
struct MountFilters {
    #[serde(default)]
    skip_fs_types: Vec<String>,
    #[serde(default)]
    skip_path_prefixes: Vec<String>,
    #[serde(default)]
    network_fs_types: Vec<String>,
}

fn load_baseline() -> MountFilters {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/data/scan_system/mount_filters.toml"
    );
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read bundled mount_filters.toml at {path}: {e}"));
    toml::from_str(&text).unwrap_or_else(|e| panic!("parse bundled mount_filters.toml: {e}"))
}

#[test]
fn baseline_parses_and_carries_expected_filters() {
    let f = load_baseline();

    let fs: BTreeSet<&str> = f.skip_fs_types.iter().map(String::as_str).collect();
    for ty in [
        "proc", "sysfs", "tmpfs", "devtmpfs", "cgroup2", "overlay", "squashfs", "rootfs",
    ] {
        assert!(fs.contains(ty), "skip_fs_types missing {ty}");
    }
    // The baseline must not silently shrink below its shipped size.
    assert!(
        f.skip_fs_types.len() >= 29,
        "baseline skip_fs_types shrank to {} (expected >= 29)",
        f.skip_fs_types.len()
    );

    let prefixes: BTreeSet<&str> = f.skip_path_prefixes.iter().map(String::as_str).collect();
    for p in ["/run/", "/proc/", "/sys/", "/dev/", "/snap/"] {
        assert!(prefixes.contains(p), "skip_path_prefixes missing {p}");
    }

    let net: BTreeSet<&str> = f.network_fs_types.iter().map(String::as_str).collect();
    for ty in ["nfs", "nfs4", "cifs", "smb", "ceph", "9p"] {
        assert!(net.contains(ty), "network_fs_types missing {ty}");
    }
}

#[test]
fn network_types_are_not_also_unconditionally_skipped() {
    // A network filesystem listed in `skip_fs_types` would be dropped even with
    // `--include-network`, defeating the flag. Keep the two sets disjoint.
    let f = load_baseline();
    let skip: BTreeSet<&str> = f.skip_fs_types.iter().map(String::as_str).collect();
    for ty in &f.network_fs_types {
        assert!(
            !skip.contains(ty.as_str()),
            "network fs {ty} is also in skip_fs_types: --include-network could never re-enable it"
        );
    }
}
