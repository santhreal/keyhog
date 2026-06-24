use keyhog::testing::{CliTestApi as _, API};
use keyhog_core::{MatchLocation, RawMatch, Severity};
use std::sync::Arc;

fn raw_match(i: usize) -> RawMatch {
    let credential = format!("AKIA_SECRET_PLAINTEXT_{i:08}");
    RawMatch {
        detector_id: Arc::from("aws-access-key"),
        detector_name: Arc::from("AWS Access Key"),
        service: Arc::from("aws"),
        severity: Severity::High,
        credential: keyhog_core::SensitiveString::from(credential.as_str()),
        credential_hash: raw_hash(i).into(),
        companions: std::collections::HashMap::new(),
        location: MatchLocation {
            source: Arc::from("filesystem"),
            file_path: Some(Arc::from(format!("/tmp/leak{i}.env").as_str())),
            line: Some(i + 1),
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        entropy: Some(4.2),
        confidence: Some(0.9),
    }
}

fn raw_hash(i: usize) -> [u8; 32] {
    let mut hash = [0u8; 32];
    hash[..8].copy_from_slice(&((i as u64) + 1).to_le_bytes());
    hash
}

#[test]
fn sink_starts_empty() {
    let sink = API.finding_sink_new();
    assert!(API.finding_sink_is_empty(&sink));
    assert_eq!(API.finding_sink_total(&sink), 0);
    assert_eq!(API.finding_sink_retained_len(&sink), 0);
}

#[test]
fn sink_absorbs_and_counts_below_cap() {
    let mut sink = API.finding_sink_new();
    API.finding_sink_absorb(&mut sink, (0..10).map(raw_match).collect());
    assert_eq!(API.finding_sink_total(&sink), 10);
    assert_eq!(API.finding_sink_retained_len(&sink), 10);
    assert!(!API.finding_sink_is_empty(&sink));
}

#[test]
fn sink_retains_only_redacted_never_plaintext() {
    let mut sink = API.finding_sink_new();
    API.finding_sink_absorb(&mut sink, vec![raw_match(7)]);
    let json = API
        .finding_sink_retained_json(&sink)
        .expect("serialize retained findings");
    assert!(
        !json.contains("AKIA_SECRET_PLAINTEXT_00000007"),
        "plaintext credential leaked into retained findings: {json}"
    );
    assert_eq!(API.finding_sink_retained_len(&sink), 1);
    assert_eq!(
        API.finding_sink_retained_hash(&sink, 0),
        Some(raw_hash(7).into())
    );
}

#[test]
fn sink_caps_resident_set_but_keeps_counting() {
    let cap = 3;
    let mut sink = API.finding_sink_with_cap(cap);

    API.finding_sink_absorb(&mut sink, (0..2).map(raw_match).collect());
    API.finding_sink_absorb(&mut sink, (2..50).map(raw_match).collect());

    assert_eq!(API.finding_sink_total(&sink), 50);
    assert_eq!(API.finding_sink_retained_len(&sink), cap);
    assert!(API.finding_sink_capped_warned(&sink));
    assert!(!API.finding_sink_is_empty(&sink));
    assert_eq!(
        API.finding_sink_retained_hash(&sink, 0),
        Some(raw_hash(0).into())
    );
    assert_eq!(
        API.finding_sink_retained_hash(&sink, cap - 1),
        Some(raw_hash(cap - 1).into())
    );
}

#[test]
fn default_cap_is_the_module_ceiling() {
    let sink = API.finding_sink_new();
    assert_eq!(API.finding_sink_cap(&sink), API.max_resident_findings());
}

#[test]
fn space_cap_policy_refuses_first_over_cap_chunk_before_absorb() {
    assert!(
        API.scan_system_chunk_fits_space_cap(0, 10, 10),
        "a chunk that exactly reaches the cap is allowed"
    );
    assert!(
        !API.scan_system_chunk_fits_space_cap(9, 2, 10),
        "a chunk that would exceed the cap must be refused before scan/absorb"
    );
    assert!(
        !API.scan_system_chunk_fits_space_cap(10, 0, 10),
        "once the cap is reached, even zero-byte follow-up chunks stop the scope"
    );
    assert!(
        !API.scan_system_chunk_fits_space_cap(u64::MAX - 1, usize::MAX, u64::MAX),
        "overflow in cap arithmetic must fail closed instead of wrapping under the cap"
    );
}

#[test]
fn skipped_chunks_start_at_zero_and_accumulate() {
    // Law 10: an unreadable source chunk (corrupt git object, perm-denied path)
    // is unscanned bytes. The sink counts each one so the final summary can warn
    // the audit did NOT cover everything, instead of the old silent
    // `Err(_) => continue` that made a partial scan look complete.
    let mut sink = API.finding_sink_new();
    assert_eq!(
        API.finding_sink_skipped_chunks(&sink),
        0,
        "a fresh sink has skipped nothing"
    );

    for _ in 0..5 {
        API.finding_sink_record_skipped_chunk(&mut sink);
    }
    assert_eq!(
        API.finding_sink_skipped_chunks(&sink),
        5,
        "every dropped chunk must be counted so the recall loss is surfaced"
    );

    // Skips are tracked independently of findings: a scan can drop chunks AND
    // still surface findings, and both counts must be honest.
    API.finding_sink_absorb(&mut sink, vec![raw_match(1)]);
    assert_eq!(
        API.finding_sink_total(&sink),
        1,
        "findings count is unaffected by skip tracking"
    );
    assert_eq!(
        API.finding_sink_skipped_chunks(&sink),
        5,
        "skip count is unaffected by findings"
    );
}

#[test]
fn git_repo_discovery_does_not_flatten_read_dir_errors() {
    let src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/subcommands/scan_system.rs"
    ))
    .expect("scan-system source readable");
    assert!(
        !src.contains("entries.flatten()"),
        "scan-system repo discovery must match read_dir entry errors explicitly so skipped subtrees are logged"
    );
    assert!(
        src.contains("record_git_discovery_gap")
            && src.contains("\"directory entry read\"")
            && src.contains("\"directory read\"")
            && src.contains("\"root canonicalization\"")
            && src.contains("\"subtree canonicalization\""),
        "scan-system repo discovery must use the shared loud discovery-gap reporter for canonicalization, per-entry, and whole-directory read failures"
    );
    let discovery_fn = src
        .split("fn discover_git_repos")
        .nth(1)
        .and_then(|rest| rest.split("fn record_git_discovery_gap").next())
        .expect(
            "scan-system source must contain discover_git_repos before record_git_discovery_gap",
        );
    assert!(
        !discovery_fn.contains("space_cap"),
        "scan-system repo discovery must not advertise a fake space-cap traversal contract"
    );
}

#[test]
fn macos_scan_system_mount_enumeration_does_not_fall_back_to_path() {
    let src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/subcommands/scan_system/mounts.rs"
    ))
    .expect("scan-system mount source readable");
    assert!(
        src.contains(r#"resolve_safe_bin("mount")"#),
        "macOS scan-system mount enumeration must use the trusted absolute binary resolver"
    );
    assert!(
        !src.contains(r#"resolve_or_fallback("mount")"#),
        "macOS scan-system must not execute an untrusted PATH mount binary when trusted resolution misses"
    );
    assert!(
        src.contains("[system].trusted_bin_dirs"),
        "trusted mount resolution failure must tell the operator how to configure a non-standard mount path"
    );
}

#[test]
fn linux_mount_filters_are_tier_b_and_match_decoded_targets() {
    let src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/subcommands/scan_system/mounts.rs"
    ))
    .expect("scan-system mount source readable");
    let data = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/data/scan_system/mount_filters.toml"
    ))
    .expect("scan-system mount filter data readable");

    assert!(
        src.contains("include_str!(\"../../../data/scan_system/mount_filters.toml\")")
            && src.contains("fn load_mount_filters()")
            && !src.contains("const SKIP_FS_TYPES")
            && !src.contains("const SKIP_PATH_PREFIXES")
            && !src.contains("const NETWORK_FS_TYPES"),
        "linux mount filtering must be loaded from Tier-B data instead of local hardcoded lists"
    );
    assert!(
        data.contains("skip_fs_types")
            && data.contains("skip_path_prefixes")
            && data.contains("network_fs_types")
            && data.contains("\"proc\"")
            && data.contains("\"devfs\"")
            && data.contains("\"/snap/\"")
            && data.contains("\"nfs\"")
            && data.contains("\"afpfs\""),
        "mount_filters.toml must carry the linux and macOS skip/network filter sets"
    );
    assert!(
        src.contains("fn macos_mounts(")
            && src.contains("let filters = load_mount_filters()?;")
            && src.contains("skip_fs_types.contains(fstype)")
            && src.contains("network_fs_types.contains(fstype)")
            && !src.contains(r#"matches!(fstype, "devfs" | "autofs" | "tmpfs")"#)
            && !src.contains(r#"matches!(fstype, "nfs" | "smbfs" | "afpfs")"#),
        "macOS scan-system mount filtering must use the shared Tier-B policy instead of local hardcoded lists"
    );

    let decode_pos = src
        .find("let decoded = decode_octal_escapes(target)")
        .expect("linux mount enumeration must decode /proc/mounts targets");
    let skip_pos = src
        .find("decoded.starts_with(prefix)")
        .expect("linux mount skip prefixes must compare against decoded targets");
    assert!(
        decode_pos < skip_pos,
        "linux scan-system must decode escaped mount targets before applying skip_path_prefixes"
    );
    assert!(
        !src.contains("target.starts_with"),
        "raw /proc/mounts targets contain octal escapes, so skip_path_prefixes must not match raw targets"
    );
}

#[test]
fn scan_system_output_uses_atomic_file_writer() {
    let scan_system = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/subcommands/scan_system.rs"
    ))
    .expect("scan-system source readable");
    let atomic_file =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/atomic_file.rs"))
            .expect("atomic file source readable");

    assert!(
        scan_system.contains("crate::atomic_file::write_bytes(out, json.as_bytes())"),
        "scan-system --output must use the shared atomic writer"
    );
    assert!(
        !scan_system.contains("std::fs::write(out"),
        "scan-system --output must not truncate/write the final report path directly"
    );
    assert!(
        atomic_file.contains("tempfile::NamedTempFile::new_in(parent)")
            && atomic_file.contains("tmp.as_file().sync_all()")
            && atomic_file.contains("tmp.persist(path)"),
        "shared CLI output writer must write a same-directory temp file, sync it, then persist over the target"
    );
}
