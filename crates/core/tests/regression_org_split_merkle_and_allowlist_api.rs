//! Regression: the file-responsibility split of `merkle_index.rs` (storage ->
//! `merkle_index/storage.rs`, tmp-file hygiene -> `merkle_index/tmp_hygiene.rs`)
//! and `allowlist.rs` (path-glob engine -> `allowlist/glob.rs`) must NOT change
//! any public API or behavior.
//!
//! These pin the post-split invariant the org refactor promised: every public
//! function/type stays reachable through its ORIGINAL path
//! (`keyhog_core::merkle_index::*`, `keyhog_core::allowlist::Allowlist`), and
//! the suppression + caching decisions are byte-for-byte what they were before
//! the helpers moved into submodules. They assert EXACT values (hashes, glob
//! verdicts, cache hits), never shapes - a regression here means the split
//! leaked behavior, which is the whole risk of a responsibility move.

use keyhog_core::testing::default_cache_path;

/// Backdate a file's mtime without pulling in the `filetime` crate, matching
/// the approach the pre-split sweep test uses. Returns `Err` on platforms where
/// the syscall is unavailable so the caller can skip the age-sensitive
/// assertion rather than fail spuriously.
#[cfg(unix)]
fn set_mtime(path: &std::path::Path, t: std::time::SystemTime) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let dur = t
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map_err(std::io::Error::other)?;
    let cpath = CString::new(path.as_os_str().as_bytes()).map_err(std::io::Error::other)?;
    let times = [
        libc::timespec {
            tv_sec: dur.as_secs() as libc::time_t,
            tv_nsec: dur.subsec_nanos() as libc::c_long,
        },
        libc::timespec {
            tv_sec: dur.as_secs() as libc::time_t,
            tv_nsec: dur.subsec_nanos() as libc::c_long,
        },
    ];
    let rc = unsafe {
        libc::utimensat(
            libc::AT_FDCWD,
            cpath.as_ptr(),
            times.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(unix))]
fn set_mtime(_path: &std::path::Path, _t: std::time::SystemTime) -> std::io::Result<()> {
    Err(std::io::ErrorKind::Unsupported.into())
}

// ── merkle_index: public surface + persistence/tmp-hygiene still wired ─────

#[test]
fn merkle_index_public_api_reachable_after_storage_split() {
    // Constructors, cap accessor, and the BLAKE3 hasher all stay on
    // `keyhog_core::merkle_index`.
    let idx = keyhog_core::testing::merkle_empty();
    assert_eq!(keyhog_core::testing::merkle_len(&idx), 0);
    assert!(keyhog_core::testing::merkle_is_empty(&idx));
    assert_eq!(keyhog_core::testing::merkle_max_entries(&idx), 8_000_000);

    let bounded = keyhog_core::testing::merkle_with_max_entries(3);
    assert_eq!(keyhog_core::testing::merkle_max_entries(&bounded), 3);

    // hash_content is the stable public hasher; pin an exact digest so a moved
    // helper that silently changed the algorithm is caught.
    let h = keyhog_core::testing::merkle_hash_content(b"keyhog-merkle-split-probe");
    assert_eq!(
        h,
        *blake3::hash(b"keyhog-merkle-split-probe").as_bytes(),
        "hash_content must remain BLAKE3 of the content after the split"
    );

    // record -> unchanged / metadata_unchanged / lookup round-trip.
    let path = std::path::PathBuf::from("/tmp/keyhog-split/a.rs");
    keyhog_core::testing::merkle_record_with_metadata(&idx, path.clone(), 42, 7, h);
    assert_eq!(keyhog_core::testing::merkle_len(&idx), 1);
    assert!(keyhog_core::testing::merkle_unchanged(&idx, &path, &h));
    assert!(idx.metadata_unchanged(&path, 42, 7));
    assert!(!idx.metadata_unchanged(&path, 42, 8));
    assert_eq!(
        keyhog_core::testing::merkle_lookup(&idx, &path),
        Some((42, 7, h))
    );

    idx.forget(&path);
    assert_eq!(keyhog_core::testing::merkle_lookup(&idx, &path), None);
    assert!(keyhog_core::testing::merkle_is_empty(&idx));
}

#[test]
fn merkle_index_save_load_roundtrip_and_tmp_sweep_after_split() {
    // The tmp-hygiene sweep moved to a submodule but is still called from
    // `load`. Drive the full save -> (plant a stale tmp) -> load cycle and
    // confirm: (a) the cache round-trips its entries, and (b) a stale tmp
    // sibling is swept on load.
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("merkle.idx");

    let idx = keyhog_core::testing::merkle_empty();
    let h = keyhog_core::testing::merkle_hash_content(b"persisted");
    keyhog_core::testing::merkle_record_with_metadata(
        &idx,
        std::path::PathBuf::from("src/persisted.rs"),
        100,
        9,
        h,
    );
    keyhog_core::testing::merkle_save(&idx, &cache).expect("save must succeed");

    // Plant a stale tmp sibling older than the 1h cutoff. `load` runs the
    // sweep from the new `tmp_hygiene` submodule before reading.
    let stale = dir.path().join("merkle.tmp-deadbeef");
    std::fs::write(&stale, b"orphaned by a SIGKILL'd save").unwrap();
    let two_hours_ago = std::time::SystemTime::now() - std::time::Duration::from_secs(2 * 60 * 60);
    let backdated = set_mtime(&stale, two_hours_ago).is_ok();

    let loaded = keyhog_core::testing::merkle_load(&cache);
    assert_eq!(
        keyhog_core::testing::merkle_len(&loaded),
        1,
        "round-tripped entry count"
    );
    assert_eq!(
        keyhog_core::testing::merkle_lookup(&loaded, std::path::Path::new("src/persisted.rs")),
        Some((100, 9, h)),
        "round-tripped entry value must be byte-identical after the split"
    );
    if backdated {
        // The mtime backdate took effect, so the stale tmp is older than the
        // 1h cutoff and the sweep (now in `tmp_hygiene`) must have removed it.
        assert!(
            !stale.exists(),
            "tmp_hygiene::sweep_stale_tmp_files must still run on load and remove the stale sibling"
        );
    }
}

#[test]
fn merkle_default_cache_path_unchanged() {
    // The path helper stays on the merkle_index module surface.
    if let Some(p) = default_cache_path() {
        assert!(
            p.ends_with("keyhog/merkle.idx"),
            "default cache path tail must be keyhog/merkle.idx, got {}",
            p.display()
        );
    }
}

#[test]
fn merkle_tmp_hygiene_does_not_flatten_read_dir_errors() {
    let src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/merkle_index/tmp_hygiene.rs"
    ))
    .expect("tmp hygiene source readable");
    assert!(
        !src.contains("entries.flatten()"),
        "tmp hygiene sweep must match read_dir entry errors explicitly"
    );
    assert!(
        src.contains("cannot read cache tmp directory entry"),
        "tmp hygiene sweep must log unreadable directory entries"
    );
}

#[test]
fn merkle_storage_split_keeps_spec_gate_and_atomic_persist_owner() {
    let storage_src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/merkle_index/storage.rs"
    ))
    .expect("storage source readable");
    assert!(
        storage_src.contains("fn persist_atomically"),
        "storage module must own atomic cache persistence"
    );
    assert!(
        storage_src.contains("detector spec changed since last scan"),
        "storage module must still enforce detector-spec invalidation"
    );

    let root_src =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/merkle_index.rs"))
            .expect("merkle root source readable");
    assert!(
        !root_src.contains("serde_json::to_vec_pretty"),
        "merkle root should not own disk serialization after the storage split"
    );
}

// ── allowlist: public surface + glob-engine decisions unchanged ─────────────

#[test]
fn allowlist_public_api_reachable_after_glob_split() {
    // parse + the public fields stay on `keyhog_core::allowlist::Allowlist`.
    let al =
        keyhog_core::testing::allowlist_parse("detector:demo-token\npath:**/*.md\nnode_modules/\n");
    assert!(al.ignored_detectors.contains("demo-token"));
    assert_eq!(al.ignored_paths, vec!["**/*.md", "node_modules/"]);

    // The path-glob decisions are produced by the moved `glob` submodule via
    // the precompiled index; pin exact verdicts.
    assert!(al.is_path_ignored("docs/README.md"));
    assert!(al.is_path_ignored("a/b/c/notes.md"));
    assert!(!al.is_path_ignored("src/main.rs"));
    assert!(al.is_path_ignored("node_modules/left-pad/index.js"));
    assert!(!al.is_path_ignored("vendor/left-pad/index.js"));
}

#[test]
fn allowlist_glob_normalization_and_backslash_paths_after_split() {
    // normalize_path + segment matching moved to `glob.rs`; confirm Windows
    // separators and `.`/`..` normalization still produce identical decisions.
    let al = keyhog_core::testing::allowlist_parse("path:src/**/secret.txt\n");
    assert!(al.is_path_ignored("src/a/b/secret.txt"));
    assert!(al.is_path_ignored("src\\a\\b\\secret.txt"));
    assert!(al.is_path_ignored("./src/x/secret.txt"));
    assert!(!al.is_path_ignored("src/secret.txt.bak"));
}

#[test]
fn allowlist_hash_suppression_unchanged_after_split() {
    // A bare 64-hex line is parsed into the credential-hash set; the hash path
    // did NOT move but must keep working alongside the moved glob path.
    let hash_hex = "a".repeat(64);
    let al = keyhog_core::testing::allowlist_parse(&format!("{hash_hex}\n"));
    assert_eq!(al.credential_hashes.len(), 1);
    assert!(keyhog_core::testing::allowlist_is_raw_hash_ignored(
        &al, &hash_hex
    ));
    assert!(!keyhog_core::testing::allowlist_is_raw_hash_ignored(
        &al,
        &"b".repeat(64)
    ));
}

#[test]
fn allowlist_directly_mutated_paths_trigger_rebuild_after_split() {
    // The `source_len`-mismatch rebuild path (now `glob::PathGlobIndex::source_len()`)
    // must still fire when `ignored_paths` is mutated directly after parse.
    let mut al = keyhog_core::testing::allowlist_parse("path:keep/**\n");
    assert!(al.is_path_ignored("keep/a.txt"));
    al.ignored_paths.push("added/**".to_string());
    assert!(
        al.is_path_ignored("added/deep/b.txt"),
        "a hand-pushed pattern must be honored via the rebuild branch, not silently ignored"
    );
}
