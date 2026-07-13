//! Regression: the file-responsibility split of `merkle_index.rs` (storage ->
//! `merkle_index/storage.rs`, tmp-file hygiene -> `merkle_index/tmp_hygiene.rs`)
//! and `allowlist.rs` (path-glob engine -> `allowlist/glob.rs`) must NOT change
//! any public API or behavior.
//!
//! These pin the post-split invariant the org refactor promised: every public
//! function/type stays reachable through its ORIGINAL path
//! (`keyhog_core::merkle_index::*`, `keyhog_core::Allowlist`), and
//! the suppression + caching decisions are byte-for-byte what they were before
//! the helpers moved into submodules. They assert EXACT values (hashes, glob
//! verdicts, cache hits), never shapes - a regression here means the split
//! leaked behavior, which is the whole risk of a responsibility move.

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
    let idx = keyhog_core::testing::CoreTestApi::merkle_empty(&keyhog_core::testing::TestApi);
    assert_eq!(
        keyhog_core::testing::CoreTestApi::merkle_len(&keyhog_core::testing::TestApi, &idx),
        0
    );
    assert!(keyhog_core::testing::CoreTestApi::merkle_is_empty(
        &keyhog_core::testing::TestApi,
        &idx
    ));
    assert_eq!(
        keyhog_core::testing::CoreTestApi::merkle_max_entries(&keyhog_core::testing::TestApi, &idx),
        8_000_000
    );

    let bounded = keyhog_core::testing::CoreTestApi::merkle_with_max_entries(
        &keyhog_core::testing::TestApi,
        3,
    );
    assert_eq!(
        keyhog_core::testing::CoreTestApi::merkle_max_entries(
            &keyhog_core::testing::TestApi,
            &bounded
        ),
        3
    );

    // hash_content is the stable public hasher; pin an exact digest so a moved
    // helper that silently changed the algorithm is caught.
    let h = keyhog_core::testing::CoreTestApi::merkle_hash_content(
        &keyhog_core::testing::TestApi,
        b"keyhog-merkle-split-probe",
    );
    assert_eq!(
        h,
        *blake3::hash(b"keyhog-merkle-split-probe").as_bytes(),
        "hash_content must remain BLAKE3 of the content after the split"
    );

    // record -> unchanged / metadata_unchanged / lookup round-trip.
    let path = std::path::PathBuf::from("/tmp/keyhog-split/a.rs");
    keyhog_core::testing::CoreTestApi::merkle_record_with_metadata(
        &keyhog_core::testing::TestApi,
        &idx,
        path.clone(),
        42,
        7,
        h,
    );
    assert_eq!(
        keyhog_core::testing::CoreTestApi::merkle_len(&keyhog_core::testing::TestApi, &idx),
        1
    );
    assert!(keyhog_core::testing::CoreTestApi::merkle_unchanged(
        &keyhog_core::testing::TestApi,
        &idx,
        &path,
        &h
    ));
    assert!(idx.metadata_unchanged(&path, 42, 7));
    assert!(!idx.metadata_unchanged(&path, 42, 8));
    assert_eq!(
        keyhog_core::testing::CoreTestApi::merkle_lookup(
            &keyhog_core::testing::TestApi,
            &idx,
            &path
        ),
        Some((42, 7, h))
    );

    idx.forget(&path);
    assert_eq!(
        keyhog_core::testing::CoreTestApi::merkle_lookup(
            &keyhog_core::testing::TestApi,
            &idx,
            &path
        ),
        None
    );
    assert!(keyhog_core::testing::CoreTestApi::merkle_is_empty(
        &keyhog_core::testing::TestApi,
        &idx
    ));
}

#[test]
fn merkle_index_save_load_roundtrip_and_tmp_sweep_after_split() {
    // The tmp-hygiene sweep moved to a submodule but is still called from
    // `load`. Drive the full save -> (plant a stale tmp) -> load cycle and
    // confirm: (a) the cache round-trips its entries, and (b) a stale tmp
    // sibling is swept on load.
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("merkle.idx");

    let idx = keyhog_core::testing::CoreTestApi::merkle_empty(&keyhog_core::testing::TestApi);
    let h = keyhog_core::testing::CoreTestApi::merkle_hash_content(
        &keyhog_core::testing::TestApi,
        b"persisted",
    );
    keyhog_core::testing::CoreTestApi::merkle_record_with_metadata(
        &keyhog_core::testing::TestApi,
        &idx,
        std::path::PathBuf::from("src/persisted.rs"),
        100,
        9,
        h,
    );
    keyhog_core::testing::CoreTestApi::merkle_save(&keyhog_core::testing::TestApi, &idx, &cache)
        .expect("save must succeed");

    // Plant a stale tmp sibling older than the 1h cutoff. `load` runs the
    // sweep from the new `tmp_hygiene` submodule before reading.
    let stale = dir.path().join("merkle.tmp-deadbeef");
    std::fs::write(&stale, b"orphaned by a SIGKILL'd save").unwrap();
    let two_hours_ago = std::time::SystemTime::now() - std::time::Duration::from_secs(2 * 60 * 60);
    let backdated = set_mtime(&stale, two_hours_ago).is_ok();

    let loaded =
        keyhog_core::testing::CoreTestApi::merkle_load(&keyhog_core::testing::TestApi, &cache);
    assert_eq!(
        keyhog_core::testing::CoreTestApi::merkle_len(&keyhog_core::testing::TestApi, &loaded),
        1,
        "round-tripped entry count"
    );
    assert_eq!(
        keyhog_core::testing::CoreTestApi::merkle_lookup(
            &keyhog_core::testing::TestApi,
            &loaded,
            std::path::Path::new("src/persisted.rs")
        ),
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
    if let Some(p) =
        keyhog_core::testing::CoreTestApi::merkle_default_cache_path(&keyhog_core::testing::TestApi)
    {
        assert!(
            p.ends_with("keyhog/merkle.idx"),
            "default cache path tail must be keyhog/merkle.idx, got {}",
            p.display()
        );
    }
}

#[test]
fn root_cache_path_exports_use_explicit_owner_names() {
    let api = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/api.rs"))
        .expect("core api source readable");
    let calibration =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/calibration.rs"))
            .expect("calibration source readable");
    let merkle_index =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/merkle_index.rs"))
            .expect("merkle index source readable");
    let merkle_storage = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/merkle_index/storage.rs"
    ))
    .expect("merkle storage source readable");

    assert!(
        calibration.contains("pub fn calibration_default_cache_path()")
            && merkle_storage.contains("pub fn merkle_default_cache_path()")
            && merkle_index
                .contains("pub use storage::{default_cache_path, merkle_default_cache_path};"),
        "cache path owners must expose explicit names at their ownership boundary"
    );
    assert!(
        api.contains("calibration_default_cache_path")
            && api.contains("merkle_default_cache_path")
            && !api.contains("default_cache_path as calibration_default_cache_path")
            && !api.contains("default_cache_path as merkle_default_cache_path"),
        "root api.rs must re-export explicit cache path names instead of resolving name clashes with import aliases"
    );
}

#[test]
fn merkle_tmp_hygiene_does_not_flatten_read_dir_errors() {
    // The dir-entry read loop is now owned by the shared sweeper
    // `state_file::sweep_stale_tmp_siblings` (merkle + calibration both delegate
    // to it: ONE place). The no-silent-drop contract must hold at that owner:
    // each read_dir entry error is matched explicitly and logged, never
    // `.flatten()`-ed away (which would silently skip unreadable entries).
    let state_file_src =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/state_file.rs"))
            .expect("state_file source readable");
    let sweep_body = state_file_src
        .split("fn sweep_stale_tmp_siblings(")
        .nth(1)
        .expect("sweep_stale_tmp_siblings exists")
        .split("\nfn ")
        .next()
        .expect("sweep body");
    assert!(
        !sweep_body.contains(".flatten()"),
        "shared tmp sweep must match read_dir entry errors explicitly, not flatten them away"
    );
    assert!(
        sweep_body.contains("skip unreadable tmp dir entry"),
        "shared tmp sweep must log unreadable directory entries rather than silently drop them"
    );
    // And the merkle sweep still routes through that shared error-explicit owner.
    let tmp_hygiene_src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/merkle_index/tmp_hygiene.rs"
    ))
    .expect("tmp hygiene source readable");
    assert!(
        tmp_hygiene_src.contains("state_file::sweep_stale_tmp_siblings("),
        "merkle tmp hygiene must delegate to the shared error-explicit sweeper"
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
    assert!(
        storage_src.contains("tmp_hygiene::{sweep_stale_tmp_files, MERKLE_TMP_PREFIX}")
            && storage_src
                .contains("state_file::write_atomically(path, MERKLE_TMP_PREFIX, serialized)")
            && !storage_src.contains("tempfile::NamedTempFile::new_in(parent)"),
        "merkle storage must persist through the shared atomic writer, handing it the explicit \
         keyhog prefix that tmp_hygiene sweeps"
    );
    // The shared writer is the single owner that stamps that caller prefix onto
    // the temp file, verify it there so the delegation can't route through a
    // prefix-ignoring writer.
    let state_file_src =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/state_file.rs"))
            .expect("state_file source readable");
    assert!(
        state_file_src.contains("fn write_atomically(path: &Path, prefix: &str, bytes: &[u8])")
            && state_file_src.contains(".prefix(prefix)"),
        "the shared atomic writer must create the temp file with the caller's explicit prefix"
    );

    let root_src =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/merkle_index.rs"))
            .expect("merkle root source readable");
    assert!(
        !root_src.contains("serde_json::to_vec_pretty"),
        "merkle root should not own disk serialization after the storage split"
    );
}

#[test]
fn cache_temp_file_prefix_contract_is_explicit() {
    let tmp_hygiene_src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/merkle_index/tmp_hygiene.rs"
    ))
    .expect("tmp hygiene source readable");
    assert!(
        tmp_hygiene_src.contains("pub(super) const MERKLE_TMP_PREFIX"),
        "tmp hygiene must own the merkle cache temp-file prefix constant"
    );
    assert!(
        tmp_hygiene_src.contains("&[MERKLE_TMP_PREFIX, &legacy_tmp_prefix]")
            && tmp_hygiene_src.contains("legacy_cache_tmp_prefix(cache_path)")
            && !tmp_hygiene_src.contains("name_str.starts_with(\".tmp\")"),
        "tmp hygiene must hand the shared sweeper its explicit keyhog-owned prefixes \
         (current + legacy), never a broad anonymous .tmp match"
    );
    // Prefix-scoped deletion is enforced in ONE place (the shared sweeper).
    let state_file_src =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/state_file.rs"))
            .expect("state_file source readable");
    assert!(
        state_file_src.contains("if !prefixes.iter().any(|p| name_str.starts_with(p))"),
        "the shared tmp sweeper must only remove files whose name starts with a caller-supplied prefix"
    );

    let calibration_src =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/calibration.rs"))
            .expect("calibration source readable");
    assert!(
        calibration_src.contains("const CALIBRATION_TMP_PREFIX")
            && calibration_src.contains("sweep_stale_calibration_tmp_files(path);")
            && calibration_src.contains(
                "state_file::write_atomically(path, CALIBRATION_TMP_PREFIX, &serialized)"
            )
            && !calibration_src.contains("tempfile::NamedTempFile::new_in(parent)"),
        "calibration saves must use and sweep an explicit cache temp-file prefix through the \
         shared atomic writer instead of anonymous .tmp siblings"
    );
}

#[test]
fn merkle_tmp_sweep_never_deletes_the_active_cache_path() {
    let dir = tempfile::tempdir().unwrap();
    let cache_path = dir.path().join(".tmp.keyhog-merkle-cache");
    std::fs::write(&cache_path, b"not-json").unwrap();
    let two_hours_ago = std::time::SystemTime::now() - std::time::Duration::from_secs(2 * 60 * 60);
    let _ = set_mtime(&cache_path, two_hours_ago);

    let _ =
        keyhog_core::testing::CoreTestApi::merkle_load(&keyhog_core::testing::TestApi, &cache_path);

    assert!(
        cache_path.exists(),
        "merkle tmp sweep must never remove the active cache path even when its name matches the tmp prefix"
    );
}

#[test]
fn calibration_load_sweeps_only_keyhog_calibration_tmp_files() {
    let dir = tempfile::tempdir().unwrap();
    let cache_path = dir.path().join("calibration.json");
    let stale = dir.path().join(".tmp.keyhog-calibration-deadbeef");
    let fresh = dir.path().join(".tmp.keyhog-calibration-fresh");
    let unrelated = dir.path().join(".tmp-other-app");
    std::fs::write(&stale, b"stale calibration tmp").unwrap();
    std::fs::write(&fresh, b"fresh calibration tmp").unwrap();
    std::fs::write(&unrelated, b"not ours").unwrap();
    let two_hours_ago = std::time::SystemTime::now() - std::time::Duration::from_secs(2 * 60 * 60);
    let stale_backdated = set_mtime(&stale, two_hours_ago).is_ok();
    let _ = keyhog_core::Calibration::try_load(&cache_path);

    if stale_backdated {
        assert!(
            !stale.exists(),
            "calibration load should sweep stale keyhog-owned calibration tmp files"
        );
    }
    assert!(
        fresh.exists(),
        "calibration load must not sweep fresh in-flight temp files"
    );
    assert!(
        unrelated.exists(),
        "calibration load must not sweep unrelated anonymous .tmp files"
    );
}

// ── allowlist: public surface + glob-engine decisions unchanged ─────────────

#[test]
fn allowlist_public_api_reachable_after_glob_split() {
    // parse + the public fields stay on `keyhog_core::Allowlist`.
    let al = keyhog_core::testing::CoreTestApi::allowlist_parse(
        &keyhog_core::testing::TestApi,
        "detector:demo-token\npath:**/*.md\nnode_modules/\n",
    );
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
    let al = keyhog_core::testing::CoreTestApi::allowlist_parse(
        &keyhog_core::testing::TestApi,
        "path:src/**/secret.txt\n",
    );
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
    let al = keyhog_core::testing::CoreTestApi::allowlist_parse(
        &keyhog_core::testing::TestApi,
        &format!("{hash_hex}\n"),
    );
    assert_eq!(al.credential_hashes.len(), 1);
    assert!(
        keyhog_core::testing::CoreTestApi::allowlist_is_raw_hash_ignored(
            &keyhog_core::testing::TestApi,
            &al,
            &hash_hex
        )
    );
    assert!(
        !keyhog_core::testing::CoreTestApi::allowlist_is_raw_hash_ignored(
            &keyhog_core::testing::TestApi,
            &al,
            &"b".repeat(64)
        )
    );
}

#[test]
fn allowlist_directly_mutated_paths_trigger_rebuild_after_split() {
    // The source-mismatch rebuild path (now `glob::PathGlobIndex::matches_sources()`)
    // must still fire when `ignored_paths` is mutated directly after parse.
    let mut al = keyhog_core::testing::CoreTestApi::allowlist_parse(
        &keyhog_core::testing::TestApi,
        "path:keep/**\n",
    );
    assert!(al.is_path_ignored("keep/a.txt"));
    al.ignored_paths.push("added/**".to_string());
    assert!(
        al.is_path_ignored("added/deep/b.txt"),
        "a hand-pushed pattern must be honored via the rebuild branch, not silently ignored"
    );
}
