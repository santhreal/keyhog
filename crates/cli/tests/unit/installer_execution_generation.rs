use super::*;
use keyhog_scanner::execution_pack::ExecutionPackSigningKey;

fn write(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).expect("write test fixture");
}

#[test]
fn signing_key_creation_is_exact_stable_and_private() {
    let root = tempfile::tempdir().expect("temporary cache root");
    let path = root.path().join("signing.key");

    assert!(ensure_signing_key(&path).expect("create signing key"));
    let first = fs::read(&path).expect("read created signing key");
    assert_eq!(first.len(), 32);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&path)
                .expect("key metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    assert!(!ensure_signing_key(&path).expect("reuse signing key"));
    assert_eq!(fs::read(&path).expect("read reused signing key"), first);
}

#[test]
fn signing_key_rejects_wrong_length_and_symlinks() {
    let root = tempfile::tempdir().expect("temporary cache root");
    let short = root.path().join("short.key");
    write(&short, &[7; 31]);
    let error = ensure_signing_key(&short).expect_err("short key must fail");
    assert!(error.to_string().contains("exactly 32 bytes"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let real = root.path().join("real.key");
        let link = root.path().join("link.key");
        write(&real, &[9; 32]);
        symlink(&real, &link).expect("create key symlink");
        let error = ensure_signing_key(&link).expect_err("key symlink must fail");
        assert!(error.to_string().contains("must be a regular file"));
    }
}

#[test]
fn uncommitted_generation_restores_every_previous_artifact() {
    let root = tempfile::tempdir().expect("temporary cache root");
    let stage = tempfile::tempdir_in(root.path()).expect("transaction stage");
    let current_packs = root.path().join("current");
    let current_cache = root.path().join("autoroute.json");
    let old_packs = stage.path().join("previous-packs");
    let old_cache = stage.path().join("previous-autoroute.json");
    let signing_key = root.path().join("signing.key");

    fs::create_dir(&current_packs).expect("new packs");
    fs::create_dir(&old_packs).expect("old packs");
    write(&current_packs.join("generation"), b"new");
    write(&old_packs.join("generation"), b"old");
    write(&current_cache, b"new-cache");
    write(&old_cache, b"old-cache");
    write(&signing_key, &[3; 32]);

    drop(ExecutionGenerationInstallTransaction {
        current_packs: current_packs.clone(),
        current_cache: current_cache.clone(),
        old_packs,
        old_cache,
        _stage: Some(stage),
        packs_published: true,
        cache_published: true,
        had_old_packs: true,
        had_old_cache: true,
        created_signing_key: Some(signing_key.clone()),
        committed: false,
    });

    assert_eq!(
        fs::read(current_packs.join("generation")).expect("restored packs"),
        b"old"
    );
    assert_eq!(
        fs::read(&current_cache).expect("restored cache"),
        b"old-cache"
    );
    assert!(!signing_key.exists(), "an uncommitted key must be removed");
}

#[test]
fn committed_generation_retains_published_artifacts() {
    let root = tempfile::tempdir().expect("temporary cache root");
    let stage = tempfile::tempdir_in(root.path()).expect("transaction stage");
    let current_packs = root.path().join("current");
    let current_cache = root.path().join("autoroute.json");
    let signing_key = root.path().join("signing.key");
    fs::create_dir(&current_packs).expect("published packs");
    write(&current_packs.join("generation"), b"new");
    write(&current_cache, b"new-cache");
    write(&signing_key, &[5; 32]);

    ExecutionGenerationInstallTransaction {
        current_packs: current_packs.clone(),
        current_cache: current_cache.clone(),
        old_packs: stage.path().join("previous-packs"),
        old_cache: stage.path().join("previous-autoroute.json"),
        _stage: Some(stage),
        packs_published: true,
        cache_published: true,
        had_old_packs: false,
        had_old_cache: false,
        created_signing_key: Some(signing_key.clone()),
        committed: false,
    }
    .commit();

    assert_eq!(
        fs::read(current_packs.join("generation")).expect("published packs"),
        b"new"
    );
    assert_eq!(
        fs::read(&current_cache).expect("published cache"),
        b"new-cache"
    );
    assert_eq!(fs::read(&signing_key).expect("published key"), vec![5; 32]);
}
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn signing_key_debug_formatting_does_not_leak_key_bytes() {
    let raw_key = [0xab; 32];
    let key = ExecutionPackSigningKey::from_bytes(raw_key).expect("valid signing key");
    let debug_str = format!("{key:?}");
    assert!(
        !debug_str.contains(&hex_encode(&raw_key)),
        "debug output must not leak secret key bytes"
    );
    assert_eq!(
        debug_str,
        format!(
            "ExecutionPackSigningKey {{ key_id: {:?}, .. }}",
            hex_encode(&key.key_id())
        ),
        "debug output must match expected key_id formatting"
    );
}

/// WHY: deterministic test keys cannot detect an installer that accidentally persists one shared key across independent cache roots.
#[test]
fn independent_installations_have_isolated_signing_keys() {
    let root_a = tempfile::tempdir().expect("installation A cache root");
    let root_b = tempfile::tempdir().expect("installation B cache root");
    let path_a = root_a.path().join("signing.key");
    let path_b = root_b.path().join("signing.key");

    assert!(ensure_signing_key(&path_a).expect("create installation A key"));
    assert!(ensure_signing_key(&path_b).expect("create installation B key"));

    let raw_a: [u8; 32] = fs::read(&path_a)
        .expect("read installation A key")
        .try_into()
        .expect("installation A key length");
    let raw_b: [u8; 32] = fs::read(&path_b)
        .expect("read installation B key")
        .try_into()
        .expect("installation B key length");
    assert_ne!(
        raw_a, raw_b,
        "independent installations must not share keys"
    );

    let key_a = ExecutionPackSigningKey::from_bytes(raw_a).expect("installation A key");
    let key_b = ExecutionPackSigningKey::from_bytes(raw_b).expect("installation B key");
    assert_ne!(
        key_a.key_id(),
        key_b.key_id(),
        "independent installation key IDs must differ"
    );
}
