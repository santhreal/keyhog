//! `--no-default-excludes` (the `with_default_excludes(false)` builder) must reach
//! the WALKER's built-in lock/minified/vendored filter, not only the codewalk glob
//! layer. Regression for the wiring gap where a secret committed inside
//! `package-lock.json` stayed silently excluded even with the flag set.

mod support;

use keyhog_core::{Chunk, Source};
use keyhog_sources::testing::{SourceTestApi, TestApi};
use keyhog_sources::{skip_counts, FilesystemSource};
use rars::{rar15_40, ArchiveVersion, FeatureSet};
use std::fs;
use std::io::Write;
use support::archive::{
    build_seven_zip, crx_with_zip_payload, stored_zip_with_duplicate_names, tar_with_entries,
    zip_with_entries,
};
use support::split_chunk_results;

static SKIP_COUNTER_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn counter_guard() -> std::sync::MutexGuard<'static, ()> {
    SKIP_COUNTER_GUARD
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn scan_dir(dir: &std::path::Path, respect_default_excludes: bool) -> Vec<Chunk> {
    let source =
        FilesystemSource::new(dir.to_path_buf()).with_default_excludes(respect_default_excludes);
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);
    assert!(
        errors.is_empty(),
        "default-excludes fixture must not emit SourceError rows, got {errors:?}"
    );
    chunks.into_iter().cloned().collect()
}

fn body_contains(chunks: &[Chunk], needle: &str) -> bool {
    chunks.iter().any(|c| c.data.contains(needle))
}

const SENTINEL: &str = "ghp_defaultexcludesentinel0123456789ABCD";
const RAR_UNIX_REGULAR_MODE: u64 = 0o100644;
const RAR15_40_UNIX_HOST_OS: u64 = 3;

fn make_corpus() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    // Default-excluded by FILENAME (filter::is_default_excluded FILENAMES list).
    fs::write(
        dir.path().join("package-lock.json"),
        format!("{{ \"token\": \"{SENTINEL}\" }}\n"),
    )
    .unwrap();
    // Default-excluded by the `.min.` SUFFIX check.
    fs::write(
        dir.path().join("app.min.js"),
        format!("var t=\"{SENTINEL}\";\n"),
    )
    .unwrap();
    // A normal file that is NEVER excluded — the control: it must be scanned in
    // BOTH modes, proving the source actually walks the dir.
    fs::write(
        dir.path().join("config.env"),
        "API=normal_always_scanned_marker\n",
    )
    .unwrap();
    dir
}

fn write_zip_with_default_excluded_entry(path: &std::path::Path) {
    fs::write(
        path,
        zip_with_entries(&[
            (
                "package-lock.json",
                format!("{{ \"token\": \"{SENTINEL}\" }}\n").as_bytes(),
            ),
            (
                "config.env",
                b"API=archive_normal_always_scanned_marker\n".as_slice(),
            ),
        ]),
    )
    .unwrap();
}

fn zip_bytes_with_default_excluded_entry() -> Vec<u8> {
    zip_with_entries(&[
        (
            "package-lock.json",
            format!("{{ \"token\": \"{SENTINEL}\" }}\n").as_bytes(),
        ),
        (
            "config.env",
            b"API=nested_archive_normal_always_scanned_marker\n".as_slice(),
        ),
    ])
}

fn write_nested_zip_with_default_excluded_entry(path: &std::path::Path) {
    fs::write(
        path,
        zip_with_entries(&[
            ("inner.zip", &zip_bytes_with_default_excluded_entry()),
            (
                "outer.env",
                b"API=outer_archive_normal_always_scanned_marker\n".as_slice(),
            ),
        ]),
    )
    .unwrap();
}

fn write_duplicate_zip_with_default_excluded_entries(path: &std::path::Path) {
    fs::write(
        path,
        stored_zip_with_duplicate_names(&[
            (
                "package-lock.json",
                format!("{{ \"token\": \"{SENTINEL}_one\" }}\n").as_bytes(),
            ),
            (
                "package-lock.json",
                format!("{{ \"token\": \"{SENTINEL}_two\" }}\n").as_bytes(),
            ),
            (
                "config.env",
                b"API=duplicate_zip_normal_always_scanned_marker\n".as_slice(),
            ),
        ]),
    )
    .unwrap();
}

fn tar_bytes_with_default_excluded_entry() -> Vec<u8> {
    tar_with_entries(&[
        (
            "package-lock.json",
            format!("{{ \"token\": \"{SENTINEL}\" }}\n").as_bytes(),
        ),
        (
            "config.env",
            b"API=tar_normal_always_scanned_marker\n".as_slice(),
        ),
    ])
}

fn write_tar_with_default_excluded_entry(path: &std::path::Path) {
    fs::write(path, tar_bytes_with_default_excluded_entry()).unwrap();
}

fn write_nested_tar_with_default_excluded_entry(path: &std::path::Path) {
    let inner = tar_bytes_with_default_excluded_entry();
    fs::write(
        path,
        tar_with_entries(&[
            ("inner.tar", inner.as_slice()),
            (
                "outer.env",
                b"API=outer_tar_normal_always_scanned_marker\n".as_slice(),
            ),
        ]),
    )
    .unwrap();
}

fn write_tgz_with_default_excluded_entry(path: &std::path::Path) {
    let mut encoder = flate2::write::GzEncoder::new(
        fs::File::create(path).unwrap(),
        flate2::Compression::default(),
    );
    encoder
        .write_all(&tar_bytes_with_default_excluded_entry())
        .unwrap();
    encoder.finish().unwrap();
}

fn write_seven_zip_with_default_excluded_entry(path: &std::path::Path) {
    fs::write(
        path,
        build_seven_zip(&[
            (
                "package-lock.json",
                format!("{{ \"token\": \"{SENTINEL}\" }}\n").as_bytes(),
            ),
            (
                "config.env",
                b"API=seven_zip_normal_always_scanned_marker\n".as_slice(),
            ),
        ]),
    )
    .unwrap();
}

fn write_rar_with_default_excluded_entry(path: &std::path::Path) {
    let archive = rar15_40::write_stored_archive(
        &[
            rar15_40::StoredEntry {
                name: b"package-lock.json",
                data: format!("{{ \"token\": \"{SENTINEL}\" }}\n").as_bytes(),
                file_time: 0,
                file_attr: (RAR_UNIX_REGULAR_MODE as u32) << 16,
                host_os: RAR15_40_UNIX_HOST_OS as u8,
                password: None,
                file_comment: None,
            },
            rar15_40::StoredEntry {
                name: b"config.env",
                data: b"API=rar_normal_always_scanned_marker\n",
                file_time: 0,
                file_attr: (RAR_UNIX_REGULAR_MODE as u32) << 16,
                host_os: RAR15_40_UNIX_HOST_OS as u8,
                password: None,
                file_comment: None,
            },
        ],
        rar15_40::WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only()),
    )
    .expect("write RAR fixture");
    fs::write(path, archive).unwrap();
}

fn write_crx_with_default_excluded_entry(path: &std::path::Path) {
    fs::write(
        path,
        crx_with_zip_payload(&zip_with_entries(&[
            (
                "package-lock.json",
                format!("{{ \"token\": \"{SENTINEL}\" }}\n").as_bytes(),
            ),
            (
                "config.env",
                b"API=crx_normal_always_scanned_marker\n".as_slice(),
            ),
        ])),
    )
    .unwrap();
}

#[cfg(feature = "git")]
fn run_git(repo: &std::path::Path, args: &[&str]) {
    let output = std::process::Command::new("git")
        .args(args)
        .current_dir(repo)
        .output()
        .expect("run git");
    assert!(
        output.status.success(),
        "git {args:?} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(feature = "git")]
fn git_body_contains<S: keyhog_core::Source + ?Sized>(source: &S, needle: &str) -> bool {
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);
    assert!(
        errors.is_empty(),
        "git default-excludes fixture must not emit SourceError rows, got {errors:?}"
    );
    chunks.iter().any(|chunk| chunk.data.contains(needle))
}

#[test]
fn default_excludes_drop_lockfiles_then_flag_includes_them() {
    let _guard = counter_guard();
    let dir = make_corpus();

    TestApi.reset_skip_counters();
    // Default (respect = true): the lock file + min.js are excluded by the
    // source-owned process_entry filter, so the sentinel never reaches a chunk.
    // The control file is still scanned.
    let kept = scan_dir(dir.path(), true);
    assert!(
        body_contains(&kept, "normal_always_scanned_marker"),
        "control file config.env must always be scanned"
    );
    assert!(
        !body_contains(&kept, SENTINEL),
        "package-lock.json / *.min.js must be excluded by default; sentinel leaked into a chunk"
    );
    assert_eq!(
        skip_counts().excluded,
        2,
        "walked default-excluded files must be counted instead of hidden by codewalk"
    );

    // --no-default-excludes (respect = false): the previously-excluded files are
    // now scanned, so the sentinel reaches a chunk. This is the wiring the bug
    // dropped — the flag previously only touched the glob layer.
    TestApi.reset_skip_counters();
    let included = scan_dir(dir.path(), false);
    assert!(
        body_contains(&included, "normal_always_scanned_marker"),
        "control file config.env must still be scanned with the flag"
    );
    assert!(
        body_contains(&included, SENTINEL),
        "with --no-default-excludes the walker must scan package-lock.json / *.min.js"
    );
    assert_eq!(
        skip_counts().excluded,
        0,
        "--no-default-excludes must not emit default-exclude skip counts"
    );
}

#[test]
fn default_excludes_apply_to_direct_include_paths_by_relative_path() {
    let _guard = counter_guard();
    let dir = tempfile::tempdir().unwrap();
    let excluded = dir.path().join("node_modules").join("pkg");
    fs::create_dir_all(&excluded).unwrap();
    let secret = excluded.join("token.env");
    fs::write(&secret, format!("TOKEN={SENTINEL}\n")).unwrap();

    TestApi.reset_skip_counters();
    let skipped_source =
        FilesystemSource::new(dir.path().to_path_buf()).with_include_paths(vec![secret.clone()]);
    let skipped_rows: Vec<_> = skipped_source.chunks().collect();
    let (skipped_chunks, skipped_errors) = split_chunk_results(&skipped_rows);
    assert!(
        skipped_errors.is_empty(),
        "default-excluded direct include must not emit SourceError rows, got {skipped_errors:?}"
    );
    let skipped = skipped_chunks.into_iter().cloned().collect::<Vec<_>>();
    assert!(
        !body_contains(&skipped, SENTINEL),
        "source-owned default excludes must classify direct include paths by relative path"
    );
    assert_eq!(
        skip_counts().excluded,
        1,
        "direct include default-exclude skip must be surfaced through the typed counter"
    );

    TestApi.reset_skip_counters();
    let included_source = FilesystemSource::new(dir.path().to_path_buf())
        .with_include_paths(vec![secret])
        .with_default_excludes(false);
    let included_rows: Vec<_> = included_source.chunks().collect();
    let (included_chunks, included_errors) = split_chunk_results(&included_rows);
    assert!(
        included_errors.is_empty(),
        "included direct path must not emit SourceError rows, got {included_errors:?}"
    );
    let included = included_chunks.into_iter().cloned().collect::<Vec<_>>();
    assert!(
        body_contains(&included, SENTINEL),
        "--no-default-excludes must scan the direct include path"
    );
    assert_eq!(
        skip_counts().excluded,
        0,
        "disabled default excludes must not emit excluded skip events"
    );
}

#[test]
fn default_excludes_apply_to_cache_directories() {
    let _guard = counter_guard();
    let dir = tempfile::tempdir().unwrap();
    let excluded = dir.path().join(".cache");
    fs::create_dir_all(&excluded).unwrap();
    let secret = excluded.join("token.env");
    fs::write(&secret, format!("TOKEN={SENTINEL}\n")).unwrap();

    TestApi.reset_skip_counters();
    let skipped = scan_dir(dir.path(), true);
    assert!(
        !body_contains(&skipped, SENTINEL),
        ".cache directories must be source-owned default excludes, not CLI-only skips"
    );
    assert_eq!(
        skip_counts().excluded,
        1,
        "walked default-excluded directories must count skipped files instead of disappearing in codewalk"
    );

    TestApi.reset_skip_counters();
    let included = scan_dir(dir.path(), false);
    assert!(
        body_contains(&included, SENTINEL),
        "--no-default-excludes must scan .cache directories"
    );
    assert_eq!(
        skip_counts().excluded,
        0,
        "--no-default-excludes must not count the .cache file as excluded"
    );
}

#[cfg(feature = "git")]
#[test]
fn default_excludes_apply_inside_git_blob_source() {
    let _guard = counter_guard();
    let (_tmp, repo) = support::git::init_repo();
    support::git::commit(
        &repo,
        "package-lock.json",
        &format!("{{ \"token\": \"{SENTINEL}\" }}\n"),
        "add lockfile",
    );
    support::git::commit(
        &repo,
        "config.env",
        "API=git_blob_normal_always_scanned_marker\n",
        "add config",
    );

    TestApi.reset_skip_counters();
    let skipped = keyhog_sources::GitSource::new(repo.clone()).with_max_commits(5);
    assert!(
        git_body_contains(&skipped, "git_blob_normal_always_scanned_marker"),
        "control Git blob path must be scanned when git default excludes are enabled"
    );
    assert!(
        !git_body_contains(&skipped, SENTINEL),
        "default-excluded Git blob paths must not leak into chunks by default"
    );
    assert!(
        skip_counts().excluded >= 1,
        "default-excluded Git blob paths must emit excluded telemetry"
    );

    TestApi.reset_skip_counters();
    let included = keyhog_sources::GitSource::new(repo)
        .with_max_commits(5)
        .with_default_excludes(false);
    assert!(
        git_body_contains(&included, SENTINEL),
        "--no-default-excludes must scan default-excluded paths in GitSource"
    );
    assert_eq!(skip_counts().excluded, 0);
}

#[cfg(feature = "git")]
#[test]
fn default_excludes_apply_inside_git_history_source() {
    let _guard = counter_guard();
    let (_tmp, repo) = support::git::init_repo();
    support::git::commit(
        &repo,
        "package-lock.json",
        &format!("{{ \"token\": \"{SENTINEL}\" }}\n"),
        "add lockfile",
    );
    support::git::commit(
        &repo,
        "config.env",
        "API=git_history_normal_always_scanned_marker\n",
        "add config",
    );

    TestApi.reset_skip_counters();
    let skipped = keyhog_sources::GitHistorySource::new(repo.clone()).with_max_commits(5);
    assert!(
        git_body_contains(&skipped, "git_history_normal_always_scanned_marker"),
        "control Git history path must be scanned when git default excludes are enabled"
    );
    assert!(
        !git_body_contains(&skipped, SENTINEL),
        "default-excluded Git history paths must not leak into chunks by default"
    );
    assert!(
        skip_counts().excluded >= 1,
        "default-excluded Git history paths must emit excluded telemetry"
    );

    TestApi.reset_skip_counters();
    let included = keyhog_sources::GitHistorySource::new(repo)
        .with_max_commits(5)
        .with_default_excludes(false);
    assert!(
        git_body_contains(&included, SENTINEL),
        "--no-default-excludes must scan default-excluded paths in GitHistorySource"
    );
    assert_eq!(skip_counts().excluded, 0);
}

#[cfg(feature = "git")]
#[test]
fn default_excludes_apply_inside_git_diff_source() {
    let _guard = counter_guard();
    let (_tmp, repo) = support::git::init_repo();
    support::git::commit(&repo, "README.md", "base\n", "base");
    run_git(&repo, &["checkout", "-b", "feature"]);
    support::git::commit(
        &repo,
        "package-lock.json",
        &format!("{{ \"token\": \"{SENTINEL}\" }}\n"),
        "add lockfile",
    );
    support::git::commit(
        &repo,
        "config.env",
        "API=git_diff_normal_always_scanned_marker\n",
        "add config",
    );

    TestApi.reset_skip_counters();
    let skipped = keyhog_sources::GitDiffSource::new(repo.clone(), "main").with_head_ref("feature");
    assert!(
        git_body_contains(&skipped, "git_diff_normal_always_scanned_marker"),
        "control Git diff path must be scanned when git default excludes are enabled"
    );
    assert!(
        !git_body_contains(&skipped, SENTINEL),
        "default-excluded Git diff paths must not leak into chunks by default"
    );
    assert!(
        skip_counts().excluded >= 1,
        "default-excluded Git diff paths must emit excluded telemetry"
    );

    TestApi.reset_skip_counters();
    let included = keyhog_sources::GitDiffSource::new(repo, "main")
        .with_head_ref("feature")
        .with_default_excludes(false);
    assert!(
        git_body_contains(&included, SENTINEL),
        "--no-default-excludes must scan default-excluded paths in GitDiffSource"
    );
    assert_eq!(skip_counts().excluded, 0);
}

#[test]
fn default_excludes_apply_inside_zip_archives() {
    let _guard = counter_guard();
    let dir = tempfile::tempdir().unwrap();
    write_zip_with_default_excluded_entry(&dir.path().join("fixture.zip"));

    TestApi.reset_skip_counters();
    let skipped = scan_dir(dir.path(), true);
    assert!(
        body_contains(&skipped, "archive_normal_always_scanned_marker"),
        "control ZIP entry must be scanned when archive default excludes are enabled"
    );
    assert!(
        !body_contains(&skipped, SENTINEL),
        "default-excluded ZIP entries must not leak into chunks by default"
    );
    assert_eq!(
        skip_counts().excluded,
        1,
        "default-excluded ZIP entries must increment the typed excluded counter"
    );

    TestApi.reset_skip_counters();
    let included = scan_dir(dir.path(), false);
    assert!(
        body_contains(&included, "archive_normal_always_scanned_marker"),
        "control ZIP entry must still be scanned with --no-default-excludes"
    );
    assert!(
        body_contains(&included, SENTINEL),
        "--no-default-excludes must scan default-excluded entries inside ZIP archives"
    );
    assert_eq!(
        skip_counts().excluded,
        0,
        "--no-default-excludes must not count ZIP entries as default-excluded"
    );
}

#[test]
fn default_excludes_apply_inside_openpack_zip_archives() {
    let _guard = counter_guard();
    let dir = tempfile::tempdir().unwrap();
    write_zip_with_default_excluded_entry(&dir.path().join("fixture.jar"));

    TestApi.reset_skip_counters();
    let skipped = scan_dir(dir.path(), true);
    assert!(
        body_contains(&skipped, "archive_normal_always_scanned_marker"),
        "control JAR entry must be scanned when archive default excludes are enabled"
    );
    assert!(
        !body_contains(&skipped, SENTINEL),
        "default-excluded JAR entries must not leak into chunks by default"
    );
    assert_eq!(skip_counts().excluded, 1);

    TestApi.reset_skip_counters();
    let included = scan_dir(dir.path(), false);
    assert!(
        body_contains(&included, SENTINEL),
        "--no-default-excludes must scan default-excluded entries inside OpenPack ZIP archives"
    );
    assert_eq!(skip_counts().excluded, 0);
}

#[test]
fn default_excludes_apply_inside_crx_archives() {
    let _guard = counter_guard();
    let dir = tempfile::tempdir().unwrap();
    write_crx_with_default_excluded_entry(&dir.path().join("fixture.crx"));

    TestApi.reset_skip_counters();
    let skipped = scan_dir(dir.path(), true);
    assert!(
        body_contains(&skipped, "crx_normal_always_scanned_marker"),
        "control CRX entry must be scanned when archive default excludes are enabled"
    );
    assert!(
        !body_contains(&skipped, SENTINEL),
        "default-excluded CRX entries must not leak into chunks by default"
    );
    assert_eq!(skip_counts().excluded, 1);

    TestApi.reset_skip_counters();
    let included = scan_dir(dir.path(), false);
    assert!(
        body_contains(&included, SENTINEL),
        "--no-default-excludes must scan default-excluded entries inside CRX archives"
    );
    assert_eq!(skip_counts().excluded, 0);
}

#[test]
fn default_excludes_apply_inside_duplicate_zip_central_directory_archives() {
    let _guard = counter_guard();
    let dir = tempfile::tempdir().unwrap();
    write_duplicate_zip_with_default_excluded_entries(&dir.path().join("duplicate.zip"));

    TestApi.reset_skip_counters();
    let skipped = scan_dir(dir.path(), true);
    assert!(
        body_contains(&skipped, "duplicate_zip_normal_always_scanned_marker"),
        "control duplicate-ZIP entry must be scanned when archive default excludes are enabled"
    );
    assert!(
        !body_contains(&skipped, SENTINEL),
        "default-excluded duplicate-ZIP entries must not leak into chunks by default"
    );
    assert_eq!(
        skip_counts().excluded,
        2,
        "both duplicated package-lock entries must increment the typed excluded counter"
    );

    TestApi.reset_skip_counters();
    let included = scan_dir(dir.path(), false);
    assert!(
        body_contains(&included, SENTINEL),
        "--no-default-excludes must scan default-excluded entries in duplicate-ZIP mode"
    );
    assert_eq!(skip_counts().excluded, 0);
}

#[test]
fn default_excludes_apply_inside_nested_zip_archives() {
    let _guard = counter_guard();
    let dir = tempfile::tempdir().unwrap();
    write_nested_zip_with_default_excluded_entry(&dir.path().join("outer.zip"));

    TestApi.reset_skip_counters();
    let skipped = scan_dir(dir.path(), true);
    assert!(
        body_contains(&skipped, "nested_archive_normal_always_scanned_marker"),
        "control nested ZIP entry must be scanned when archive default excludes are enabled"
    );
    assert!(
        body_contains(&skipped, "outer_archive_normal_always_scanned_marker"),
        "outer ZIP control entry must still be scanned"
    );
    assert!(
        !body_contains(&skipped, SENTINEL),
        "default-excluded nested ZIP entries must not leak into chunks by default"
    );
    assert_eq!(skip_counts().excluded, 1);

    TestApi.reset_skip_counters();
    let included = scan_dir(dir.path(), false);
    assert!(
        body_contains(&included, SENTINEL),
        "--no-default-excludes must scan default-excluded entries inside nested ZIP archives"
    );
    assert_eq!(skip_counts().excluded, 0);
}

#[test]
fn default_excludes_apply_inside_raw_tar_archives() {
    let _guard = counter_guard();
    let dir = tempfile::tempdir().unwrap();
    write_tar_with_default_excluded_entry(&dir.path().join("fixture.tar"));

    TestApi.reset_skip_counters();
    let skipped = scan_dir(dir.path(), true);
    assert!(
        body_contains(&skipped, "tar_normal_always_scanned_marker"),
        "control TAR entry must be scanned when archive default excludes are enabled"
    );
    assert!(
        !body_contains(&skipped, SENTINEL),
        "default-excluded TAR entries must not leak into chunks by default"
    );
    assert_eq!(skip_counts().excluded, 1);

    TestApi.reset_skip_counters();
    let included = scan_dir(dir.path(), false);
    assert!(
        body_contains(&included, SENTINEL),
        "--no-default-excludes must scan default-excluded entries inside raw TAR archives"
    );
    assert_eq!(skip_counts().excluded, 0);
}

#[test]
fn default_excludes_apply_inside_nested_tar_archives() {
    let _guard = counter_guard();
    let dir = tempfile::tempdir().unwrap();
    write_nested_tar_with_default_excluded_entry(&dir.path().join("outer.tar"));

    TestApi.reset_skip_counters();
    let skipped = scan_dir(dir.path(), true);
    assert!(
        body_contains(&skipped, "tar_normal_always_scanned_marker"),
        "control nested TAR entry must be scanned when archive default excludes are enabled"
    );
    assert!(
        body_contains(&skipped, "outer_tar_normal_always_scanned_marker"),
        "outer TAR control entry must still be scanned"
    );
    assert!(
        !body_contains(&skipped, SENTINEL),
        "default-excluded nested TAR entries must not leak into chunks by default"
    );
    assert_eq!(skip_counts().excluded, 1);

    TestApi.reset_skip_counters();
    let included = scan_dir(dir.path(), false);
    assert!(
        body_contains(&included, SENTINEL),
        "--no-default-excludes must scan default-excluded entries inside nested TAR archives"
    );
    assert_eq!(skip_counts().excluded, 0);
}

#[test]
fn default_excludes_apply_inside_compressed_tar_archives() {
    let _guard = counter_guard();
    let dir = tempfile::tempdir().unwrap();
    write_tgz_with_default_excluded_entry(&dir.path().join("fixture.tgz"));

    TestApi.reset_skip_counters();
    let skipped = scan_dir(dir.path(), true);
    assert!(
        body_contains(&skipped, "tar_normal_always_scanned_marker"),
        "control compressed-TAR entry must be scanned when archive default excludes are enabled"
    );
    assert!(
        !body_contains(&skipped, SENTINEL),
        "default-excluded compressed-TAR entries must not leak into chunks by default"
    );
    assert_eq!(skip_counts().excluded, 1);

    TestApi.reset_skip_counters();
    let included = scan_dir(dir.path(), false);
    assert!(
        body_contains(&included, SENTINEL),
        "--no-default-excludes must scan default-excluded entries inside compressed TAR archives"
    );
    assert_eq!(skip_counts().excluded, 0);
}

#[test]
fn default_excludes_apply_inside_seven_zip_archives() {
    let _guard = counter_guard();
    let dir = tempfile::tempdir().unwrap();
    write_seven_zip_with_default_excluded_entry(&dir.path().join("fixture.7z"));

    TestApi.reset_skip_counters();
    let skipped = scan_dir(dir.path(), true);
    assert!(
        body_contains(&skipped, "seven_zip_normal_always_scanned_marker"),
        "control 7z entry must be scanned when archive default excludes are enabled"
    );
    assert!(
        !body_contains(&skipped, SENTINEL),
        "default-excluded 7z entries must not leak into chunks by default"
    );
    assert_eq!(skip_counts().excluded, 1);

    TestApi.reset_skip_counters();
    let included = scan_dir(dir.path(), false);
    assert!(
        body_contains(&included, SENTINEL),
        "--no-default-excludes must scan default-excluded entries inside 7z archives"
    );
    assert_eq!(skip_counts().excluded, 0);
}

#[test]
fn default_excludes_apply_inside_rar_archives() {
    let _guard = counter_guard();
    let dir = tempfile::tempdir().unwrap();
    write_rar_with_default_excluded_entry(&dir.path().join("fixture.rar"));

    TestApi.reset_skip_counters();
    let skipped = scan_dir(dir.path(), true);
    assert!(
        body_contains(&skipped, "rar_normal_always_scanned_marker"),
        "control RAR entry must be scanned when archive default excludes are enabled"
    );
    assert!(
        !body_contains(&skipped, SENTINEL),
        "default-excluded RAR entries must not leak into chunks by default"
    );
    assert_eq!(skip_counts().excluded, 1);

    TestApi.reset_skip_counters();
    let included = scan_dir(dir.path(), false);
    assert!(
        body_contains(&included, SENTINEL),
        "--no-default-excludes must scan default-excluded entries inside RAR archives"
    );
    assert_eq!(skip_counts().excluded, 0);
}
