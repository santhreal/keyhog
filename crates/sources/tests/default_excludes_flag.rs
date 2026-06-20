//! `--no-default-excludes` (the `with_default_excludes(false)` builder) must reach
//! the WALKER's built-in lock/minified/vendored filter, not only the codewalk glob
//! layer. Regression for the wiring gap where a secret committed inside
//! `package-lock.json` stayed silently excluded even with the flag set.

mod support;

use keyhog_core::Chunk;
use keyhog_sources::testing::{SourceTestApi, TestApi};
use keyhog_sources::{skip_counts, FilesystemSource};
use std::fs;
use support::collect_chunks;

static SKIP_COUNTER_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn scan_dir(dir: &std::path::Path, respect_default_excludes: bool) -> Vec<Chunk> {
    collect_chunks(
        &FilesystemSource::new(dir.to_path_buf()).with_default_excludes(respect_default_excludes),
    )
    .into_iter()
    .collect()
}

fn body_contains(chunks: &[Chunk], needle: &str) -> bool {
    chunks.iter().any(|c| c.data.contains(needle))
}

const SENTINEL: &str = "ghp_defaultexcludesentinel0123456789ABCD";

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

#[test]
fn default_excludes_drop_lockfiles_then_flag_includes_them() {
    let dir = make_corpus();

    // Default (respect = true): the lock file + min.js are excluded by the walker,
    // so the sentinel never reaches a chunk. The control file is still scanned.
    let kept = scan_dir(dir.path(), true);
    assert!(
        body_contains(&kept, "normal_always_scanned_marker"),
        "control file config.env must always be scanned"
    );
    assert!(
        !body_contains(&kept, SENTINEL),
        "package-lock.json / *.min.js must be excluded by default; sentinel leaked into a chunk"
    );

    // --no-default-excludes (respect = false): the previously-excluded files are
    // now scanned, so the sentinel reaches a chunk. This is the wiring the bug
    // dropped — the flag previously only touched the glob layer.
    let included = scan_dir(dir.path(), false);
    assert!(
        body_contains(&included, "normal_always_scanned_marker"),
        "control file config.env must still be scanned with the flag"
    );
    assert!(
        body_contains(&included, SENTINEL),
        "with --no-default-excludes the walker must scan package-lock.json / *.min.js"
    );
}

#[test]
fn default_excludes_apply_to_direct_include_paths_by_relative_path() {
    let _guard = SKIP_COUNTER_GUARD.lock().expect("counter guard");
    let dir = tempfile::tempdir().unwrap();
    let excluded = dir.path().join("node_modules").join("pkg");
    fs::create_dir_all(&excluded).unwrap();
    let secret = excluded.join("token.env");
    fs::write(&secret, format!("TOKEN={SENTINEL}\n")).unwrap();

    TestApi.reset_skip_counters();
    let skipped = collect_chunks(
        &FilesystemSource::new(dir.path().to_path_buf()).with_include_paths(vec![secret.clone()]),
    )
    .into_iter()
    .collect::<Vec<_>>();
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
    let included = collect_chunks(
        &FilesystemSource::new(dir.path().to_path_buf())
            .with_include_paths(vec![secret])
            .with_default_excludes(false),
    )
    .into_iter()
    .collect::<Vec<_>>();
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
