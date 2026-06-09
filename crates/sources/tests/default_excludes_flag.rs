//! `--no-default-excludes` (the `with_default_excludes(false)` builder) must reach
//! the WALKER's built-in lock/minified/vendored filter, not only the codewalk glob
//! layer. Regression for the wiring gap where a secret committed inside
//! `package-lock.json` stayed silently excluded even with the flag set.

use keyhog_core::{Chunk, Source};
use keyhog_sources::FilesystemSource;
use std::fs;

fn scan_dir(dir: &std::path::Path, respect_default_excludes: bool) -> Vec<Chunk> {
    FilesystemSource::new(dir.to_path_buf())
        .with_default_excludes(respect_default_excludes)
        .chunks()
        .flatten()
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
