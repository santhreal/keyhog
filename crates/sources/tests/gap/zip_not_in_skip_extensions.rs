//! KH-GAP-018 (A5): `.zip` must route through the archive-unpack branch, not
//! be skipped by extension.
//!
//! 2026-05-29 dogfood: a secret in a `.zip` was silently missed while the same
//! bytes in a `.jar` were found. Root cause: there are TWO `SKIP_EXTENSIONS`
//! consts - `filesystem.rs` (consulted by the per-file READ gate, the one that
//! returns before the `ext == "zip"|"jar"|...` archive branch) and
//! `filesystem/skip_lists.rs` (consulted by the walker). The old version of
//! this test only checked `skip_lists.rs` (which correctly omits zip) and
//! passed, while the `filesystem.rs` copy still listed "zip" - so the gate
//! skipped every .zip before extraction. This test now guards BOTH consts so a
//! re-add to either file fails CI. (The duplication itself is tracked as a
//! dedup follow-up; until merged, both must agree.)

fn read(rel: &str) -> String {
    let path = format!("{}/{}", env!("CARGO_MANIFEST_DIR"), rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

#[test]
fn zip_not_in_skip_extensions() {
    // The walker's exclude list.
    let skip_lists = read("src/filesystem/skip_lists.rs");
    assert!(
        !skip_lists.contains("\"zip\""),
        "skip_lists.rs SKIP_EXTENSIONS must not list \"zip\" - the archive branch handles it"
    );
    assert!(
        skip_lists.contains("archive-unpack branch"),
        "skip_lists.rs must document zip archive routing"
    );

    // The per-file READ gate (`if SKIP_EXTENSIONS.contains(ext) { return }`)
    // runs BEFORE the `ext == \"zip\"|\"apk\"|\"ipa\"|\"crx\"|\"jar\"`
    // archive-unpack branch, so a "zip" here is the bug that hid secrets in
    // committed .zip files. `.jar`/`.apk`/`.ipa`/`.crx` are in neither list -
    // "zip" must match them (absent) so it reaches extraction identically.
    let filesystem = read("src/filesystem.rs");
    let gate = filesystem
        .split_once("const SKIP_EXTENSIONS")
        .and_then(|(_, rest)| rest.split_once("];"))
        .map(|(decl, _)| decl)
        .expect("filesystem.rs must declare SKIP_EXTENSIONS");
    assert!(
        !gate.contains("\"zip\""),
        "filesystem.rs SKIP_EXTENSIONS (the read gate at the `contains(ext)` check) must not \
         list \"zip\": it returns before the archive-unpack branch, so listing zip silently \
         skips every .zip - secrets inside are never scanned (2026-05-29 dogfood regression)."
    );
}

/// The two duplicate `SKIP_EXTENSIONS` consts (read gate in filesystem.rs,
/// walker in skip_lists.rs) MUST stay in sync until they are merged. The zip
/// recall bug happened precisely because they drifted - one listed "zip", the
/// other didn't, and each gate consulted a different copy. Asserting set
/// equality catches ANY future drift, not just zip. (Dedup-into-one is the
/// real fix; this guards the interim.)
#[test]
fn the_two_skip_extension_lists_stay_in_sync() {
    fn entries(src: &str) -> std::collections::BTreeSet<String> {
        let body = src
            .split_once("SKIP_EXTENSIONS")
            .and_then(|(_, rest)| rest.split_once("];"))
            .map(|(decl, _)| decl)
            .expect("SKIP_EXTENSIONS array");
        body.lines()
            .filter_map(|l| {
                let t = l.trim();
                (t.starts_with('"') && t.ends_with("\",")).then(|| t.trim_matches(['"', ',']).to_string())
            })
            .collect()
    }
    let fs = entries(&read("src/filesystem.rs"));
    let sl = entries(&read("src/filesystem/skip_lists.rs"));
    assert_eq!(
        fs, sl,
        "the two SKIP_EXTENSIONS consts drifted - read gate (filesystem.rs) vs walker \
         (skip_lists.rs). They must list the same extensions until merged into one const. \
         Diff: only-in-filesystem={:?} only-in-skip_lists={:?}",
        fs.difference(&sl).collect::<Vec<_>>(),
        sl.difference(&fs).collect::<Vec<_>>(),
    );
}
