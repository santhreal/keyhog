//! KH-GAP-018 (A5): `.zip` must route through the archive-unpack branch, not
//! be skipped by extension.
//!
//! 2026-05-29 dogfood: a secret in a `.zip` was silently missed while the same
//! bytes in a `.jar` were found. The read gate and walker now share the single
//! `filesystem/filter.rs` extension list; this test prevents reintroducing
//! `zip` to that denylist, which would bypass the archive extraction branch.

fn read(rel: &str) -> String {
    let path = format!("{}/{}", env!("CARGO_MANIFEST_DIR"), rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

#[test]
fn zip_not_in_skip_extensions() {
    // The per-file READ gate (`if skip_extensions().contains(ext) { return }`)
    // runs BEFORE the `ext == \"zip\"|\"apk\"|\"ipa\"|\"crx\"|\"jar\"`
    // archive-unpack branch, so a "zip" here is the bug that hid secrets in
    // committed .zip files. `.jar`/`.apk`/`.ipa`/`.crx` are in neither list -
    // "zip" must match them (absent) so it reaches extraction identically.
    let filter = read("src/filesystem/filter.rs");
    let gate = filter
        .split_once("const SKIP_EXTENSIONS")
        .and_then(|(_, rest)| rest.split_once("];"))
        .map(|(decl, _)| decl)
        .expect("filesystem/filter.rs must declare SKIP_EXTENSIONS");
    assert!(
        !gate.contains("\"zip\""),
        "filesystem/filter.rs SKIP_EXTENSIONS (the read gate at the `contains(ext)` check) must not \
         list \"zip\": it returns before the archive-unpack branch, so listing zip silently \
         skips every .zip - secrets inside are never scanned (2026-05-29 dogfood regression)."
    );
    assert!(
        filter.contains("archive-unpack branch"),
        "filesystem/filter.rs must document zip archive routing"
    );
}
