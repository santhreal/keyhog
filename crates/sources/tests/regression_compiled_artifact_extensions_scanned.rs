//! #121 capability: compiled / published package artifacts that are ZIP
//! containers (Python wheels, Java WAR/EAR, Android AAR, NuGet, browser/editor
//! extensions, Python eggs) must be UNPACKED and their entries scanned, not read
//! as opaque binary.
//!
//! `OPENPACK_EXTS` already routed `.zip`/`.jar`/`.apk`/`.ipa`/`.crx` (+ OOXML/ODF)
//! to the archive extractor, but `.whl`/`.war`/`.ear`/`.aar`/`.nupkg`/`.snupkg`/
//! `.egg`/`.xpi`/`.vsix` fell through to the general read path — so a credential
//! baked into a DEFLATE-compressed entry (a `application.properties` in a WAR, a
//! config in a wheel, `appsettings.json` in a NuGet package) was never reached.
//! Adding those extensions routes them through `OpenPack::open`.
//!
//! The proof each format is unpacked: a `source_type == "filesystem/archive"`
//! chunk whose path is `<artifact>//<entry>`. That source_type is emitted ONLY by
//! the archive extractor — a raw-binary read of the same `.whl` would tag the
//! chunk `filesystem/binary`/`...windowed`, never `filesystem/archive`. So the
//! assertion is a definitive lock on the routing, independent of whether the entry
//! happened to be STORED or compressed.

#![cfg(unix)]

mod support;

use keyhog_core::Source;
use keyhog_sources::FilesystemSource;
use support::archive::zip_with_entries;
use support::split_chunk_results;

const SECRET: &str = "KEYHOG_ARTIFACT_SENTINEL_8f2a91xc";
const ENTRY: &str = "config/app.properties";

/// A STORED zip carrying one text entry with the sentinel secret.
fn secret_zip(entry: &str) -> Vec<u8> {
    let body = format!("api_key={SECRET}\nendpoint=https://api.example.com\n");
    zip_with_entries(&[(entry, body.as_bytes())])
}

/// Write `bytes` to `pkg.<ext>` in a fresh tempdir and scan that dir; returns the
/// owned (chunks, errors) split so callers can assert without borrow gymnastics.
fn scan_named(ext: &str, bytes: &[u8]) -> (tempfile::TempDir, Vec<keyhog_core::Chunk>, Vec<String>) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(format!("pkg.{ext}")), bytes).unwrap();
    let source = FilesystemSource::new(dir.path().to_path_buf());
    let rows: Vec<_> = source.chunks().collect();
    let (chunk_refs, err_refs) = split_chunk_results(&rows);
    let chunks = chunk_refs.into_iter().cloned().collect();
    let errors = err_refs.into_iter().map(|e| e.to_string()).collect();
    (dir, chunks, errors)
}

/// Assert `pkg.<ext>` (a real zip with the sentinel) is unpacked: a
/// `filesystem/archive` chunk whose path is `<artifact>//<entry>` carries it.
fn assert_artifact_unpacked(ext: &str) {
    let (_dir, chunks, errors) = scan_named(ext, &secret_zip(ENTRY));
    assert!(errors.is_empty(), ".{ext} artifact must not emit errors; got {errors:?}");
    let archive_chunk = chunks
        .iter()
        .find(|c| c.metadata.source_type == "filesystem/archive")
        .unwrap_or_else(|| {
            panic!(
                ".{ext} must be UNPACKED (a filesystem/archive chunk); got source_types {:?}",
                chunks.iter().map(|c| c.metadata.source_type.as_str()).collect::<Vec<_>>()
            )
        });
    assert!(
        archive_chunk.data.contains(SECRET),
        ".{ext} unpacked entry must carry the embedded secret"
    );
    assert!(
        archive_chunk
            .metadata
            .path
            .as_deref()
            .is_some_and(|p| p.contains(&format!(".{ext}//{ENTRY}"))),
        ".{ext} chunk path must be <artifact>//<entry>; got {:?}",
        archive_chunk.metadata.path
    );
}

// ── one routing lock per newly-supported format ─────────────────────────────

#[test]
fn python_wheel_whl_is_unpacked_and_scanned() {
    assert_artifact_unpacked("whl");
}
#[test]
fn java_war_is_unpacked_and_scanned() {
    assert_artifact_unpacked("war");
}
#[test]
fn java_ear_is_unpacked_and_scanned() {
    assert_artifact_unpacked("ear");
}
#[test]
fn android_aar_is_unpacked_and_scanned() {
    assert_artifact_unpacked("aar");
}
#[test]
fn nuget_nupkg_is_unpacked_and_scanned() {
    assert_artifact_unpacked("nupkg");
}
#[test]
fn nuget_snupkg_is_unpacked_and_scanned() {
    assert_artifact_unpacked("snupkg");
}
#[test]
fn python_egg_is_unpacked_and_scanned() {
    assert_artifact_unpacked("egg");
}
#[test]
fn firefox_xpi_is_unpacked_and_scanned() {
    assert_artifact_unpacked("xpi");
}
#[test]
fn vscode_vsix_is_unpacked_and_scanned() {
    assert_artifact_unpacked("vsix");
}

// ── existing formats must keep working (no regression from the list change) ──

#[test]
fn jar_still_unpacked_after_adding_artifact_exts() {
    assert_artifact_unpacked("jar");
}
#[test]
fn apk_still_unpacked_after_adding_artifact_exts() {
    assert_artifact_unpacked("apk");
}
#[test]
fn plain_zip_still_unpacked() {
    assert_artifact_unpacked("zip");
}

// ── structural / boundary aspects ───────────────────────────────────────────

#[test]
fn artifact_extension_match_is_case_insensitive() {
    // is_openpack_archive_ext folds case, so an uppercase `.WHL` must route too.
    let (_dir, chunks, _errors) = scan_named("WHL", &secret_zip(ENTRY));
    assert!(
        chunks.iter().any(|c| c.metadata.source_type == "filesystem/archive"
            && c.data.contains(SECRET)),
        "an uppercase .WHL extension must still route to the archive extractor"
    );
}

#[test]
fn whl_chunk_path_uses_archive_double_slash_separator() {
    let (_dir, chunks, _errors) = scan_named("whl", &secret_zip("META-INF/MANIFEST.MF"));
    let chunk = chunks
        .iter()
        .find(|c| c.metadata.source_type == "filesystem/archive")
        .expect("whl unpacked");
    assert!(
        chunk
            .metadata
            .path
            .as_deref()
            .is_some_and(|p| p.contains(".whl//META-INF/MANIFEST.MF")),
        "the entry path must join archive and entry with `//`; got {:?}",
        chunk.metadata.path
    );
}

#[test]
fn war_with_multiple_entries_all_surface() {
    let secret2 = "KEYHOG_WAR_SECOND_SENTINEL_b71d";
    let zip = zip_with_entries(&[
        ("WEB-INF/web.xml", format!("<db-pass>{SECRET}</db-pass>").as_bytes()),
        (
            "WEB-INF/classes/application.properties",
            format!("token={secret2}").as_bytes(),
        ),
    ]);
    let (_dir, chunks, _errors) = scan_named("war", &zip);
    let archive: String = chunks
        .iter()
        .filter(|c| c.metadata.source_type == "filesystem/archive")
        .map(|c| c.data.to_string())
        .collect();
    assert!(archive.contains(SECRET), "first WAR entry secret must surface");
    assert!(archive.contains(secret2), "second WAR entry secret must surface");
}

#[test]
fn deeply_nested_war_entry_path_surfaces() {
    let entry = "WEB-INF/classes/com/example/app/config.properties";
    let (_dir, chunks, _errors) = scan_named("war", &secret_zip(entry));
    let chunk = chunks
        .iter()
        .find(|c| c.metadata.source_type == "filesystem/archive")
        .expect("war unpacked");
    assert!(chunk.data.contains(SECRET));
    assert!(
        chunk.metadata.path.as_deref().is_some_and(|p| p.contains(entry)),
        "a deep entry path must be preserved; got {:?}",
        chunk.metadata.path
    );
}

#[test]
fn whl_secret_is_archive_chunk_not_raw_binary() {
    // The secret must arrive on a filesystem/archive chunk — NOT on a
    // binary/windowed chunk, which is what a non-unpacked read would produce.
    let (_dir, chunks, _errors) = scan_named("whl", &secret_zip(ENTRY));
    let carriers: Vec<&str> = chunks
        .iter()
        .filter(|c| c.data.contains(SECRET))
        .map(|c| c.metadata.source_type.as_str())
        .collect();
    assert!(!carriers.is_empty(), "the secret must be found at all");
    assert!(
        carriers.iter().all(|st| *st == "filesystem/archive"),
        "the secret must arrive via unpacking (filesystem/archive), not a raw read; got {carriers:?}"
    );
}

#[test]
fn binary_entry_in_whl_surfaces_as_archive_binary() {
    // A non-text (binary) entry with an embedded printable run is still scanned —
    // as a `filesystem/archive-binary` chunk via printable-strings extraction.
    let mut body = vec![0x00u8, 0x01, 0x02, 0xff];
    body.extend_from_slice(format!("embedded_{SECRET}_run").as_bytes());
    body.extend_from_slice(&[0x00, 0x00, 0x03]);
    let zip = zip_with_entries(&[("native/lib.so", &body)]);
    let (_dir, chunks, _errors) = scan_named("whl", &zip);
    assert!(
        chunks.iter().any(|c| c.metadata.source_type == "filesystem/archive-binary"
            && c.data.contains(SECRET)),
        "a binary entry's printable secret must surface as filesystem/archive-binary; \
         got source_types {:?}",
        chunks.iter().map(|c| c.metadata.source_type.as_str()).collect::<Vec<_>>()
    );
}

#[test]
fn realistic_nupkg_appsettings_secret_surfaces() {
    let entry = "content/appsettings.json";
    let body = format!(r#"{{"ConnectionStrings":{{"Db":"Password={SECRET};"}}}}"#);
    let zip = zip_with_entries(&[(entry, body.as_bytes())]);
    let (_dir, chunks, _errors) = scan_named("nupkg", &zip);
    assert!(
        chunks.iter().any(|c| c.metadata.source_type == "filesystem/archive"
            && c.data.contains(SECRET)),
        "a NuGet appsettings.json secret must surface from the unpacked package"
    );
}

// ── negatives: a non-zip with an artifact extension must not crash or fake an
//    archive chunk ──────────────────────────────────────────────────────────

#[test]
fn non_zip_named_whl_produces_no_archive_chunk() {
    // Random non-zip bytes (no zip local-file-header) named `.whl`: OpenPack::open
    // fails, so there must be NO filesystem/archive chunk — and no panic.
    let junk: Vec<u8> = (0u8..=255).cycle().take(2048).collect();
    let (_dir, chunks, _errors) = scan_named("whl", &junk);
    assert!(
        chunks.iter().all(|c| c.metadata.source_type != "filesystem/archive"),
        "a non-zip .whl must not yield a filesystem/archive chunk; got {:?}",
        chunks.iter().map(|c| c.metadata.source_type.as_str()).collect::<Vec<_>>()
    );
}

#[test]
fn non_zip_named_whl_does_not_panic_and_completes() {
    // The scan must terminate (collect returns) on a malformed artifact — the
    // assertion is simply that we reach this line.
    let junk = b"this is not a zip file at all, just plain text masquerading as a wheel";
    let (_dir, _chunks, _errors) = scan_named("whl", junk);
}

#[test]
fn empty_text_named_whl_yields_no_archive_chunk() {
    let (_dir, chunks, _errors) = scan_named("whl", b"");
    assert!(
        chunks.iter().all(|c| c.metadata.source_type != "filesystem/archive"),
        "an empty .whl is not a valid zip and must not produce an archive chunk"
    );
}
