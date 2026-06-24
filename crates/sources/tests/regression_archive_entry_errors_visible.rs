fn source(path: &str) -> String {
    std::fs::read_to_string(format!("{}/{}", env!("CARGO_MANIFEST_DIR"), path))
        .unwrap_or_else(|error| panic!("{path} must be readable: {error}"))
}

#[test]
fn zip_entry_read_failures_emit_source_errors() {
    let zip = source("src/filesystem/extract/archive/zip_scan.rs");
    let duplicate_zip = source("src/filesystem/extract/archive/zip_scan/duplicates.rs");

    assert!(
        zip.contains("failed to scan ZIP entry"),
        "ZIP entry read failures must emit machine-visible SourceError rows"
    );
    assert!(
        zip.contains("cannot read entry ({error}); entry was not scanned"),
        "ZIP entry errors must explain that one archive entry was unscanned"
    );
    assert!(
        duplicate_zip.contains("failed to scan duplicate ZIP entry"),
        "duplicate ZIP entry read/rebuild failures must emit machine-visible SourceError rows"
    );
}

#[test]
fn seven_zip_entry_read_failures_emit_source_errors() {
    let seven_zip = source("src/filesystem/extract/seven_zip.rs");

    assert!(
        seven_zip.contains("failed to scan 7z entry"),
        "7z entry read failures must emit machine-visible SourceError rows"
    );
    assert!(
        seven_zip.contains("return Ok(false);"),
        "7z entry error emission must respect consumer backpressure"
    );
}

#[test]
fn rar_entry_read_failures_emit_source_errors() {
    let rar = source("src/filesystem/extract/rar.rs");

    assert!(
        rar.contains("failed to scan RAR entry"),
        "RAR entry read failures must emit machine-visible SourceError rows"
    );
    assert!(
        rar.contains("{reason}; entry was not scanned"),
        "unsupported encrypted/split RAR entries must emit machine-visible SourceError rows"
    );
    assert!(
        rar.contains("self.consumer_stopped = !emit(Err(SourceError::Other(format!("),
        "RAR entry error emission must respect consumer backpressure"
    );
}
