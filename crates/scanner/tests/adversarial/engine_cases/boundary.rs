use super::support::*;

#[test]
fn secret_at_start_of_chunk_is_detected() {
    let scanner = test_scanner();
    let chunk = make_chunk(&format!("{VALID_CREDENTIAL}\nsome other content\n"));
    let matches = scanner.scan(&chunk);
    assert!(
        !matches.is_empty(),
        "secret at chunk start must be detected"
    );
    assert_eq!(matches[0].credential.as_ref(), VALID_CREDENTIAL);
}

#[test]
fn secret_at_end_of_chunk_is_detected() {
    let scanner = test_scanner();
    let filler = "x".repeat(500);
    let chunk = make_chunk(&format!("{filler}\n{VALID_CREDENTIAL}"));
    let matches = scanner.scan(&chunk);
    assert!(!matches.is_empty(), "secret at chunk end must be detected");
}

#[test]
fn secret_in_large_chunk_is_detected_via_windowing() {
    let scanner = test_scanner();
    // Place secret deep in a large file to exercise windowed scanning.
    let filler = "harmless data line\n".repeat(60_000);
    let chunk = make_chunk(&format!("{filler}API_KEY={VALID_CREDENTIAL}\n"));
    let matches = scanner.scan(&chunk);
    assert!(
        !matches.is_empty(),
        "secret in large chunk (>1MB) must be detected via window splitting"
    );
}
