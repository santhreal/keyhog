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
    let hit = matches
        .iter()
        .find(|m| m.credential.as_ref() == VALID_CREDENTIAL)
        .expect("secret at chunk end must be detected with the exact credential bytes");
    assert!(
        hit.location.offset >= filler.len(),
        "match offset must land past the {}-byte filler (got offset={})",
        filler.len(),
        hit.location.offset
    );
}

#[test]
fn secret_in_large_chunk_is_detected_via_windowing() {
    let scanner = test_scanner();
    // Place secret deep in a large file to exercise windowed scanning.
    let filler = "harmless data line\n".repeat(60_000);
    let body = format!("{filler}API_KEY={VALID_CREDENTIAL}\n");
    let chunk = make_chunk(&body);
    let matches = scanner.scan(&chunk);
    let hit = matches
        .iter()
        .find(|m| m.credential.as_ref() == VALID_CREDENTIAL)
        .expect("secret in large chunk (>1MB) must surface with exact credential bytes - \
                 a non-empty matches vector is not enough (could be a different rule firing on filler)");
    // MatchLocation.offset is the line-start where the credential lives
    // (the engine anchors at the keyword line, not the credential byte).
    // Anything past filler.len() proves the windowed scan reached the
    // post-filler region; equality nails it to the exact line.
    assert_eq!(
        hit.location.offset,
        filler.len(),
        "match must anchor at the line containing API_KEY= (filler.len()={}), \
         not at any cross-window seam - actual offset {}",
        filler.len(),
        hit.location.offset
    );
}
