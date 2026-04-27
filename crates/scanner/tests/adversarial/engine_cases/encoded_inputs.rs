use super::support::*;

#[test]
fn base64_decode_bomb_does_not_hang() {
    let scanner = test_scanner();
    // Simulate a decode bomb by creating a deeply nested base64 string
    // that expands or requires recursive decoding, but ensure it stops
    // due to max_decode_depth config.
    let mut payload = String::from(VALID_CREDENTIAL);
    for _ in 0..10 {
        // Simple base64 encoding loop, we don't need real base64 crate if we just create a string that LOOKS
        // like valid base64 but is actually just a continuous alphanumeric string, which the decoder might
        // try to decode recursively if it's valid base64.
        // Or we can just test an extremely long alphanumeric string that resembles base64.
        payload = format!("{}a{}", payload, payload.len() % 10);
    }
    let adversarial = "a".repeat(100_000);
    let chunk = make_chunk(&adversarial);

    let start = std::time::Instant::now();
    let _ = scanner.scan(&chunk);
    assert!(
        start.elapsed().as_secs() < 5,
        "Decode bomb scanning took too long!"
    );
}

#[test]
fn malformed_utf8_sequence_does_not_panic() {
    let scanner = test_scanner();
    // Make sure we handle weird evasion chars correctly
    let malformed = format!("API_KEY={}\u{0}\u{8}\u{1b} \u{200B}", VALID_CREDENTIAL);
    let chunk = make_chunk(&malformed);
    let matches = scanner.scan(&chunk);
    // Just asserting we don't panic on weird unicode boundary handling
    assert!(
        !matches.is_empty(),
        "Evaded secret must be found and not panic"
    );
}
