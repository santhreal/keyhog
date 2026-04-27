use super::support::*;

#[test]
fn utf8_bom_does_not_prevent_detection() {
    let scanner = test_scanner();
    let bom = "\u{FEFF}";
    let chunk = make_chunk(&format!("{bom}KEY={VALID_CREDENTIAL}\n"));
    let matches = scanner.scan(&chunk);
    assert!(
        !matches.is_empty(),
        "UTF-8 BOM prefix must not suppress detection"
    );
}

#[test]
fn unicode_homoglyph_does_not_evade() {
    let scanner = test_scanner();
    // The actual ASCII credential should still be found even with nearby Unicode.
    let chunk = make_chunk(&format!("# Uñiçödé comments\ntoken = {VALID_CREDENTIAL}\n"));
    let matches = scanner.scan(&chunk);
    assert!(
        !matches.is_empty(),
        "unicode context must not prevent ASCII credential detection"
    );
}

#[test]
fn scanner_is_thread_safe_under_parallel_load() {
    use std::sync::Arc;

    let scanner = Arc::new(test_scanner());
    let chunk = Arc::new(make_chunk(&format!(
        "first={VALID_CREDENTIAL}\nsecond={VALID_CREDENTIAL}\n"
    )));

    let baseline = scanner.scan(&chunk);
    assert!(
        !baseline.is_empty(),
        "baseline scan must find the credential"
    );

    let handles: Vec<_> = (0..16)
        .map(|_| {
            let scanner = Arc::clone(&scanner);
            let chunk = Arc::clone(&chunk);
            std::thread::spawn(move || scanner.scan(&chunk))
        })
        .collect();

    for handle in handles {
        let matches = handle.join().unwrap();
        assert_eq!(matches.len(), baseline.len());
        assert_eq!(matches[0].credential, baseline[0].credential);
    }
}
