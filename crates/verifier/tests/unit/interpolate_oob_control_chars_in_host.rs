use keyhog_verifier::interpolate::{companions_with_oob, interpolate};
use std::collections::HashMap;

#[test]
fn interpolate_oob_control_chars_in_host() {
    // A hostile --oob-server carrying control characters must have them
    // stripped at the sanitization boundary, preventing injection into
    // headers (where CR/LF would split them), JSON bodies, or URLs.
    let hostile_host = "evil.com\u{001B}[31mRED\u{000D}\u{000A}X-Injected: true";
    let comps = companions_with_oob(
        &HashMap::new(),
        hostile_host,
        &format!("https://{hostile_host}"),
        "abc123",
    );

    let header = interpolate("Authorization: Bearer {{interactsh}}", "cred", &comps);

    // No CR/LF from the hostile host survives
    assert!(!header.contains('\r'), "CR leaked into header: {header}");
    assert!(!header.contains('\n'), "LF leaked into header: {header}");

    // No ESC or control bytes survive
    assert!(!header.contains('\u{001B}'), "ESC byte leaked: {header}");

    // The template's own structure is intact
    assert!(
        header.starts_with("Authorization: Bearer"),
        "header prefix mangled: {header}"
    );
}
