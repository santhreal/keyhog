//! Entropy extraction must not turn the random-looking handle inside a prose
//! sentence into a secret. A standalone random token remains detectable; the
//! surrounding prose is the required discriminant.

mod support;

use support::contracts::{make_chunk, scanner};

#[test]
fn random_handle_inside_sentence_does_not_surface() {
    let scanner = scanner();
    let core = "IWQQo8uAXr86GkrRnqMI6GC80XjNqFSND1";
    let handle = "IWQQo8uAXr86GkrRnqMI6GC80XjNqFSND1.";
    let body =
        format!("TOKEN = \"Session opened with handle {handle} See documentation for details.\"\n");
    let matches = scanner.scan(&make_chunk(&body, "filesystem", "/repo/configs/audit.py"));
    assert!(
        !matches.iter().any(|m| {
            let credential = m.credential.as_ref();
            credential.contains(core) || core.contains(credential)
        }),
        "sentence-internal random handle must not surface: {matches:#?}"
    );
}

#[test]
fn standalone_random_secret_still_surfaces() {
    let scanner = scanner();
    let secret = "IWQQo8uAXr86GkrRnqMI6GC80XjNqFSND1";
    let body = format!("TOKEN=\"{secret}\"\n");
    let matches = scanner.scan(&make_chunk(&body, "filesystem", "/repo/configs/app.env"));
    assert!(
        matches.iter().any(|m| m.credential.as_ref() == secret),
        "standalone random secret must surface: {matches:#?}"
    );
}
