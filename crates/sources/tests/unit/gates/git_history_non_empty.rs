//! Gate `git::history`: substantive source, no todo!/unimplemented! in prod paths.

#[test]
fn git_history_non_empty() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/git/history.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        src.trim().len() >= 20,
        "git::history: expected substantive source, got {} trimmed bytes",
        src.trim().len()
    );
    let prod = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !prod.contains("todo!()") && !prod.contains("unimplemented!()"),
        "git::history: todo!/unimplemented! forbidden in non-test source"
    );
}
