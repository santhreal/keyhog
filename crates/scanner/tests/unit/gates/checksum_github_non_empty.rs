//! Gate `checksum::github`: substantive source, no todo!/unimplemented! in prod paths.

#[test]
fn checksum_github_non_empty() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/checksum/github.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        src.trim().len() >= 20,
        "checksum::github: expected substantive source, got {} trimmed bytes",
        src.trim().len()
    );
    let prod = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !prod.contains("todo!()") && !prod.contains("unimplemented!()"),
        "checksum::github: todo!/unimplemented! forbidden in non-test source"
    );
    assert!(
        prod.contains("fn split_fine_grained_payload("),
        "checksum::github: fine-grained PAT segment parsing must have one owner"
    );
    assert!(
        !prod.contains("Vec<&str>") && !prod.contains(".split('_').collect()"),
        "checksum::github: fine-grained PAT validation must not allocate split segments"
    );
}
