//! LR2-A8 harness integration: no duplicate KH-GAP ids

#[test]
fn gap_findings_ids_unique() {
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap();
    let raw = std::fs::read_to_string(repo.join("GAP_FINDINGS.toml")).expect("registry");
    let mut ids = Vec::new();
    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix("id = ") {
            ids.push(rest.trim_matches('"').to_string());
        }
    }
    let mut sorted = ids.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(ids.len(), sorted.len(), "duplicate gap ids detected");
}
