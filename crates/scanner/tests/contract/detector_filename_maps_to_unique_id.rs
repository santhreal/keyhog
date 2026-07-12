//! Contract: each detector TOML filename maps to exactly one loaded id.

use crate::support::paths::detector_dir;
use std::collections::BTreeMap;
use std::path::PathBuf;

fn parse_id(path: &PathBuf) -> String {
    let text = std::fs::read_to_string(path).expect("read detector toml");
    for line in text.lines() {
        if let Some(rest) = line.trim().strip_prefix("id = \"") {
            if let Some(id) = rest.strip_suffix('"') {
                return id.to_string();
            }
        }
    }
    path.file_stem().unwrap().to_string_lossy().into_owned()
}

#[test]
fn detector_filename_maps_to_unique_id() {
    let mut by_id: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for entry in std::fs::read_dir(detector_dir()).expect("detectors dir") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|s| s.to_str()) != Some("toml") {
            continue;
        }
        let id = parse_id(&path);
        by_id
            .entry(id)
            .or_default()
            .push(path.file_name().unwrap().to_string_lossy().into_owned());
    }

    let dupes: Vec<_> = by_id
        .iter()
        .filter(|(_, files)| files.len() > 1)
        .map(|(id, files)| format!("{id} ← {:?}", files))
        .collect();

    assert!(
        dupes.is_empty(),
        "multiple detector files share the same id: {:?}",
        dupes
    );
}
