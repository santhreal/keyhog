use keyhog_scanner::compiler_prefix::{extract_literal_prefixes, extract_inner_literals};
use std::collections::HashSet;

#[test]
fn analyze_keyword_only_detectors() {
    let mut results = Vec::new();
    let generic: HashSet<String> = ["id", "key", "token"]
        .iter()
        .map(|s| s.to_lowercase())
        .collect();

    let entries = std::fs::read_dir("detectors").unwrap();
    for entry in entries {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("toml") {
            continue;
        }
        let content = std::fs::read_to_string(&path).unwrap();
        let detector: keyhog_core::DetectorSpec = match toml::from_str(&content) {
            Ok(d) => d,
            Err(_) => continue,
        };

        let all_keyword_only = detector.patterns.iter().all(|p| {
            extract_literal_prefixes(&p.regex).is_empty() && extract_inner_literals(&p.regex).is_empty()
        });

        if !all_keyword_only {
            continue;
        }

        let kws: Vec<&str> = detector.keywords.iter().map(|s| s.as_str()).collect();
        if kws.is_empty() {
            continue;
        }

        let all_short = kws.iter().all(|kw| kw.len() < 4);
        let all_generic = kws.iter().all(|kw| generic.contains(kw.to_lowercase().as_str()));

        if all_short {
            results.push((detector.id.clone(), "too short".to_string()));
        } else if all_generic {
            results.push((detector.id.clone(), "too generic".to_string()));
        }
    }

    results.sort_by(|a, b| a.0.cmp(&b.0));

    for (id, issue) in &results {
        assert!(!id.is_empty(), "flagged detector must have an id");
        assert!(
            issue == "too short" || issue == "too generic",
            "unknown issue class for {id}: {issue}"
        );
    }

    assert!(
        results.len() <= 500,
        "{} keyword-only detectors flagged as too-short or too-generic (cap 500 — \
         add literal anchors or tighten keywords)",
        results.len()
    );
}
