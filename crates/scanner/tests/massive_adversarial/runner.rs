//! Data-driven runner for the massive adversarial suite cases.
//!
//! Loads `tests/massive_adversarial/data.toml` and validates each assertion
//! through the production adversarial oracle scanner.

use std::path::PathBuf;

use super::oracle_support;

#[derive(Debug, serde::Deserialize)]
struct Suite {
    case: Vec<Case>,
}

#[derive(Debug, serde::Deserialize)]
struct Case {
    detector_id: String,
    suite: usize,
    assertion: Vec<Assertion>,
}

#[derive(Debug, serde::Deserialize)]
struct Assertion {
    kind: String,
    name: String,
    text: String,
    #[serde(default)]
    credential: Option<String>,
}

#[test]
fn massive_adversarial_data_driven() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let data_path = manifest.join("tests/massive_adversarial/data.toml");
    let content =
        std::fs::read_to_string(&data_path).expect("read tests/massive_adversarial/data.toml");
    let suite: Suite = toml::from_str(&content).expect("parse tests/massive_adversarial/data.toml");

    let mut total = 0usize;
    let mut failures = Vec::new();
    for case in &suite.case {
        for assertion in &case.assertion {
            total += 1;
            if let Some(failure) = assertion_failure(case, assertion) {
                failures.push(failure);
            }
        }
    }

    if !failures.is_empty() {
        let mut shown = failures.iter().take(100).cloned().collect::<Vec<_>>();
        if failures.len() > shown.len() {
            shown.push(format!(
                "... {} additional failures omitted",
                failures.len() - shown.len()
            ));
        }
        panic!(
            "massive_adversarial_data_driven failed {}/{} assertions:\n{}",
            failures.len(),
            total,
            shown.join("\n")
        );
    }

    eprintln!("massive_adversarial_data_driven ran {total} assertions");
}

fn assertion_failure(case: &Case, assertion: &Assertion) -> Option<String> {
    match assertion.kind.as_str() {
        "fires" => fires_failure(case, assertion),
        "silent" => silent_failure(case, assertion),
        _ => Some(format!(
            "{} suite {} assertion {} has unknown kind {:?}",
            case.detector_id, case.suite, assertion.name, assertion.kind
        )),
    }
}

fn fires_failure(case: &Case, assertion: &Assertion) -> Option<String> {
    let Some(credential) = assertion.credential.as_ref() else {
        return Some(format!(
            "{} suite {} assertion {} is missing credential",
            case.detector_id, case.suite, assertion.name
        ));
    };
    let matches = oracle_support::scan_text(
        &assertion.text,
        &format!("{}-positive.txt", case.detector_id),
    );
    if matches.iter().any(|m| {
        let normalized =
            keyhog_scanner::testing::unicode_hardening::normalize_homoglyphs(m.credential.as_ref());
        normalized.contains(credential)
    }) {
        return None;
    }
    Some(format!(
        "{} suite {} assertion {} must fire; credential={credential:?} all={:?}",
        case.detector_id,
        case.suite,
        assertion.name,
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref()))
            .collect::<Vec<_>>()
    ))
}

fn silent_failure(case: &Case, assertion: &Assertion) -> Option<String> {
    let matches = oracle_support::scan_text(
        &assertion.text,
        &format!("{}-near-miss.txt", case.detector_id),
    );
    let hits = oracle_support::hits_for_detector(&matches, &case.detector_id);
    if hits.is_empty() {
        return None;
    }
    Some(format!(
        "{} suite {} assertion {} must stay silent; got {:?}",
        case.detector_id,
        case.suite,
        assertion.name,
        hits.iter()
            .map(|m| m.credential.as_ref())
            .collect::<Vec<_>>()
    ))
}
