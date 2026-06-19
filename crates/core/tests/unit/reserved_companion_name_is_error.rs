//! Migrated from `src/spec/validate.rs` inline tests.
use keyhog_core::{validate_detector, QualityIssue};

fn errors_for(toml_src: &str) -> Vec<String> {
    let detectors = keyhog_core::testing::CoreTestApi::load_detectors_from_str(
        &keyhog_core::testing::TestApi,
        toml_src,
    )
    .expect("toml parses");
    let mut errs = Vec::new();
    for d in &detectors {
        for issue in validate_detector(d) {
            if let QualityIssue::Error(msg) = issue {
                errs.push(msg);
            }
        }
    }
    errs
}

#[test]
fn reserved_companion_name_is_error() {
    let toml_src = r#"
[detector]
id = "reserved-name"
name = "Reserved name collision"
service = "github"
severity = "high"
keywords = ["GHTOKEN"]

[[detector.patterns]]
regex = "GHTOKEN_[A-Z0-9]{16}"

[[detector.companions]]
name = "__keyhog_oob_url"
regex = "(?:URL=)([a-z]{4,})"
within_lines = 5
"#;
    let errs = errors_for(toml_src);
    assert!(
        errs.iter()
            .any(|e| e.contains("__keyhog_oob_url") && e.contains("reserved")),
        "expected reserved-name error; got {errs:?}"
    );
}
