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
fn oob_with_interactsh_token_passes() {
    let toml_src = r#"
[detector]
id = "oob-good"
name = "OOB with token"
service = "github"
severity = "high"
ml = { match_mode = "disabled", entropy_mode = "disabled", weight = 0.0, context_radius_lines = 0 }
keywords = ["GHTOKEN"]

[[detector.patterns]]
regex = "GHTOKEN_[A-Z0-9]{16}"

[detector.verify]
method = "POST"
url = "https://api.github.com/probe"
body = '{"target":"https://{{interactsh}}/x"}'

[detector.verify.oob]
protocol = "http"
"#;
    let errs = errors_for(toml_src);
    let oob_related: Vec<_> = errs
        .iter()
        .filter(|e| e.contains("oob") || e.contains("interactsh"))
        .collect();
    assert!(
        oob_related.is_empty(),
        "unexpected OOB errors: {oob_related:?}"
    );
}
