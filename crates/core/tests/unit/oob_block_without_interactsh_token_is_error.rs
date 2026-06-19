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
fn oob_block_without_interactsh_token_is_error() {
    let toml_src = r#"
[detector]
id = "oob-no-token"
name = "OOB without token"
service = "github"
severity = "high"
keywords = ["GHTOKEN"]

[[detector.patterns]]
regex = "GHTOKEN_[A-Z0-9]{16}"

[detector.verify]
method = "POST"
url = "https://api.github.com/probe"
body = '{"static":"payload"}'

[detector.verify.oob]
protocol = "http"
"#;
    let errs = errors_for(toml_src);
    assert!(
        errs.iter().any(|e| e.contains("verify.oob is set but no")),
        "expected oob-without-token error; got {errs:?}"
    );
}
