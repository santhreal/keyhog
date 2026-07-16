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
fn interactsh_token_without_oob_block_is_error() {
    let toml_src = r#"
[detector]
id = "token-no-oob"
name = "Token without OOB"
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
"#;
    let errs = errors_for(toml_src);
    assert!(
        errs.iter()
            .any(|e| e.contains("token is referenced") && e.contains("no [detector.verify.oob]")),
        "expected token-without-oob error; got {errs:?}"
    );
}
