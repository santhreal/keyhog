use keyhog_core::{validate_detector, QualityIssue};

#[test]
fn validator_rejects_multi_step_oob_before_runtime_can_drop_callbacks() {
    let toml_src = r#"
[detector]
id = "multi-step-oob"
name = "Multi-step OOB"
service = "test"
severity = "critical"
keywords = ["MSOOB"]

[[detector.patterns]]
regex = "MSOOB_[A-Z0-9]{16}"

[detector.verify]
service = "test"
allowed_domains = ["api.example.com"]

[[detector.verify.steps]]
name = "probe"
method = "POST"
url = "https://api.example.com/probe"
auth = { type = "none" }
body = '{"callback":"{{interactsh.url}}"}'
success = { status = 200 }

[detector.verify.oob]
protocol = "http"
policy = "oob_and_http"
"#;

    let detectors = keyhog_core::testing::CoreTestApi::load_detectors_from_str(
        &keyhog_core::testing::TestApi,
        toml_src,
    )
    .expect("test detector TOML parses");
    let errors: Vec<_> = validate_detector(&detectors[0])
        .into_iter()
        .filter_map(|issue| match issue {
            QualityIssue::Error(message) => Some(message),
            QualityIssue::Warning(_) => None,
        })
        .collect();

    assert!(
        errors.iter().any(|message| {
            message.contains("verify.oob cannot be combined with multi-step verification")
                && message.contains("concrete request step")
        }),
        "multi-step OOB must be rejected at detector validation; got {errors:?}"
    );
}
