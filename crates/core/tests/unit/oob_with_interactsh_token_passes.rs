//! Migrated from `src/spec/validate.rs` inline tests.
use keyhog_core::spec::load_detectors_from_str;
use keyhog_core::{validate_detector, AuthSpec, QualityIssue};

fn errors_for(toml_src: &str) -> Vec<String> {
    let detectors = load_detectors_from_str(toml_src).expect("toml parses");
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

fn regex_has_capture_group(pattern: &str) -> bool {
    let bytes = pattern.as_bytes();
    let mut i = 0;
    let mut in_class = false;
    let mut escape = false;
    while i < bytes.len() {
        let b = bytes[i];
        if escape { escape = false; i += 1; continue; }
        match b {
            b'\\' => escape = true,
            b'[' if !in_class => in_class = true,
            b']' if in_class => in_class = false,
            b'(' if !in_class => {
                if i + 1 < bytes.len() && bytes[i + 1] == b'?' {
                    let after = &bytes[i + 2..];
                    if after.starts_with(b"P<") { return true; }
                    if after.starts_with(b"<") {
                        if !(after.starts_with(b"<=") || after.starts_with(b"<!")) { return true; }
                    }
                } else { return true; }
            }
            _ => {}
        }
        i += 1;
    }
    false
}

fn regex_likely_includes_anchor_prefix(pattern: &str) -> bool {
    let bytes = pattern.as_bytes();
    let mut i = 0;
    let mut in_class = false;
    let mut escape = false;
    while i < bytes.len() {
        let b = bytes[i];
        if escape { escape = false; i += 1; continue; }
        match b {
            b'\\' => escape = true,
            b'[' if !in_class => in_class = true,
            b']' if in_class => in_class = false,
            b'=' if !in_class => return true,
            _ => {}
        }
        i += 1;
    }
    false
}
#[test]
    fn oob_with_interactsh_token_passes() {
        let toml_src = r#"
[detector]
id = "oob-good"
name = "OOB with token"
service = "github"
severity = "high"
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
