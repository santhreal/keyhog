use keyhog_core::allowlist::Allowlist;
use keyhog_core::{
    load_detectors_with_gate, redact, validate_detector, DetectorSpec, PatternSpec, Severity,
};
use std::path::Path;

fn main() {
    let detector = DetectorSpec {
        id: "demo-token".into(),
        name: "Demo Token".into(),
        service: "demo".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: "demo_[A-Z0-9]{8}".into(),
            description: Some("Simple standalone example".into()),
            group: None,
        }],
        companions: Vec::new(),
        verify: None,
        keywords: vec!["demo_".into()],
    };

    let issues = validate_detector(&detector);
    let allowlist = Allowlist::parse("path:**/*.md\n");
    let maybe_detectors = load_detectors_with_gate(Path::new("detectors"), true).ok();

    println!("detector={} issues={}", detector.id, issues.len());
    println!("redacted={}", redact("demo_ABC12345"));
    println!(
        "ignores_docs={}",
        allowlist.is_path_ignored("docs/README.md")
    );
    println!(
        "workspace_detectors_loaded={}",
        maybe_detectors.as_ref().map_or(0, Vec::len)
    );
}
