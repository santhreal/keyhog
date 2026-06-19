use keyhog_core::{
    load_detectors, redact, validate_detector, Allowlist, DetectorSpec, PatternSpec, Severity,
};
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let detector = DetectorSpec {
        tests: Vec::new(),
        id: "demo-token".into(),
        name: "Demo Token".into(),
        service: "demo".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: "demo_[A-Z0-9]{8}".into(),
            description: Some("Simple standalone example".into()),
            ..Default::default()
        }],
        companions: Vec::new(),
        verify: None,
        keywords: vec!["demo_".into()],
        min_confidence: None,
    };

    let issues = validate_detector(&detector);
    let ignore_path = std::env::temp_dir().join("keyhog-core-standalone.keyhogignore");
    std::fs::write(&ignore_path, "path:**/*.md\n")?;
    let allowlist = Allowlist::load(&ignore_path)?;
    let _ = std::fs::remove_file(&ignore_path);
    let maybe_detectors = load_detectors(Path::new("detectors")).ok();

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
    Ok(())
}
