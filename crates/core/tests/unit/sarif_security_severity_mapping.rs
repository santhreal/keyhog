//! GitHub code-scanning sets an alert's Critical/High/Medium/Low band from the
//! rule's `security-severity` (a 0.0-10.0 string). keyhog must map its own
//! severity onto GitHub's bands (>=9.0 critical, 7.0-8.9 high, 4.0-6.9 medium,
//! 0.1-3.9 low) or every alert shows a flat default severity, breaking triage.
use keyhog_core::report::sarif_uri::apply_code_scanning_props;
use keyhog_core::Severity;

#[test]
fn sarif_security_severity_mapping() {
    let lo_hi = |s: Severity| -> (f64, f64) {
        match s {
            Severity::Critical => (9.0, 10.0001),
            Severity::High => (7.0, 9.0),
            Severity::Medium => (4.0, 7.0),
            Severity::Low => (0.1, 4.0),
            Severity::ClientSafe | Severity::Info => (0.0, 1.0001),
        }
    };
    for sev in [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::ClientSafe,
        Severity::Info,
    ] {
        let mut props = serde_json::Map::new();
        apply_code_scanning_props(&mut props, sev);

        let score: f64 = props["security-severity"]
            .as_str()
            .unwrap_or_else(|| panic!("{sev:?}: security-severity must be a string"))
            .parse()
            .unwrap_or_else(|_| panic!("{sev:?}: security-severity must be numeric"));
        let (lo, hi) = lo_hi(sev);
        assert!(
            score >= lo && score < hi,
            "{sev:?}: security-severity {score} not in GitHub band [{lo}, {hi})"
        );

        let tags = props["tags"].as_array().expect("tags must be an array");
        assert!(
            tags.iter().any(|t| t == "security"),
            "{sev:?}: rule must carry the `security` tag"
        );
    }
}
