use keyhog_core::{DetectorSpec, MatchLocation, PatternSpec, RawMatch, Severity};
use keyhog_verifier::{dedup_matches, DedupScope, VerificationEngine, VerifyConfig};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), keyhog_verifier::VerifyError> {
    let detector = DetectorSpec {
        id: "demo-token".into(),
        name: "Demo Token".into(),
        service: "demo".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: "demo_[A-Z0-9]{8}".into(),
            description: None,
            group: None,
        }],
        companions: Vec::new(),
        verify: None,
        keywords: vec!["demo_".into()],
    };

    let engine = VerificationEngine::new(&[detector], VerifyConfig::default())?;
    let groups = dedup_matches(
        vec![RawMatch {
            detector_id: "demo-token".into(),
            detector_name: "Demo Token".into(),
            service: "demo".into(),
            severity: Severity::High,
            credential: "demo_ABC12345".into(),
            credential_hash: "hash".into(),
            companions: std::collections::HashMap::new(),
            location: MatchLocation {
                source: "example".into(),
                file_path: Some("example.env".into()),
                line: Some(1),
                offset: 0,
                commit: None,
                author: None,
                date: None,
            },
            entropy: None,
            confidence: Some(0.95),
        }],
        &DedupScope::Credential,
    );

    let findings = engine.verify_all(groups).await;
    println!("findings={}", findings.len());
    println!("verification={:?}", findings[0].verification);
    Ok(())
}
