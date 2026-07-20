//! Pipeline: findings from multiple sources accumulate.

use super::support::{
    make_chunk, make_detector, make_orchestrator, scan_sources_for_test, StaticSource,
};
use keyhog_core::Source;

#[test]
fn pipeline_processes_chunks_across_multiple_sources() {
    let orch = make_orchestrator(vec![make_detector()]);
    let sources: Vec<Box<dyn Source>> = vec![
        Box::new(StaticSource {
            chunks: vec![make_chunk("STATIC_SECRET_1 here", "a.rs")],
        }),
        Box::new(StaticSource {
            chunks: vec![make_chunk("STATIC_SECRET_2 there", "b.rs")],
        }),
    ];
    let findings = scan_sources_for_test(&orch, sources, false, None).expect("scan sources");
    assert_eq!(findings.len(), 2);
    let mut creds: Vec<String> = findings
        .iter()
        .map(|f| f.credential.as_str().to_string())
        .collect();
    creds.sort();
    assert_eq!(creds, vec!["STATIC_SECRET_1", "STATIC_SECRET_2"]);
}
