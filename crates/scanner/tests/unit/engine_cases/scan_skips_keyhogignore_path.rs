use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::CompiledScanner;
#[test]
fn scan_skips_keyhogignore_path() {
    let d = DetectorSpec {
        id: "a".into(), name: "A".into(), service: "s".into(), severity: Severity::Low,
        patterns: vec![PatternSpec { regex: "secret".into(), description: None, group: None }],
        companions: vec![], verify: None, keywords: vec!["secret".into()], ..Default::default()
    };
    let s = CompiledScanner::compile(vec![d]).unwrap();
    let chunk = Chunk {
        data: "secret=abc".into(),
        metadata: ChunkMetadata { path: Some(".keyhogignore".into()), ..Default::default() },
    };
    assert!(s.scan(&chunk).is_empty());
}
