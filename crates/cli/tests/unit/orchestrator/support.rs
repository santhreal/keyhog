use clap::Parser;
use keyhog::args::ScanArgs;
use keyhog::orchestrator::ScanOrchestrator;
use keyhog_core::{
    Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity, Source, SourceError,
};
use keyhog_scanner::CompiledScanner;
use std::sync::Arc;

pub struct StaticSource {
    pub chunks: Vec<Chunk>,
}

impl Source for StaticSource {
    fn name(&self) -> &str {
        "static"
    }
    fn chunks(&self) -> Box<dyn Iterator<Item = Result<Chunk, SourceError>> + '_> {
        Box::new(self.chunks.clone().into_iter().map(Ok))
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

pub fn make_chunk(text: &str, path: &str) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "test".into(),
            path: Some(path.into()),
            ..Default::default()
        },
    }
}

pub fn make_detector() -> DetectorSpec {
    DetectorSpec {
        id: "static-test".into(),
        name: "Static Test".into(),
        service: "test".into(),
        severity: Severity::Medium,
        patterns: vec![PatternSpec {
            regex: r"STATIC_SECRET_[0-9]+".into(),
            description: None,
            group: None,
        }],
        companions: Vec::new(),
        verify: None,
        keywords: vec!["STATIC_SECRET".into()],
    }
}

pub fn make_orchestrator(detectors: Vec<DetectorSpec>) -> ScanOrchestrator {
    let args = ScanArgs::try_parse_from(["scan"]).expect("parse scan args");
    let scanner = Arc::new(CompiledScanner::compile(detectors.clone()).expect("compile"));
    let signatures = detectors
        .iter()
        .flat_map(|d| d.patterns.iter().map(|p| Arc::from(p.regex.as_str())))
        .collect();
    ScanOrchestrator::from_parts_for_test(
        args,
        detectors,
        scanner,
        signatures,
        keyhog::test_fixture_suppressions::TestFixtureSuppressions::bundled(),
    )
}
