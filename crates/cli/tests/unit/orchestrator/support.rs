use clap::Parser;
use keyhog::args::ScanArgs;
use keyhog::testing::{CliTestApi as _, ScanOrchestrator, API};
use keyhog_core::{
    Chunk, ChunkMetadata, DetectorSpec, PatternSpec, RawMatch, Severity, Source, SourceError,
};
use keyhog_scanner::CompiledScanner;
use std::sync::Arc;
use std::sync::Mutex;

pub static ENV_LOCK: Mutex<()> = Mutex::new(());

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
        kind: Default::default(),
        entropy_floor: Vec::new(),
        tests: Vec::new(),
        id: "static-test".into(),
        name: "Static Test".into(),
        service: "test".into(),
        severity: Severity::Medium,
        patterns: vec![PatternSpec {
            regex: r"STATIC_SECRET_[0-9]+".into(),
            ..Default::default()
        }],
        companions: Vec::new(),
        verify: None,
        keywords: vec!["STATIC_SECRET".into()],
        min_confidence: None,
        // Robust to future DetectorSpec field additions (this exhaustive literal
        // was already stale — missing allowlist_paths/values, entropy_high, etc.);
        // fall through to Default for any field not set explicitly above.
        ..Default::default()
    }
}

pub fn make_orchestrator(detectors: Vec<DetectorSpec>) -> ScanOrchestrator {
    let args = ScanArgs::try_parse_from(["scan"]).expect("parse scan args");
    make_orchestrator_with_args(detectors, args)
}

pub fn make_orchestrator_with_args(
    detectors: Vec<DetectorSpec>,
    args: ScanArgs,
) -> ScanOrchestrator {
    let scanner = Arc::new(CompiledScanner::compile(detectors.clone()).expect("compile"));
    let signatures = detectors
        .iter()
        .flat_map(|d| d.patterns.iter().map(|p| Arc::from(p.regex.as_str())))
        .collect();
    API.scan_orchestrator_from_parts_for_test(
        args,
        detectors,
        scanner,
        signatures,
        API.bundled_test_fixture_suppressions(),
    )
}

pub fn scan_sources_for_test(
    orchestrator: &ScanOrchestrator,
    sources: Vec<Box<dyn Source>>,
    show_progress: bool,
    merkle: Option<Arc<keyhog_core::MerkleIndex>>,
) -> anyhow::Result<Vec<RawMatch>> {
    let guard = API.scan_runtime_guard_for_test();
    API.scan_orchestrator_scan_sources_for_test(
        orchestrator,
        sources,
        show_progress,
        merkle,
        &guard,
    )
}
