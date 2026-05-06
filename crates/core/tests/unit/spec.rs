use keyhog_core::{
    load_detector_cache, load_detectors_with_gate, save_detector_cache, validate_detector,
    CompanionSpec, DetectorFile, DetectorSpec, PatternSpec, QualityIssue, Severity,
};
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing_subscriber::fmt::MakeWriter;

#[derive(Clone, Default)]
struct SharedWriter(Arc<Mutex<Vec<u8>>>);

struct GuardedWriter(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for GuardedWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for SharedWriter {
    type Writer = GuardedWriter;

    fn make_writer(&'a self) -> Self::Writer {
        GuardedWriter(self.0.clone())
    }
}

fn capture_logs<F: FnOnce()>(f: F) -> String {
    let writer = SharedWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(writer.clone())
        .without_time()
        .finish();
    tracing::subscriber::with_default(subscriber, f);
    let bytes = writer.0.lock().unwrap().clone();
    String::from_utf8(bytes).unwrap()
}

fn temp_dir(name: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("keyhog-core-{name}-{unique}"));
    fs::create_dir_all(&path).unwrap();
    path
}

fn valid_detector() -> DetectorSpec {
    DetectorSpec {
        id: "demo-token".into(),
        name: "Demo Token".into(),
        service: "demo".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: "demo_[A-Z0-9]{8}".into(),
            description: Some("demo".into()),
            group: None,
        }],
        companions: Vec::new(),
        verify: None,
        keywords: vec!["demo_".into()],
    }
}

#[test]
fn detector_spec_deserialization() {
    let toml_str = r#"
        [detector]
        id = "test-id"
        name = "Test Name"
        service = "test-service"
        severity = "high"
        keywords = ["KEY", "secret"]

        [[detector.patterns]]
        regex = 'key-[a-z0-9]{32}'
        description = "Test pattern"
    "#;

    let file: DetectorFile = toml::from_str(toml_str).unwrap();
    let spec = file.detector;
    assert_eq!(spec.id, "test-id");
    assert_eq!(spec.severity, Severity::High);
    assert_eq!(spec.patterns.len(), 1);
    assert_eq!(spec.keywords.len(), 2);
}

#[test]
fn pattern_spec_with_group() {
    let pattern = PatternSpec {
        regex: "API_KEY=(.*)".to_string(),
        description: Some("capture group test".to_string()),
        group: Some(1),
    };
    assert_eq!(pattern.group, Some(1));
}

#[test]
fn detector_spec_no_longer_derives_default() {
    let detector = valid_detector();
    assert!(validate_detector(&detector).is_empty());
}

#[test]
fn companion_regexes_are_validated() {
    // within_lines = 12 (> TIGHT_COMPANION_RADIUS = 5) — pure character
    // class with this much radius needs a textual anchor.
    let mut detector = valid_detector();
    detector.companions.push(CompanionSpec {
        name: "secondary".into(),
        regex: "[A-Za-z0-9+/=]{40,}".into(),
        within_lines: 12,
        required: false,
    });
    let issues = validate_detector(&detector);
    assert!(issues.iter().any(|issue| matches!(
        issue,
        QualityIssue::Error(message) if message.contains("pure character class")
    )));
}

#[test]
fn saving_invalid_detector_cache_is_rejected() {
    let mut invalid = valid_detector();
    invalid.patterns[0].regex = "(".into();
    let dir = temp_dir("cache-save");
    let cache_path = dir.join("detectors.json");
    let error = save_detector_cache(&[invalid], &cache_path).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
}

#[test]
fn invalid_cached_detector_rejects_entire_cache() {
    let dir = temp_dir("cache-load");
    let cache_path = dir.join("detectors.json");
    let source_dir = dir.join("detectors");
    fs::create_dir_all(&source_dir).unwrap();

    let invalid_cache = r#"{
        "version": 2,
        "detectors": [{
            "id": "demo-token",
            "name": "Demo Token",
            "service": "demo",
            "severity": "high",
            "patterns": [{"regex":"(","description":null,"group":null}],
            "companions": [],
            "verify": null,
            "keywords": ["demo_"]
        }]
    }"#;
    fs::write(&cache_path, invalid_cache).unwrap();
    fs::write(source_dir.join("demo.toml"), "").unwrap();

    assert!(load_detector_cache(&cache_path, &source_dir).is_none());
}

#[test]
fn malformed_toml_files_emit_warnings_and_keep_valid_detectors() {
    let dir = temp_dir("detector-load");
    fs::write(
        dir.join("valid.toml"),
        r#"
        [detector]
        id = "demo-token"
        name = "Demo Token"
        service = "demo"
        severity = "high"
        keywords = ["demo_"]

        [[detector.patterns]]
        regex = "demo_[A-Z0-9]{8}"
        "#,
    )
    .unwrap();
    fs::write(dir.join("broken.toml"), "[detector").unwrap();

    let logs = capture_logs(|| {
        let detectors = load_detectors_with_gate(&dir, true).unwrap();
        assert_eq!(detectors.len(), 1);
        assert_eq!(detectors[0].id, "demo-token");
    });

    assert!(logs.contains("failed to parse"));
    assert!(logs.contains("skipped 1 malformed detector files"));
}

#[test]
fn no_detector_uses_singular_companion_table() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    // The in-crate `detectors` is a Unix symlink to `../../detectors`. On
    // Windows checkouts without core.symlinks the symlink lands as a plain
    // file holding the link target, so prefer the workspace-root path and
    // fall back to the in-crate path. Mirrors `crates/core/build.rs`.
    let manifest_path = std::path::Path::new(&manifest_dir);
    let workspace_detectors = manifest_path
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.join("detectors"))
        .filter(|p| p.is_dir());
    let in_crate = manifest_path.join("detectors");
    let detectors_dir = workspace_detectors
        .or_else(|| {
            if in_crate.is_dir() {
                Some(in_crate.clone())
            } else {
                None
            }
        })
        .unwrap_or(in_crate);

    let mut violations = Vec::new();
    for entry in std::fs::read_dir(&detectors_dir).expect("failed to read detectors dir") {
        let entry = entry.expect("failed to read dir entry");
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "toml") {
            let contents = std::fs::read_to_string(&path).expect("failed to read detector file");
            if contents.contains("[detector.companion]") {
                violations.push(path.file_name().unwrap().to_string_lossy().to_string());
            }
        }
    }

    assert!(
        violations.is_empty(),
        "Found {} detector(s) using deprecated singular [detector.companion] instead of [[detector.companions]]: {}. Fix: rename to [[detector.companions]] and ensure field names match the spec",
        violations.len(),
        violations.join(", ")
    );
}
