use keyhog_profile::{RunIdentity, RunProfile, RunState, Session};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after epoch")
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("keyhog-profile-cli-{}-{nonce}", std::process::id()));
        fs::create_dir(&path).expect("create profile CLI temp directory");
        Self(path)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn profile(source: &str) -> RunProfile {
    Session::start(RunIdentity::new(
        "0.5.49",
        "detectors-a",
        "config-a",
        source,
        "small-text",
        "auto",
    ))
    .expect("start CLI profile")
    .finish(RunState::Completed)
}

fn write_profile(path: &Path, profile: &RunProfile) {
    fs::write(
        path,
        profile.to_json_pretty().expect("serialize CLI profile"),
    )
    .expect("write CLI profile");
}

fn run(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_keyhog-profile"))
        .args(arguments)
        .output()
        .expect("run keyhog-profile binary")
}

/// Inspect text must execute the shipped parser and renderer on a real profile artifact.
#[test]
fn inspect_text_renders_valid_profile_artifact() {
    let temp = TempDir::new();
    let path = temp.path("profile.json");
    write_profile(&path, &profile("stdin"));

    let output = run(&["inspect", path.to_str().expect("UTF-8 temp path")]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 inspect output");
    assert!(stdout.starts_with("KeyHog profile "));
    assert!(stdout.contains("state=completed source=stdin workload=small-text"));
    assert!(stdout.contains("collector process-resources availability="));
    assert!(output.stderr.is_empty());
}

/// Inspect JSON must validate and normalize the artifact without changing any profile evidence.
#[test]
fn inspect_json_round_trips_complete_profile() {
    let temp = TempDir::new();
    let path = temp.path("profile.json");
    let expected = profile("filesystem");
    write_profile(&path, &expected);

    let output = run(&[
        "inspect",
        path.to_str().expect("UTF-8 temp path"),
        "--format",
        "json",
    ]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let decoded: RunProfile = serde_json::from_slice(&output.stdout).expect("decode inspect JSON");
    assert_eq!(decoded, expected);
    assert!(output.stderr.is_empty());
}

/// Compatible comparison must exit successfully and report exact candidate-minus-baseline wall time.
#[test]
fn compare_compatible_profiles_returns_success_and_exact_delta() {
    let temp = TempDir::new();
    let baseline_path = temp.path("baseline.json");
    let candidate_path = temp.path("candidate.json");
    let mut baseline = profile("filesystem");
    baseline.wall_time_ns = 1_000;
    let mut candidate = baseline.clone();
    candidate.identity.run_id = "candidate-run".to_owned();
    candidate.wall_time_ns = 750;
    write_profile(&baseline_path, &baseline);
    write_profile(&candidate_path, &candidate);

    let output = run(&[
        "compare",
        baseline_path.to_str().expect("UTF-8 temp path"),
        candidate_path.to_str().expect("UTF-8 temp path"),
    ]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 compare output");
    assert!(stdout.contains("comparable=true"));
    assert!(stdout.contains("wall baseline_ns=1000 candidate_ns=750 delta_ns=-250"));
    assert!(output.stderr.is_empty());
}

/// Incompatible comparison must preserve its evidence but return the dedicated non-success status.
#[test]
fn compare_incompatible_profiles_returns_status_three() {
    let temp = TempDir::new();
    let baseline_path = temp.path("baseline.json");
    let candidate_path = temp.path("candidate.json");
    let baseline = profile("filesystem");
    let mut candidate = baseline.clone();
    candidate.identity.run_id = "candidate-run".to_owned();
    candidate.identity.detector_digest = "detectors-b".to_owned();
    write_profile(&baseline_path, &baseline);
    write_profile(&candidate_path, &candidate);

    let output = run(&[
        "compare",
        baseline_path.to_str().expect("UTF-8 temp path"),
        candidate_path.to_str().expect("UTF-8 temp path"),
        "--format",
        "json",
    ]);
    assert_eq!(output.status.code(), Some(3));
    let comparison: keyhog_profile::ProfileComparison =
        serde_json::from_slice(&output.stdout).expect("decode incompatible comparison");
    assert!(!comparison.comparable);
    assert_eq!(comparison.incompatibilities.len(), 1);
    assert_eq!(
        comparison.incompatibilities[0].field,
        "identity.detector_digest"
    );
    assert!(output.stderr.is_empty());
}

/// Malformed JSON must fail with the input path and parser context instead of emitting a partial report.
#[test]
fn inspect_rejects_malformed_json_with_status_two() {
    let temp = TempDir::new();
    let path = temp.path("malformed.json");
    fs::write(&path, b"{not-json").expect("write malformed profile");

    let output = run(&["inspect", path.to_str().expect("UTF-8 temp path")]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 parse error");
    assert!(stderr.contains("invalid profile JSON"));
    assert!(stderr.contains("malformed.json"));
}

/// Unknown envelope schemas must fail closed so fields are not interpreted with the wrong semantics.
#[test]
fn inspect_rejects_unknown_profile_schema() {
    let temp = TempDir::new();
    let path = temp.path("unknown-schema.json");
    let mut unknown = profile("stdin");
    unknown.schema = "keyhog-profile-v99".to_owned();
    write_profile(&path, &unknown);

    let output = run(&["inspect", path.to_str().expect("UTF-8 temp path")]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unsupported profile schema"));
}

/// Newer envelope versions must tell the operator to update rather than silently dropping new evidence.
#[test]
fn inspect_rejects_newer_profile_version() {
    let temp = TempDir::new();
    let path = temp.path("newer-version.json");
    let mut newer = profile("stdin");
    newer.version += 1;
    write_profile(&path, &newer);

    let output = run(&["inspect", path.to_str().expect("UTF-8 temp path")]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("newer than supported"));
    assert!(stderr.contains("update keyhog-profile"));
}

/// Oversized artifacts must be rejected from metadata before allocating or parsing attacker-controlled content.
#[test]
fn inspect_rejects_profile_over_size_limit() {
    let temp = TempDir::new();
    let path = temp.path("oversized.json");
    let file = fs::File::create(&path).expect("create oversized profile");
    file.set_len(64 * 1024 * 1024 + 1)
        .expect("extend oversized profile");

    let output = run(&["inspect", path.to_str().expect("UTF-8 temp path")]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("the limit is 67108864 bytes"));
}
