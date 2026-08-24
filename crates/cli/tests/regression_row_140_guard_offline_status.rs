//! WHY: Guard offline status and list inspectability contract (Row 140):
//! When the background daemon is not running, `keyhog guard list` and `keyhog guard status`
//! must never fail with socket connection errors. Instead, they must inspect the durable
//! guard store from disk when configured, annotating that no daemon is active.
//! `keyhog guard status` without a `<ROOT>` argument must summarize all registered roots.
//!
//! WHAT THIS DOES NOT CATCH:
//! Physical disk hardware faults preventing reading the redb database file.

#![cfg(unix)]

use keyhog_core::guard_state::{
    FilesystemAuthority, FilesystemIdentity, GuardPolicyIdentity, GuardReceipt, GuardRootMode,
    GuardRootState,
};
use keyhog_core::guard_store::DurableGuardStore;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

fn keyhog_bin() -> PathBuf {
    let cargo_bin = PathBuf::from(env!("CARGO_BIN_EXE_keyhog"));
    if cargo_bin.exists() {
        return cargo_bin;
    }
    let prebuilt =
        PathBuf::from("/mnt/FlareTraining/santh-archive/cargo-target/release-fast/keyhog");
    if prebuilt.exists() {
        return prebuilt;
    }
    cargo_bin
}
fn test_tempdir() -> TempDir {
    let target_tmp = PathBuf::from("/mnt/FlareTraining/santh-archive/cargo-target/tmp");
    if target_tmp.exists() || fs::create_dir_all(&target_tmp).is_ok() {
        tempfile::Builder::new()
            .prefix("row-140-")
            .tempdir_in(&target_tmp)
            .expect("create test tempdir in target")
    } else {
        TempDir::new().expect("create tempdir")
    }
}

struct TestEnv {
    dir: TempDir,
    store_path: PathBuf,
    socket_path: PathBuf,
}

impl TestEnv {
    fn new() -> Self {
        let dir = test_tempdir();
        let store_path = dir.path().join("guard_store.redb");
        let socket_path = dir.path().join("nonexistent_daemon.sock");
        let config_path = dir.path().join(".keyhog.toml");

        let config_content = format!("[guard]\nstate_path = \"{}\"\n", store_path.display());
        fs::write(&config_path, config_content).expect("write config");

        Self {
            dir,
            store_path,
            socket_path,
        }
    }

    fn run_cmd(&self, args: &[&str]) -> (String, String, i32) {
        let output = Command::new(keyhog_bin())
            .current_dir(self.dir.path())
            .args(args)
            .env("HOME", self.dir.path())
            .output()
            .expect("execute keyhog");

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let code = output.status.code().unwrap_or(-1);
        (stdout, stderr, code)
    }

    fn populate_store(&self, records: &[keyhog_core::guard_state::GuardRootRecord]) {
        let store = DurableGuardStore::open(&self.store_path).expect("open durable store");
        for record in records {
            store.save_root(record).expect("save root");
        }
    }
}

fn sample_root(
    path: &str,
    state: GuardRootState,
    mode: GuardRootMode,
    findings: u64,
) -> keyhog_core::guard_state::GuardRootRecord {
    let receipt = if findings > 0 || state == GuardRootState::Current {
        Some(GuardReceipt {
            objects_requested: 100,
            objects_hit: 5,
            objects_scanned: 95,
            objects_skipped: 0,
            bytes_requested: 10240,
            bytes_hit: 512,
            bytes_scanned: 9728,
            findings_count: findings,
            coverage_gaps: 0,
            terminal_state: state,
            policy_identity: GuardPolicyIdentity {
                build_identity: "test_build".to_string(),
                detector_digest: "test_detector".to_string(),
                suppression_digest: "test_suppress".to_string(),
                keyhogignore_digest: String::new(),
                config_digest: "test_config".to_string(),
                decode_policy_version: 1,
                source_policy_digest: String::new(),
                guard_schema_version: 1,
                report_semantics_version: 1,
            },
            terminal_sequence: 42,
        })
    } else {
        None
    };

    keyhog_core::guard_state::GuardRootRecord {
        canonical_path: path.as_bytes().to_vec(),
        filesystem_identity: FilesystemIdentity {
            device: 10,
            inode: 20,
        },
        filesystem_authority: FilesystemAuthority::authoritative("ext4"),
        mode,
        state,
        terminal_sequence: 42,
        accepted_event_sequence: 42,
        completed_event_sequence: 42,
        initial_reconciliation_time: Some(1700000000),
        last_reconciliation_time: Some(1700000100),
        backend_route_label: "simd".to_string(),
        recent_transitions: Vec::new(),
        last_receipt: receipt,
    }
}

#[test]
fn row_140_guard_list_offline_empty_store() {
    let env = TestEnv::new();
    let (stdout, stderr, code) = env.run_cmd(&[
        "guard",
        "list",
        "--socket",
        env.socket_path.to_str().unwrap(),
    ]);

    assert_eq!(code, 0, "offline guard list with no roots must exit 0");
    assert!(
        stderr.contains("no guard roots registered (no daemon active)"),
        "stderr must annotate that no daemon is active: {stderr}"
    );
    assert!(
        !stderr.contains("no compatible daemon"),
        "must not report socket connection error"
    );
    assert!(
        stdout.trim().is_empty(),
        "stdout should be empty when no roots"
    );
}

#[test]
fn row_140_guard_list_offline_with_roots() {
    let env = TestEnv::new();
    let root1_path = env.dir.path().join("repo1");
    let root2_path = env.dir.path().join("repo2");
    fs::create_dir_all(&root1_path).unwrap();
    fs::create_dir_all(&root2_path).unwrap();

    let r1 = sample_root(
        root1_path.to_str().unwrap(),
        GuardRootState::Current,
        GuardRootMode::Repo,
        0,
    );
    let r2 = sample_root(
        root2_path.to_str().unwrap(),
        GuardRootState::Stopped,
        GuardRootMode::Filesystem,
        0,
    );
    env.populate_store(&[r1, r2]);

    let (stdout, stderr, code) = env.run_cmd(&[
        "guard",
        "list",
        "--socket",
        env.socket_path.to_str().unwrap(),
    ]);

    assert_eq!(code, 0, "offline guard list with roots must exit 0");
    assert!(
        stderr.contains("2 guard roots registered (no daemon active)"),
        "stderr must annotate count and offline status: {stderr}"
    );
    assert!(
        stdout.contains(root1_path.to_str().unwrap()),
        "stdout must list root1: {stdout}"
    );
    assert!(
        stdout.contains(root2_path.to_str().unwrap()),
        "stdout must list root2: {stdout}"
    );
    assert!(
        stdout.contains("seq=42"),
        "stdout must show sequence: {stdout}"
    );
}

#[test]
fn row_140_guard_status_offline_no_root_arg_summarizes_all_roots_human() {
    let env = TestEnv::new();
    let root_path = env.dir.path().join("my_repo");
    fs::create_dir_all(&root_path).unwrap();

    let r = sample_root(
        root_path.to_str().unwrap(),
        GuardRootState::Current,
        GuardRootMode::Repo,
        0,
    );
    env.populate_store(&[r]);

    let (stdout, stderr, code) = env.run_cmd(&[
        "guard",
        "status",
        "--socket",
        env.socket_path.to_str().unwrap(),
    ]);

    assert_eq!(code, 0, "clean root status must exit 0");
    assert!(
        stderr.contains("1 guard root registered (no daemon active)"),
        "stderr must report count and no daemon active: {stderr}"
    );
    assert!(
        stdout.contains(&format!("root:           {}", root_path.display())),
        "stdout must summarize root path: {stdout}"
    );
    assert!(
        stdout.contains("mode:           repo"),
        "mode must match: {stdout}"
    );
    assert!(
        stdout.contains("state:          current"),
        "state must match: {stdout}"
    );
    assert!(
        stdout.contains("residency:      offline"),
        "residency must be offline: {stdout}"
    );
    assert!(
        stdout.contains("watcher:        none (daemon offline) (offline)"),
        "watcher must annotate offline: {stdout}"
    );
}

#[test]
fn row_140_guard_status_offline_no_root_arg_summarizes_all_roots_json() {
    let env = TestEnv::new();
    let root1_path = env.dir.path().join("repo_a");
    let root2_path = env.dir.path().join("repo_b");
    fs::create_dir_all(&root1_path).unwrap();
    fs::create_dir_all(&root2_path).unwrap();

    let r1 = sample_root(
        root1_path.to_str().unwrap(),
        GuardRootState::Current,
        GuardRootMode::Repo,
        0,
    );
    let r2 = sample_root(
        root2_path.to_str().unwrap(),
        GuardRootState::Dirty,
        GuardRootMode::Repo,
        0,
    );
    env.populate_store(&[r1, r2]);

    let (stdout, stderr, code) = env.run_cmd(&[
        "guard",
        "status",
        "--format",
        "json",
        "--socket",
        env.socket_path.to_str().unwrap(),
    ]);

    // r2 is Dirty -> non-clean exit code 13
    assert_eq!(code, 13, "dirty root must cause exit 13");
    assert!(
        !stderr.contains("no compatible daemon"),
        "must not report socket connection error"
    );

    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("output must be valid JSON");
    assert_eq!(parsed["daemon"], "offline");
    assert_eq!(parsed["total"], 2);
    let roots = parsed["roots"].as_array().expect("roots must be array");
    assert_eq!(roots.len(), 2);
    assert_eq!(roots[0]["root"], root1_path.to_str().unwrap());
    assert_eq!(roots[0]["state"], "current");
    assert_eq!(roots[0]["scanner_residency"], "offline");
    assert_eq!(roots[1]["root"], root2_path.to_str().unwrap());
    assert_eq!(roots[1]["state"], "dirty");
}

#[test]
fn row_140_guard_status_offline_single_root_human_and_json() {
    let env = TestEnv::new();
    let root_path = env.dir.path().join("target_repo");
    fs::create_dir_all(&root_path).unwrap();

    let r = sample_root(
        root_path.to_str().unwrap(),
        GuardRootState::Current,
        GuardRootMode::Repo,
        0,
    );
    env.populate_store(&[r]);

    // Human format single root
    let (stdout_human, _, code_human) = env.run_cmd(&[
        "guard",
        "status",
        root_path.to_str().unwrap(),
        "--socket",
        env.socket_path.to_str().unwrap(),
    ]);
    assert_eq!(code_human, 0);
    assert!(stdout_human.contains(&format!("root:           {}", root_path.display())));
    assert!(stdout_human.contains("state:          current"));
    assert!(stdout_human.contains("store schema:   1"));

    // JSON format single root
    let (stdout_json, _, code_json) = env.run_cmd(&[
        "guard",
        "status",
        root_path.to_str().unwrap(),
        "--format",
        "json",
        "--socket",
        env.socket_path.to_str().unwrap(),
    ]);
    assert_eq!(code_json, 0);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout_json).expect("single root output must be JSON object");
    assert_eq!(parsed["root"], root_path.to_str().unwrap());
    assert_eq!(parsed["state"], "current");
    assert_eq!(parsed["mode"], "repo");
    assert_eq!(parsed["scanner_residency"], "offline");
}

#[test]
fn row_140_guard_status_offline_unregistered_root_fails_gracefully() {
    let env = TestEnv::new();
    let root_path = env.dir.path().join("unregistered");
    fs::create_dir_all(&root_path).unwrap();

    let (_stdout, stderr, code) = env.run_cmd(&[
        "guard",
        "status",
        root_path.to_str().unwrap(),
        "--socket",
        env.socket_path.to_str().unwrap(),
    ]);

    assert_ne!(code, 0, "unregistered root must fail");
    assert!(
        stderr.contains("not registered in durable store") && stderr.contains("no daemon active"),
        "must report not registered in durable store (no daemon active): {stderr}"
    );
    assert!(
        !stderr.contains("no compatible daemon"),
        "must not be socket connection error"
    );
}

#[test]
fn row_140_guard_status_invalid_format_fails_early() {
    let env = TestEnv::new();
    let (_stdout, stderr, code) = env.run_cmd(&[
        "guard",
        "status",
        "--format",
        "invalid_xml",
        "--socket",
        env.socket_path.to_str().unwrap(),
    ]);

    assert_ne!(code, 0);
    assert!(
        stderr.contains("invalid format 'invalid_xml': expected 'human' or 'json'"),
        "stderr must explain invalid format: {stderr}"
    );
}

#[test]
fn row_140_guard_status_offline_all_states_exit_code_matrix() {
    for &state in GuardRootState::all() {
        let env = TestEnv::new();
        let root_path = env.dir.path().join(format!("repo_{}", state.label()));
        fs::create_dir_all(&root_path).unwrap();

        let r = sample_root(root_path.to_str().unwrap(), state, GuardRootMode::Repo, 0);
        env.populate_store(&[r]);

        let (_stdout, _stderr, code) = env.run_cmd(&[
            "guard",
            "status",
            root_path.to_str().unwrap(),
            "--socket",
            env.socket_path.to_str().unwrap(),
        ]);

        let expected_code = match state {
            GuardRootState::Current => 0,
            GuardRootState::Blocked => 1,
            GuardRootState::Stopped
            | GuardRootState::Indexing
            | GuardRootState::Dirty
            | GuardRootState::Degraded
            | GuardRootState::StalePolicy => 13,
        };

        assert_eq!(
            code,
            expected_code,
            "state {} must yield exit code {}",
            state.label(),
            expected_code
        );
    }
}

#[test]
fn row_140_guard_status_untrusted_socket_fails_closed() {
    let env = TestEnv::new();
    let fake_socket = env.dir.path().join("fake_socket.txt");
    fs::write(&fake_socket, "not a socket").unwrap();

    let (_stdout, stderr, code) =
        env.run_cmd(&["guard", "status", "--socket", fake_socket.to_str().unwrap()]);

    assert_ne!(code, 0);
    assert!(
        !stderr.contains("(no daemon active)"),
        "untrusted socket error must not be masked as '(no daemon active)': {stderr}"
    );
}
