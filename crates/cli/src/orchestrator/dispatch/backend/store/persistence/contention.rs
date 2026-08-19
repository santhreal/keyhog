//! Process-level regression coverage for autoroute cache locking and publication.

use super::*;
use crate::orchestrator::dispatch::backend::workload::{
    autoroute_stable_bucket, source_class_id, SourceMixtureEntry, SourceMixtureKey,
};
use keyhog_scanner::ScanBackend;
use std::ffi::OsStr;
use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const CHILD_CACHE_ENV: &str = "KEYHOG_AUTOROUTE_CONTENTION_CACHE";
const CHILD_GATE_ENV: &str = "KEYHOG_AUTOROUTE_CONTENTION_GATE";
const CHILD_READY_ENV: &str = "KEYHOG_AUTOROUTE_CONTENTION_READY";
const CHILD_ATTEMPT_ENV: &str = "KEYHOG_AUTOROUTE_CONTENTION_ATTEMPT";
const CHILD_WRITER_ENV: &str = "KEYHOG_AUTOROUTE_CONTENTION_WRITER";
const CHILD_SECRET_ENV: &str = "KEYHOG_AUTOROUTE_CONTENTION_SECRET";
const CHILD_OBSERVE_ENV: &str = "KEYHOG_ATOMIC_FILE_TEST_OBSERVE_DIR";
const CHILD_RELEASE_ENV: &str = "KEYHOG_ATOMIC_FILE_TEST_RELEASE_PATH";
const CHILD_TEST_NAME: &str = "orchestrator::dispatch::backend::store::persistence::contention::autoroute_cache_contention_writer_subprocess";
const DETECTOR_DIGEST: u64 = 0x31ca_11b4_a5e0_0310;
const RULES_DIGEST: &str = "0310310310310310310310310310310310310310310310310310310310310310";
const CONFIG_DIGESTS: [u64; 2] = [0x3100, 0x3101];
const BUCKET_BYTES: [u64; 8] = [
    4 * 1024,
    8 * 1024,
    16 * 1024,
    32 * 1024,
    4 * 1024 * 1024,
    8 * 1024 * 1024,
    16 * 1024 * 1024,
    32 * 1024 * 1024,
];
const HOST_VARIANTS: usize = 2;
const UNIQUE_WRITERS: usize = CONFIG_DIGESTS.len() * HOST_VARIANTS;
// Four distinct config/host generations plus one exact duplicate maximize
// process overlap while requiring only one fsync-heavy save per subprocess.
const WRITER_PROCESSES: usize = UNIQUE_WRITERS + 1;
// Hosted two-core runners execute these full test binaries beside the parent
// suite. Budget one minute of process startup and lock progress per writer.
const WRITER_DEADLOCK_BUDGET: Duration = Duration::from_secs(60 * WRITER_PROCESSES as u64);
const SECRET_SENTINEL: &str = "kh031-secret-material-must-never-reach-cache-or-temp";

fn host(variant: usize) -> AutorouteHostProfile {
    AutorouteHostProfile {
        os: "linux".to_string(),
        arch: "x86_64".to_string(),
        cpu_model: Some("kh031-contention-cpu".to_string()),
        physical_cores: 8 + variant,
        logical_cores: 16 + variant,
        has_avx2: true,
        has_avx512: false,
        has_neon: false,
        hyperscan_available: true,
        hyperscan_runtime_identity: Some("kh031-hyperscan-runtime".to_string()),
        gpu_name: None,
        gpu_runtime_backend: None,
        gpu_driver_runtime_identity: None,
        gpu_batch_input_limit_bytes: None,
        gpu_is_software: false,
        total_memory_mb: Some(65_536 + variant as u64),
        eligible_backends: vec![
            ScanBackend::CpuFallback.label().to_string(),
            ScanBackend::SimdCpu.label().to_string(),
        ],
    }
}

fn workload(bytes: u64) -> WorkloadKey {
    let bytes_bucket = autoroute_stable_bucket(bytes);
    WorkloadKey {
        bytes_bucket,
        chunks_bucket: autoroute_stable_bucket(1),
        max_file_bucket: bytes_bucket,
        pattern_bucket: autoroute_stable_bucket(1),
        decode_admitted: false,
        source_mixture: SourceMixtureKey {
            entries: vec![SourceMixtureEntry {
                source_class_digest: source_class_id("filesystem"),
                has_full_size: true,
            }],
        },
    }
}

fn write_spec(path: &Path, logical_writer: usize) {
    let config_index = logical_writer / HOST_VARIANTS;
    let host_variant = logical_writer % HOST_VARIANTS;
    let config = CONFIG_DIGESTS[config_index];
    let host = host(host_variant);
    let decisions = BUCKET_BYTES
        .iter()
        .map(|&bytes| {
            (
                workload(bytes),
                AutorouteDecision::new(ScanBackend::SimdCpu, bytes, 1, 12, Some(120), None),
            )
        })
        .collect::<HashMap<_, _>>();
    if let Err(error) = save_autoroute_cache(
        path,
        DETECTOR_DIGEST,
        RULES_DIGEST,
        config,
        &host,
        &decisions,
    ) {
        panic!("contention writer for config {config_index}, host {host_variant} failed: {error}");
    }
}

fn write_writer(path: &Path, logical_writer: usize) {
    write_spec(path, logical_writer % UNIQUE_WRITERS);
}

fn wait_for_gate(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !path.exists() {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for the parent contention gate"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}
fn wait_for_writer_markers(path: &Path, label: &str) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let count = std::fs::read_dir(path)
            .expect("read writer marker directory")
            .count();
        if count == WRITER_PROCESSES {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for all {WRITER_PROCESSES} contention writers to report {label}; saw {count}"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn wait_for_any_writer_marker(path: &Path, label: &str) {
    let deadline = Instant::now() + WRITER_DEADLOCK_BUDGET;
    loop {
        let count = std::fs::read_dir(path)
            .expect("read writer observation directory")
            .count();
        if count > 0 {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for a contention writer to report {label}"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// Regression: the subprocess endpoint performs one real production save only when explicitly selected by the parent contention test.
#[test]
fn autoroute_cache_contention_writer_subprocess() {
    let Some(cache) = std::env::var_os(CHILD_CACHE_ENV) else {
        return;
    };
    let gate =
        PathBuf::from(std::env::var_os(CHILD_GATE_ENV).expect("contention child gate environment"));
    let ready = PathBuf::from(
        std::env::var_os(CHILD_READY_ENV).expect("contention child ready environment"),
    );
    let attempt = PathBuf::from(
        std::env::var_os(CHILD_ATTEMPT_ENV).expect("contention child attempt environment"),
    );
    let writer = std::env::var(CHILD_WRITER_ENV)
        .expect("contention child writer environment")
        .parse::<usize>()
        .expect("numeric contention writer identity");
    let secret = std::env::var(CHILD_SECRET_ENV).expect("contention child secret sentinel");
    assert_eq!(secret, SECRET_SENTINEL);
    let marker = writer.to_string();
    std::fs::write(ready.join(&marker), []).expect("publish writer readiness");
    wait_for_gate(&gate);
    std::fs::write(attempt.join(marker), []).expect("publish writer lock attempt");
    write_writer(Path::new(&cache), writer % UNIQUE_WRITERS);
}

fn spawn_writer(
    executable: &Path,
    cache: &Path,
    gate: &Path,
    ready: &Path,
    attempt: &Path,
    observe: &Path,
    release: &Path,
    writer: usize,
) -> Child {
    Command::new(executable)
        .args(["--exact", CHILD_TEST_NAME, "--quiet"])
        .env(CHILD_CACHE_ENV, cache)
        .env(CHILD_GATE_ENV, gate)
        .env(CHILD_READY_ENV, ready)
        .env(CHILD_ATTEMPT_ENV, attempt)
        .env(CHILD_WRITER_ENV, writer.to_string())
        .env(CHILD_SECRET_ENV, SECRET_SENTINEL)
        .env(CHILD_OBSERVE_ENV, observe)
        .env(CHILD_RELEASE_ENV, release)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn autoroute cache contention writer")
}

#[cfg(unix)]
fn assert_private(path: &Path, kind: &str) {
    use std::os::unix::fs::PermissionsExt;
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => panic!("stat {kind} {}: {error}", path.display()),
    };
    let mode = metadata.permissions().mode() & 0o777;
    assert_eq!(
        mode,
        0o600,
        "{kind} {} must be private, got mode {mode:o}",
        path.display()
    );
}

#[cfg(not(unix))]
fn assert_private(_path: &Path, _kind: &str) {}

fn inspect_in_flight_artifacts(directory: &Path, cache: &Path, gate: &Path) -> usize {
    if cache.exists() {
        let bytes = std::fs::read(cache).expect("read an atomically published cache generation");
        let parsed: AutorouteCache = serde_json::from_slice(&bytes)
            .expect("every observable cache generation must be complete JSON");
        validate_cache_structure(&parsed)
            .expect("every observable cache generation must have complete structure");
        assert!(
            !bytes
                .windows(SECRET_SENTINEL.len())
                .any(|window| window == SECRET_SENTINEL.as_bytes()),
            "cache generations must never serialize scanned secret material"
        );
        assert_private(cache, "autoroute cache");
    }

    let lock_name = cache
        .file_name()
        .map(|name| {
            let mut name = name.to_os_string();
            name.push(".lock");
            name
        })
        .expect("cache filename");
    let mut temporary_artifacts = 0;
    for entry in std::fs::read_dir(directory).expect("inspect contention directory") {
        let entry = entry.expect("read contention directory entry");
        let name = entry.file_name();
        if entry.path() == cache || entry.path() == gate || name == lock_name {
            continue;
        }
        let mut file = match std::fs::File::open(entry.path()) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => panic!(
                "open in-flight autoroute temp artifact {}: {error}",
                entry.path().display()
            ),
        };
        let metadata = file
            .metadata()
            .expect("inspect open autoroute cache temp artifact");
        assert!(
            metadata.is_file(),
            "atomic cache scratch artifacts must be private regular files"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = metadata.permissions().mode() & 0o777;
            assert_eq!(
                mode,
                0o600,
                "autoroute cache temp artifact {} must be private, got mode {mode:o}",
                entry.path().display()
            );
        }
        temporary_artifacts += 1;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .expect("read open in-flight autoroute temp artifact");
        assert!(
            !bytes
                .windows(SECRET_SENTINEL.len())
                .any(|window| window == SECRET_SENTINEL.as_bytes()),
            "temporary cache artifacts must never contain scanned secret material"
        );
    }
    temporary_artifacts
}

/// Regression: independent processes racing duplicate and distinct generations merge without lost rows, torn JSON, nondeterminism, permissive artifacts, or secret residue.
#[test]
fn multiprocess_writers_publish_one_exact_private_merged_cache() {
    let directory = tempfile::tempdir().expect("create contention directory");
    let cache = directory.path().join("autoroute.json");
    let coordination = tempfile::tempdir().expect("create contention coordination directory");
    let gate = coordination.path().join("writers.go");
    let ready = coordination.path().join("ready");
    let attempt = coordination.path().join("attempt");
    let observe = coordination.path().join("observe");
    let release = coordination.path().join("observed.release");
    std::fs::create_dir(&ready).expect("create writer readiness directory");
    std::fs::create_dir(&attempt).expect("create writer attempt directory");
    std::fs::create_dir(&observe).expect("create writer observation directory");
    let current_executable = std::env::current_exe().expect("resolve current test executable");
    let expected_directory = tempfile::tempdir().expect("create serial reference directory");
    let expected_cache = expected_directory.path().join("autoroute.json");

    for logical_writer in 0..UNIQUE_WRITERS {
        write_writer(&expected_cache, logical_writer);
    }
    let expected = std::fs::read(&expected_cache).expect("read exact serial merge reference");

    let mut children = (0..WRITER_PROCESSES)
        .map(|writer| {
            Some(spawn_writer(
                &current_executable,
                &cache,
                &gate,
                &ready,
                &attempt,
                &observe,
                &release,
                writer,
            ))
        })
        .collect::<Vec<_>>();
    wait_for_writer_markers(&ready, "readiness");
    let parent_lock =
        keyhog_core::StateFileWriteLock::acquire(&cache).expect("hold canonical autoroute lock");
    let lock = keyhog_core::state_file_lock_path(&cache).expect("resolve autoroute lock path");
    assert_private(&lock, "in-flight autoroute cache lock");
    std::fs::write(&gate, []).expect("release contention writers together");
    wait_for_writer_markers(&attempt, "a lock attempt");
    std::thread::sleep(Duration::from_millis(100));
    assert!(
        !cache.exists(),
        "no writer may publish while another process owns the canonical cache lock"
    );
    drop(parent_lock);
    wait_for_any_writer_marker(&observe, "an atomic temp artifact");
    let mut observed_temporary_artifacts =
        inspect_in_flight_artifacts(directory.path(), &cache, &gate);
    assert!(
        observed_temporary_artifacts > 0,
        "the held process publication must expose a private in-flight autoroute temp artifact"
    );
    std::fs::write(&release, []).expect("release observed atomic publication");
    let deadline = Instant::now() + WRITER_DEADLOCK_BUDGET;
    // The synchronized observation above proves a real temp artifact's type,
    // permissions, and secret hygiene. Continue sampling later generations.
    while children.iter().any(Option::is_some) {
        assert!(
            Instant::now() < deadline,
            "autoroute contention writers exceeded the deadlock deadline"
        );
        observed_temporary_artifacts +=
            inspect_in_flight_artifacts(directory.path(), &cache, &gate);
        for child in &mut children {
            let Some(process) = child.as_mut() else {
                continue;
            };
            if process
                .try_wait()
                .expect("poll contention writer")
                .is_none()
            {
                continue;
            }
            let output = child
                .take()
                .expect("completed child process")
                .wait_with_output()
                .expect("collect contention writer output");
            assert!(
                output.status.success(),
                "contention writer failed: status={:?}, stdout={}, stderr={}",
                output.status.code(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        std::thread::sleep(Duration::from_millis(1));
    }

    let actual = std::fs::read(&cache).expect("read final contention cache");
    assert_eq!(
        actual, expected,
        "process write order and exact duplicate identities must produce the exact canonical serial JSON"
    );
    assert!(
        !actual
            .windows(SECRET_SENTINEL.len())
            .any(|window| window == SECRET_SENTINEL.as_bytes()),
        "the final cache must never serialize scanned secret material"
    );
    let parsed: AutorouteCache =
        serde_json::from_slice(&actual).expect("parse exact final contention JSON");
    assert_eq!(parsed.configs.len(), UNIQUE_WRITERS);
    assert!(parsed
        .configs
        .iter()
        .all(|generation| generation.decisions.len() == BUCKET_BYTES.len()));
    assert_private(&cache, "final autoroute cache");

    let lock = keyhog_core::state_file_lock_path(&cache).expect("resolve autoroute lock path");
    assert_private(&lock, "autoroute cache lock");
    assert!(
        std::fs::read(&lock).expect("read lock artifact").is_empty(),
        "lock artifacts must never retain state or secret material"
    );

    let residue = std::fs::read_dir(directory.path())
        .expect("inspect final contention directory")
        .map(|entry| entry.expect("read final directory entry").file_name())
        .filter(|name| {
            name != OsStr::new("autoroute.json") && name != OsStr::new("autoroute.json.lock")
        })
        .collect::<Vec<_>>();
    assert!(
        residue.is_empty(),
        "successful atomic publication must leave no temp residue: {residue:?}; observed {observed_temporary_artifacts} in-flight temp artifacts"
    );
}
