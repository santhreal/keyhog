//! Shared helpers for end-to-end binary tests.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
#[cfg(unix)]
use std::sync::{Mutex, MutexGuard, OnceLock};
use tempfile::TempDir;

pub fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

pub fn keyhog_command(args: &[&str]) -> Command {
    let mut cmd = Command::new(binary());
    apply_default_scan_backend(&mut cmd, args);
    cmd
}

pub fn apply_default_scan_backend(cmd: &mut Command, args: &[&str]) {
    if args.first() == Some(&"scan") && !args.iter().any(|arg| *arg == "--backend") {
        cmd.arg("scan").args(["--backend", "simd"]).args(&args[1..]);
    } else {
        cmd.args(args);
    }
}

pub fn run(args: &[&str]) -> Output {
    keyhog_command(args).output().expect("spawn keyhog")
}

pub fn workspace_detectors() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../detectors")
        .canonicalize()
        .expect("workspace detectors dir")
}

/// Write `content` to a temp file, scan with `--format json`, return output.
pub fn scan_text_file(content: &str, extra_args: &[&str]) -> (String, String, Option<i32>) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("planted.txt");
    std::fs::write(&path, content).expect("write fixture");

    let mut cmd_args: Vec<String> = vec![
        "scan".into(),
        "--no-daemon".into(),
        "--format".into(),
        "json".into(),
        "--backend".into(),
        "simd".into(),
    ];
    for arg in extra_args {
        cmd_args.push((*arg).into());
    }
    cmd_args.push(path.to_string_lossy().into_owned());

    let output = Command::new(binary())
        .args(&cmd_args)
        .output()
        .expect("spawn keyhog scan");

    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
        output.status.code(),
    )
}

pub fn write_temp_file(name: &str, content: &str) -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join(name);
    std::fs::write(&path, content).expect("write fixture");
    (dir, path)
}

pub fn scan_path(path: &Path, extra_args: &[&str]) -> Output {
    let mut args = vec![
        "scan",
        "--no-daemon",
        "--format",
        "json",
        "--backend",
        "simd",
    ];
    args.extend(extra_args);
    args.push(path.to_str().expect("utf-8 path"));
    Command::new(binary())
        .args(&args)
        .output()
        .expect("spawn keyhog scan")
}

#[cfg(unix)]
pub struct DaemonGuard {
    _slot: MutexGuard<'static, ()>,
    runtime: TempDir,
    child: std::process::Child,
}

#[cfg(unix)]
fn daemon_slot() -> MutexGuard<'static, ()> {
    static DAEMON_SLOT: OnceLock<Mutex<()>> = OnceLock::new();
    DAEMON_SLOT
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(unix)]
impl DaemonGuard {
    pub fn start() -> Self {
        Self::start_with_env(&[])
    }

    pub fn start_with_env(envs: &[(&str, &str)]) -> Self {
        use std::process::Stdio;
        use std::time::{Duration, Instant};

        let slot = daemon_slot();
        let runtime = TempDir::new().expect("runtime dir");
        let detectors = workspace_detectors();
        let mut cmd = Command::new(binary());
        cmd.env("XDG_RUNTIME_DIR", runtime.path());
        for (key, value) in envs {
            cmd.env(key, value);
        }
        let mut child = cmd
            .args([
                "daemon",
                "start",
                "--backend",
                "simd",
                "--detectors",
                detectors.to_str().expect("detectors path"),
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn keyhog daemon");

        let socket = runtime.path().join("keyhog.sock");
        let deadline = Instant::now() + Duration::from_secs(120);
        while !socket.exists() {
            if Instant::now() >= deadline {
                let output = child
                    .wait_with_output()
                    .expect("collect timed-out daemon output");
                panic!(
                    "daemon socket did not appear in time; status={:?}; stdout={}; stderr={}",
                    output.status.code(),
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            if let Some(status) = child.try_wait().expect("poll daemon startup") {
                let output = child
                    .wait_with_output()
                    .expect("collect exited daemon output");
                panic!(
                    "daemon exited before binding socket; status={:?}; stdout={}; stderr={}",
                    status.code(),
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            std::thread::sleep(Duration::from_millis(50));
        }

        Self {
            _slot: slot,
            runtime,
            child,
        }
    }

    pub fn runtime_dir(&self) -> &Path {
        self.runtime.path()
    }
}

#[cfg(unix)]
impl Drop for DaemonGuard {
    fn drop(&mut self) {
        let _ = Command::new(binary())
            .env("XDG_RUNTIME_DIR", self.runtime.path())
            .args(["daemon", "stop"])
            .output();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
