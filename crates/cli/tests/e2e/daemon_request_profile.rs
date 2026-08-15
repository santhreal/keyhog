//! `keyhog scan --daemon --profile` must isolate every daemon request profile
//! by request identity: the daemon measures the scan inside its own
//! profiling runtime, returns a bounded payload keyed by a unique request id,
//! and the client renders it on the operator profile surface.

#![cfg(unix)]

use crate::e2e::support::{binary, DaemonGuard};
use std::io::Write;
use std::process::{Command, Output, Stdio};

fn aws_key_line() -> String {
    format!(
        "AWS_ACCESS_KEY_ID = \"{}\"\n",
        concat!("ASIA", "Y34FZKBOKMUTVV7A")
    )
}

/// Every caller of this helper drives the daemon route, so `--daemon=on` is
/// part of the helper's contract rather than a per-call argument. Declaring it
/// at the subprocess construction site is also what makes the routing intent
/// of these tests visible: a bare `scan` here would ride the implicit default
/// route with no declared backend evidence.
fn daemon_scan(runtime_dir: &std::path::Path, extra_args: &[&str], stdin_bytes: &[u8]) -> Output {
    let mut cmd = Command::new(binary());
    cmd.env("XDG_RUNTIME_DIR", runtime_dir)
        .args(["scan", "--daemon=on", "--stdin", "--format", "json"])
        .args(extra_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn daemon scan");
    child
        .stdin
        .take()
        .expect("child stdin")
        .write_all(stdin_bytes)
        .expect("write stdin");
    child.wait_with_output().expect("daemon scan output")
}

fn profile_id_lines(stderr: &str) -> Vec<&str> {
    stderr
        .lines()
        .filter(|line| line.starts_with("daemon request profile id="))
        .collect()
}

fn request_id_of(line: &str) -> &str {
    line.strip_prefix("daemon request profile id=")
        .and_then(|rest| rest.split_whitespace().next())
        .expect("profile id line carries a request id")
}

/// WHY: before wire v12 the daemon route silently dropped `--profile`, so a
/// daemon-served scan reported no measurements at all. The profiled request
/// must come back with one request profile carrying a daemon-assigned request
/// id, a nonzero wall time, real per-stage call counts, and exact zero loss
/// on a small scan that cannot fill bounded storage.
#[test]
fn daemon_profile_renders_isolated_request_profile() {
    let daemon = DaemonGuard::start_cpu();
    let out = daemon_scan(
        daemon.runtime_dir(),
        &["--profile"],
        aws_key_line().as_bytes(),
    );

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(1),
        "the planted secret must keep the finding exit code; stderr={stderr}"
    );
    let id_lines = profile_id_lines(&stderr);
    assert_eq!(
        id_lines.len(),
        1,
        "one profiled request must produce exactly one profile header; stderr={stderr}"
    );
    let header = id_lines[0];
    let request_id = request_id_of(header);
    assert!(
        request_id.contains('-'),
        "request id must combine daemon generation and sequence: {request_id}"
    );
    let wall_time_ns: u64 = header
        .split_whitespace()
        .find_map(|field| field.strip_prefix("wall_time_ns="))
        .expect("profile header carries wall_time_ns")
        .parse()
        .expect("wall_time_ns is numeric");
    assert!(wall_time_ns > 0, "wall time must be measured: {header}");

    let stage_lines: Vec<&str> = stderr
        .lines()
        .filter(|line| line.starts_with("daemon request stage "))
        .collect();
    assert!(
        !stage_lines.is_empty(),
        "a profiled daemon scan must attribute at least one stage; stderr={stderr}"
    );
    let mut total_calls = 0_u64;
    for line in &stage_lines {
        let calls: u64 = line
            .split_whitespace()
            .find_map(|field| field.strip_prefix("calls="))
            .expect("stage line carries calls")
            .parse()
            .expect("calls is numeric");
        assert!(calls > 0, "a reported stage must have been called: {line}");
        total_calls = total_calls.saturating_add(calls);
    }
    assert!(
        total_calls >= stage_lines.len() as u64,
        "stage call counts must be real measurements: {stage_lines:?}"
    );

    assert!(
        stderr.contains(
            "daemon request profile loss dropped_span_events=0 dropped_point_events=0 dropped_annotations=0 sampled_out_events=0"
        ),
        "a small scan must report exact zero event loss; stderr={stderr}"
    );
}

/// WHY: profiling is opt-in. Without `--profile` the daemon must not build a
/// per-request profiling runtime and the client must render nothing, so the
/// unprofiled path pays no profiling cost and shows no profile fields.
#[test]
fn daemon_scan_without_profile_emits_no_request_profile_lines() {
    let daemon = DaemonGuard::start_cpu();
    let out = daemon_scan(daemon.runtime_dir(), &[], aws_key_line().as_bytes());

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(1),
        "the planted secret must keep the finding exit code; stderr={stderr}"
    );
    assert!(
        !stderr.contains("daemon request profile"),
        "unprofiled daemon scans must not emit profile output; stderr={stderr}"
    );
    assert!(
        !stderr.contains("daemon request stage"),
        "unprofiled daemon scans must not emit stage output; stderr={stderr}"
    );
}

/// WHY: the daemon serves concurrent clients; if profiled requests shared
/// profiling state, concurrent scans would report each other's measurements
/// under the same identity. Two overlapping profiled scans must receive
/// distinct request ids, each with its own isolated stage table.
#[test]
fn concurrent_profiled_daemon_scans_get_distinct_request_ids() {
    let daemon = DaemonGuard::start_cpu();

    let first = std::thread::spawn({
        let runtime_dir = daemon.runtime_dir().to_path_buf();
        let body = aws_key_line();
        move || daemon_scan(&runtime_dir, &["--profile"], body.as_bytes())
    });
    let second = std::thread::spawn({
        let runtime_dir = daemon.runtime_dir().to_path_buf();
        let body = format!("{}\n{}", aws_key_line(), "# second concurrent request\n");
        move || daemon_scan(&runtime_dir, &["--profile"], body.as_bytes())
    });
    let first = first.join().expect("first concurrent scan");
    let second = second.join().expect("second concurrent scan");

    let first_stderr = String::from_utf8_lossy(&first.stderr);
    let second_stderr = String::from_utf8_lossy(&second.stderr);
    assert_eq!(first.status.code(), Some(1), "stderr={first_stderr}");
    assert_eq!(second.status.code(), Some(1), "stderr={second_stderr}");

    let first_ids = profile_id_lines(&first_stderr);
    let second_ids = profile_id_lines(&second_stderr);
    assert_eq!(first_ids.len(), 1, "stderr={first_stderr}");
    assert_eq!(second_ids.len(), 1, "stderr={second_stderr}");
    let first_id = request_id_of(first_ids[0]);
    let second_id = request_id_of(second_ids[0]);
    assert_ne!(
        first_id, second_id,
        "concurrent profiled requests must be isolated by distinct request ids"
    );
    for (label, stderr) in [("first", &first_stderr), ("second", &second_stderr)] {
        assert!(
            stderr.contains("daemon request stage "),
            "{label} request must carry its own stage measurements; stderr={stderr}"
        );
    }
}

/// WHY: the mass transaction protocol profiles every batch inside its own
/// runtime (MassBegin carries the profile flag). A profiled mass scan must
/// surface at least one batch request profile; dropping the flag at MassBegin
/// would silently disable profiling for the whole transaction.
#[test]
fn mass_daemon_profile_renders_per_batch_request_profiles() {
    let daemon = DaemonGuard::start_mass();
    let work = tempfile::TempDir::new().expect("work dir");
    let fixture = work.path().join(".env.leak");
    std::fs::write(&fixture, aws_key_line()).expect("write fixture");

    let out = Command::new(binary())
        .env("XDG_RUNTIME_DIR", daemon.runtime_dir())
        .args(["scan", "--daemon=mass", "--profile", "--format", "json"])
        .arg(work.path())
        .output()
        .expect("spawn mass daemon scan");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(1),
        "the planted secret must keep the finding exit code; stderr={stderr}"
    );
    let id_lines = profile_id_lines(&stderr);
    assert!(
        !id_lines.is_empty(),
        "a profiled mass transaction must render per-batch request profiles; stderr={stderr}"
    );
    let mut distinct = std::collections::HashSet::new();
    for line in &id_lines {
        distinct.insert(request_id_of(line));
    }
    assert_eq!(
        distinct.len(),
        id_lines.len(),
        "every mass batch profile must carry a distinct request id: {id_lines:?}"
    );
}
