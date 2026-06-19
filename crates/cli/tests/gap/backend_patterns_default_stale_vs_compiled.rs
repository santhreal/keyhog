//! KH-GAP-106: `backend --patterns` defaults to 1509 but the compiled scanner
//! reports ~5769 patterns in the progress banner — routing matrix lies on fresh installs.

use crate::e2e::support::binary;
use std::path::PathBuf;
use std::process::Command;

fn repo_root() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d
}

#[test]
fn backend_default_pattern_count_matches_compiled_scanner_not_stale_1509() {
    let backend = Command::new(binary())
        .arg("backend")
        .output()
        .expect("spawn backend");
    assert_eq!(backend.status.code(), Some(0));
    let backend_out = String::from_utf8_lossy(&backend.stdout);
    assert!(
        !backend_out.contains("pattern_count = 1509"),
        "backend routing matrix must not use stale default 1509; out={backend_out}"
    );

    let repo = repo_root();
    let demo = repo.join("demo/config/demo-secret.env");
    let progress = Command::new(binary())
        .args([
            "scan",
            demo.to_str().unwrap(),
            "--progress",
            "--backend",
            "simd",
        ])
        .current_dir(&repo)
        .output()
        .expect("spawn scan --progress");
    let stderr = String::from_utf8_lossy(&progress.stderr);
    let compiled = stderr
        .split('(')
        .find_map(|s| {
            s.strip_suffix(" patterns)")
                .or_else(|| s.split(')').next()?.strip_suffix(" patterns"))
        })
        .and_then(|n| n.split_whitespace().last()?.parse::<usize>().ok())
        .or_else(|| {
            stderr
                .split(" patterns)")
                .next()?
                .rsplit_once('(')
                .map(|(_, n)| n.trim().parse::<usize>().ok())?
        })
        .unwrap_or(0);
    assert!(
        compiled > 2000,
        "expected live compiled pattern count in progress banner; stderr={stderr}"
    );
    assert!(
        backend_out.contains(&format!("pattern_count = {compiled}")),
        "backend matrix must cite compiled pattern_count={compiled}; out={backend_out}"
    );
}
