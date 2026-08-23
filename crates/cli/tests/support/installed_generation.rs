//! One prepared installation, shared by every suite that scans a hermetic cache.
//!
//! `keyhog install` is the only install path: it compiles and signs an
//! execution-pack generation and then calibrates autoroute against that exact
//! generation. A fixture that publishes packs but skips calibration leaves a
//! cache whose default `auto` scan fails closed with exit 2, which is the
//! product contract for a missing routing decision, not a test artifact.
//!
//! `#[path]`-included by the suites that need it, so each test binary prepares
//! the generation once and clones it per test.
#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::LazyLock;

/// The bounded CI calibration ladder. A `ci-lean` binary honors these sentinels
/// and probes five workloads; a default-feature binary has no fixture plan
/// compiled in and measures the full production ladder instead.
#[cfg(feature = "ci-lean")]
const CALIBRATION_FIXTURE: &[(&str, &str)] = &[
    (
        "KEYHOG_CI_AUTOROUTE_TIMING_FIXTURE",
        "confidence-separated-v1",
    ),
    (
        "KEYHOG_CI_AUTOROUTE_FIXTURE_AUTH",
        "bench-backend-parity-v1",
    ),
    ("KEYHOG_CI_AUTOROUTE_WORKLOAD_FIXTURE", "bounded-e2e-v1"),
    (
        "KEYHOG_CI_AUTOROUTE_WORKLOAD_FIXTURE_AUTH",
        "core-workload-plan-v1",
    ),
];
#[cfg(not(feature = "ci-lean"))]
const CALIBRATION_FIXTURE: &[(&str, &str)] = &[];

/// `(install root, installed cache directory)`. The cache directory holds
/// `execution-packs/` (generation plus `signing.key`) and `autoroute.json`.
static PREPARED_INSTALLATION: LazyLock<(tempfile::TempDir, PathBuf)> = LazyLock::new(|| {
    let directory = tempfile::tempdir().expect("temporary install root");
    let cache_home = directory.path().join("cache");
    fs::create_dir_all(&cache_home).expect("create hermetic cache home");

    let mut install = Command::new(env!("CARGO_BIN_EXE_keyhog"));
    install
        .arg("install")
        .env("HOME", directory.path())
        .env("XDG_CACHE_HOME", &cache_home)
        .env("NO_COLOR", "1");
    for (key, value) in CALIBRATION_FIXTURE {
        install.env(key, value);
    }
    // Working directory is inherited on purpose: calibration and the scans that
    // reuse its decisions must resolve the same detector corpus and scan
    // config, and both are resolved from the working directory.
    let result = install.output().expect("run keyhog install");
    assert!(
        result.status.success(),
        "keyhog install failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );

    let installed = cache_home.join("keyhog");
    assert!(
        installed.join("execution-packs/current").is_dir(),
        "keyhog install must publish an execution-pack generation"
    );
    // A single-backend build (portable default features) routes direct and
    // publishes no calibration table, matching `calibrate-autoroute` and the
    // fail-closed scan checks, which are all gated on the same predicate.
    if keyhog_scanner::hw_probe::multiple_backends_compiled() {
        assert!(
            installed.join("autoroute.json").is_file(),
            "keyhog install must publish autoroute calibration"
        );
    }
    (directory, installed)
});

pub fn copy_dir_all(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).expect("create destination directory");
    for entry in fs::read_dir(src).expect("read source directory") {
        let entry = entry.expect("read directory entry");
        let path = entry.path();
        let destination = dst.join(entry.file_name());
        if path.is_dir() {
            copy_dir_all(&path, &destination);
        } else {
            fs::copy(&path, &destination).expect("copy installed artifact");
        }
    }
}

/// Clone the prepared installation into `cache_home`: the execution-pack
/// generation, its verification key, and the pack-bound autoroute decisions.
/// Returns `(pack_root, current_generation)`.
pub fn clone_prepared_installation(cache_home: &Path) -> (PathBuf, PathBuf) {
    let (_root, installed) = &*PREPARED_INSTALLATION;
    let target = cache_home.join("keyhog");
    fs::create_dir_all(&target).expect("create cloned cache root");
    let pack_root = target.join("execution-packs");
    copy_dir_all(&installed.join("execution-packs"), &pack_root);
    let autoroute_src = installed.join("autoroute.json");
    if autoroute_src.is_file() {
        fs::copy(&autoroute_src, target.join("autoroute.json"))
            .expect("clone autoroute calibration");
    }
    let current = pack_root.join("current");
    (pack_root, current)
}
