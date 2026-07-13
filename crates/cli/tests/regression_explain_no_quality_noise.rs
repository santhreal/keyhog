//! Regression (dogfood): `keyhog explain <detector>` must not spam internal
//! detector-quality advisories.
//!
//! `explain` loads the whole detector set to resolve one id and show related
//! detectors. Loading ran the quality gate, which emitted a `WARN quality: ...`
//! line for every advisory (non-rejecting) nit across ALL detectors - e.g.
//! "companion regex is a pure character class; allowed because within_lines<=5"
//! - plus an aggregate "quality gate: N warnings". Those are authoring nits on
//! the already-validated, shipped detector set, irrelevant to a user asking to
//! explain ONE detector, and they buried the actual explanation under a dozen
//! lines of stderr noise. They now log at debug!; default `explain` is quiet.
//!
//! The real rejection/error signals (a detector that FAILS the gate) stay loud
//! and are covered by the core spec-load tests.

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

#[test]
fn explain_does_not_emit_advisory_quality_warnings_at_default_level() {
    let output = Command::new(binary())
        .args(["explain", "github-classic-pat"])
        .output()
        .expect("spawn keyhog explain");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // The explanation itself must still render on stdout.
    assert!(
        stdout.contains("github-classic-pat") && stdout.contains("GitHub Classic PAT"),
        "explain must print the detector spec on stdout; stdout was:\n{stdout}"
    );

    // No advisory quality noise on stderr at default verbosity.
    let noise: Vec<&str> = stderr
        .lines()
        .filter(|l| l.contains("quality: ") || l.contains("quality gate:"))
        .collect();
    assert!(
        noise.is_empty(),
        "explain must not emit advisory detector-quality warnings at default \
         level (they are debug! authoring feedback); saw {} line(s):\n{}",
        noise.len(),
        noise.join("\n")
    );
}
