//! Regression (dogfood): `keyhog watch` had no `--backend` escape hatch, so an
//! uncalibrated binary failed EVERY change scan with "autoroute calibration
//! required", and the error even advised `--backend`, a flag watch did not
//! accept. A forced explicit backend must scan WITHOUT consulting the autoroute
//! decision cache, so watch works on an uncalibrated binary.
//!
//! Relocated out of an inline `orchestrator::mod` test module (the orchestrator
//! tree forbids inline `#[cfg(test)]`; the runtime internals are reached through
//! the `CliTestApi` facade instead).

use keyhog::testing::{CliTestApi as _, API};

#[test]
fn forced_cpu_backend_scans_without_autoroute_calibration() {
    // `cpu` => CpuFallback (the scalar regex tier, always available without
    // Hyperscan), forced unconditionally, host-independent, never depends on
    // the host's persisted autoroute decisions the way a bare auto scan would.
    let ids = API
        .forced_backend_runtime_detector_ids("cpu", "AWS_ACCESS_KEY_ID=AKIAQYLPMN5HFIQR7XYA\n")
        .expect("a forced-backend scan must not require autoroute calibration");
    assert!(
        ids.iter().any(|id| id == "aws-access-key"),
        "forced-cpu scan must still detect the planted AWS key; got {ids:?}"
    );
}
