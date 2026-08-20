//! WHY: Closes the defect class where host width had no canonical owner and was queried
//! independently across 16 sites with conflicting fallback defaults (Row 110).
//! Without a single owner and provenance tracking, container cgroups, sandboxes, or platform probe
//! failures cause identity, autoroute decisions, and scheduling pools to see divergent host widths.
//!
//! What this does NOT catch: OS kernel CPU hotplug events occurring mid-process lifetime.

use keyhog_profile::{
    clear_host_parallelism_override, host_parallelism, logical_cpu_count, logical_cpus,
    set_forced_probe_failure, set_host_parallelism_override, HostIdentityV2, HostParallelism,
    ParallelismProvenance, RunIdentity, FALLBACK_LOGICAL_CPUS,
};
use parking_lot::Mutex;

static TEST_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn row_110_host_parallelism_canonical_resolution_and_provenance() {
    let _guard = TEST_LOCK.lock();
    clear_host_parallelism_override();
    set_forced_probe_failure(false);

    let p = host_parallelism();
    assert!(p.logical_cpus >= 1);
    assert_eq!(p.provenance, ParallelismProvenance::Platform);
    assert_eq!(logical_cpus(), p.logical_cpus);
    assert_eq!(logical_cpu_count(), p.logical_cpus as usize);

    // Host identity must agree exactly with resolved host parallelism
    let host_id = HostIdentityV2::capture();
    assert_eq!(host_id.logical_cpus, p.logical_cpus);

    // RunIdentity must agree exactly with resolved host parallelism
    let run_id = RunIdentity::new("0.5.82", "detectors", "config", "test", "test", "cpu-simd");
    assert_eq!(run_id.logical_cpus, p.logical_cpus as usize);
}

#[test]
fn row_110_forced_probe_failure_uses_single_written_fallback_with_provenance() {
    let _guard = TEST_LOCK.lock();
    clear_host_parallelism_override();
    set_forced_probe_failure(true);

    let p = host_parallelism();
    assert_eq!(p.logical_cpus, FALLBACK_LOGICAL_CPUS);
    assert_eq!(p.provenance, ParallelismProvenance::FallbackDefault);
    assert_eq!(p.provenance.as_str(), "fallback-default");

    // Clean up
    set_forced_probe_failure(false);
}

#[test]
fn row_110_configuration_override_bounds_host_parallelism() {
    let _guard = TEST_LOCK.lock();
    set_forced_probe_failure(false);
    // Set an explicit operator constraint (e.g. bounding a 64-core machine to 8 cores)
    set_host_parallelism_override(8);

    let p = host_parallelism();
    assert_eq!(p.logical_cpus, 8);
    assert_eq!(p.provenance, ParallelismProvenance::Configured);
    assert_eq!(p.provenance.as_str(), "configured");
    assert_eq!(logical_cpus(), 8);
    assert_eq!(logical_cpu_count(), 8);

    let host_id = HostIdentityV2::capture();
    assert_eq!(host_id.logical_cpus, 8);

    clear_host_parallelism_override();
}

#[test]
fn row_110_provenance_variant_space_sweep() {
    // Derive all provenance variants from source at runtime
    for v in ParallelismProvenance::ALL {
        let text = v.as_str();
        assert!(!text.is_empty());
        let p = HostParallelism {
            version: 1,
            logical_cpus: 4,
            provenance: v,
        };
        let json = serde_json::to_string(&p).expect("serialize HostParallelism");
        assert!(json.contains(text));
    }
}
