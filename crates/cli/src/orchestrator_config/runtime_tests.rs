#[cfg(test)]
use super::{
    gpu_runtime_policy_for_backend_override, gpu_runtime_policy_from_args,
    require_keyhog_owned_rayon_pool, sanitise_thread_count, thread_pool_needs_initialization,
};
#[cfg(test)]
use crate::args::ScanArgs;
#[cfg(test)]
use clap::Parser;
#[cfg(test)]
use keyhog_scanner::{gpu::GpuRuntimePolicy, ScanBackend};

#[cfg(test)]
#[test]
fn explicit_daemon_backend_owns_the_matching_gpu_policy() -> anyhow::Result<()> {
    assert_eq!(
        gpu_runtime_policy_for_backend_override(Some(ScanBackend::GpuCuda))?,
        GpuRuntimePolicy::Required,
    );
    assert_eq!(
        gpu_runtime_policy_for_backend_override(Some(ScanBackend::GpuWgpu))?,
        GpuRuntimePolicy::Required,
    );
    assert_eq!(
        gpu_runtime_policy_for_backend_override(Some(ScanBackend::SimdCpu))?,
        GpuRuntimePolicy::Disabled,
    );
    assert_eq!(
        gpu_runtime_policy_for_backend_override(Some(ScanBackend::CpuFallback))?,
        GpuRuntimePolicy::Disabled,
    );
    assert_eq!(
        gpu_runtime_policy_for_backend_override(None)?,
        GpuRuntimePolicy::Auto,
    );
    Ok(())
}

#[cfg(test)]
#[test]
fn explicit_scan_gpu_peers_are_required() -> anyhow::Result<()> {
    for backend in ["gpu-cuda", "gpu-wgpu"] {
        let args = ScanArgs::try_parse_from(["scan", "--backend", backend, "--stdin"])?;
        assert_eq!(
            gpu_runtime_policy_from_args(&args),
            GpuRuntimePolicy::Required,
            "explicit {backend} must never relax to automatic GPU policy"
        );
    }
    Ok(())
}

#[cfg(test)]
#[test]
fn repeated_rayon_configuration_accepts_the_live_width() -> anyhow::Result<()> {
    assert!(!thread_pool_needs_initialization(Some(16), 16, "test")?);
    assert!(thread_pool_needs_initialization(None, 16, "test")?);
    Ok(())
}

#[cfg(test)]
#[test]
fn repeated_rayon_configuration_rejects_a_different_width() -> anyhow::Result<()> {
    let error = match thread_pool_needs_initialization(Some(16), 8, "test") {
        Ok(_) => panic!("an initialized Rayon pool cannot honor a different width"),
        Err(e) => e.to_string(),
    };
    assert!(
        error.contains("already has 16 threads") && error.contains("requested 8"),
        "mismatch diagnostic must name the live and requested widths: {error}"
    );
    Ok(())
}

#[cfg(test)]
#[test]
fn sanitise_thread_count_rejects_zero() {
    assert_eq!(sanitise_thread_count(0, 16, "test"), 16);
    assert_eq!(sanitise_thread_count(0, 1, "test"), 1);
}

#[cfg(test)]
#[test]
fn externally_owned_same_width_rayon_pool_is_rejected() -> anyhow::Result<()> {
    let error = match require_keyhog_owned_rayon_pool(Err("already initialized"), 16, "test", || 16)
    {
        Ok(_) => panic!("same-width external Rayon ownership must be rejected"),
        Err(e) => e.to_string(),
    };
    assert!(
        error.contains("initialized outside KeyHog")
            && error.contains("KeyHog-owned pool with 16 threads")
            && error.contains("8 MiB worker stacks"),
        "same-width external ownership must fail closed with the unverifiable setting: {error}"
    );
    Ok(())
}
