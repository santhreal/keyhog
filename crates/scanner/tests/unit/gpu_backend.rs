use super::*;
#[cfg(target_os = "linux")]
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Locks out accidental CUDA, Metal, or WGPU driver work on the production
/// CPU-absence state by proving every exact backend identity remains uninitialized.
#[test]
fn default_backend_peers_are_cpu_absent_and_lazy() {
    let peers = GpuBackendPeers::default();
    assert_eq!(peers.availability(), GpuBackendAvailability::default());
    for backend in [
        crate::ScanBackend::GpuCuda,
        crate::ScanBackend::GpuMetal,
        crate::ScanBackend::GpuWgpu,
    ] {
        assert!(peers.get(backend).is_none());
        assert!(peers.initialized(backend).is_none());
        assert!(peers.initialization_error(backend).is_none());
    }
}

/// Locks out probing or acquiring either GPU backend when census reports a
/// CPU-only host; the lazy closure must remain completely untouched.
#[test]
fn unavailable_peer_never_runs_lazy_acquisition() {
    let slot = OnceLock::<Result<usize, String>>::new();
    let calls = AtomicUsize::new(0);
    let result = lazy_acquire(false, &slot, || {
        calls.fetch_add(1, Ordering::Relaxed);
        Ok(7)
    });
    assert!(result.is_none());
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    assert!(slot.get().is_none());
}

/// Locks out duplicate CUDA/WGPU lifecycle work by proving each backend's
/// independent slot acquires at most once and retains its own identity.
#[test]
fn backend_slots_are_lazy_once_and_identity_preserving() {
    let cuda = OnceLock::<Result<&'static str, String>>::new();
    let wgpu = OnceLock::<Result<&'static str, String>>::new();
    let calls = AtomicUsize::new(0);
    for _ in 0..2 {
        let cuda_result = lazy_acquire(true, &cuda, || {
            calls.fetch_add(1, Ordering::Relaxed);
            Ok("cuda")
        })
        .expect("available CUDA slot must initialize");
        assert_eq!(
            cuda_result.as_ref().expect("synthetic CUDA acquisition"),
            &"cuda"
        );
        let wgpu_result = lazy_acquire(true, &wgpu, || {
            calls.fetch_add(1, Ordering::Relaxed);
            Ok("wgpu")
        })
        .expect("available WGPU slot must initialize");
        assert_eq!(
            wgpu_result.as_ref().expect("synthetic WGPU acquisition"),
            &"wgpu"
        );
    }
    assert_eq!(calls.load(Ordering::Relaxed), 2);
}

/// Locks out cudarc's release-build abort path by proving a failed dynamic
/// library preflight prevents the CUDA acquisition closure from running.
#[cfg(target_os = "linux")]
#[test]
fn failed_cuda_preflight_short_circuits_acquisition() {
    let acquired = AtomicBool::new(false);
    let error = run_cuda_after_preflight(
        || Err("synthetic missing libcuda".to_owned()),
        || {
            acquired.store(true, Ordering::Relaxed);
            Ok(())
        },
        "backend acquisition",
    )
    .expect_err("a failed driver preflight must fail CUDA acquisition");
    assert_eq!(error, "synthetic missing libcuda");
    assert!(!acquired.load(Ordering::Relaxed));
}
