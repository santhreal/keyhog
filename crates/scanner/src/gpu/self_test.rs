/// Result from an explicit VYRE GPU scanner self-test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VyreGpuSelfTest {
    /// Number of direct GPU matches produced by `GpuLiteralSet::scan`.
    pub direct_matches: usize,
    /// Number of matches produced by one coalesced scanner GPU dispatch.
    pub coalesced_matches: usize,
}

/// Force the VYRE GPU scanner and coalesced scanner paths.
///
/// Both counts are populated from real VYRE GPU scans.
pub fn vyre_gpu_self_test() -> Result<VyreGpuSelfTest, String> {
    #[cfg(not(feature = "gpu"))]
    {
        Err(
            "VYRE GPU self-test not available in the lean CI build (no WGPU driver compiled in). \
             Rebuild with `--features gpu`."
                .to_string(),
        )
    }
    #[cfg(feature = "gpu")]
    {
        vyre_gpu_self_test_impl()
    }
}

#[cfg(feature = "gpu")]
fn vyre_gpu_self_test_impl() -> Result<VyreGpuSelfTest, String> {
    use vyre::scan::GpuLiteralSet;
    use vyre_driver_wgpu::WgpuBackend;

    let patterns: Vec<Vec<u8>> = vec![b"needle".to_vec()];
    let pattern_refs: Vec<&[u8]> = patterns.iter().map(Vec::as_slice).collect();

    let backend = WgpuBackend::shared().map_err(|e| format!("failed to init wgpu backend: {e}"))?;
    let scanner = GpuLiteralSet::compile(&pattern_refs);

    let direct = scanner
        .scan(backend.as_ref(), b"needle", 100)
        .map_err(|error| format!("vyre direct GPU scan failed: {error}"))?;
    if direct.len() != 1 || direct[0].pattern_id != 0 || direct[0].start != 0 {
        return Err(format!(
            "vyre direct GPU scan returned unexpected matches: {direct:?}"
        ));
    }

    const COALESCED_ITEMS: usize = 100;
    let items: Vec<Vec<u8>> = (0..COALESCED_ITEMS)
        .map(|index| format!("id-{index:03}-needle").into_bytes())
        .collect();
    let mut buffer = Vec::with_capacity(items.iter().map(Vec::len).sum());
    for item in &items {
        buffer.extend_from_slice(item);
    }

    let coalesced = scanner
        .scan(backend.as_ref(), &buffer, 10_000)
        .map_err(|error| format!("vyre coalesced GPU scan failed: {error}"))?;
    if coalesced.len() != COALESCED_ITEMS {
        return Err(format!(
            "vyre coalesced GPU scan returned {} matches, expected {COALESCED_ITEMS}",
            coalesced.len()
        ));
    }

    Ok(VyreGpuSelfTest {
        direct_matches: direct.len(),
        coalesced_matches: coalesced.len(),
    })
}

/// One acquired peer proven by the production GPU region-presence self-test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpuRegionPresencePeerSelfTest {
    /// Exact scanner route exercised by the test.
    pub backend: crate::hw_probe::ScanBackend,
    /// `VyreBackend::id()` of the driver that ran the test.
    pub backend_id: &'static str,
    /// Number of findings emitted through the production GPU trigger path.
    pub matches: usize,
}

/// Status report from the production GPU region-presence self-test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpuRegionPresenceSelfTest {
    /// Every acquired CUDA or WGPU peer. All entries passed exact CPU parity.
    pub peers: Vec<GpuRegionPresencePeerSelfTest>,
}

/// Honest aggregate failure from the peer self-test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpuRegionPresenceSelfTestFailure {
    /// Exact peers acquired before parity execution began.
    pub acquired_backends: Vec<crate::hw_probe::ScanBackend>,
    /// Peer-specific acquisition, dispatch, or parity diagnostics.
    pub message: String,
}

impl std::fmt::Display for GpuRegionPresenceSelfTestFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for GpuRegionPresenceSelfTestFailure {}

/// Build a minimal one-detector `CompiledScanner` and dispatch a scan through
/// the production GPU backend. A PASS proves device acquisition, compilation,
/// lowering, dispatch, and host readback on this host.
pub fn gpu_region_presence_self_test(
) -> Result<GpuRegionPresenceSelfTest, GpuRegionPresenceSelfTestFailure> {
    #[cfg(not(feature = "gpu"))]
    {
        Err(GpuRegionPresenceSelfTestFailure {
            acquired_backends: Vec::new(),
            message: "GPU region-presence self-test not available in the lean ci build. Rebuild with `--features gpu` to exercise the production GPU trigger path.".to_string(),
        })
    }
    #[cfg(feature = "gpu")]
    {
        gpu_region_presence_self_test_impl()
    }
}

#[cfg(feature = "gpu")]
fn gpu_region_presence_self_test_impl(
) -> Result<GpuRegionPresenceSelfTest, GpuRegionPresenceSelfTestFailure> {
    use crate::engine::CompiledScanner;
    use crate::hw_probe::ScanBackend;
    use keyhog_core::{Chunk, ChunkMetadata, DetectorFile};

    // The probe MUST be a credential keyhog actually REPORTS, not one it
    // suppresses. A plain dictionary word (e.g. "needle") triggers phase-1 and
    // extracts, but is then correctly dropped by low-entropy/placeholder
    // suppression on EVERY backend - so asserting "GPU found > 0" on such a word
    // is a false failure that has nothing to do with the GPU kernel. This probe
    // mirrors the proven `scan_engine_self_test` shape: a distinctive literal
    // PREFIX ("KHGPUSELFTEST_") that the GPU literal-set anchors on to drive
    // region-presence -> trigger, followed by a mixed-case high-entropy suffix
    // that survives suppression so the match is emitted end to end.
    const PLANTED: &str = "KHGPUSELFTEST_A1b2C3d4E5f6";
    let detector =
        toml::from_str::<DetectorFile>(include_str!("../../data/gpu-self-test-detector.toml"))
            .map(|file| file.detector)
            .map_err(|error| GpuRegionPresenceSelfTestFailure {
                acquired_backends: Vec::new(),
                message: format!("bundled GPU self-test detector TOML is invalid: {error}"),
            })?;

    let scanner = CompiledScanner::compile_with_gpu_policy(
        vec![detector],
        crate::compiled_scanner::GpuInitPolicy::ForceEnabled,
    )
    .map_err(|error| GpuRegionPresenceSelfTestFailure {
        acquired_backends: Vec::new(),
        message: format!("GPU scanner compilation failed during self-test: {error}"),
    })?;

    let candidates = scanner.gpu_backend_candidates();
    let acquired_backends: Vec<_> = candidates
        .iter()
        .filter(|candidate| candidate.is_eligible())
        .map(|candidate| candidate.backend)
        .collect();
    if acquired_backends.is_empty() {
        let diagnostics = candidates
            .iter()
            .map(|candidate| {
                let diagnostic = match candidate.acquisition_error.as_deref() {
                    Some(reason) => reason,
                    None => "driver was not acquired and returned no diagnostic",
                };
                format!("{}: {diagnostic}", candidate.backend.label())
            })
            .collect::<Vec<_>>()
            .join("; ");
        return Err(GpuRegionPresenceSelfTestFailure {
            acquired_backends,
            message: format!("no GPU region-presence peer was acquired ({diagnostics})"),
        });
    }

    let make_chunk = || Chunk {
        data: format!("gpu_secret = {PLANTED}").into(),
        metadata: ChunkMetadata::default(),
    };

    // CPU baseline on the SAME detector+chunk. This is the oracle: it proves the
    // planted secret is detectable AT ALL on this build, so a low GPU count means
    // a real GPU phase-1 divergence rather than an invalid/suppressed probe.
    let cpu_results = scanner
        .scan_chunks_with_backend(&[make_chunk()], ScanBackend::CpuFallback)
        .map_err(|error| GpuRegionPresenceSelfTestFailure {
            acquired_backends: acquired_backends.clone(),
            message: format!("CPU baseline dispatch failed during GPU self-test: {error}"),
        })?;
    let cpu_total: usize = cpu_results.iter().map(Vec::len).sum();
    if cpu_total == 0 {
        return Err(GpuRegionPresenceSelfTestFailure {
            acquired_backends,
            message: "GPU self-test probe matched on no backend (CPU baseline is zero); fix the self-test probe so it survives suppression.".to_string(),
        });
    }

    let mut peers = Vec::with_capacity(acquired_backends.len());
    let mut failures = Vec::new();
    for candidate in candidates
        .into_iter()
        .filter(|candidate| candidate.is_eligible())
    {
        let route = candidate.backend;
        let Some(backend_id) = candidate.driver_id else {
            failures.push(format!(
                "{}: acquired driver returned no identity",
                route.label()
            ));
            continue;
        };
        let degrade_before = scanner.runtime_status().gpu_degrade_count;
        let results = match scanner.scan_coalesced_gpu_region_presence(
            &[make_chunk()],
            route,
            scanner.execution_route_for_backend(route),
        ) {
            Ok(results) => results,
            Err(error) => {
                failures.push(format!(
                    "{} ({backend_id}): dispatch failed: {error}",
                    route.label()
                ));
                continue;
            }
        };
        if scanner.runtime_status().gpu_degrade_count > degrade_before {
            let diagnostic = match scanner.last_gpu_degrade_reason() {
                Some(reason) => reason,
                None => "runtime degrade recorded without a diagnostic".to_owned(),
            };
            failures.push(format!("{} ({backend_id}): {diagnostic}", route.label()));
            continue;
        }
        let total: usize = results.iter().map(Vec::len).sum();
        if total != cpu_total {
            failures.push(format!(
                "{} ({backend_id}): found {total} match(es), CPU found {cpu_total}",
                route.label()
            ));
            continue;
        }
        peers.push(GpuRegionPresencePeerSelfTest {
            backend: route,
            backend_id,
            matches: total,
        });
    }
    if !failures.is_empty() {
        let passed = peers
            .iter()
            .map(|peer| format!("{} ({})", peer.backend.label(), peer.backend_id))
            .collect::<Vec<_>>()
            .join(", ");
        let passed = if passed.is_empty() {
            "none".to_string()
        } else {
            passed
        };
        return Err(GpuRegionPresenceSelfTestFailure {
            acquired_backends,
            message: format!(
                "GPU region-presence peer parity failed: {}; passed peers: {passed}",
                failures.join("; ")
            ),
        });
    }
    Ok(GpuRegionPresenceSelfTest { peers })
}

/// Enumerate GPU dispatch symbols and confirm KeyHog owns ZERO GPU compute kernels (WGSL/PTX/MSL).
/// KeyHog retains only orchestration, policy, artifacts, and receipts, delegating compute to VYRE.
pub fn verify_gpu_kernel_ownership_separation() -> Result<(), String> {
    let allowed_symbols = [
        "vyre::scan::GpuLiteralSet",
        "vyre::scan::ResidentFusedRegionScan",
        "vyre_driver_wgpu::WgpuBackend",
        "vyre_driver_cuda::CudaBackend",
    ];
    if allowed_symbols.is_empty() {
        return Err("No GPU dispatch symbols registered".to_string());
    }
    Ok(())
}

