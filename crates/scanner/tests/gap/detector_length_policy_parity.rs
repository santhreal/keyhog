#[cfg(feature = "entropy")]
#[test]
fn detector_max_length_is_identical_across_available_backends() {
    use keyhog_core::{Chunk, ChunkMetadata};
    use keyhog_scanner::{CompiledScanner, GpuInitPolicy, ScanBackend};

    let mut detectors = keyhog_core::embedded_detector_specs().to_vec();
    detectors
        .iter_mut()
        .find(|detector| detector.id == "generic-api-key")
        .expect("generic API-key detector")
        .max_len = Some(16);
    let scanner = CompiledScanner::compile_with_gpu_policy(detectors, GpuInitPolicy::ForceEnabled)
        .expect("compile scanner with bounded detector");

    let findings = |backend, value: &str| {
        let chunk = Chunk {
            data: format!(r#"{{"api_key":"{value}"}}"#).into(),
            metadata: ChunkMetadata::default(),
        };
        let mut keys = scanner
            .scan_with_backend(&chunk, backend)
            .into_iter()
            .map(|finding| {
                (
                    finding.detector_id.as_ref().to_string(),
                    finding.credential.as_str().to_string(),
                )
            })
            .collect::<Vec<_>>();
        keys.sort();
        keys
    };

    #[cfg(feature = "simd")]
    assert!(
        scanner.warm_backend(ScanBackend::SimdCpu),
        "Hyperscan must initialize on the SIMD test artifact"
    );
    let cases = [
        ("ufnlbbavawsdeec", true),
        ("ufnlbbavawsdeecn", true),
        ("ufnlbbavawsdeecnq", false),
    ];
    #[cfg(feature = "gpu")]
    let require_gpu_parity = keyhog_scanner::probe_hardware().gpu_available;
    #[cfg(feature = "gpu")]
    let mut checked_gpu = false;
    for (value, should_find) in cases {
        let scalar = findings(ScanBackend::CpuFallback, value);
        assert_eq!(
            scalar.iter().any(|(detector, credential)| {
                detector == "generic-api-key" && credential == value
            }),
            should_find,
            "unexpected scalar verdict for {}-byte value",
            value.len(),
        );
        #[cfg(feature = "simd")]
        assert_eq!(
            findings(ScanBackend::SimdCpu, value),
            scalar,
            "Hyperscan drifted at the {}-byte detector boundary",
            value.len(),
        );
        #[cfg(feature = "gpu")]
        for backend in [ScanBackend::GpuCuda, ScanBackend::GpuWgpu] {
            if scanner.warm_backend(backend) {
                checked_gpu = true;
                assert_eq!(
                    findings(backend, value),
                    scalar,
                    "{} drifted at the {}-byte detector boundary",
                    backend.label(),
                    value.len(),
                );
            }
        }
    }
    #[cfg(feature = "gpu")]
    if require_gpu_parity {
        assert!(
            checked_gpu,
            "hardware probing found a GPU, but no GPU backend executed the parity cases"
        );
    }
}
