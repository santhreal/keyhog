//! Shared helpers for scanner integration tests.
//!
//! Each `tests/*.rs` file is its own integration-test crate that pulls this
//! tree in via `mod support;`. A given runner uses only the submodules it
//! needs, so any helper unused by *that* binary trips `dead_code`: an
//! artifact of cargo's per-binary test compilation, not real dead code (every
//! helper here is exercised by at least one runner). Silence it tree-wide
//! rather than scatter per-item attributes.
#![allow(dead_code)]

use keyhog_scanner::CompiledScanner;

pub mod contracts;
pub mod gpu_gate;
pub mod paths;
pub mod vendorgen;

pub fn compile_full_detector_scanner() -> CompiledScanner {
    let detectors = keyhog_core::load_detectors(&paths::detector_dir()).expect("detectors");
    CompiledScanner::compile(detectors).expect("compile")
}

pub struct ExactCpuScanners {
    simd: CompiledScanner,
    scalar: CompiledScanner,
}

impl ExactCpuScanners {
    pub fn compile(detectors: Vec<keyhog_core::DetectorSpec>) -> keyhog_scanner::Result<Self> {
        let simd = CompiledScanner::compile_for_backend(
            detectors.clone(),
            keyhog_scanner::ScanBackend::SimdCpu,
        )?;
        let scalar = CompiledScanner::compile_for_backend(
            detectors,
            keyhog_scanner::ScanBackend::CpuFallback,
        )?;
        Ok(Self { simd, scalar })
    }

    fn selected(&self, backend: keyhog_scanner::ScanBackend) -> &CompiledScanner {
        match backend {
            keyhog_scanner::ScanBackend::SimdCpu => &self.simd,
            keyhog_scanner::ScanBackend::CpuFallback => &self.scalar,
            _ => panic!("ExactCpuScanners supports only the two CPU backends"),
        }
    }

    pub fn clear_fragment_cache(&self) {
        self.simd.clear_fragment_cache();
        self.scalar.clear_fragment_cache();
    }

    pub fn scan_with_backend(
        &self,
        chunk: &keyhog_core::Chunk,
        backend: keyhog_scanner::ScanBackend,
    ) -> keyhog_scanner::Result<Vec<keyhog_core::RawMatch>> {
        self.selected(backend).scan_with_backend(chunk, backend)
    }

    pub fn scan_chunks_with_backend(
        &self,
        chunks: &[keyhog_core::Chunk],
        backend: keyhog_scanner::ScanBackend,
    ) -> keyhog_scanner::Result<Vec<Vec<keyhog_core::RawMatch>>> {
        self.selected(backend)
            .scan_chunks_with_backend(chunks, backend)
    }
}
