//! Core scanning engine implementation.

mod backend;
mod backend_dispatch;
mod backend_pattern_hits;
mod backend_prepared;
mod backend_triggered;
pub mod boundary;
mod compile;
mod extract;
mod fallback;
mod fallback_entropy;
mod fallback_entropy_helpers;
mod fallback_generic;
mod gpu_ac_phase1;
mod gpu_cache;
mod gpu_coalesce;
#[allow(dead_code)]
pub mod gpu_decode_scan;
mod gpu_dispatch;
mod gpu_forced;
mod gpu_lazy;
mod gpu_literal_phase1;
mod gpu_megascan;
mod gpu_phase2;
pub(crate) mod gpu_postprocess;
#[allow(dead_code)]
pub mod gpu_program_fusion;
#[allow(dead_code)]
pub mod gpu_regex_dfa;
mod gpu_scan_wrappers;
mod hot_patterns;
mod process;
mod rule_pipeline;
mod scan;
mod scan_filters;
mod scan_postprocess;
pub mod segment_attribution;
mod windowed;

pub(crate) use backend_prepared::{build_simd_scanner, PreparedChunk};
pub use gpu_cache::{AcConstPacks, GpuConstPacks};
pub use gpu_coalesce::coalesce_chunks;
pub use gpu_regex_dfa::{build_regex_dfa, RegexDfaError};
pub use gpu_scan_wrappers::GpuPhase1Output;
pub use rule_pipeline::{
    build_rule_pipeline, megascan_input_len, rule_pipeline_cached, AC_GPU_MAX_MATCHES_PER_DISPATCH,
    MEGASCAN_INPUT_LEN, MEGASCAN_INPUT_LEN_DEFAULT,
};
pub use windowed::{
    floor_char_boundary, line_number_for_offset, next_window_offset, record_window_match,
    window_chunk, window_end_offset,
};

use crate::compiler::*;
use crate::error::Result;
use crate::pipeline::*;
use crate::types::*;
use aho_corasick::AhoCorasick;
use keyhog_core::{Chunk, DetectorSpec, RawMatch};
use std::sync::Arc;
use std::sync::OnceLock;

pub use vyre_libs::scan::LiteralMatch;

/// Read `KEYHOG_PER_CHUNK_TIMEOUT_MS` and turn it into a per-chunk
/// deadline `Instant`. Returns `None` when the env var is unset or
/// malformed - the historical "scan until done" behavior.
///
/// Wired into the public `scan` / `scan_with_backend` entry points
/// so a hostile or pathological input (e.g. the Apple Silicon
/// regex-DFA construction stall surfaced during cross-platform
/// dogfood - a single 171-byte line with `var token = identifier.Flag(...)`
/// shape spends minutes inside the multiline preprocessor) bails
/// after the configured budget instead of hanging the entire
/// `keyhog scan <repo>` run. The CLI orchestrator path runs scans
/// in parallel via rayon; a stuck worker would otherwise keep one
/// core pinned at 100% indefinitely.
///
/// Default unset (no timeout) preserves prior behavior. Recommend
/// `export KEYHOG_PER_CHUNK_TIMEOUT_MS=30000` (30 s) for production
/// scans where bounded latency matters more than scan completeness.
fn env_per_chunk_deadline() -> Option<std::time::Instant> {
    static MS: std::sync::OnceLock<Option<u64>> = std::sync::OnceLock::new();
    let ms = *MS.get_or_init(|| {
        std::env::var("KEYHOG_PER_CHUNK_TIMEOUT_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|&v| v > 0)
    });
    ms.map(|ms| std::time::Instant::now() + std::time::Duration::from_millis(ms))
}

pub enum MlScoreResult {
    /// Score is final and the match can be pushed immediately.
    Final(f64),
    #[cfg(feature = "ml")]
    /// ML scoring is deferred to a batch call at the end of the scan.
    Pending {
        heuristic_conf: f64,
        code_context: crate::context::CodeContext,
        credential: String,
        ml_context: String,
    },
}

pub struct CompiledScanner {
    pub(crate) fragment_cache: crate::fragment_cache::FragmentCache,
    pub(crate) ac: Option<AhoCorasick>,
    pub(crate) gpu_backend: Option<Arc<dyn vyre::VyreBackend>>,
    pub(crate) wgpu_backend: Option<Arc<vyre_driver_wgpu::WgpuBackend>>,
    pub(crate) gpu_literals: Option<Arc<Vec<Vec<u8>>>>,
    pub(crate) gpu_matcher: OnceLock<Option<vyre_libs::scan::GpuLiteralSet>>,
    pub(crate) gpu_const_packs: OnceLock<GpuConstPacks>,
    pub(crate) gpu_ac_const_packs: OnceLock<AcConstPacks>,
    pub(crate) ac_gpu_program: OnceLock<Option<vyre::Program>>,
    pub(crate) rule_pipeline: OnceLock<Option<vyre_libs::scan::RulePipeline>>,
    /// Fused AC + rule pipeline program (single GPU dispatch instead of two).
    /// Lazily built on first access via `fused_program()`.
    pub(crate) fused_program: OnceLock<Option<vyre::Program>>,
    /// Fused decode→scan programs for base64/hex GPU decode.
    /// Lazily built on first access.
    pub(crate) fused_decode_programs: OnceLock<Option<gpu_decode_scan::FusedDecodeScanPrograms>>,
    pub(crate) static_intern: Arc<crate::static_intern::StaticInterner>,
    pub(crate) ac_map: Vec<CompiledPattern>,
    pub(crate) prefix_propagation: Vec<Vec<usize>>,
    pub(crate) fallback: Vec<(CompiledPattern, Vec<String>)>,
    pub(crate) companions: Vec<Vec<CompiledCompanion>>,
    pub(crate) detectors: Vec<DetectorSpec>,
    pub(crate) same_prefix_patterns: Vec<Vec<usize>>,
    pub(crate) fallback_keyword_ac: Option<AhoCorasick>,
    pub(crate) fallback_keyword_to_patterns: Vec<Vec<usize>>,
    pub(crate) fallback_always_active: Vec<bool>,
    #[cfg(feature = "simd")]
    pub(crate) simd_prefilter: Option<crate::simd::backend::HsScanner>,
    #[cfg(feature = "simd")]
    pub(crate) hs_index_map: Vec<Vec<usize>>,
    pub config: ScannerConfig,
    pub alphabet_screen: Option<crate::alphabet_filter::AlphabetScreen>,
    pub(crate) bigram_bloom: crate::bigram_bloom::BigramBloom,
}

const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    let _ = assert_send_sync::<CompiledScanner>;
};

impl CompiledScanner {
    /// Number of loaded detectors.
    pub fn detector_count(&self) -> usize {
        self.detectors.len()
    }

    /// Total number of patterns (AC + fallback).
    pub fn pattern_count(&self) -> usize {
        self.ac_map.len() + self.fallback.len()
    }

    /// Iterator over the FINAL regex source strings (post anchoring /
    /// group extraction / normalization) the scanner uses.
    pub fn pattern_regex_strs(&self) -> Vec<&str> {
        let mut out = Vec::with_capacity(self.ac_map.len() + self.fallback.len());
        out.extend(self.ac_map.iter().map(|p| p.regex.as_str()));
        out.extend(self.fallback.iter().map(|(p, _)| p.regex.as_str()));
        out
    }

    /// Return the preferred backend for a file of the given size.
    #[must_use]
    pub fn select_backend_for_file(&self, file_size: u64) -> crate::hw_probe::ScanBackend {
        crate::hw_probe::select_backend(
            crate::hw_probe::probe_hardware(),
            file_size,
            self.pattern_count(),
        )
    }

    /// Identifier of the GPU backend acquired at compile time, or
    /// None if scanning routes to CPU/SIMD only. Mirrors
    /// `VyreBackend::id()` which returns "cuda", "wgpu", or the
    /// driver-defined name. The startup banner uses this so the
    /// operator can tell at a glance whether they got CUDA (the
    /// headline 5-10x faster path on NVIDIA hardware) or the WGPU
    /// fallback, rather than just "Gpu" which collapses both.
    #[must_use]
    pub fn gpu_backend_label(&self) -> Option<&'static str> {
        self.gpu_backend.as_ref().map(|b| b.id())
    }

    /// Return the steady-state backend label used for startup reporting.
    #[must_use]
    pub fn preferred_backend_label(&self) -> &'static str {
        self.select_backend_for_file(0).label()
    }

    /// Warm backend resources that are initialized lazily during scanning.
    pub fn warm_backend(&self, backend: crate::hw_probe::ScanBackend) -> bool {
        let ready = match backend {
            crate::hw_probe::ScanBackend::Gpu => self.gpu_stack_usable(),
            crate::hw_probe::ScanBackend::MegaScan => {
                let pipeline_ready = self.rule_pipeline().is_some();
                let stack_ready = self.gpu_stack_usable();
                if !pipeline_ready && stack_ready {
                    gpu_forced::deny_silent_megascan_degrade(
                        "regex pipeline compile rejected the detector set",
                    );
                }
                pipeline_ready && stack_ready
            }
            crate::hw_probe::ScanBackend::SimdCpu | crate::hw_probe::ScanBackend::CpuFallback => {
                true
            }
        };
        if !ready {
            gpu_forced::deny_silent_gpu_degrade(self, backend);
        }
        ready
    }

    /// Scan a chunk of text and return all raw credential matches.
    pub fn scan(&self, chunk: &Chunk) -> Vec<RawMatch> {
        self.scan_with_deadline(chunk, env_per_chunk_deadline())
    }

    /// Scan a chunk using a caller-selected backend.
    pub fn scan_with_backend(
        &self,
        chunk: &Chunk,
        backend: crate::hw_probe::ScanBackend,
    ) -> Vec<RawMatch> {
        self.scan_with_deadline_and_backend(chunk, env_per_chunk_deadline(), Some(backend))
    }

    /// Scan multiple chunks using a caller-selected backend.
    pub fn scan_chunks_with_backend(
        &self,
        chunks: &[Chunk],
        backend: crate::hw_probe::ScanBackend,
    ) -> Vec<Vec<RawMatch>> {
        gpu_forced::deny_silent_gpu_degrade(self, backend);
        self.scan_chunks_with_backend_internal(chunks, backend)
    }

    /// Reset the cross-file fragment-reassembly cache.
    pub fn clear_fragment_cache(&self) {
        self.fragment_cache.clear();
    }

    /// Scan a chunk of text against all compiled detectors.
    pub fn scan_with_deadline(
        &self,
        chunk: &Chunk,
        deadline: Option<std::time::Instant>,
    ) -> Vec<RawMatch> {
        self.scan_with_deadline_and_backend(chunk, deadline, None)
    }

    pub fn scan_with_deadline_and_backend(
        &self,
        chunk: &Chunk,
        deadline: Option<std::time::Instant>,
        backend: Option<crate::hw_probe::ScanBackend>,
    ) -> Vec<RawMatch> {
        if let Some(path) = chunk.metadata.path.as_deref() {
            let filename = path.rsplit(['/', '\\']).next().unwrap_or(path);
            if filename == ".keyhog"
                || filename == ".keyhogignore"
                || path.split(['/', '\\']).any(|c| c == "detectors")
            {
                return Vec::new();
            }
        }

        if let Some(screen) = &self.alphabet_screen {
            if !screen.screen(chunk.data.as_bytes()) {
                return Vec::new();
            }
        }

        if chunk.data.len() >= 64 && !self.bigram_bloom.maybe_overlaps(chunk.data.as_bytes()) {
            return Vec::new();
        }

        let selected_backend =
            backend.unwrap_or_else(|| self.select_backend_for_file(chunk.data.len() as u64));
        gpu_forced::deny_silent_gpu_degrade(self, selected_backend);
        tracing::trace!(
            target: "keyhog::routing",
            backend = selected_backend.label(),
            chunk_bytes = chunk.data.len(),
            source_type = chunk.metadata.source_type.as_str(),
            "scan dispatch"
        );
        let mut matches = if chunk.data.len() > MAX_SCAN_CHUNK_BYTES {
            self.scan_windowed(chunk, deadline)
        } else {
            self.scan_inner(chunk, selected_backend, deadline)
        };

        self.post_process_matches(chunk, &mut matches, deadline);

        matches
    }
}
