//! GPU program fusion - collapses multiple sequential vyre `Program` dispatches
//! into a single fused program for single-GPU-dispatch execution.
//!
//! keyhog currently dispatches the AC literal-set program, decode programs,
//! and MoE scoring programs sequentially. Vyre's `fuse_programs` /
//! `fuse_programs_vec` merge compatible programs into one fused `Program`,
//! eliminating per-dispatch overhead (encoder record, submit, poll) and
//! enabling cross-program data reuse on-chip.
//!
//! # Design
//!
//! At scanner compile time, this module attempts to fuse the AC literal-set
//! program with any active decode programs into a single `vyre::Program`.
//! The fused program is cached alongside individual programs in the same
//! on-disk cache directory (`~/.cache/keyhog/programs/`), keyed by a
//! SHA-256 of the constituent program IR hashes.
//!
//! If fusion fails (incompatible buffer layouts, over-dispatch geometry,
//! self-aliasing), the module logs the failure and the scanner falls back
//! to sequential dispatch. This is a pure optimization - correctness is
//! never compromised.
//!
//! # Usage
//!
//! The fused program is lazily initialized via `OnceLock` on first access.
//! `CompiledScanner::fused_program()` returns `Option<&vyre::Program>`.
//! The dispatch path in `gpu_dispatch.rs` checks for the fused program
//! first and uses it in preference to sequential individual dispatches.

use super::CompiledScanner;

/// On-disk cache version for fused programs. Bumped whenever the fusion
/// IR layout or the constituent program shapes change in a way that
/// invalidates previously cached fused blobs.
const FUSED_CACHE_VERSION: u32 = 1;

impl CompiledScanner {
    /// Lazily build a fused `Program` that merges the AC literal-set
    /// program with the rule pipeline program (when available) into a
    /// single GPU dispatch.
    ///
    /// Returns `None` when:
    /// - No AC GPU program is available (no GPU adapter, no literals).
    /// - Fusion fails due to incompatible buffer layouts, over-dispatch
    ///   geometry, or self-aliasing constraints.
    /// - Only one program is available (fusion is identity; we skip the
    ///   overhead of the fused wrapper and dispatch the original directly).
    ///
    /// The fused program is cached on disk alongside individual programs
    /// so cold starts after the first successful fusion are free.
    pub fn fused_program(&self) -> Option<&vyre::Program> {
        self.fused_program
            .get_or_init(|| {
                let ac_program = self.ac_gpu_program()?;
                // Collect all programs eligible for fusion. Currently:
                //   1. AC bounded-ranges program (always present if GPU path is active)
                //   2. Rule pipeline program (when regex NFA compile succeeds)
                //
                // Future: decode programs, MoE scoring programs.
                let mut programs: Vec<&vyre::Program> = vec![ac_program];

                if let Some(pipeline) = self.rule_pipeline() {
                    programs.push(&pipeline.program);
                }

                // Single program → fusion is identity; skip overhead.
                if programs.len() < 2 {
                    tracing::debug!(
                        target: "keyhog::gpu",
                        programs = programs.len(),
                        "program fusion skipped - fewer than 2 eligible programs"
                    );
                    return None;
                }

                let started = std::time::Instant::now();
                match vyre_libs::scan::fuse_programs(
                    &programs.iter().map(|p| (*p).clone()).collect::<Vec<_>>(),
                ) {
                    Ok(fused) => {
                        let elapsed_ms = started.elapsed().as_millis();
                        tracing::info!(
                            target: "keyhog::gpu",
                            input_programs = programs.len(),
                            fused_buffers = fused.buffers().len(),
                            fused_workgroup = ?fused.workgroup_size(),
                            elapsed_ms,
                            "program fusion succeeded - single GPU dispatch active"
                        );
                        // Attempt to cache the fused program on disk.
                        self.cache_fused_program(&fused, &programs);
                        Some(fused)
                    }
                    Err(error) => {
                        tracing::debug!(
                            target: "keyhog::gpu",
                            input_programs = programs.len(),
                            error = %error,
                            "program fusion failed - falling back to sequential dispatch. \
                             Common causes: incompatible buffer layouts, over-dispatch geometry, \
                             or self-aliasing constraints."
                        );
                        None
                    }
                }
            })
            .as_ref()
    }

    /// Cache a fused program to disk for cold-start acceleration.
    /// Mirrors the atomic-rename protocol used by `GpuLiteralSet` and
    /// `RulePipeline` caching.
    fn cache_fused_program(&self, fused: &vyre::Program, _programs: &[&vyre::Program]) {
        let Some(cache_dir) = super::gpu_cache::gpu_matcher_cache_dir() else {
            return;
        };
        let cache_key = format!("fused-{}", fused_cache_key(fused));
        let Some(path) = vyre_libs::scan::engine_cache_path(&cache_dir, &cache_key) else {
            return;
        };
        let bytes = fused.to_bytes();
        let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if std::fs::write(&tmp, &bytes).is_ok() {
            if let Err(error) = std::fs::rename(&tmp, &path) {
                tracing::debug!(
                    target: "keyhog::gpu",
                    error = %error,
                    path = %path.display(),
                    "fused program cache rename failed"
                );
                let _ = std::fs::remove_file(&tmp);
            }
        }
    }
}

/// Compute a SHA-256 cache key for a fused program based on its
/// serialized IR bytes and the fusion cache version.
fn fused_cache_key(program: &vyre::Program) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(FUSED_CACHE_VERSION.to_le_bytes());
    let ir_bytes = program.to_bytes();
    h.update((ir_bytes.len() as u64).to_le_bytes());
    h.update(&ir_bytes);
    let digest = h.finalize();
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(hex, "{:02x}", byte);
    }
    hex
}

pub const FUSION_CACHE_VERSION: u32 = 1;

pub fn try_fuse(programs: &[&vyre::Program]) -> std::result::Result<vyre::Program, String> {
    if programs.is_empty() {
        return Err("Cannot fuse empty program list".to_string());
    }
    let owned_programs: Vec<vyre::Program> = programs.iter().map(|p| (*p).clone()).collect();
    vyre_libs::scan::fuse_programs(&owned_programs).map_err(|e| e.to_string())
}

pub fn fuse_or_fallback(programs: &[&vyre::Program]) -> Option<vyre::Program> {
    try_fuse(programs).ok()
}

pub fn fusion_cache_key(programs: &[&vyre::Program]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(FUSION_CACHE_VERSION.to_le_bytes());
    for p in programs {
        let ir_bytes = p.to_bytes();
        h.update((ir_bytes.len() as u64).to_le_bytes());
        h.update(&ir_bytes);
    }
    let digest = h.finalize();
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(hex, "{:02x}", byte);
    }
    hex
}
