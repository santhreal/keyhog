//! Core scanning orchestration logic for the KeyHog CLI.

mod allowlist;
mod dispatch;
mod postprocess;
mod reporting;
mod run;

use crate::args::ScanArgs;
use crate::config::apply_config_file;
use crate::orchestrator_config::{
    auto_discover_detectors, build_scanner_config, configure_threads, load_detectors_no_cache,
    load_detectors_with_cache,
};
use anyhow::{Context, Result};
use keyhog_core::{DetectorSpec, RawMatch, Source};
use keyhog_scanner::CompiledScanner;
use std::path::PathBuf;
use std::sync::Arc;

pub use run::{EXIT_LIVE_CREDENTIALS, EXIT_SCANNER_PANIC};

#[doc(hidden)]
pub use dispatch::explicit_backend_override;

#[doc(hidden)]
pub fn allowlist_root_for_test(path: &std::path::Path) -> std::path::PathBuf {
    allowlist::allowlist_root(path)
}

pub struct ScanOrchestrator {
    pub(crate) args: ScanArgs,
    pub(crate) detectors: Vec<DetectorSpec>,
    pub(crate) scanner: Arc<CompiledScanner>,
    pub(crate) signatures: std::collections::HashSet<Arc<str>>,
    pub(crate) test_fixture_suppressions: crate::test_fixture_suppressions::TestFixtureSuppressions,
}

impl ScanOrchestrator {
    pub fn new(mut args: ScanArgs) -> Result<Self> {
        // Grep/wc/curl convention: a positional `-` means "read from
        // stdin". Some users will try `keyhog scan - --stdin <<<...`
        // and otherwise hit `error: path '-' does not exist`. Promote
        // bare `-` to `--stdin` and drop it from the path slot so the
        // existing stdin-reading source picks up. Falls through cleanly
        // when `--stdin` was already passed.
        if matches!(args.input.as_deref().and_then(|p| p.to_str()), Some("-"))
            || matches!(args.path.as_deref().and_then(|p| p.to_str()), Some("-"))
        {
            args.stdin = true;
            args.input = None;
            args.path = None;
        }
        if args.path.is_none() {
            args.path = args.input.clone();
        }
        #[cfg(feature = "git")]
        if args.git_staged && args.path.is_none() {
            args.path = Some(PathBuf::from("."));
        }
        apply_config_file(&mut args);

        let hw = keyhog_scanner::hw_probe::probe_hardware();
        configure_threads(args.threads, hw.physical_cores);

        let detectors_path = auto_discover_detectors(&args.detectors)?;
        let detectors = if args.lockdown {
            load_detectors_no_cache(&detectors_path)
                .context("loading detectors (lockdown: cache disabled)")?
        } else {
            load_detectors_with_cache(&detectors_path)?
        };

        let mut scanner_config = build_scanner_config(&args);

        if let Some(mem_mb) = hw.total_memory_mb {
            if mem_mb < 4096 {
                scanner_config.max_matches_per_chunk =
                    scanner_config.max_matches_per_chunk.min(500);
                scanner_config.max_decode_bytes = scanner_config.max_decode_bytes.min(256 * 1024);
            }
        }

        let scanner = Arc::new(
            CompiledScanner::compile(detectors.clone())
                .with_context(|| {
                    format!("compiling scanner from {} detector specs", detectors.len())
                })?
                .with_config(scanner_config),
        );

        let signatures: std::collections::HashSet<Arc<str>> = detectors
            .iter()
            .flat_map(|d| d.patterns.iter().map(|p| Arc::from(p.regex.as_str())))
            .chain(
                detectors
                    .iter()
                    .flat_map(|d| d.companions.iter().map(|c| Arc::from(c.regex.as_str()))),
            )
            .collect();

        let test_fixture_suppressions = if args.no_suppress_test_fixtures {
            crate::test_fixture_suppressions::TestFixtureSuppressions::empty()
        } else {
            crate::test_fixture_suppressions::TestFixtureSuppressions::bundled()
        };

        Ok(Self {
            args,
            detectors,
            scanner,
            signatures,
            test_fixture_suppressions,
        })
    }

    pub fn scanner(&self) -> &CompiledScanner {
        self.scanner.as_ref()
    }

    pub fn args(&self) -> &ScanArgs {
        &self.args
    }

    pub(crate) fn incremental_cache_path(&self) -> Option<std::path::PathBuf> {
        if !self.args.incremental {
            return None;
        }
        if self.args.lockdown {
            tracing::warn!("lockdown mode: --incremental disabled (cache writes refused)");
            return None;
        }
        self.args
            .incremental_cache
            .clone()
            .or_else(keyhog_core::merkle_index::default_cache_path)
    }

    pub(crate) fn build_merkle_index(&self) -> Option<Arc<keyhog_core::merkle_index::MerkleIndex>> {
        let path = self.incremental_cache_path()?;
        let spec_hash = keyhog_core::merkle_index::compute_spec_hash(&self.detectors);
        let idx = keyhog_core::merkle_index::MerkleIndex::load_with_spec(&path, &spec_hash);
        tracing::info!(indexed = idx.len(), "incremental scan: loaded merkle index");
        Some(Arc::new(idx))
    }

    /// Test-only entry point for the producer/scanner pipeline.
    #[doc(hidden)]
    pub fn scan_sources_for_test(
        &self,
        sources: Vec<Box<dyn Source>>,
        show_progress: bool,
        merkle: Option<Arc<keyhog_core::merkle_index::MerkleIndex>>,
    ) -> Vec<RawMatch> {
        self.scan_sources(sources, show_progress, merkle)
    }

    /// Test-only constructor bypassing detector-cache and lockdown gating.
    #[doc(hidden)]
    pub fn from_parts_for_test(
        args: ScanArgs,
        detectors: Vec<DetectorSpec>,
        scanner: Arc<CompiledScanner>,
        signatures: std::collections::HashSet<Arc<str>>,
        test_fixture_suppressions: crate::test_fixture_suppressions::TestFixtureSuppressions,
    ) -> Self {
        Self {
            args,
            detectors,
            scanner,
            signatures,
            test_fixture_suppressions,
        }
    }
}

// `reporting::dump_dogfood_trace` is consumed by sibling `run.rs` via
// `use reporting::{dump_dogfood_trace, …};` directly. The re-export
// that lived here was unused and tripped the unused-imports lint.
