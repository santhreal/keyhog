//! Swappable compiled-binary analyzer contract and implementations.

use std::path::Path;

use keyhog_core::{Chunk, SourceError};

mod ghidra;
#[cfg(test)]
mod tests;

pub(super) use ghidra::{find_ghidra_headless, GhidraAnalyzer};

pub(super) struct BinaryAnalysisRequest<'a> {
    pub(super) path: &'a Path,
    pub(super) decompiled_bytes_limit: u64,
    pub(super) timeout: std::time::Duration,
}

pub(super) trait BinaryAnalyzer {
    fn analyze(
        &self,
        request: BinaryAnalysisRequest<'_>,
    ) -> Result<BinaryAnalysisOutcome, SourceError>;
}

#[derive(Debug)]
pub(super) enum BinaryAnalysisOutcome {
    Complete(Vec<Chunk>),
    Degraded(BinaryAnalysisDegradation),
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum BinaryAnalysisDegradation {
    ToolFailure {
        reason: String,
        stderr_excerpt: String,
    },
    OutputTooLarge {
        actual_bytes: u64,
        limit_bytes: u64,
    },
}
