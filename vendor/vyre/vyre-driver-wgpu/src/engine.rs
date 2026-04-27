//! Layer 3 complete compute engines.
//!
//! Each engine is a self-contained GPU compute pipeline: structured input
//! in, compute passes on a real GPU backend, typed output back.
//!
//! The 0.6 cycle keeps only the substrate-neutral engines (graph
//! execution, multi-GPU work partitioning, persistent megakernel,
//! host-ingress compatibility streaming, shared record/readback). Dialect-specific
//! engines (dataflow, decode, decompress, dfa, string matching) were
//! removed alongside the WGSL-string dialects they rode on; they
//! return in 0.7 against the naga-AST emitter.

/// GPU-resident command graph execution.
pub mod graph;
/// Mockable multi-GPU work partitioning.
pub mod multi_gpu;
/// Resident persistent-kernel queue engine.
pub mod persistent;
/// Shared command recording and readback for vyre IR dispatch paths.
pub(crate) mod record_and_readback;
/// Host-ingress chunk bridge for callers that still receive bytes through CPU memory.
pub mod streaming;
