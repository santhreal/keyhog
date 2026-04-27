//! Shared megakernel queue types for wgpu integrations.
//!
//! The runtime-owned dispatch wrapper lives in `vyre-runtime`; this
//! module re-exports the stable public work-queue types so existing
//! callers do not need to learn a second crate just to build queues.

pub use vyre_driver_megakernel::{MegakernelCaps, MegakernelConfig, MegakernelReport, WorkItem};
