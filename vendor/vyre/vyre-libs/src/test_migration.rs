//! Shader-snapshot migration entries collected by inventory.
//!
//! Each dialect op that generates a WGSL kernel submits a
//! `MigrationEntry` so the pre-sweep snapshot tool can dump every shader
//! to disk and compare future runs byte-for-byte against the locked
//! snapshot. The entry carries the op id, the destination snapshot path,
//! and a closure that emits the WGSL source on demand.

/// Snapshot migration entry for a single op.
pub struct MigrationEntry {
    /// Stable op identifier (e.g. `"workgroup.visitor"`).
    pub op_id: &'static str,
    /// On-disk path relative to the repo root where the snapshot lives.
    pub snapshot_path: &'static str,
    /// Emits the WGSL source this op generates.
    pub emit: fn() -> String,
}

inventory::collect!(MigrationEntry);
