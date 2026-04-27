//! Dialect registry, OpDef registration, and TOML loader.

/// Indirection helpers for cross-crate `core` registry access.
pub mod core_indirect;
/// Dialect schema, version, and `DialectRegistration` inventory type.
pub mod dialect;
/// `EnforceGate` trait + `EnforceVerdict` enum.
pub mod enforce;
/// `intern_string` / `InternedOpId` global string interner.
pub mod interner;
/// I/O lowering helpers (DMA, NVMe passthrough).
pub mod io;
/// Naga / SPIR-V / PTX / Metal builder traits + `LoweringTable`.
pub mod lowering;
/// `Migration` and `Deprecation` inventory types for op-id renames.
pub mod migration;
/// `MutationClass` declarations carried by every op.
pub mod mutation;
/// `OpDef` + `OpDefRegistration` — stable definition surface every backend reads.
pub mod op_def;
/// `DialectRegistry` — the frozen lookup table walked at dispatch time.
pub mod registry;
/// TOML-source dialect/op loader for Tier B community extensibility.
pub mod toml_loader;

pub use core_indirect::INDIRECT_DISPATCH_OP_ID;
pub use dialect::{
    default_validator, Dialect, DialectRegistration, OpBackendTarget, OpDefRegistration,
};
pub use enforce::{Chain, EnforceGate, EnforceVerdict};
pub use interner::{intern_string, InternedOpId};
pub use lowering::{
    LoweringCtx, LoweringTable, MetalBuilder, MetalModule, NagaBuilder, PtxBuilder, PtxModule,
    ReferenceKind, SpirvBuilder,
};
pub use migration::{
    deprecation_diagnostic, AttrMap, AttrValue, Deprecation, Migration, MigrationError,
    MigrationRegistry, Semver,
};
pub use mutation::MutationClass;
pub use op_def::{AttrSchema, AttrType, Category, OpDef, Signature, TypedParam};
pub use registry::{DialectRegistry, DuplicateOpIdError, Target};
pub use toml_loader::{
    workspace_dialect_fixture_path, DialectManifest, OpManifest, TomlDialectStore, CODE_PARSE,
};
