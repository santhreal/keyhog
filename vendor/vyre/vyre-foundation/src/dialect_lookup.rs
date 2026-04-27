#![allow(clippy::expect_used)]
//! Dialect lookup contract shared by foundation-side consumers.
//!
//! This module is the dependency-inversion boundary between the reference
//! interpreter and the driver registry. Reference code may ask for op ids and
//! frozen op definitions through [`DialectLookup`], but it must not depend on
//! `vyre-driver` or the `vyre` meta crate.
//!
//! The trait is deliberately sealed by a hidden `__sealed` method on
//! [`DialectLookup`]. Downstream crates can consume a lookup, but the only sanctioned
//! implementations are installed by vyre driver crates so this surface can grow
//! through additive default methods without breaking external implementors.

use crate::ir_inner::model::program::Program;
use lasso::ThreadedRodeo;
use std::sync::{Arc, OnceLock};
use vyre_spec::{AlgebraicLaw, CpuFn};

/// Interned operation identifier used by every dialect lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InternedOpId(pub u32);

fn get_interner() -> &'static ThreadedRodeo {
    static INTERNER: OnceLock<ThreadedRodeo> = OnceLock::new();
    INTERNER.get_or_init(ThreadedRodeo::new)
}

/// Intern a stable operation-id string into a compact process-local id.
#[must_use]
pub fn intern_string(s: &str) -> InternedOpId {
    let interner = get_interner();
    let key = interner.get_or_intern(s);
    InternedOpId(key.into_inner().get())
}

/// Function pointer used by reference-backend lowerings.
pub type ReferenceKind = CpuFn;

/// Backend lowering context retained for source compatibility.
#[derive(Default, Debug, Clone)]
pub struct LoweringCtx<'a> {
    /// Marker tying future context references to the call lifetime.
    pub unused: std::marker::PhantomData<&'a ()>,
}

/// PTX module descriptor reserved for future native lowering builders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PtxModule {
    /// PTX assembly text.
    pub asm: String,
    /// PTX version encoded by the builder.
    pub version: u32,
}

/// Metal module descriptor reserved for future native lowering builders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetalModule {
    /// Backend-owned serialized AST payload.
    pub ast: Vec<u8>,
    /// Entry-point name.
    pub entry: String,
}

/// Reserved builder type for native Naga WGSL lowering.
pub type NagaBuilder = fn(&LoweringCtx<'_>) -> Result<(), String>;
/// Reserved builder type for native SPIR-V lowering.
pub type SpirvBuilder = fn(&LoweringCtx<'_>) -> Vec<u32>;
/// Reserved builder type for future PTX lowering.
pub type PtxBuilder = fn(&LoweringCtx<'_>) -> PtxModule;
/// Reserved builder type for future Metal lowering.
pub type MetalBuilder = fn(&LoweringCtx<'_>) -> MetalModule;
/// Builder-type erased payload for any out-of-tree backend.
///
/// Extension lowerings register a function that reads the shared
/// [`LoweringCtx`] and writes backend-specific bytes into an opaque
/// output buffer. The caller backend owns the payload format; the
/// core dialect registry does not interpret the bytes — it only
/// dispatches to the right builder by `BackendId`.
///
/// This is the extensibility lever: a CUDA, Vulkan-compute, photonic,
/// CPU-SIMD, or distributed backend appends a new lowering *without*
/// editing vyre-foundation, vyre-driver, or vyre-spec. The core
/// surface remains frozen.
pub type ExtensionLoweringFn =
    fn(&LoweringCtx<'_>) -> Result<std::vec::Vec<u8>, std::string::String>;

/// Lowering function table attached to an operation definition.
///
/// `naga_wgsl`, `naga_spv`, `ptx`, `metal` are the terminal 0.6
/// in-tree slots — every vyre backend shipped from the santh tree
/// uses one of them. `extensions` is the open-ended slot: any
/// out-of-tree backend registers its builder under its stable
/// backend-id string. Look up by id via
/// [`LoweringTable::extension`].
///
/// Not `#[non_exhaustive]` so static registrations can use functional
/// record update (`..LoweringTable::empty()`) from `inventory::submit!`
/// closures. Future additions land with a [`Default`]-carrying field
/// so the spread form keeps working without a breaking change.
#[derive(Clone)]
pub struct LoweringTable {
    /// Portable CPU reference implementation.
    pub cpu_ref: ReferenceKind,
    /// Native Naga/WGSL builder. `None` in v0.6 pure-IR ops.
    pub naga_wgsl: Option<NagaBuilder>,
    /// Native SPIR-V builder. `None` in v0.6 pure-IR ops.
    pub naga_spv: Option<SpirvBuilder>,
    /// Native PTX builder. `None` until CUDA/PTX support lands.
    pub ptx: Option<PtxBuilder>,
    /// Native Metal builder. `None` until Metal support lands.
    pub metal: Option<MetalBuilder>,
    /// Open extension map for out-of-tree backends. Keyed by backend
    /// id (matches the string a `VyreBackend::id` returns). Builders
    /// are by-value function pointers so lookup is allocation-free
    /// and the map stays `Clone + Send + Sync` without interior
    /// locking.
    pub extensions: rustc_hash::FxHashMap<&'static str, ExtensionLoweringFn>,
}

impl Default for LoweringTable {
    fn default() -> Self {
        Self::empty()
    }
}

impl LoweringTable {
    /// Build a CPU-only lowering table.
    #[must_use]
    pub fn new(cpu_ref: ReferenceKind) -> Self {
        Self {
            cpu_ref,
            naga_wgsl: None,
            naga_spv: None,
            ptx: None,
            metal: None,
            extensions: rustc_hash::FxHashMap::default(),
        }
    }

    /// Empty table whose CPU path reports the structured intrinsic fallback.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            cpu_ref: crate::cpu_op::structured_intrinsic_cpu,
            naga_wgsl: None,
            naga_spv: None,
            ptx: None,
            metal: None,
            extensions: rustc_hash::FxHashMap::default(),
        }
    }

    /// Register an out-of-tree backend's lowering. Stable backend id
    /// is the key a future `DialectRegistry::get_lowering` call
    /// will look it up by — pick it carefully, it is a wire-like
    /// identifier.
    #[must_use]
    pub fn with_extension(
        mut self,
        backend_id: &'static str,
        builder: ExtensionLoweringFn,
    ) -> Self {
        self.extensions.insert(backend_id, builder);
        self
    }

    /// Look up an extension builder by backend id.
    #[must_use]
    pub fn extension(&self, backend_id: &str) -> Option<ExtensionLoweringFn> {
        self.extensions.get(backend_id).copied()
    }
}

impl std::fmt::Debug for LoweringTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoweringTable")
            .field("cpu_ref", &"<fn>")
            .field("naga_wgsl", &self.naga_wgsl.map(|_| "<fn>"))
            .field("naga_spv", &self.naga_spv.map(|_| "<fn>"))
            .field("ptx", &self.ptx.map(|_| "<fn>"))
            .field("metal", &self.metal.map(|_| "<fn>"))
            .field(
                "extensions",
                &self
                    .extensions
                    .keys()
                    .copied()
                    .collect::<std::vec::Vec<_>>(),
            )
            .finish()
    }
}

/// Attribute value type declared by an operation schema.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AttrType {
    /// Unsigned 32-bit integer.
    U32,
    /// Signed 32-bit integer.
    I32,
    /// IEEE-754 binary32.
    F32,
    /// Boolean.
    Bool,
    /// Opaque byte string.
    Bytes,
    /// UTF-8 string.
    String,
    /// Enumerated string value.
    Enum(&'static [&'static str]),
    /// Unknown extension attribute.
    Unknown,
}

/// Attribute schema entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttrSchema {
    /// Attribute name.
    pub name: &'static str,
    /// Attribute value type.
    pub ty: AttrType,
    /// Optional default value.
    pub default: Option<&'static str>,
}

/// Typed input or output parameter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedParam {
    /// Parameter name.
    pub name: &'static str,
    /// Stable type spelling.
    pub ty: &'static str,
}

/// Operation signature contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    /// Input parameters.
    pub inputs: &'static [TypedParam],
    /// Output parameters.
    pub outputs: &'static [TypedParam],
    /// Attribute parameters.
    pub attrs: &'static [AttrSchema],
    /// True when this op may read `DataType::Bytes` buffers.
    pub bytes_extraction: bool,
}

impl Signature {
    /// Construct a signature for an op that performs bytes extraction.
    #[must_use]
    pub const fn bytes_extractor(
        inputs: &'static [TypedParam],
        outputs: &'static [TypedParam],
        attrs: &'static [AttrSchema],
    ) -> Self {
        Self {
            inputs,
            outputs,
            attrs,
            bytes_extraction: true,
        }
    }
}

/// Operation category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    /// Composition over IR.
    Composite,
    /// Extension op supplied by another crate.
    Extension,
    /// Intrinsic op supplied by a backend or primitive table.
    Intrinsic,
}

/// Frozen operation definition.
#[derive(Debug, Clone)]
pub struct OpDef {
    /// Stable operation id.
    pub id: &'static str,
    /// Stable dialect namespace.
    pub dialect: &'static str,
    /// Operation category.
    pub category: Category,
    /// Operation signature.
    pub signature: Signature,
    /// Backend lowering entries.
    pub lowerings: LoweringTable,
    /// Algebraic laws declared for conformance.
    pub laws: &'static [AlgebraicLaw],
    /// Composition-inlinable program builder.
    pub compose: Option<fn() -> Program>,
}

impl OpDef {
    /// Stable operation id.
    #[must_use]
    pub const fn id(&self) -> &'static str {
        self.id
    }

    /// Build the canonical composition program when the operation has one.
    #[must_use]
    pub fn program(&self) -> Option<Program> {
        self.compose
            .map(|compose| compose().with_entry_op_id(self.id))
    }
}

impl Default for OpDef {
    fn default() -> Self {
        Self {
            id: "",
            dialect: "",
            category: Category::Intrinsic,
            signature: Signature {
                inputs: &[],
                outputs: &[],
                attrs: &[],
                bytes_extraction: false,
            },
            lowerings: LoweringTable::empty(),
            laws: &[],
            compose: None,
        }
    }
}

#[doc(hidden)]
pub mod private {
    pub trait Sealed {}
}

/// Minimal lookup surface consumed by foundation-side reference code.
pub trait DialectLookup: private::Sealed + Send + Sync {
    /// Stable identifier naming the provider implementation.
    ///
    /// Two installs sharing the same `provider_id` are treated as the same
    /// logical provider — a second install is an idempotent no-op. Two
    /// installs with different ids are a conflict and trigger a panic at
    /// [`install_dialect_lookup`] time so divergent providers are caught
    /// at startup rather than silently corrupting lookups at runtime.
    fn provider_id(&self) -> &'static str;

    /// Intern a stable operation id.
    fn intern_op(&self, name: &str) -> InternedOpId;

    /// Resolve an interned operation id to its frozen definition.
    fn lookup(&self, id: InternedOpId) -> Option<&'static OpDef>;
}

static DIALECT_LOOKUP: OnceLock<Arc<dyn DialectLookup>> = OnceLock::new();

/// Install the process-wide dialect lookup provider.
///
/// First caller wins. A second install from a provider that reports the
/// same [`DialectLookup::provider_id`] is a silent no-op so harnesses can
/// defensively call this at the top of every test without racing. A second
/// install from a provider reporting a DIFFERENT `provider_id` panics with
/// both ids named, because two divergent providers mapping the same op ids
/// would corrupt every lookup-dependent pass (validator, reference, shadow
/// diff, conformance matrix) in ways that are hard to attribute back to the
/// install site. Failing here keeps the 60-second root-cause trace from
/// LAW 4 intact.
pub fn install_dialect_lookup(lookup: Arc<dyn DialectLookup>) {
    match DIALECT_LOOKUP.get() {
        Some(existing) => {
            let existing_id = existing.provider_id();
            let incoming_id = lookup.provider_id();
            assert!(
                existing_id == incoming_id,
                "dialect lookup already installed by provider `{existing_id}`; \
                 second installer `{incoming_id}` reports a different id. \
                 Fix: pick one provider for the process or reuse the first \
                 provider's id. Silent replacement is refused because two \
                 divergent lookups would mis-resolve op ids at runtime."
            );
        }
        None => {
            if let Err(lookup) = DIALECT_LOOKUP.set(lookup) {
                // Lost a race with another thread; still need to validate
                // idempotency so a concurrent install with a different id
                // does not silently corrupt the process-wide lookup.
                let existing = DIALECT_LOOKUP
                    .get()
                    .expect("set failed so value must exist");
                let existing_id = existing.provider_id();
                let incoming_id = lookup.provider_id();
                assert!(
                    existing_id == incoming_id,
                    "dialect lookup already installed by provider `{existing_id}`; \
                     second installer `{incoming_id}` reports a different id. \
                     Fix: pick one provider for the process or reuse the first \
                     provider's id. Silent replacement is refused because two \
                     divergent lookups would mis-resolve op ids at runtime."
                );
            }
        }
    }
}

/// Return the installed process-wide dialect lookup provider.
#[must_use]
pub fn dialect_lookup() -> Option<&'static dyn DialectLookup> {
    DIALECT_LOOKUP.get().map(Arc::as_ref)
}
