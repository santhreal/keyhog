//! Descriptor for a Category C hardware intrinsic.
//!
//! `IntrinsicDescriptor` binds a stable name, a required hardware unit, and a
//! CPU reference function. Backends that claim support for the intrinsic must
//! produce output that matches the CPU reference exactly on every witnessed
//! input. Conform proofs carry this descriptor so that any reader can audit
//! the hardware contract that the backend claims to satisfy.

use std::sync::Arc;

/// Flat byte-ABI CPU reference function used by Category C descriptors.
///
/// The function reads raw bytes from `input`, computes the operation's
/// semantics, and appends the result bytes to `output`. This type lives in
/// `vyre-spec` so that conform certificates can embed the function pointer
/// without dragging the rest of the compiler into the data contract.
pub type CpuFn = fn(input: &[u8], output: &mut Vec<u8>);

/// Stable string identity for a backend.
///
/// Usage: `BackendId::new("wgpu")`. Hash + Eq operate on the interned string
/// value — two `BackendId`s with identical content compare equal regardless
/// of Arc reuse.
#[derive(Debug, Clone)]
pub struct BackendId(Arc<str>);

impl BackendId {
    /// Construct a backend id from any string-like value.
    #[must_use]
    pub fn new(name: impl Into<Arc<str>>) -> Self {
        Self(name.into())
    }

    /// Return the backend id as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for BackendId {
    fn from(name: &str) -> Self {
        Self(Arc::from(name))
    }
}

impl From<String> for BackendId {
    fn from(name: String) -> Self {
        Self(Arc::from(name))
    }
}

impl core::fmt::Display for BackendId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl PartialEq for BackendId {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_ref() == other.0.as_ref()
    }
}

impl Eq for BackendId {}

impl core::hash::Hash for BackendId {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.0.as_ref().hash(state);
    }
}

impl From<&Backend> for BackendId {
    fn from(backend: &Backend) -> Self {
        Self::from(backend.id())
    }
}

/// A trait for extension backends.
pub trait BackendKind: std::fmt::Debug + Send + Sync + 'static {
    /// Friendly name of the backend.
    fn name(&self) -> &str;
    /// Stable string identifier for this backend.
    fn id(&self) -> &str;
}

/// A named backend provided by an external crate.
#[derive(Debug, Clone)]
pub struct ExtensionBackend(pub Arc<dyn BackendKind>);

impl PartialEq for ExtensionBackend {
    fn eq(&self, other: &Self) -> bool {
        self.0.id() == other.0.id()
    }
}
impl Eq for ExtensionBackend {}

impl std::hash::Hash for ExtensionBackend {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.id().hash(state);
    }
}

/// Backend identity used when checking Category C intrinsic availability.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Backend {
    /// The reference WGSL backend.
    Wgsl,
    /// A CUDA backend.
    Cuda,
    /// A SPIR-V backend.
    SpirV,
    /// A Metal backend.
    Metal,
    /// A backend provided by an external crate.
    Extension(ExtensionBackend),
}

impl Backend {
    /// Stable string identifier for this backend.
    #[must_use]
    pub fn id(&self) -> &str {
        match self {
            Self::Wgsl => "wgsl",
            Self::Cuda => "cuda",
            Self::SpirV => "spirv",
            Self::Metal => "metal",
            Self::Extension(ext) => ext.0.id(),
        }
    }
}

use crate::op_contract::OperationContract;

/// Descriptor for a Category C hardware intrinsic.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct IntrinsicDescriptor {
    name: &'static str,
    hardware: &'static str,
    cpu_fn: CpuFn,
    contract: Option<OperationContract>,
}

impl IntrinsicDescriptor {
    /// Create an intrinsic descriptor with an explicit CPU reference function.
    #[must_use]
    pub const fn new(name: &'static str, hardware: &'static str, cpu_fn: CpuFn) -> Self {
        Self {
            name,
            hardware,
            cpu_fn,
            contract: None,
        }
    }

    /// Create an intrinsic descriptor with optional execution contract metadata.
    #[must_use]
    pub const fn with_contract(
        name: &'static str,
        hardware: &'static str,
        cpu_fn: CpuFn,
        contract: OperationContract,
    ) -> Self {
        Self {
            name,
            hardware,
            cpu_fn,
            contract: Some(contract),
        }
    }

    /// Stable intrinsic name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// Required hardware unit or backend feature.
    #[must_use]
    pub const fn hardware(&self) -> &'static str {
        self.hardware
    }

    /// CPU reference implementation for this intrinsic.
    #[must_use]
    pub const fn cpu_fn(&self) -> CpuFn {
        self.cpu_fn
    }

    /// Optional capability and execution contract annotations.
    #[must_use]
    pub const fn contract(&self) -> Option<&OperationContract> {
        self.contract.as_ref()
    }
}
