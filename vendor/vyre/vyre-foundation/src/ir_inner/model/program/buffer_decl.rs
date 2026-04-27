use std::ops::Range;
use std::sync::Arc;

use crate::ir_inner::model::types::{BufferAccess, DataType};

use super::{MemoryHints, MemoryKind};

/// A named buffer binding in a program.
///
/// # Examples
///
/// ```
/// use vyre::ir::{BufferDecl, BufferAccess, DataType};
///
/// let buf = BufferDecl::read("input", 0, DataType::U32);
/// assert_eq!(buf.name(), "input");
/// assert_eq!(buf.binding(), 0);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BufferDecl {
    /// Human-readable name. Referenced by `Expr::Load`, `Node::Store`, etc.
    pub name: Arc<str>,
    /// Binding slot: `@binding(N)`. All buffers are in `@group(0)`.
    /// Ignored for `BufferAccess::Workgroup`.
    pub binding: u32,
    /// Access mode.
    pub access: BufferAccess,
    /// Memory tier.
    pub kind: MemoryKind,
    /// Element data type.
    pub element: DataType,
    /// Number of elements.
    ///
    /// For `Workgroup` memory this is the static array length.
    /// For storage and uniform buffers this is `0` (runtime-sized).
    pub count: u32,
    /// Whether this buffer is the scalar expression output for composition inlining.
    pub is_output: bool,
    /// Whether the end-to-end pipeline reads this buffer after Program execution.
    ///
    /// Passes must treat this as an externally-visible sink even when the IR
    /// itself does not read the buffer again.
    pub pipeline_live_out: bool,
    /// Optional byte range to read back from this output buffer.
    ///
    /// `None` preserves the historical behavior and reads back the full
    /// declared output buffer.
    pub output_byte_range: Option<Range<usize>>,
    /// Non-binding backend optimization hints.
    pub hints: MemoryHints,
    /// When true, admits `DataType::Bytes` load/store despite V013.
    ///
    /// Bytes-producing or bytes-extraction ops (decode.base64,
    /// compression.lz4_decompress, match.dfa_scan position emission, etc.)
    /// opt into V013 relaxation per-buffer. Default false keeps scalar
    /// arithmetic protected from accidental bytes-blob reinterpretation.
    pub bytes_extraction: bool,
}

impl BufferDecl {
    /// Create a storage buffer declaration.
    ///
    /// # Examples
    ///
    /// ```
    /// use vyre::ir::{BufferDecl, BufferAccess, DataType};
    /// let _ = BufferDecl::storage("a", 0, BufferAccess::ReadOnly, DataType::U32);
    /// ```
    #[must_use]
    #[inline]
    pub fn storage(name: &str, binding: u32, access: BufferAccess, element: DataType) -> Self {
        let kind = match &access {
            BufferAccess::ReadOnly => MemoryKind::Readonly,
            BufferAccess::ReadWrite => MemoryKind::Global,
            BufferAccess::Uniform => MemoryKind::Uniform,
            BufferAccess::Workgroup => MemoryKind::Shared,
            _ => MemoryKind::Global,
        };
        Self {
            name: Arc::from(name),
            binding,
            access,
            kind,
            element,
            count: 0,
            is_output: false,
            pipeline_live_out: false,
            output_byte_range: None,
            hints: MemoryHints::default(),
            bytes_extraction: false,
        }
    }

    /// Shorthand for a read-only storage buffer.
    ///
    /// # Examples
    ///
    /// ```
    /// use vyre::ir::{BufferDecl, DataType};
    /// let _ = BufferDecl::read("a", 0, DataType::U32);
    /// ```
    #[must_use]
    #[inline]
    pub fn read(name: &str, binding: u32, element: DataType) -> Self {
        Self::storage(name, binding, BufferAccess::ReadOnly, element)
    }

    /// Shorthand for a read-write storage buffer.
    ///
    /// # Examples
    ///
    /// ```
    /// use vyre::ir::{BufferDecl, DataType};
    /// let _ = BufferDecl::read_write("a", 0, DataType::U32);
    /// ```
    #[must_use]
    #[inline]
    pub fn read_write(name: &str, binding: u32, element: DataType) -> Self {
        Self::storage(name, binding, BufferAccess::ReadWrite, element)
    }

    /// Shorthand for the read-write result buffer used by call inlining.
    ///
    /// # Examples
    ///
    /// ```
    /// use vyre::ir::{BufferDecl, DataType};
    /// let _ = BufferDecl::output("a", 0, DataType::U32);
    /// ```
    #[must_use]
    #[inline]
    pub fn output(name: &str, binding: u32, element: DataType) -> Self {
        Self {
            is_output: true,
            pipeline_live_out: true,
            ..Self::read_write(name, binding, element)
        }
    }

    /// Mark whether a caller/backend observes this buffer after Program execution.
    #[must_use]
    #[inline]
    pub fn with_pipeline_live_out(mut self, flag: bool) -> Self {
        self.pipeline_live_out = flag;
        self
    }

    /// Attach an output byte range for backends that can read back a slice.
    #[must_use]
    #[inline]
    pub fn with_output_byte_range(mut self, range: Range<usize>) -> Self {
        self.output_byte_range = Some(range);
        self
    }

    /// Set the static element count for storage-style buffers.
    ///
    /// `count` must be strictly positive. A runtime-sized buffer is
    /// declared by *not* calling `with_count` at all (so the count field
    /// stays at the structural default of `0`, which the validator and
    /// backends interpret as "length discovered at dispatch time"). An
    /// explicit `with_count(0)` is always a mistake: the author has told
    /// the IR that the buffer is exactly zero elements long, which every
    /// shipped backend (WebGPU `ZERO_SIZE_BUFFER_USAGE`, Vulkan zero-size
    /// allocation, reference interpreter) treats as a validation
    /// failure. Panic loudly at construction so the author fixes the
    /// call site instead of chasing an opaque dispatch error.
    #[must_use]
    #[inline]
    pub fn with_count(mut self, count: u32) -> Self {
        assert!(
            count > 0,
            "Fix: BufferDecl::with_count(0) is rejected. Drop the `.with_count(0)` \
             call to declare a runtime-sized buffer, or pass a strictly positive \
             count. Zero-length static buffers are a validation failure on every \
             shipped backend."
        );
        self.count = count;
        self
    }

    /// Shorthand for a uniform buffer.
    ///
    /// # Examples
    ///
    /// ```
    /// use vyre::ir::{BufferDecl, DataType};
    /// let _ = BufferDecl::uniform("a", 0, DataType::U32);
    /// ```
    #[must_use]
    #[inline]
    pub fn uniform(name: &str, binding: u32, element: DataType) -> Self {
        Self::storage(name, binding, BufferAccess::Uniform, element)
    }

    /// Shorthand for a workgroup-local shared array.
    ///
    /// `count` is the static number of elements visible to all invocations
    /// in the same workgroup.
    ///
    /// # Examples
    ///
    /// ```
    /// use vyre::ir::{BufferAccess, BufferDecl, DataType, MemoryKind};
    ///
    /// let scratch = BufferDecl::workgroup("scratch", 64, DataType::U32);
    ///
    /// assert_eq!(scratch.name(), "scratch");
    /// assert_eq!(scratch.access(), BufferAccess::Workgroup);
    /// assert_eq!(scratch.kind(), MemoryKind::Shared);
    /// assert_eq!(scratch.count(), 64);
    /// ```
    #[must_use]
    #[inline]
    pub fn workgroup(name: &str, count: u32, element: DataType) -> Self {
        // CRITIQUE_FIX_REVIEW_2026-04-23 Finding #3: F-IR-05 added the
        // zero-count panic to `with_count` but left this constructor as
        // an unguarded bypass. Zero-count workgroup buffers pass
        // construction, fail at wire-encode time, or crash on the GPU
        // with a cryptic backend error instead of the actionable
        // construction-time message. Mirror the with_count contract
        // here so every public path to a Workgroup BufferDecl rejects
        // count == 0 with the same Fix: hint.
        assert!(
            count > 0,
            "Fix: BufferDecl::workgroup(count=0) is rejected. Workgroup \
             allocations must be strictly positive; pick the real element \
             count the parser / composer expects. Zero-size workgroup \
             buffers are a GPU validation failure on every shipped backend."
        );
        Self {
            name: Arc::from(name),
            binding: 0,
            access: BufferAccess::Workgroup,
            kind: MemoryKind::Shared,
            element,
            count,
            is_output: false,
            pipeline_live_out: false,
            output_byte_range: None,
            hints: MemoryHints::default(),
            bytes_extraction: false,
        }
    }

    /// Mark this buffer as a bytes-extraction context so V013 admits Bytes load/store.
    #[must_use]
    #[inline]
    pub fn with_bytes_extraction(mut self, flag: bool) -> Self {
        self.bytes_extraction = flag;
        self
    }

    /// Override the memory tier.
    #[must_use]
    #[inline]
    pub fn with_kind(mut self, kind: MemoryKind) -> Self {
        self.kind = kind;
        self
    }

    /// Override memory optimization hints.
    #[must_use]
    #[inline]
    pub fn with_hints(mut self, hints: MemoryHints) -> Self {
        self.hints = hints;
        self
    }

    /// Buffer name.
    #[must_use]
    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Binding slot.
    #[must_use]
    #[inline]
    pub fn binding(&self) -> u32 {
        self.binding
    }

    /// Buffer access mode.
    #[must_use]
    #[inline]
    pub fn access(&self) -> BufferAccess {
        self.access.clone()
    }

    /// Memory tier.
    #[must_use]
    #[inline]
    pub fn kind(&self) -> MemoryKind {
        self.kind
    }

    /// Non-binding memory hints.
    #[must_use]
    #[inline]
    pub fn hints(&self) -> MemoryHints {
        self.hints
    }

    /// Element data type.
    #[must_use]
    #[inline]
    pub fn element(&self) -> DataType {
        self.element.clone()
    }

    /// Static element count for workgroup buffers.
    #[must_use]
    #[inline]
    pub fn count(&self) -> u32 {
        self.count
    }

    /// Return true when this buffer is the unique inlining result buffer.
    #[must_use]
    #[inline]
    pub fn is_output(&self) -> bool {
        self.is_output
    }

    /// Return true when the buffer must survive IR-local deadness analysis.
    #[must_use]
    #[inline]
    pub fn is_pipeline_live_out(&self) -> bool {
        self.pipeline_live_out
    }

    /// Byte range the consumer needs from this output buffer, if declared.
    #[must_use]
    #[inline]
    pub fn output_byte_range(&self) -> Option<Range<usize>> {
        self.output_byte_range.clone()
    }
}
