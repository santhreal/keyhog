use std::sync::{Arc, OnceLock};

use rustc_hash::FxHashMap;

use crate::ir_inner::model::arena::{ArenaProgram, ExprArena};
use crate::ir_inner::model::node::Node;

use super::{BufferDecl, Program};

impl Program {
    /// Synthetic generator id used when callers submit a raw top-level body
    /// instead of an explicit `Node::Region`.
    pub const ROOT_REGION_GENERATOR: &'static str = "vyre.program.root";

    /// Create a complete program from buffer declarations, workgroup size, and
    /// entry-point nodes, auto-wrapping the top-level body in a root Region
    /// when necessary.
    ///
    /// This is the default construction path for runnable Programs.
    ///
    /// # Examples
    ///
    /// ```
    /// use vyre::ir::{BufferAccess, BufferDecl, DataType, Node, Program};
    ///
    /// let program = Program::wrapped(
    ///     vec![BufferDecl::storage(
    ///         "output",
    ///         0,
    ///         BufferAccess::ReadWrite,
    ///         DataType::U32,
    ///     )],
    ///     [64, 1, 1],
    ///     Vec::new(),
    /// );
    ///
    /// assert_eq!(program.workgroup_size(), [64, 1, 1]);
    /// assert_eq!(program.buffers().len(), 1);
    /// assert!(matches!(program.entry(), [Node::Region { .. }]));
    /// ```
    #[must_use]
    #[inline]
    pub fn wrapped(buffers: Vec<BufferDecl>, workgroup_size: [u32; 3], entry: Vec<Node>) -> Self {
        Self::new_raw(buffers, workgroup_size, Self::wrap_entry(entry))
    }

    /// Create a complete program from buffer declarations, workgroup size, and
    /// entry-point nodes.
    ///
    /// # Examples
    ///
    /// ```
    /// use vyre::ir::{BufferAccess, BufferDecl, DataType, Program};
    ///
    /// let program = Program::wrapped(
    ///     vec![BufferDecl::storage(
    ///         "output",
    ///         0,
    ///         BufferAccess::ReadWrite,
    ///         DataType::U32,
    ///     )],
    ///     [64, 1, 1],
    ///     Vec::new(),
    /// );
    ///
    /// assert_eq!(program.workgroup_size(), [64, 1, 1]);
    /// assert_eq!(program.buffers().len(), 1);
    /// assert!(matches!(program.entry(), [Node::Region { .. }]));
    /// ```
    #[deprecated(
        note = "Program::new preserves raw top-level entry nodes. Use Program::wrapped for runnable programs; reserve Program::new for wire decode and negative tests."
    )]
    #[must_use]
    #[inline]
    pub fn new(buffers: Vec<BufferDecl>, workgroup_size: [u32; 3], entry: Vec<Node>) -> Self {
        Self::new_raw(buffers, workgroup_size, entry)
    }

    #[must_use]
    #[inline]
    pub(crate) fn new_raw(
        buffers: Vec<BufferDecl>,
        workgroup_size: [u32; 3],
        entry: Vec<Node>,
    ) -> Self {
        let mut interner = FxHashMap::<Arc<str>, Arc<str>>::default();
        interner.reserve(buffers.len());
        let buffers: Vec<BufferDecl> = buffers
            .into_iter()
            .map(|mut b| {
                let arc = interner
                    .entry(Arc::clone(&b.name))
                    .or_insert_with(|| Arc::clone(&b.name))
                    .clone();
                b.name = arc;
                b
            })
            .collect();
        let buffer_index = Self::build_buffer_index(&buffers);
        Self {
            entry_op_id: None,
            buffers: Arc::from(buffers),
            buffer_index: Arc::new(buffer_index),
            workgroup_size,
            entry: Arc::new(entry),
            hash: OnceLock::new(),
            validation_set: Arc::new(dashmap::DashSet::new()),
            structural_validated: std::sync::atomic::AtomicBool::new(false),
            fingerprint: OnceLock::new(),
            output_buffer_index: OnceLock::new(),
            has_indirect_dispatch: OnceLock::new(),
            stats: OnceLock::new(),
            non_composable_with_self: false,
        }
    }

    /// Clone this program with a replacement entry body while preserving the
    /// existing buffer table, workgroup size, and optional certified op id.
    #[must_use]
    #[inline]
    pub fn with_rewritten_entry(&self, entry: Vec<Node>) -> Self {
        Self {
            entry_op_id: self.entry_op_id.clone(),
            buffers: Arc::clone(&self.buffers),
            buffer_index: Arc::clone(&self.buffer_index),
            workgroup_size: self.workgroup_size,
            entry: Arc::new(entry),
            hash: OnceLock::new(),
            validation_set: Arc::new(dashmap::DashSet::new()),
            structural_validated: std::sync::atomic::AtomicBool::new(false),
            fingerprint: OnceLock::new(),
            output_buffer_index: OnceLock::new(),
            has_indirect_dispatch: OnceLock::new(),
            stats: OnceLock::new(),
            non_composable_with_self: self.non_composable_with_self,
        }
    }

    #[must_use]
    #[inline]
    pub(crate) fn into_entry_vec(self) -> Vec<Node> {
        Arc::try_unwrap(self.entry).unwrap_or_else(|entry| entry.as_ref().clone())
    }

    /// Create an arena-backed program scaffold.
    ///
    /// This constructor is the opt-in migration path for builders that want
    /// [`ExprRef`](crate::ir_inner::model::arena::ExprRef) handles instead of boxed
    /// expression trees. [`Program::new`] remains the boxed-tree constructor.
    #[must_use]
    #[inline]
    pub fn with_arena(
        arena: &ExprArena,
        buffers: Vec<BufferDecl>,
        workgroup_size: [u32; 3],
    ) -> ArenaProgram<'_> {
        ArenaProgram::new(arena, buffers, workgroup_size)
    }

    /// Create a minimal program with no buffers and an empty body.
    ///
    /// # Examples
    ///
    /// ```
    /// use vyre::ir::Program;
    ///
    /// let program = Program::empty();
    ///
    /// assert!(program.buffers().is_empty());
    /// assert_eq!(program.workgroup_size(), [1, 1, 1]);
    /// assert!(program.is_explicit_noop());
    /// ```
    #[must_use]
    #[inline]
    pub fn empty() -> Self {
        Self::wrapped(Vec::new(), [1, 1, 1], Vec::new())
    }

    /// Attach the stable operation ID whose conform registry entry certifies
    /// this program for runtime lowering.
    #[must_use]
    #[inline]
    pub fn with_entry_op_id(mut self, op_id: impl Into<String>) -> Self {
        self.entry_op_id = Some(op_id.into());
        self.invalidate_caches();
        self
    }

    /// Stable operation ID required by the conform gate.
    #[must_use]
    #[inline]
    pub fn entry_op_id(&self) -> Option<&str> {
        self.entry_op_id.as_deref()
    }

    /// Attach an optional operation ID while preserving anonymous test IR.
    #[must_use]
    #[inline]
    pub(crate) fn with_optional_entry_op_id(mut self, op_id: Option<String>) -> Self {
        self.entry_op_id = op_id;
        self.invalidate_caches();
        self
    }
}
