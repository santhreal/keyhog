#![allow(clippy::expect_used)]
use std::sync::atomic::Ordering;
use std::sync::Arc;
use vyre_spec::bin_op::OpIntensity;

use crate::ir_inner::model::expr::Ident;
use crate::ir_inner::model::node::Node;
use crate::ir_inner::model::types::BufferAccess;

use super::Program;

impl Program {
    /// Re-apply the same top-level `Node::Region` contract as
    /// [`Program::wrapped`].
    ///
    /// The [`transform::optimize::region_inline`](crate::transform::optimize::region_inline)
    /// pass flattens small Category-A regions so CSE/DCE can see a single
    /// function-shaped body, which can leave a statement-shaped entry list. The
    /// standard optimizer run ends with this helper so the program remains in
    /// a runnable, validator/reference-interpreter–compatible form while
    /// still benefiting from the inline pass.
    #[must_use]
    pub fn reconcile_runnable_top_level(self) -> Self {
        let new_entry = Self::wrap_entry(self.entry().to_vec());
        self.with_rewritten_entry(new_entry)
    }

    /// Look up a buffer declaration by name.
    #[must_use]
    #[inline]
    pub fn buffer(&self, name: &str) -> Option<&super::BufferDecl> {
        self.buffer_index
            .get(name)
            .and_then(|&index| self.buffers.get(index))
    }

    /// Declared buffers.
    #[must_use]
    #[inline]
    pub fn buffers(&self) -> &[super::BufferDecl] {
        self.buffers.as_ref()
    }

    /// Compare two programs by observable IR structure.
    ///
    /// This walk intentionally ignores buffer declaration order and never
    /// consults arena-local allocation identity. Two programs are structurally
    /// equal when they declare the same buffers, workgroup size, optional entry
    /// op id, and entry body semantics.
    #[must_use]
    #[inline]
    pub fn structural_eq(&self, other: &Self) -> bool {
        // Identity short-circuit: Program::clone shares all the
        // inner Arcs, so comparing a cloned program against its
        // source (the common optimizer-pipeline pattern) is pure
        // refcount comparison.
        if std::ptr::eq(self, other)
            || (Arc::ptr_eq(&self.buffers, &other.buffers)
                && Arc::ptr_eq(&self.entry, &other.entry)
                && self.entry_op_id == other.entry_op_id
                && self.non_composable_with_self == other.non_composable_with_self
                && self.workgroup_size == other.workgroup_size)
        {
            return true;
        }
        self.entry_op_id == other.entry_op_id
            && self.non_composable_with_self == other.non_composable_with_self
            && buffers_equal_ignoring_declaration_order(&self.buffers, &other.buffers)
            && self.workgroup_size == other.workgroup_size
            && self.entry == other.entry
    }

    /// Workgroup dimensions.
    #[must_use]
    #[inline]
    pub fn workgroup_size(&self) -> [u32; 3] {
        self.workgroup_size
    }

    /// Substrate-neutral alias for [`workgroup_size`](Self::workgroup_size).
    ///
    /// Naming: "workgroup" is the WGSL spelling of the parallel region that
    /// maps to one dispatch invocation grouping. Backends that have their
    /// own spelling (CUDA block, Metal threadgroup, SPIR-V local workgroup,
    /// photonic batch) use this alias to avoid picking a single substrate's
    /// word. See `docs/ARCHITECTURE.md` Law H.
    #[must_use]
    #[inline]
    pub fn parallel_region_size(&self) -> [u32; 3] {
        self.workgroup_size
    }

    /// Return true when this program must not be fused with another copy
    /// of itself in the same megakernel.
    #[must_use]
    #[inline]
    pub fn is_non_composable_with_self(&self) -> bool {
        self.non_composable_with_self
    }

    /// Mark this program as non-composable with itself.
    #[must_use]
    #[inline]
    pub fn with_non_composable_with_self(mut self, flag: bool) -> Self {
        self.non_composable_with_self = flag;
        self.invalidate_caches();
        self
    }

    /// Set the workgroup dimensions in place. Used by harnesses that
    /// need to clone-and-rewrite a program's workgroup size for fallback
    /// dispatch — the alternative was to reconstruct the entire Program,
    /// which is unnecessarily expensive when only one field changes.
    #[inline]
    pub fn set_workgroup_size(&mut self, workgroup_size: [u32; 3]) {
        self.workgroup_size = workgroup_size;
        self.invalidate_caches();
    }

    /// Substrate-neutral alias for [`set_workgroup_size`](Self::set_workgroup_size).
    #[inline]
    pub fn set_parallel_region_size(&mut self, parallel_region_size: [u32; 3]) {
        self.workgroup_size = parallel_region_size;
    }

    /// Entry-point nodes.
    #[must_use]
    #[inline]
    pub fn entry(&self) -> &[Node] {
        self.entry.as_ref().as_slice()
    }

    /// Return true when this Program is the canonical no-op shape produced by
    /// [`Program::empty`]: no buffers and a single empty root Region.
    #[must_use]
    #[inline]
    pub fn is_explicit_noop(&self) -> bool {
        self.buffers().is_empty()
            && matches!(self.entry(), [Node::Region { body, .. }] if body.is_empty())
    }

    /// Return true when the program satisfies the top-level region-chain
    /// invariant: at least one top-level node, and every top-level node is a
    /// `Node::Region`.
    #[must_use]
    #[inline]
    pub fn is_top_level_region_wrapped(&self) -> bool {
        !self.entry.is_empty()
            && self
                .entry()
                .iter()
                .all(|node| matches!(node, Node::Region { .. }))
    }

    /// Actionable error text describing why the top-level region invariant
    /// failed, or `None` when the entry is valid.
    #[must_use]
    pub fn top_level_region_violation(&self) -> Option<String> {
        if self.entry().is_empty() {
            return Some(
                "program entry has no top-level Region. Fix: construct runnable programs with Program::wrapped(...) or wrap the body in Node::Region before validation, interpretation, or dispatch."
                    .to_string(),
            );
        }

        self.entry()
            .iter()
            .enumerate()
            .find(|(_, node)| !matches!(node, Node::Region { .. }))
            .map(|(index, node)| {
                format!(
                    "program entry node {index} is `{}` instead of `Node::Region`. Fix: construct runnable programs with Program::wrapped(...) or wrap the top-level body in Node::Region; raw Program::new is reserved for wire decode and negative tests.",
                    Self::top_level_node_name(node)
                )
            })
    }

    /// Mutable entry-point nodes for transformation passes.
    #[must_use]
    #[inline]
    pub fn entry_mut(&mut self) -> &mut Vec<Node> {
        self.invalidate_caches();
        Arc::make_mut(&mut self.entry)
    }

    /// Stable blake3 fingerprint of the canonical wire-format bytes.
    #[must_use]
    #[inline]
    pub fn fingerprint(&self) -> [u8; 32] {
        *self.fingerprint.get_or_init(|| {
            let hash = self.compute_wire_hash();
            let _ = self.hash.set(hash);
            *hash.as_bytes()
        })
    }

    /// Indices of read-write buffers in `buffers()` order.
    #[must_use]
    #[inline]
    pub fn output_buffer_indices(&self) -> &[u32] {
        self.output_buffer_index
            .get_or_init(|| {
                Arc::new(
                    self.buffers()
                        .iter()
                        .enumerate()
                        .filter_map(|(index, buffer)| {
                            (buffer.access() == BufferAccess::ReadWrite).then_some(index as u32)
                        })
                        .collect(),
                )
            })
            .as_slice()
    }

    /// True when the entry walk discovers any indirect dispatch node.
    #[must_use]
    #[inline]
    pub fn has_indirect_dispatch(&self) -> bool {
        *self.has_indirect_dispatch.get_or_init(|| {
            let mut stack: Vec<&Node> = self.entry().iter().rev().collect();
            while let Some(node) = stack.pop() {
                match node {
                    Node::IndirectDispatch { .. } => return true,
                    Node::If {
                        then, otherwise, ..
                    } => {
                        stack.extend(otherwise.iter().rev());
                        stack.extend(then.iter().rev());
                    }
                    Node::Loop { body, .. } | Node::Block(body) => {
                        stack.extend(body.iter().rev());
                    }
                    Node::Region { body, .. } => {
                        stack.extend(body.iter().rev());
                    }
                    Node::Let { .. }
                    | Node::Assign { .. }
                    | Node::Store { .. }
                    | Node::Return
                    | Node::Barrier
                    | Node::AsyncLoad { .. }
                    | Node::AsyncStore { .. }
                    | Node::AsyncWait { .. }
                    | Node::Trap { .. }
                    | Node::Resume { .. }
                    | Node::Opaque(_) => {}
                }
            }
            false
        })
    }

    /// Check whether a named buffer exists.
    #[must_use]
    #[inline]
    pub fn has_buffer(&self, name: &str) -> bool {
        self.buffer_index.contains_key(name)
    }

    /// Number of declared buffers.
    #[must_use]
    #[inline]
    pub fn buffer_count(&self) -> usize {
        self.buffers.len()
    }

    #[inline]
    pub(super) fn build_buffer_index(
        buffers: &[super::BufferDecl],
    ) -> rustc_hash::FxHashMap<Arc<str>, usize> {
        let mut index = rustc_hash::FxHashMap::default();
        index.reserve(buffers.len());
        for (buffer_index, buffer) in buffers.iter().enumerate() {
            index
                .entry(Arc::clone(&buffer.name))
                .or_insert(buffer_index);
        }
        index
    }

    /// Mark this program as successfully validated structurally.
    #[inline]
    pub fn mark_structurally_validated(&self) {
        self.structural_validated.store(true, Ordering::Release);
    }

    /// Return true once structural validation has succeeded for this program shape.
    #[must_use]
    #[inline]
    pub fn is_structurally_validated(&self) -> bool {
        self.structural_validated.load(Ordering::Acquire)
    }

    /// Mark this program as successfully validated for a specific backend.
    #[inline]
    pub fn mark_validated_on(&self, backend_id: &str) {
        self.validation_set.insert(Arc::from(backend_id));
    }

    /// Return true if this program has been validated for the given backend.
    #[must_use]
    #[inline]
    pub fn is_validated_on(&self, backend_id: &str) -> bool {
        self.validation_set.contains(backend_id)
    }

    /// Deprecated: use `is_structurally_validated` or `is_validated_on`.
    #[deprecated(note = "use is_structurally_validated or is_validated_on")]
    #[must_use]
    #[inline]
    pub fn is_validated(&self) -> bool {
        self.is_structurally_validated()
    }

    /// Deprecated: use `mark_structurally_validated` or `mark_validated_on`.
    #[deprecated(note = "use mark_structurally_validated or mark_validated_on")]
    #[inline]
    pub fn mark_validated(&self) {
        self.mark_structurally_validated();
    }

    /// Validate the program and cache the successful result on the program.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::WireFormatValidation`] with every validation
    /// message joined when the structural validator rejects the program.
    pub fn validate(&self) -> crate::error::Result<()> {
        if self.is_structurally_validated() {
            return Ok(());
        }
        let errors = crate::validate::validate(self);
        if errors.is_empty() {
            self.mark_structurally_validated();
            return Ok(());
        }
        let message = errors
            .into_iter()
            .map(|error| error.message().to_string())
            .collect::<Vec<_>>()
            .join("; ");
        Err(crate::error::Error::WireFormatValidation { message })
    }

    #[inline]
    /// Estimate the peak VRAM byte size of this Program.
    ///
    /// Innovation I.11: Static VRAM Pressure Analysis.
    /// Returns the total bytes required by all storage and uniform buffers
    /// declared in the Program. Optimizer passes use this to automatically
    /// partition workloads if they would exceed a backend-specific safety
    /// margin.
    #[must_use]
    pub fn estimate_peak_vram_bytes(&self) -> u64 {
        self.buffers
            .iter()
            .map(|buffer| {
                let element_size = buffer.element.size_bytes().unwrap_or(4);
                (buffer.count as u64) * (element_size as u64)
            })
            .sum()
    }

    /// Return the peak computational intensity found in any instruction.
    #[must_use]
    pub fn peak_intensity(&self) -> OpIntensity {
        let mut peak = OpIntensity::Free;
        for node in self.entry().iter() {
            peak = peak.max(self.node_intensity(node));
        }
        peak
    }

    fn node_intensity(&self, node: &crate::ir::Node) -> OpIntensity {
        use crate::ir::Node;
        match node {
            Node::Let { value, .. } | Node::Assign { value, .. } => self.expr_intensity(value),
            Node::Store { index, value, .. } => {
                self.expr_intensity(index).max(self.expr_intensity(value))
            }
            Node::If {
                cond,
                then,
                otherwise,
            } => {
                let mut p = self.expr_intensity(cond);
                for n in then {
                    p = p.max(self.node_intensity(n));
                }
                for n in otherwise {
                    p = p.max(self.node_intensity(n));
                }
                p
            }
            Node::Loop { from, to, body, .. } => {
                let mut p = self.expr_intensity(from).max(self.expr_intensity(to));
                for n in body.iter() {
                    p = p.max(self.node_intensity(n));
                }
                p
            }
            Node::Block(nodes) => {
                let mut p = OpIntensity::Free;
                for n in nodes {
                    p = p.max(self.node_intensity(n));
                }
                p
            }
            Node::Region { body, .. } => {
                let mut p = OpIntensity::Free;
                for n in body.iter() {
                    p = p.max(self.node_intensity(n));
                }
                p
            }
            _ => OpIntensity::Free,
        }
    }

    #[allow(clippy::only_used_in_recursion)]
    fn expr_intensity(&self, expr: &crate::ir::Expr) -> OpIntensity {
        use crate::ir::Expr;
        match expr {
            Expr::BinOp { op, left, right } => op
                .intensity()
                .max(self.expr_intensity(left))
                .max(self.expr_intensity(right)),
            Expr::UnOp { operand, .. } => self.expr_intensity(operand),
            Expr::Load { index, .. } => self.expr_intensity(index),
            Expr::Select {
                cond,
                true_val,
                false_val,
            } => self
                .expr_intensity(cond)
                .max(self.expr_intensity(true_val))
                .max(self.expr_intensity(false_val)),
            Expr::Cast { value, .. } => self.expr_intensity(value),
            Expr::Fma { a, b, c } => self
                .expr_intensity(a)
                .max(self.expr_intensity(b))
                .max(self.expr_intensity(c)),
            Expr::Atomic {
                index,
                value,
                expected,
                ..
            } => {
                let mut p = self.expr_intensity(index).max(self.expr_intensity(value));
                if let Some(e) = expected {
                    p = p.max(self.expr_intensity(e));
                }
                p.max(OpIntensity::Heavy)
            }
            Expr::SubgroupBallot { cond } => self.expr_intensity(cond).max(OpIntensity::Heavy),
            Expr::SubgroupShuffle { value, lane } => self
                .expr_intensity(value)
                .max(self.expr_intensity(lane))
                .max(OpIntensity::Heavy),
            Expr::SubgroupAdd { value } => self.expr_intensity(value).max(OpIntensity::Heavy),
            _ => OpIntensity::Free,
        }
    }

    fn compute_wire_hash(&self) -> blake3::Hash {
        let wire = self.to_wire().expect(
            "Fix: fingerprinting requires a wire-serializable Program; validate or repair the IR before caching its fingerprint.",
        );
        blake3::hash(&wire)
    }

    #[inline]
    pub(super) fn invalidate_caches(&mut self) {
        self.structural_validated.store(false, Ordering::Release);
        self.validation_set.clear();
        let _ = self.hash.take();
        let _ = self.fingerprint.take();
        let _ = self.output_buffer_index.take();
        let _ = self.has_indirect_dispatch.take();
        let _ = self.stats.take();
    }

    #[inline]
    pub(super) fn wrap_entry(entry: Vec<Node>) -> Vec<Node> {
        if !Self::entry_needs_root_region(&entry) {
            return entry;
        }
        vec![Node::Region {
            generator: Ident::from(Self::ROOT_REGION_GENERATOR),
            source_region: None,
            body: Arc::new(entry),
        }]
    }

    #[inline]
    fn entry_needs_root_region(entry: &[Node]) -> bool {
        entry.is_empty()
            || entry
                .iter()
                .any(|node| !matches!(node, Node::Region { .. }))
    }

    #[inline]
    fn top_level_node_name(node: &Node) -> &'static str {
        match node {
            Node::Let { .. } => "Let",
            Node::Assign { .. } => "Assign",
            Node::Store { .. } => "Store",
            Node::If { .. } => "If",
            Node::Loop { .. } => "Loop",
            Node::Return => "Return",
            Node::Block(_) => "Block",
            Node::Barrier => "Barrier",
            Node::Region { .. } => "Region",
            Node::IndirectDispatch { .. } => "IndirectDispatch",
            Node::AsyncLoad { .. } => "AsyncLoad",
            Node::AsyncStore { .. } => "AsyncStore",
            Node::AsyncWait { .. } => "AsyncWait",
            Node::Trap { .. } => "Trap",
            Node::Resume { .. } => "Resume",
            Node::Opaque(_) => "Opaque",
        }
    }
}

pub(crate) fn buffers_equal_ignoring_declaration_order(
    left: &[super::BufferDecl],
    right: &[super::BufferDecl],
) -> bool {
    if left.len() != right.len() {
        return false;
    }

    // VYRE_IR_HOTSPOTS HIGH (meta.rs:360-379): previous impl allocated
    // two Vec<Vec<u8>> then sorted on every equality call. Fast-path:
    // if the slices compare equal in-place (declaration orders match)
    // we skip the key-materialization entirely. This catches every
    // Program::clone(prog) == prog and every `Arc::clone`-equivalent
    // comparison, which dominate the call distribution.
    if left == right {
        return true;
    }

    let mut left_keys = left
        .iter()
        .map(buffer_decl_canonical_key)
        .collect::<Vec<_>>();
    let mut right_keys = right
        .iter()
        .map(buffer_decl_canonical_key)
        .collect::<Vec<_>>();
    left_keys.sort_unstable();
    right_keys.sort_unstable();
    left_keys == right_keys
}

fn buffer_decl_canonical_key(buffer: &super::BufferDecl) -> Vec<u8> {
    use crate::serial::wire::framing::{put_len_u32, put_u32, put_u8};
    use crate::serial::wire::tags::put_data_type;

    let mut key = Vec::with_capacity(96);
    put_len_u32(&mut key, buffer.name.len(), "buffer name length")
        .expect("Fix: Program equality requires encodable buffer names");
    key.extend_from_slice(buffer.name.as_bytes());
    put_u32(&mut key, buffer.binding);
    put_u8(
        &mut key,
        crate::serial::wire::tags::access_tag::access_tag(buffer.access.clone())
            .expect("Fix: Program equality requires a stable BufferAccess tag"),
    );
    put_u8(
        &mut key,
        match buffer.kind {
            super::MemoryKind::Global => 0,
            super::MemoryKind::Shared => 1,
            super::MemoryKind::Uniform => 2,
            super::MemoryKind::Local => 3,
            super::MemoryKind::Readonly => 4,
            super::MemoryKind::Persistent => 5,
            super::MemoryKind::Push => 6,
        },
    );
    put_data_type(&mut key, &buffer.element)
        .expect("Fix: Program equality requires a wire-tagged DataType");
    put_u32(&mut key, buffer.count);
    put_u8(&mut key, u8::from(buffer.is_output));
    put_u8(&mut key, u8::from(buffer.pipeline_live_out));
    match &buffer.output_byte_range {
        Some(range) => {
            put_u8(&mut key, 1);
            put_u32(
                &mut key,
                u32::try_from(range.start)
                    .expect("Fix: output range start must fit in canonical Program equality key"),
            );
            put_u32(
                &mut key,
                u32::try_from(range.end)
                    .expect("Fix: output range end must fit in canonical Program equality key"),
            );
        }
        None => put_u8(&mut key, 0),
    }
    match buffer.hints.coalesce_axis {
        Some(axis) => {
            put_u8(&mut key, 1);
            put_u8(&mut key, axis);
        }
        None => put_u8(&mut key, 0),
    }
    put_u32(&mut key, buffer.hints.preferred_alignment);
    put_u8(
        &mut key,
        match buffer.hints.cache_locality {
            super::CacheLocality::Streaming => 0,
            super::CacheLocality::Temporal => 1,
            super::CacheLocality::Random => 2,
        },
    );
    put_u8(&mut key, u8::from(buffer.bytes_extraction));
    key
}
