#![allow(clippy::unwrap_used)]
//! Top-level validation entry point.
//!
//! This module runs the complete validation pipeline on a `Program`:
//! buffer declarations, node structure, expression types, depth limits,
//! and output markers. Every error is returned as a `ValidationError`
//! with an actionable `Fix:` hint.

pub use super::depth::{
    DEFAULT_MAX_CALL_DEPTH, DEFAULT_MAX_EXPR_DEPTH, DEFAULT_MAX_NESTING_DEPTH,
    DEFAULT_MAX_NODE_COUNT,
};
use super::expr_rules::validate_output_markers;
use super::fusion_safety::{collect_expr_accesses, NodeAccesses};
// Self-composition (duplicate self-exclusive regions) is enforced in
// `PreorderValidator::run` via `self_comp_counts` — do not add a second
// `duplicate_self_exclusive_regions` walk here.
use super::{depth, err, nodes, ValidationError, ValidationOptions, ValidationReport};
use crate::composition::self_exclusive_region_key;
use crate::ir_inner::model::expr::{Expr, Ident};
use crate::ir_inner::model::node::Node;
use crate::ir_inner::model::program::Program;
use crate::ir_inner::model::types::{BufferAccess, DataType};
use crate::visit::traits::{dispatch_node, NodeVisitor};
use rustc_hash::{FxHashMap, FxHashSet};
use std::convert::Infallible;
use std::ops::ControlFlow;

/// Validate a program for structural and semantic correctness.
///
/// The validator checks the stable rules documented in
/// `vyre/docs/ir/validation.md`: workgroup dimensions must be positive,
/// buffer names and bindings must be unique, workgroup buffers must have
/// a positive element count, and the node tree must respect depth limits.
/// A successful validation (empty error vector) means the program is
/// safe to lower to any backend.
///
/// # Examples
///
/// ```
/// use vyre::ir::{Program, validate};
///
/// let program = Program::wrapped(Vec::new(), [1, 1, 1], Vec::new());
/// let errors = validate(&program);
/// assert!(errors.is_empty());
/// ```
#[inline]
#[must_use]
pub fn validate(program: &Program) -> Vec<ValidationError> {
    validate_with_options(program, ValidationOptions::default()).errors
}

/// Validate a program with explicit backend/shadowing options.
///
/// `ValidationOptions::default()` performs best-effort universal validation:
/// it enforces backend-independent structural rules but does not reject
/// backend-specific cast targets unless a concrete backend capability contract
/// is supplied.
#[inline]
#[must_use]
pub fn validate_with_options(
    program: &Program,
    options: ValidationOptions<'_>,
) -> ValidationReport {
    let mut report = ValidationReport {
        errors: Vec::with_capacity(program.buffers().len() + program.entry().len()),
        warnings: Vec::new(),
    };

    if let Some(message) = program.top_level_region_violation() {
        report.errors.push(err(message));
    }

    for (axis, &size) in program.workgroup_size.iter().enumerate() {
        if size == 0 {
            report.errors.push(err(format!(
                "workgroup_size[{axis}] is 0. Fix: all workgroup dimensions must be >= 1."
            )));
        }
    }

    let mut seen_names = FxHashSet::default();
    seen_names.reserve(program.buffers().len());
    let mut seen_bindings = FxHashSet::default();
    seen_bindings.reserve(program.buffers().len());
    for buf in program.buffers() {
        if !seen_names.insert(&buf.name) {
            report.errors.push(err(format!(
                "duplicate buffer name `{}`. Fix: each buffer must have a unique name.",
                buf.name
            )));
        }
        if buf.access != BufferAccess::Workgroup && !seen_bindings.insert(buf.binding) {
            report.errors.push(err(format!(
                "duplicate binding slot {} (buffer `{}`). Fix: each buffer must have a unique binding.",
                buf.binding, buf.name
            )));
        }
        if buf.access == BufferAccess::Workgroup && buf.count == 0 {
            report.errors.push(err(format!(
                "workgroup buffer `{}` has count 0. Fix: declare a positive element count.",
                buf.name
            )));
        }
        validate_output_buffer_element_type(buf, &mut report.errors);
    }
    validate_output_markers(program.buffers(), &mut report.errors);

    let mut buffer_map: FxHashMap<&str, &crate::ir_inner::model::program::BufferDecl> =
        FxHashMap::default();
    buffer_map.reserve(program.buffers().len());
    buffer_map.extend(program.buffers().iter().map(|b| (b.name.as_ref(), b)));

    let mut validator = PreorderValidator::new(program, options, buffer_map);
    validator.run(program.entry());
    report.errors.append(&mut validator.errors);
    report.warnings.append(&mut validator.warnings);

    report
}

fn validate_output_buffer_element_type(
    buf: &crate::ir_inner::model::program::BufferDecl,
    errors: &mut Vec<ValidationError>,
) {
    if !buf.is_output() {
        return;
    }

    if matches!(buf.element(), DataType::Array { .. } | DataType::Tensor) {
        errors.push(err(format!(
            "output buffer `{}` uses unsupported element type `{}`. Fix: output buffers must use fixed-width scalar or vector element types, not Array or Tensor.",
            buf.name(),
            buf.element()
        )));
    }
}

// ------------------------------------------------------------------
// PreorderValidator — single-pass explicit-stack traversal
// ------------------------------------------------------------------

use super::barrier;
use super::binding::{check_sibling_duplicate, Binding};
use super::bytes_rejection;
use super::expr_rules;
use super::shadowing;
use super::typecheck::expr_type;
use super::uniformity::is_uniform;
// use super::report::warn;

/// Scope frame pushed for every nested node sequence.
struct ScopeFrame<'p> {
    scope_log: nodes::ScopeLog,
    region_bindings: FxHashSet<String>,
    divergent: bool,
    depth: usize,
    nodes: &'p [Node],
}

/// Stack frames for the explicit traversal.
enum Frame<'p> {
    /// Visit a single node (pre-order).
    Child(&'p Node),
    /// Post-order action for `If`: extend parent alias state with cond accesses.
    PostIf,
    /// Post-order action for `Loop`: extend parent alias state with from/to accesses.
    PostLoop,
    /// Enter a new scope.
    PushScope {
        divergent: bool,
        depth: usize,
        nodes: &'p [Node],
    },
    /// Leave the current scope and check `Return` position.
    PopScope,
    /// Enter a fresh alias tracking frame.
    PushAlias,
    /// Restore the parent alias tracking frame.
    PopAlias,
    /// Inject the loop variable binding into the current scope. The
    /// `uniform` flag mirrors the loop's bound uniformity: in a
    /// uniform-bound loop every invocation walks the same iteration
    /// count with the same counter value, so the loop var is itself
    /// uniform.
    InsertLoopVar { var: Ident, uniform: bool },
}

/// Single-pass validator that performs all node-tree checks in one
/// explicit-stack traversal.
struct PreorderValidator<'p, 'o> {
    program: &'p Program,
    options: ValidationOptions<'o>,
    buffers: FxHashMap<&'p str, &'p crate::ir_inner::model::program::BufferDecl>,
    scope: FxHashMap<String, Binding>,
    scope_stack: Vec<ScopeFrame<'p>>,
    limits: depth::LimitState,
    alias_reads: FxHashSet<String>,
    alias_atomics: FxHashSet<String>,
    alias_stack: Vec<(FxHashSet<String>, FxHashSet<String>)>,
    pending_alias_extensions: Vec<NodeAccesses>,
    self_comp_counts: FxHashMap<String, usize>,
    errors: Vec<ValidationError>,
    warnings: Vec<super::ValidationWarning>,
}

impl<'p, 'o> PreorderValidator<'p, 'o> {
    fn new(
        program: &'p Program,
        options: ValidationOptions<'o>,
        buffers: FxHashMap<&'p str, &'p crate::ir_inner::model::program::BufferDecl>,
    ) -> Self {
        Self {
            program,
            options,
            buffers,
            scope: FxHashMap::default(),
            scope_stack: Vec::new(),
            limits: depth::LimitState::default(),
            alias_reads: FxHashSet::default(),
            alias_atomics: FxHashSet::default(),
            alias_stack: Vec::new(),
            pending_alias_extensions: Vec::new(),
            self_comp_counts: FxHashMap::default(),
            errors: Vec::new(),
            warnings: Vec::new(),
        }
    }

    fn run(&mut self, nodes: &'p [Node]) {
        let mut stack: Vec<Frame<'p>> = Vec::new();
        stack.push(Frame::PopScope);
        for node in nodes.iter().rev() {
            stack.push(Frame::Child(node));
        }
        stack.push(Frame::PushAlias);
        stack.push(Frame::PushScope {
            divergent: false,
            depth: 0,
            nodes,
        });

        while let Some(frame) = stack.pop() {
            match frame {
                Frame::Child(node) => {
                    if dispatch_node(self, node).is_break() {
                        break;
                    }
                    match node {
                        Node::If {
                            cond,
                            then,
                            otherwise,
                            ..
                        } => {
                            let depth = self.current_depth();
                            // Branches stay non-divergent only when the
                            // parent scope is already uniform AND the
                            // condition is uniform across the workgroup.
                            // A non-uniform cond splits invocations
                            // across the two branches, so any barrier
                            // inside is reached by only some lanes.
                            let parent_divergent = self.current_divergent();
                            let branch_divergent =
                                parent_divergent || !is_uniform(cond, &self.scope);
                            stack.push(Frame::PostIf);
                            push_nested_sequence(
                                &mut stack,
                                otherwise,
                                branch_divergent,
                                depth + 1,
                                None,
                            );
                            push_nested_sequence(
                                &mut stack,
                                then,
                                branch_divergent,
                                depth + 1,
                                None,
                            );
                        }
                        Node::Loop {
                            var,
                            from,
                            to,
                            body,
                        } => {
                            let depth = self.current_depth();
                            // The loop body is divergent only when its
                            // parent already is OR when either bound
                            // varies across the workgroup. Uniform
                            // bounds keep every invocation in lockstep
                            // — same iteration count, same loop-var
                            // value at each step — so a barrier inside
                            // is reached by every lane simultaneously.
                            let parent_divergent = self.current_divergent();
                            let bounds_uniform =
                                is_uniform(from, &self.scope) && is_uniform(to, &self.scope);
                            let body_divergent = parent_divergent || !bounds_uniform;
                            // Loop var inherits the bounds' uniformity
                            // when the parent is also uniform; if the
                            // parent is divergent the var only matters
                            // within already-divergent context.
                            let var_uniform = bounds_uniform && !parent_divergent;
                            stack.push(Frame::PostLoop);
                            push_nested_sequence(
                                &mut stack,
                                body,
                                body_divergent,
                                depth + 1,
                                Some(Frame::InsertLoopVar {
                                    var: var.clone(),
                                    uniform: var_uniform,
                                }),
                            );
                        }
                        Node::Block(body) => {
                            let depth = self.current_depth();
                            let divergent = self.current_divergent();
                            push_nested_sequence(&mut stack, body, divergent, depth + 1, None);
                        }
                        Node::Region { body, .. } => {
                            let depth = self.current_depth();
                            let divergent = self.current_divergent();
                            push_nested_sequence(&mut stack, body, divergent, depth + 1, None);
                        }
                        _ => {}
                    }
                }
                Frame::PostIf => {
                    if let Some(accesses) = self.pending_alias_extensions.pop() {
                        self.extend_alias(&accesses);
                    }
                }
                Frame::PostLoop => {
                    if let Some(accesses) = self.pending_alias_extensions.pop() {
                        self.extend_alias(&accesses);
                    }
                }
                Frame::PushScope {
                    divergent,
                    depth,
                    nodes,
                } => {
                    self.scope_stack.push(ScopeFrame {
                        scope_log: Vec::new(),
                        region_bindings: FxHashSet::default(),
                        divergent,
                        depth,
                        nodes,
                    });
                }
                Frame::PopScope => {
                    let Some(frame) = self.scope_stack.pop() else {
                        self.errors.push(err(
                            "malformed validation frame stream: PopScope without matching PushScope. Fix: rebuild the program through the structured IR builder before validation.".to_string(),
                        ));
                        continue;
                    };
                    nodes::restore_scope(&mut self.scope, frame.scope_log);
                    if let Some(pos) = frame.nodes.iter().position(|n| matches!(n, Node::Return)) {
                        if pos != frame.nodes.len().saturating_sub(1) {
                            self.errors.push(err(
                                "unreachable statements after `return`. Fix: remove statements after `return` or reorder them.".to_string(),
                            ));
                        }
                    }
                }
                Frame::PushAlias => {
                    let reads = std::mem::take(&mut self.alias_reads);
                    let atomics = std::mem::take(&mut self.alias_atomics);
                    self.alias_stack.push((reads, atomics));
                    self.alias_reads = FxHashSet::default();
                    self.alias_atomics = FxHashSet::default();
                }
                Frame::PopAlias => {
                    let Some((reads, atomics)) = self.alias_stack.pop() else {
                        self.errors.push(err(
                            "malformed validation frame stream: PopAlias without matching PushAlias. Fix: rebuild the program through the structured IR builder before validation.".to_string(),
                        ));
                        continue;
                    };
                    let _ = std::mem::take(&mut self.alias_reads);
                    let _ = std::mem::take(&mut self.alias_atomics);
                    self.alias_reads = reads;
                    self.alias_atomics = atomics;
                }
                Frame::InsertLoopVar { var, uniform } => {
                    let Some(frame) = self.scope_stack.last_mut() else {
                        self.errors.push(err(format!(
                            "malformed validation frame stream: loop variable `{var}` inserted outside any scope. Fix: rebuild the program through the structured IR builder before validation."
                        )));
                        continue;
                    };
                    nodes::insert_binding(
                        &mut self.scope,
                        var.to_string(),
                        Binding {
                            ty: DataType::U32,
                            mutable: false,
                            uniform,
                        },
                        Some(&mut frame.scope_log),
                    );
                }
            }
        }

        // Emit self-composition errors deterministically.
        let mut duplicates: Vec<String> = self
            .self_comp_counts
            .drain()
            .filter_map(|(generator, count)| (count > 1).then_some(generator))
            .collect();
        duplicates.sort();
        for generator in duplicates {
            self.errors.push(err(format!(
                "region `{generator}` is marked non-composable with itself but appears multiple times in one fused program. Fix: split the parser into separate dispatches, or give each instance distinct scratch storage before fusion."
            )));
        }
    }

    #[inline]
    fn current_divergent(&self) -> bool {
        self.scope_stack
            .last()
            .map(|f| f.divergent)
            .unwrap_or(false)
    }

    #[inline]
    fn current_depth(&self) -> usize {
        self.scope_stack.last().map(|f| f.depth).unwrap_or(0)
    }

    /// Run the legacy `validate_expr` helper and merge its diagnostics.
    fn validate_expr(&mut self, expr: &Expr, depth_level: usize) {
        let mut report = ValidationReport {
            errors: Vec::new(),
            warnings: Vec::new(),
        };
        expr_rules::validate_expr(
            expr,
            &self.buffers,
            &self.scope,
            self.options,
            &mut report,
            depth_level,
        );
        self.errors.append(&mut report.errors);
        self.warnings.append(&mut report.warnings);
    }

    /// Report fusion-alias hazards between `accesses` and the current linear state.
    fn report_alias_hazards(&mut self, accesses: &NodeAccesses) {
        let mut hazards = accesses
            .atomic_buffers
            .intersection(&self.alias_reads)
            .cloned()
            .collect::<Vec<_>>();
        hazards.extend(
            accesses
                .read_buffers
                .intersection(&self.alias_atomics)
                .cloned(),
        );
        hazards.sort();
        hazards.dedup();

        for buffer in hazards {
            self.errors.push(err(format!(
                "fusion hazard on buffer `{buffer}`: one node reads it non-atomically while another issues an atomic access without an explicit barrier. Fix: insert `Node::barrier()` between the read path and the atomic path, or rename the buffers before fusion."
            )));
        }
    }

    /// Extend the current alias frame with `accesses`.
    fn extend_alias(&mut self, accesses: &NodeAccesses) {
        self.alias_reads
            .extend(accesses.read_buffers.iter().cloned());
        self.alias_atomics
            .extend(accesses.atomic_buffers.iter().cloned());
    }
}

/// Push the stack frames needed to process a nested node sequence.
fn push_nested_sequence<'p>(
    stack: &mut Vec<Frame<'p>>,
    nodes: &'p [Node],
    divergent: bool,
    depth: usize,
    pre_children: Option<Frame<'p>>,
) {
    stack.push(Frame::PopScope);
    stack.push(Frame::PopAlias);
    for child in nodes.iter().rev() {
        stack.push(Frame::Child(child));
    }
    if let Some(pre) = pre_children {
        stack.push(pre);
    }
    stack.push(Frame::PushAlias);
    stack.push(Frame::PushScope {
        divergent,
        depth,
        nodes,
    });
}

// ------------------------------------------------------------------
// NodeVisitor implementation
// ------------------------------------------------------------------

impl NodeVisitor for PreorderValidator<'_, '_> {
    type Break = Infallible;

    fn visit_let(&mut self, _node: &Node, name: &Ident, value: &Expr) -> ControlFlow<Self::Break> {
        let depth = self.current_depth();
        depth::check_limits(&mut self.limits, depth, &mut self.errors);
        self.validate_expr(value, 0);

        let Some(frame) = self.scope_stack.last_mut() else {
            self.errors.push(err(format!(
                "malformed validation frame stream: let binding `{name}` appeared outside any scope. Fix: rebuild the program through the structured IR builder before validation."
            )));
            return ControlFlow::Continue(());
        };
        let duplicate_sibling =
            check_sibling_duplicate(name, &mut frame.region_bindings, &mut self.errors);
        if !duplicate_sibling {
            shadowing::check_local(name, &self.scope, self.options, &mut self.errors);
        }
        let ty = expr_type(value, &self.buffers, &self.scope).unwrap_or(DataType::U32);
        let uniform = is_uniform(value, &self.scope);
        nodes::insert_binding(
            &mut self.scope,
            name.to_string(),
            Binding {
                ty,
                mutable: true,
                uniform,
            },
            Some(&mut frame.scope_log),
        );

        let mut accesses = NodeAccesses::default();
        collect_expr_accesses(value, &mut accesses);
        self.report_alias_hazards(&accesses);
        self.extend_alias(&accesses);

        ControlFlow::Continue(())
    }

    fn visit_assign(
        &mut self,
        _node: &Node,
        name: &Ident,
        value: &Expr,
    ) -> ControlFlow<Self::Break> {
        let depth = self.current_depth();
        depth::check_limits(&mut self.limits, depth, &mut self.errors);
        if let Some(binding) = self.scope.get(name.as_str()) {
            if !binding.mutable {
                self.errors.push(err(format!(
                    "V011: assignment to loop variable `{name}`. Fix: loop variables are immutable."
                )));
            }
        } else {
            self.errors.push(err(format!(
                "assignment to undeclared variable `{name}`. Fix: add `let {name} = ...;` before this assignment."
            )));
        }
        self.validate_expr(value, 0);

        // Reassigning with a divergent rhs taints the binding's
        // uniformity for the remainder of its lifetime.
        let new_uniform = is_uniform(value, &self.scope);
        if let Some(binding) = self.scope.get_mut(name.as_str()) {
            binding.uniform = binding.uniform && new_uniform;
        }

        let mut accesses = NodeAccesses::default();
        collect_expr_accesses(value, &mut accesses);
        self.report_alias_hazards(&accesses);
        self.extend_alias(&accesses);

        ControlFlow::Continue(())
    }

    fn visit_store(
        &mut self,
        _node: &Node,
        buffer: &Ident,
        index: &Expr,
        value: &Expr,
    ) -> ControlFlow<Self::Break> {
        let depth = self.current_depth();
        depth::check_limits(&mut self.limits, depth, &mut self.errors);
        bytes_rejection::check_store(buffer, &self.buffers, &mut self.errors);
        if let Some(buf) = self.buffers.get(buffer.as_str()) {
            if let Some(val_ty) = expr_type(value, &self.buffers, &self.scope) {
                let elem = &buf.element;
                let compatible = val_ty == *elem
                    || matches!(
                        (&val_ty, elem),
                        (DataType::U32, DataType::Bytes)
                            | (DataType::Bytes, DataType::U32)
                            | (DataType::U32, DataType::Bool)
                            | (DataType::Bool, DataType::U32)
                    )
                    || matches!((&val_ty, elem), (DataType::F32, DataType::F32));
                if !compatible {
                    let legal_targets = nodes::store_value_targets(elem);
                    self.errors.push(err(format!(
                        "Node::Store buffer `{buffer}` value has type `{val_ty}` but element type is `{elem}`. Fix: cast/store using one of {}.", legal_targets
                    )));
                }
            }
            nodes::check_constant_store_index(buffer, buf, index, &mut self.errors);
        }
        self.validate_expr(index, 0);
        self.validate_expr(value, 0);

        let mut accesses = NodeAccesses::default();
        accesses.read_buffers.insert(buffer.to_string());
        collect_expr_accesses(index, &mut accesses);
        collect_expr_accesses(value, &mut accesses);
        self.report_alias_hazards(&accesses);
        self.extend_alias(&accesses);

        ControlFlow::Continue(())
    }

    fn visit_if(
        &mut self,
        _node: &Node,
        cond: &Expr,
        _then: &[Node],
        _otherwise: &[Node],
    ) -> ControlFlow<Self::Break> {
        let depth = self.current_depth();
        depth::check_limits(&mut self.limits, depth, &mut self.errors);
        self.validate_expr(cond, 0);
        if let Some(cond_ty) = expr_type(cond, &self.buffers, &self.scope) {
            if !matches!(cond_ty, DataType::U32 | DataType::Bool) {
                self.errors.push(err(format!(
                    "Node::If condition has type `{cond_ty}` but must be `u32` or `bool`. Fix: cast or rewrite the condition expression to produce `u32` or `bool`."
                )));
            }
        }

        let mut accesses = NodeAccesses::default();
        collect_expr_accesses(cond, &mut accesses);
        self.report_alias_hazards(&accesses);
        self.pending_alias_extensions.push(accesses);

        ControlFlow::Continue(())
    }

    fn visit_loop(
        &mut self,
        _node: &Node,
        var: &Ident,
        from: &Expr,
        to: &Expr,
        _body: &[Node],
    ) -> ControlFlow<Self::Break> {
        let depth = self.current_depth();
        depth::check_limits(&mut self.limits, depth, &mut self.errors);
        self.validate_expr(from, 0);
        self.validate_expr(to, 0);
        if let Some(from_ty) = expr_type(from, &self.buffers, &self.scope) {
            if from_ty != DataType::U32 {
                self.errors.push(err(format!(
                    "Node::Loop from-bound has type `{from_ty}`; legal loop bound type is `u32`. Fix: cast the `from` bound to `u32`."
                )));
            }
        }
        if let Some(to_ty) = expr_type(to, &self.buffers, &self.scope) {
            if to_ty != DataType::U32 {
                self.errors.push(err(format!(
                    "Node::Loop to-bound has type `{to_ty}`; legal loop bound type is `u32`. Fix: cast the `to` bound to `u32`."
                )));
            }
        }
        shadowing::check_local(var, &self.scope, self.options, &mut self.errors);

        let mut accesses = NodeAccesses::default();
        collect_expr_accesses(from, &mut accesses);
        collect_expr_accesses(to, &mut accesses);
        self.report_alias_hazards(&accesses);
        self.pending_alias_extensions.push(accesses);

        ControlFlow::Continue(())
    }

    fn visit_indirect_dispatch(
        &mut self,
        _node: &Node,
        count_buffer: &Ident,
        count_offset: u64,
    ) -> ControlFlow<Self::Break> {
        let depth = self.current_depth();
        depth::check_limits(&mut self.limits, depth, &mut self.errors);
        if count_offset % 4 != 0 {
            self.errors.push(err(format!(
                "indirect dispatch offset {count_offset} is not 4-byte aligned. Fix: use an offset aligned to a u32 dispatch count tuple."
            )));
        }
        if !self.buffers.contains_key(count_buffer.as_str()) {
            self.errors.push(err(format!(
                "indirect dispatch references unknown buffer `{count_buffer}`. Fix: declare the count buffer before validation."
            )));
        }

        let mut accesses = NodeAccesses::default();
        accesses.read_buffers.insert(count_buffer.to_string());
        self.report_alias_hazards(&accesses);
        self.extend_alias(&accesses);

        ControlFlow::Continue(())
    }

    fn visit_async_load(
        &mut self,
        _node: &Node,
        source: &Ident,
        destination: &Ident,
        _offset: &Expr,
        _size: &Expr,
        tag: &Ident,
    ) -> ControlFlow<Self::Break> {
        let depth = self.current_depth();
        depth::check_limits(&mut self.limits, depth, &mut self.errors);
        if tag.is_empty() {
            self.errors.push(err(
                "async stream tag is empty. Fix: use a stable non-empty tag to pair AsyncLoad and AsyncWait nodes."
                    .to_string(),
            ));
        }

        let mut accesses = NodeAccesses::default();
        accesses.read_buffers.insert(source.to_string());
        accesses.read_buffers.insert(destination.to_string());
        self.report_alias_hazards(&accesses);
        self.extend_alias(&accesses);

        ControlFlow::Continue(())
    }

    fn visit_async_store(
        &mut self,
        _node: &Node,
        source: &Ident,
        destination: &Ident,
        _offset: &Expr,
        _size: &Expr,
        tag: &Ident,
    ) -> ControlFlow<Self::Break> {
        let depth = self.current_depth();
        depth::check_limits(&mut self.limits, depth, &mut self.errors);
        if tag.is_empty() {
            self.errors.push(err(
                "async stream tag is empty. Fix: use a stable non-empty tag to pair AsyncLoad and AsyncWait nodes."
                    .to_string(),
            ));
        }

        let mut accesses = NodeAccesses::default();
        accesses.read_buffers.insert(source.to_string());
        accesses.read_buffers.insert(destination.to_string());
        self.report_alias_hazards(&accesses);
        self.extend_alias(&accesses);

        ControlFlow::Continue(())
    }

    fn visit_async_wait(&mut self, _node: &Node, tag: &Ident) -> ControlFlow<Self::Break> {
        let depth = self.current_depth();
        depth::check_limits(&mut self.limits, depth, &mut self.errors);
        if tag.is_empty() {
            self.errors.push(err(
                "async stream tag is empty. Fix: use a stable non-empty tag to pair AsyncLoad and AsyncWait nodes."
                    .to_string(),
            ));
        }
        ControlFlow::Continue(())
    }

    fn visit_trap(
        &mut self,
        _node: &Node,
        _address: &Expr,
        _tag: &Ident,
    ) -> ControlFlow<Self::Break> {
        let depth = self.current_depth();
        depth::check_limits(&mut self.limits, depth, &mut self.errors);
        ControlFlow::Continue(())
    }

    fn visit_resume(&mut self, _node: &Node, _tag: &Ident) -> ControlFlow<Self::Break> {
        let depth = self.current_depth();
        depth::check_limits(&mut self.limits, depth, &mut self.errors);
        ControlFlow::Continue(())
    }

    fn visit_return(&mut self, _node: &Node) -> ControlFlow<Self::Break> {
        let depth = self.current_depth();
        depth::check_limits(&mut self.limits, depth, &mut self.errors);
        ControlFlow::Continue(())
    }

    fn visit_barrier(&mut self, _node: &Node) -> ControlFlow<Self::Break> {
        let depth = self.current_depth();
        depth::check_limits(&mut self.limits, depth, &mut self.errors);
        let divergent = self.current_divergent();
        barrier::check_barrier(divergent, &mut self.errors);
        self.alias_reads.clear();
        self.alias_atomics.clear();
        ControlFlow::Continue(())
    }

    fn visit_block(&mut self, _node: &Node, _body: &[Node]) -> ControlFlow<Self::Break> {
        let depth = self.current_depth();
        depth::check_limits(&mut self.limits, depth, &mut self.errors);
        ControlFlow::Continue(())
    }

    fn visit_region(
        &mut self,
        _node: &Node,
        generator: &Ident,
        _source_region: &Option<crate::ir_inner::model::expr::GeneratorRef>,
        _body: &[Node],
    ) -> ControlFlow<Self::Break> {
        let depth = self.current_depth();
        depth::check_limits(&mut self.limits, depth, &mut self.errors);
        if let Some(base) = self_exclusive_region_key(generator.as_str()) {
            *self.self_comp_counts.entry(base.to_string()).or_insert(0) += 1;
        }
        ControlFlow::Continue(())
    }

    fn visit_opaque_node(
        &mut self,
        _node: &Node,
        extension: &dyn crate::ir_inner::model::node::NodeExtension,
    ) -> ControlFlow<Self::Break> {
        let depth = self.current_depth();
        depth::check_limits(&mut self.limits, depth, &mut self.errors);
        if extension.extension_kind().is_empty() {
            self.errors.push(err(
                "V031: opaque node extension has an empty extension_kind. Fix: return a stable non-empty namespace from NodeExtension::extension_kind.",
            ));
        }
        if extension.debug_identity().is_empty() {
            self.errors.push(err(format!(
                "V031: opaque node extension `{}` has an empty debug_identity. Fix: return a stable human-readable identity from NodeExtension::debug_identity.",
                extension.extension_kind()
            )));
        }
        if let Err(message) = extension.validate_extension() {
            self.errors.push(err(format!(
                "V031: opaque node extension `{}`/`{}` failed validation: {message}",
                extension.extension_kind(),
                extension.debug_identity()
            )));
        }
        ControlFlow::Continue(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{
        AtomicOp, BinOp, BufferAccess, BufferDecl, DataType, Expr, Node, Program, UnOp,
    };
    use crate::validate::fusion_safety::validate_fusion_alias_hazards;
    use crate::validate::self_composition::validate_self_composition;
    use proptest::prelude::*;

    // ------------------------------------------------------------------
    // Legacy multi-walk validator (copied from pre-refactor code) for
    // regression testing.
    // ------------------------------------------------------------------
    fn validate_with_options_legacy(
        program: &Program,
        options: ValidationOptions<'_>,
    ) -> ValidationReport {
        let mut report = ValidationReport {
            errors: Vec::with_capacity(program.buffers().len() + program.entry().len()),
            warnings: Vec::new(),
        };

        if let Some(message) = program.top_level_region_violation() {
            report.errors.push(err(message));
        }

        for (axis, &size) in program.workgroup_size.iter().enumerate() {
            if size == 0 {
                report.errors.push(err(format!(
                    "workgroup_size[{axis}] is 0. Fix: all workgroup dimensions must be >= 1."
                )));
            }
        }

        let mut seen_names = FxHashSet::default();
        let mut seen_bindings = FxHashSet::default();
        for buf in program.buffers() {
            if !seen_names.insert(&buf.name) {
                report.errors.push(err(format!(
                    "duplicate buffer name `{}`. Fix: each buffer must have a unique name.",
                    buf.name
                )));
            }
            if buf.access != BufferAccess::Workgroup && !seen_bindings.insert(buf.binding) {
                report.errors.push(err(format!(
                    "duplicate binding slot {} (buffer `{}`). Fix: each buffer must have a unique binding.",
                    buf.binding, buf.name
                )));
            }
            if buf.access == BufferAccess::Workgroup && buf.count == 0 {
                report.errors.push(err(format!(
                    "workgroup buffer `{}` has count 0. Fix: declare a positive element count.",
                    buf.name
                )));
            }
            validate_output_buffer_element_type(buf, &mut report.errors);
        }
        validate_output_markers(program.buffers(), &mut report.errors);

        let mut buffer_map: FxHashMap<&str, &crate::ir_inner::model::program::BufferDecl> =
            FxHashMap::default();
        buffer_map.reserve(program.buffers().len());
        buffer_map.extend(program.buffers().iter().map(|b| (b.name.as_ref(), b)));

        let mut scope = FxHashMap::default();
        let mut limits = depth::LimitState::default();
        nodes::validate_nodes(
            program.entry(),
            &buffer_map,
            &mut scope,
            false,
            0,
            &mut limits,
            options,
            &mut report,
        );
        validate_fusion_alias_hazards(program.entry(), &mut report.errors);
        validate_self_composition(program.entry(), &mut report.errors);

        report
    }

    // ------------------------------------------------------------------
    // Proptest generators (adapted from transform::visit tests).
    // ------------------------------------------------------------------
    fn arb_ident() -> BoxedStrategy<String> {
        prop::sample::select(&["x", "y", "idx", "i", "acc"][..])
            .prop_map(str::to_string)
            .boxed()
    }

    fn arb_buffer_name() -> BoxedStrategy<String> {
        prop::sample::select(&["out", "input", "rw", "counts", "scratch"][..])
            .prop_map(str::to_string)
            .boxed()
    }

    fn arb_expr() -> BoxedStrategy<Expr> {
        let leaf = prop_oneof![
            any::<u32>().prop_map(Expr::LitU32),
            any::<i32>().prop_map(Expr::LitI32),
            any::<bool>().prop_map(Expr::LitBool),
            arb_ident().prop_map(Expr::var),
            arb_buffer_name().prop_map(Expr::buf_len),
        ];

        leaf.prop_recursive(3, 48, 3, |inner| {
            prop_oneof![
                (arb_buffer_name(), inner.clone()).prop_map(|(buffer, index)| Expr::Load {
                    buffer: buffer.into(),
                    index: Box::new(index),
                }),
                (inner.clone(), inner.clone()).prop_map(|(left, right)| Expr::BinOp {
                    op: BinOp::Add,
                    left: Box::new(left),
                    right: Box::new(right),
                }),
                (inner.clone(), inner.clone()).prop_map(|(left, right)| Expr::BinOp {
                    op: BinOp::Sub,
                    left: Box::new(left),
                    right: Box::new(right),
                }),
                inner.clone().prop_map(|operand| Expr::UnOp {
                    op: UnOp::Negate,
                    operand: Box::new(operand),
                }),
                (inner.clone(), inner.clone(), inner.clone()).prop_map(
                    |(cond, true_val, false_val)| Expr::Select {
                        cond: Box::new(cond),
                        true_val: Box::new(true_val),
                        false_val: Box::new(false_val),
                    }
                ),
                inner.clone().prop_map(|value| Expr::Cast {
                    target: DataType::U32,
                    value: Box::new(value),
                }),
                (
                    arb_buffer_name(),
                    inner.clone(),
                    proptest::option::of(inner.clone()),
                    inner.clone(),
                )
                    .prop_map(|(buffer, index, expected, value)| Expr::Atomic {
                        op: AtomicOp::Add,
                        buffer: buffer.into(),
                        index: Box::new(index),
                        expected: expected.map(Box::new),
                        value: Box::new(value),
                    }),
            ]
        })
        .boxed()
    }

    fn arb_node() -> BoxedStrategy<Node> {
        arb_node_with_depth(3)
    }

    fn arb_node_with_depth(depth: u32) -> BoxedStrategy<Node> {
        let leaf = prop_oneof![
            (arb_ident(), arb_expr()).prop_map(|(name, value)| Node::Let {
                name: name.into(),
                value,
            }),
            (arb_ident(), arb_expr()).prop_map(|(name, value)| Node::Assign {
                name: name.into(),
                value,
            }),
            (arb_buffer_name(), arb_expr(), arb_expr()).prop_map(|(buffer, index, value)| {
                Node::Store {
                    buffer: buffer.into(),
                    index,
                    value,
                }
            }),
            Just(Node::Return),
            Just(Node::Barrier),
        ];

        if depth == 0 {
            return leaf.boxed();
        }

        leaf.prop_recursive(2, 32, 2, move |inner| {
            prop_oneof![
                (
                    arb_expr(),
                    prop::collection::vec(inner.clone(), 0..=3),
                    prop::collection::vec(inner.clone(), 0..=3),
                )
                    .prop_map(|(cond, then, otherwise)| Node::If {
                        cond,
                        then,
                        otherwise,
                    }),
                (
                    arb_ident(),
                    arb_expr(),
                    arb_expr(),
                    prop::collection::vec(inner.clone(), 0..=3),
                )
                    .prop_map(|(var, from, to, body)| Node::Loop {
                        var: var.into(),
                        from,
                        to,
                        body,
                    }),
                prop::collection::vec(inner, 0..=3).prop_map(Node::Block),
            ]
        })
        .boxed()
    }

    fn arb_program() -> BoxedStrategy<Program> {
        prop::collection::vec(arb_node(), 0..=8)
            .prop_map(|entry| {
                Program::wrapped(
                    vec![
                        BufferDecl::output("out", 0, DataType::U32)
                            .with_count(8)
                            .with_output_byte_range(0..16),
                        BufferDecl::read("input", 1, DataType::U32).with_count(8),
                        BufferDecl::read_write("rw", 2, DataType::U32).with_count(8),
                        BufferDecl::read("counts", 3, DataType::U32).with_count(8),
                        BufferDecl::workgroup("scratch", 4, DataType::U32),
                    ],
                    [1, 1, 1],
                    entry,
                )
            })
            .boxed()
    }

    // ------------------------------------------------------------------
    // Regression test: new single-pass validator must emit exactly the
    // same errors (+ warnings) as the old four-walk validator.
    // ------------------------------------------------------------------
    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 50,
            ..ProptestConfig::default()
        })]

        #[test]
        fn single_pass_validator_matches_legacy(program in arb_program()) {
            let legacy = validate_with_options_legacy(&program, ValidationOptions::default());
            let modern = validate_with_options(&program, ValidationOptions::default());

            // Deterministic ordering: sort both error sets by message.
            let mut legacy_errors = legacy.errors;
            let mut modern_errors = modern.errors;
            legacy_errors.sort_by(|a, b| a.message.cmp(&b.message));
            modern_errors.sort_by(|a, b| a.message.cmp(&b.message));

            prop_assert_eq!(
                legacy_errors, modern_errors,
                "error mismatch between legacy and single-pass validator"
            );

            let mut legacy_warnings = legacy.warnings;
            let mut modern_warnings = modern.warnings;
            legacy_warnings.sort_by(|a, b| a.message.cmp(&b.message));
            modern_warnings.sort_by(|a, b| a.message.cmp(&b.message));

            prop_assert_eq!(
                legacy_warnings, modern_warnings,
                "warning mismatch between legacy and single-pass validator"
            );
        }
    }
}
