use crate::ir_inner::model::expr::Expr;
use crate::ir_inner::model::node::Node;
use crate::ir_inner::model::program::BufferDecl;
use crate::ir_inner::model::types::DataType;
use crate::validate::barrier;
use crate::validate::binding::check_sibling_duplicate;
use crate::validate::bytes_rejection;
use crate::validate::depth::{self, LimitState};
use crate::validate::expr_rules::validate_expr;
use crate::validate::shadowing;
use crate::validate::typecheck::expr_type;
use crate::validate::uniformity::is_uniform;
use crate::validate::{err, Binding, ValidationError, ValidationOptions, ValidationReport};
use rustc_hash::{FxHashMap, FxHashSet};

pub(crate) type ScopeLog = Vec<(String, Option<Binding>)>;

#[inline]
pub(crate) fn validate_nodes(
    nodes: &[Node],
    buffers: &FxHashMap<&str, &BufferDecl>,
    scope: &mut FxHashMap<String, Binding>,
    divergent: bool,
    depth: usize,
    limits: &mut LimitState,
    options: ValidationOptions<'_>,
    report: &mut ValidationReport,
) {
    let mut region_bindings = FxHashSet::default();
    validate_nodes_inner(
        nodes,
        buffers,
        scope,
        divergent,
        depth,
        limits,
        options,
        report,
        &mut region_bindings,
        None,
    );
}

#[allow(clippy::too_many_arguments)]
fn validate_nodes_inner(
    nodes: &[Node],
    buffers: &FxHashMap<&str, &BufferDecl>,
    scope: &mut FxHashMap<String, Binding>,
    divergent: bool,
    depth: usize,
    limits: &mut LimitState,
    options: ValidationOptions<'_>,
    report: &mut ValidationReport,
    region_bindings: &mut FxHashSet<String>,
    mut scope_log: Option<&mut ScopeLog>,
) {
    for node in nodes {
        validate_node_inner(
            node,
            buffers,
            scope,
            divergent,
            depth,
            limits,
            options,
            report,
            region_bindings,
            scope_log.as_deref_mut(),
        );
    }

    if let Some(pos) = nodes.iter().position(|n| matches!(n, Node::Return)) {
        if pos != nodes.len().saturating_sub(1) {
            report.errors.push(err(
                "unreachable statements after `return`. Fix: remove statements after `return` or reorder them.".to_string(),
            ));
        }
    }
}

#[allow(clippy::too_many_lines, clippy::unnested_or_patterns)]
fn validate_node_inner(
    node: &Node,
    buffers: &FxHashMap<&str, &BufferDecl>,
    scope: &mut FxHashMap<String, Binding>,
    divergent: bool,
    depth: usize,
    limits: &mut LimitState,
    options: ValidationOptions<'_>,
    report: &mut ValidationReport,
    region_bindings: &mut FxHashSet<String>,
    scope_log: Option<&mut ScopeLog>,
) {
    depth::check_limits(limits, depth, &mut report.errors);

    match node {
        Node::Let { name, value } => {
            validate_expr(value, buffers, scope, options, report, 0);
            let duplicate_sibling =
                check_sibling_duplicate(name, region_bindings, &mut report.errors);
            if !duplicate_sibling {
                shadowing::check_local(name, scope, options, &mut report.errors);
            }
            let ty = expr_type(value, buffers, scope).unwrap_or(DataType::U32);
            let uniform = is_uniform(value, scope);
            insert_binding(
                scope,
                name.to_string(),
                Binding {
                    ty,
                    mutable: true,
                    uniform,
                },
                scope_log,
            );
        }
        Node::Assign { name, value } => {
            if let Some(binding) = scope.get(name.as_str()) {
                if !binding.mutable {
                    report.errors.push(err(format!(
                        "V011: assignment to loop variable `{name}`. Fix: loop variables are immutable."
                    )));
                }
            } else {
                report.errors.push(err(format!(
                    "assignment to undeclared variable `{name}`. Fix: add `let {name} = ...;` before this assignment."
                )));
            }
            validate_expr(value, buffers, scope, options, report, 0);
            // Reassignment with a divergent rhs taints the binding's
            // uniformity for the remainder of its lifetime.
            let new_uniform = is_uniform(value, scope);
            if let Some(binding) = scope.get_mut(name.as_str()) {
                binding.uniform = binding.uniform && new_uniform;
            }
        }
        Node::Store {
            buffer,
            index,
            value,
        } => {
            bytes_rejection::check_store(buffer, buffers, &mut report.errors);
            if let Some(buf) = buffers.get(buffer.as_str()) {
                if let Some(val_ty) = expr_type(value, buffers, scope) {
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
                        let legal_targets = store_value_targets(elem);
                        report.errors.push(err(format!(
                            "Node::Store buffer `{buffer}` value has type `{val_ty}` but element type is `{elem}`. Fix: cast/store using one of {}.", legal_targets
                        )));
                    }
                }
                check_constant_store_index(buffer, buf, index, &mut report.errors);
            }
            validate_expr(index, buffers, scope, options, report, 0);
            validate_expr(value, buffers, scope, options, report, 0);
        }
        Node::If {
            cond,
            then,
            otherwise,
        } => {
            validate_expr(cond, buffers, scope, options, report, 0);
            if let Some(cond_ty) = expr_type(cond, buffers, scope) {
                if !matches!(cond_ty, DataType::U32 | DataType::Bool) {
                    report.errors.push(err(format!(
                        "Node::If condition has type `{cond_ty}` but must be `u32` or `bool`. Fix: cast or rewrite the condition expression to produce `u32` or `bool`."
                    )));
                }
            }
            // Branches stay non-divergent only when the parent scope is
            // already uniform AND the condition is uniform across the
            // workgroup. A non-uniform cond splits invocations across
            // the two branches; a divergent parent already failed the
            // uniformity precondition so we conservatively propagate.
            let branch_divergent = divergent || !is_uniform(cond, scope);
            validate_scoped_nested_nodes(
                then,
                buffers,
                scope,
                branch_divergent,
                depth,
                limits,
                options,
                report,
                |_, _| {},
            );
            validate_scoped_nested_nodes(
                otherwise,
                buffers,
                scope,
                branch_divergent,
                depth,
                limits,
                options,
                report,
                |_, _| {},
            );
        }
        Node::Loop {
            var,
            from,
            to,
            body,
        } => {
            validate_expr(from, buffers, scope, options, report, 0);
            validate_expr(to, buffers, scope, options, report, 0);
            if let Some(from_ty) = expr_type(from, buffers, scope) {
                if from_ty != DataType::U32 {
                    report.errors.push(err(format!(
                        "Node::Loop from-bound has type `{from_ty}`; legal loop bound type is `u32`. Fix: cast the `from` bound to `u32`."
                    )));
                }
            }
            if let Some(to_ty) = expr_type(to, buffers, scope) {
                if to_ty != DataType::U32 {
                    report.errors.push(err(format!(
                        "Node::Loop to-bound has type `{to_ty}`; legal loop bound type is `u32`. Fix: cast the `to` bound to `u32`."
                    )));
                }
            }
            shadowing::check_local(var, scope, options, &mut report.errors);
            // The loop body is divergent only when its parent already is
            // OR when either bound varies across the workgroup. Uniform
            // bounds keep every invocation in lockstep — same iteration
            // count, same loop-var value at each step — so a barrier
            // inside is reached by every lane simultaneously.
            let bounds_uniform = is_uniform(from, scope) && is_uniform(to, scope);
            let body_divergent = divergent || !bounds_uniform;
            // The loop counter inherits the bounds' uniformity; in a
            // uniform-bound loop every lane sees the same counter value
            // at the same source position.
            let var_uniform = bounds_uniform && !divergent;
            validate_scoped_nested_nodes(
                body,
                buffers,
                scope,
                body_divergent,
                depth,
                limits,
                options,
                report,
                |scope, scope_log| {
                    insert_binding(
                        scope,
                        var.to_string(),
                        Binding {
                            ty: DataType::U32,
                            mutable: false,
                            uniform: var_uniform,
                        },
                        Some(scope_log),
                    );
                },
            );
        }
        Node::Return => {}
        Node::Block(nodes) => {
            validate_scoped_nested_nodes(
                nodes,
                buffers,
                scope,
                divergent,
                depth,
                limits,
                options,
                report,
                |_, _| {},
            );
        }
        Node::Barrier => {
            barrier::check_barrier(divergent, &mut report.errors);
        }
        Node::IndirectDispatch {
            count_buffer,
            count_offset,
        } => {
            if count_offset % 4 != 0 {
                report.errors.push(err(format!(
                    "indirect dispatch offset {count_offset} is not 4-byte aligned. Fix: use an offset aligned to a u32 dispatch count tuple."
                )));
            }
            if !buffers.contains_key(count_buffer.as_str()) {
                report.errors.push(err(format!(
                    "indirect dispatch references unknown buffer `{count_buffer}`. Fix: declare the count buffer before validation."
                )));
            }
        }
        Node::AsyncLoad { tag, .. } | Node::AsyncStore { tag, .. } | Node::AsyncWait { tag } => {
            if tag.is_empty() {
                report.errors.push(err(
                    "async stream tag is empty. Fix: use a stable non-empty tag to pair AsyncLoad and AsyncWait nodes."
                        .to_string(),
                ));
            }
        }
        Node::Trap { .. } | Node::Resume { .. } => {}
        Node::Region { body, .. } => {
            validate_scoped_nested_nodes(
                body,
                buffers,
                scope,
                divergent,
                depth,
                limits,
                options,
                report,
                |_, _| {},
            );
        }
        Node::Opaque(extension) => {
            if extension.extension_kind().is_empty() {
                report.errors.push(err(
                    "V031: opaque node extension has an empty extension_kind. Fix: return a stable non-empty namespace from NodeExtension::extension_kind.",
                ));
            }
            if extension.debug_identity().is_empty() {
                report.errors.push(err(format!(
                    "V031: opaque node extension `{}` has an empty debug_identity. Fix: return a stable human-readable identity from NodeExtension::debug_identity.",
                    extension.extension_kind()
                )));
            }
            if let Err(message) = extension.validate_extension() {
                report.errors.push(err(format!(
                    "V031: opaque node extension `{}`/`{}` failed validation: {message}",
                    extension.extension_kind(),
                    extension.debug_identity()
                )));
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_scoped_nested_nodes(
    nodes: &[Node],
    buffers: &FxHashMap<&str, &BufferDecl>,
    scope: &mut FxHashMap<String, Binding>,
    divergent: bool,
    depth: usize,
    limits: &mut LimitState,
    options: ValidationOptions<'_>,
    report: &mut ValidationReport,
    configure_scope: impl FnOnce(&mut FxHashMap<String, Binding>, &mut ScopeLog),
) {
    let mut scope_log = Vec::new();
    let mut region_bindings = FxHashSet::default();
    configure_scope(scope, &mut scope_log);
    validate_nodes_inner(
        nodes,
        buffers,
        scope,
        divergent,
        depth.saturating_add(1),
        limits,
        options,
        report,
        &mut region_bindings,
        Some(&mut scope_log),
    );
    restore_scope(scope, scope_log);
}

pub(crate) fn check_constant_store_index(
    buffer_name: &str,
    buffer: &BufferDecl,
    index: &Expr,
    errors: &mut Vec<ValidationError>,
) {
    if buffer.count == 0 {
        return;
    }
    match index {
        Expr::LitU32(value) => {
            if *value >= buffer.count {
                errors.push(err(format!(
                    "V036: store index {value} overflows buffer `{buffer_name}` with count {}. Fix: keep constant store indices below the declared element count.",
                    buffer.count
                )));
            }
        }
        Expr::LitI32(value) if *value < 0 => {
            errors.push(err(format!(
                "V036: store index {value} overflows buffer `{buffer_name}` with count {}. Fix: keep constant store indices in 0..{}.",
                buffer.count,
                buffer.count
            )));
        }
        Expr::LitI32(value) => {
            let as_u32 = *value as u32;
            if as_u32 >= buffer.count {
                errors.push(err(format!(
                    "V036: store index {value} overflows buffer `{buffer_name}` with count {}. Fix: keep constant store indices below the declared element count.",
                    buffer.count
                )));
            }
        }
        _ => {}
    }
}

pub(crate) fn insert_binding(
    scope: &mut FxHashMap<String, Binding>,
    name: String,
    binding: Binding,
    scope_log: Option<&mut ScopeLog>,
) {
    let previous = scope.insert(name.clone(), binding);
    if let Some(scope_log) = scope_log {
        scope_log.push((name, previous));
    }
}

pub(crate) fn restore_scope(scope: &mut FxHashMap<String, Binding>, mut scope_log: ScopeLog) {
    while let Some((name, previous)) = scope_log.pop() {
        if let Some(binding) = previous {
            scope.insert(name, binding);
        } else {
            scope.remove(&name);
        }
    }
}

#[inline]
pub(crate) fn store_value_targets(element: &DataType) -> String {
    let mut targets = vec![element.clone()];
    let legal = match element {
        DataType::U32 => vec![DataType::Bytes, DataType::Bool],
        DataType::Bytes => vec![DataType::U32],
        DataType::Bool => vec![DataType::U32],
        _ => Vec::new(),
    };
    for target in legal {
        if !targets.contains(&target) {
            targets.push(target);
        }
    }

    targets
        .into_iter()
        .map(|target| format!("`{target}`"))
        .collect::<Vec<_>>()
        .join(", ")
}
