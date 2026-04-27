//! Statement executor that gives the parity engine a pure-Rust ground truth
//! for every `Node` variant.
//!
//! This module simulates the exact control-flow, memory, and barrier behavior
//! that a correct GPU backend must produce. Any divergence in `If`, `Loop`,
//! `Barrier`, or `Store` semantics is caught by the conform gate as a concrete
//! counterexample.

use vyre::ir::{Expr, Node, Program};

use crate::{
    eval_expr, oob,
    workgroup::{Frame, Invocation, Memory},
};
use vyre::Error;

/// Execute one scheduling step for an invocation.
///
/// # Errors
///
/// Returns [`Error::Interp`] for uniform-control-flow violations,
/// out-of-bounds stores, malformed loops, or expression evaluation failures.
pub fn step<'a>(
    invocation: &mut Invocation<'a>,
    memory: &mut Memory,
    program: &'a Program,
) -> Result<(), vyre::Error> {
    if invocation.done() || invocation.waiting_at_barrier {
        return Ok(());
    }

    loop {
        let Some(frame) = invocation.frames_mut().pop() else {
            return Ok(());
        };
        match frame {
            Frame::Nodes {
                nodes,
                index,
                scoped,
            } => {
                if step_nodes_frame(invocation, memory, program, nodes, index, scoped)? {
                    return Ok(());
                }
            }
            Frame::Loop {
                var,
                next,
                to,
                body,
            } => step_loop_frame(invocation, var, next, to, body)?,
        }
    }
}

fn step_nodes_frame<'a>(
    invocation: &mut Invocation<'a>,
    memory: &mut Memory,
    program: &'a Program,
    nodes: &'a [Node],
    index: usize,
    scoped: bool,
) -> Result<bool, vyre::Error> {
    if index >= nodes.len() {
        if scoped {
            invocation.pop_scope();
        }
        return Ok(false);
    }

    invocation.frames_mut().push(Frame::Nodes {
        nodes,
        index: index + 1,
        scoped,
    });
    execute_node(&nodes[index], invocation, memory, program)?;
    Ok(true)
}

fn step_loop_frame<'a>(
    invocation: &mut Invocation<'a>,
    var: &'a str,
    next: u32,
    to: u32,
    body: &'a [Node],
) -> Result<(), vyre::Error> {
    if next >= to {
        return Ok(());
    }
    invocation.frames_mut().push(Frame::Loop {
        var,
        next: next.wrapping_add(1),
        to,
        body,
    });
    invocation.push_scope();
    invocation.bind_loop_var(var, crate::value::Value::U32(next))?;
    invocation.frames_mut().push(Frame::Nodes {
        nodes: body,
        index: 0,
        scoped: true,
    });
    Ok(())
}

fn execute_node<'a>(
    node: &'a Node,
    invocation: &mut Invocation<'a>,
    memory: &mut Memory,
    program: &'a Program,
) -> Result<(), vyre::Error> {
    match node {
        Node::Let { name, value } => eval_let(name, value, invocation, memory, program),
        Node::Assign { name, value } => eval_assign(name, value, invocation, memory, program),
        Node::Store {
            buffer,
            index,
            value,
        } => eval_store(buffer, index, value, invocation, memory, program),
        Node::If {
            cond,
            then,
            otherwise,
        } => eval_if(cond, then, otherwise, node, invocation, memory, program),
        Node::Loop {
            var,
            from,
            to,
            body,
        } => eval_loop(var, from, to, body, invocation, memory, program),
        Node::Return => eval_return(invocation),
        Node::Block(nodes) => eval_block(nodes, invocation),
        Node::Barrier => eval_barrier(invocation),
        Node::IndirectDispatch {
            count_buffer,
            count_offset,
        } => eval_indirect_dispatch(count_buffer, *count_offset, memory, program),
        Node::AsyncLoad {
            source,
            destination,
            offset,
            size,
            tag,
        } => eval_async_load(
            AsyncLoadEval {
                source,
                destination,
                offset,
                size,
                tag,
            },
            invocation,
            memory,
            program,
        ),
        Node::AsyncStore { tag, .. } => Err(vyre::Error::interp(format!(
            "reference interpreter does not support AsyncStore `{tag}` in the legacy evaluator. Fix: route async stores through the hashmap reference path or a backend runtime that owns async IO state."
        ))),
        Node::AsyncWait { tag } => eval_async_wait(tag, invocation),
        Node::Trap { address, tag } => {
            let address = eval_expr::eval(address, invocation, memory, program)?
                .try_as_u32()
                .ok_or_else(|| {
                    Error::interp(format!(
                        "reference trap `{tag}` address is not a u32. Fix: pass a scalar u32 trap address."
                    ))
                })?;
            Err(vyre::Error::interp(format!(
                "reference dispatch trapped: address={address}, tag=`{tag}`. Fix: handle the trap condition or route this Program through a backend/runtime with replay support."
            )))
        }
        Node::Resume { tag } => Err(vyre::Error::interp(format!(
            "reference dispatch reached Resume `{tag}` without a replay runtime. Fix: lower Resume through a runtime-owned replay path before reference execution."
        ))),
        Node::Region { body, .. } => eval_block(body, invocation),
        Node::Opaque(extension) => Err(vyre::Error::interp(format!(
            "reference interpreter does not support opaque node extension `{}`/`{}`. Fix: provide a reference evaluator for this NodeExtension or lower it to core Node variants before evaluation.",
            extension.extension_kind(),
            extension.debug_identity()
        ))),
        _ => Err(vyre::Error::interp(
            "reference interpreter encountered an unknown future Node variant. Fix: update vyre-reference before executing this IR.",
        )),
    }
}

fn eval_let(
    name: &str,
    value: &Expr,
    invocation: &mut Invocation<'_>,
    memory: &mut Memory,
    program: &Program,
) -> Result<(), vyre::Error> {
    let value = eval_expr::eval(value, invocation, memory, program)?;
    invocation.bind(name, value)
}

fn eval_assign(
    name: &str,
    value: &Expr,
    invocation: &mut Invocation<'_>,
    memory: &mut Memory,
    program: &Program,
) -> Result<(), vyre::Error> {
    let value = eval_expr::eval(value, invocation, memory, program)?;
    invocation.assign(name, value)
}

fn eval_store(
    buffer: &str,
    index: &Expr,
    value: &Expr,
    invocation: &mut Invocation<'_>,
    memory: &mut Memory,
    program: &Program,
) -> Result<(), vyre::Error> {
    let index = eval_expr::eval(index, invocation, memory, program)?;
    let index = index
        .try_as_u32()
        .ok_or_else(|| Error::interp(format!(
                "store index {index:?} cannot be represented as u32. Fix: use a non-negative scalar index within u32."
        )))?;
    let value = eval_expr::eval(value, invocation, memory, program)?;
    let target = eval_expr::buffer_mut(memory, program, buffer)?;
    oob::store(target, index, &value);
    Ok(())
}

fn eval_indirect_dispatch(
    count_buffer: &str,
    count_offset: u64,
    memory: &Memory,
    program: &Program,
) -> Result<(), vyre::Error> {
    if count_offset % 4 != 0 {
        return Err(Error::interp(format!(
            "indirect dispatch offset {count_offset} is not 4-byte aligned. Fix: use a u32-aligned dispatch tuple."
        )));
    }
    let decl = program.buffer(count_buffer).ok_or_else(|| {
        Error::interp(format!(
            "indirect dispatch references unknown buffer `{count_buffer}`. Fix: declare the count buffer before execution."
        ))
    })?;
    let buffer = if decl.access() == vyre::ir::BufferAccess::Workgroup {
        memory.workgroup.get(count_buffer)
    } else {
        memory.storage.get(count_buffer)
    }
    .ok_or_else(|| {
        Error::interp(format!(
            "indirect dispatch buffer `{count_buffer}` is missing. Fix: initialize the count buffer before execution."
        ))
    })?;
    let required_end = count_offset.checked_add(12).ok_or_else(|| {
        Error::interp(
            "indirect dispatch byte range overflowed u64. Fix: shrink the count offset."
                .to_string(),
        )
    })?;
    if u64::try_from(buffer.bytes.read().unwrap().len()).unwrap_or(u64::MAX) < required_end {
        return Err(Error::interp(format!(
            "indirect dispatch buffer `{count_buffer}` is too short for a 3-word dispatch tuple at byte offset {count_offset}. Fix: provide 12 readable bytes starting at that offset."
        )));
    }
    Ok(())
}

struct AsyncLoadEval<'a> {
    source: &'a str,
    destination: &'a str,
    offset: &'a Expr,
    size: &'a Expr,
    tag: &'a str,
}

fn eval_async_load(
    request: AsyncLoadEval<'_>,
    invocation: &mut Invocation<'_>,
    memory: &mut Memory,
    program: &Program,
) -> Result<(), vyre::Error> {
    let _ = eval_expr::eval(request.offset, invocation, memory, program)?
        .try_as_u64()
        .ok_or_else(|| {
            Error::interp(
                "async load offset cannot be represented as u64. Fix: use an in-range non-negative offset."
                    .to_string(),
            )
        })?;
    let _ = eval_expr::eval(request.size, invocation, memory, program)?
        .try_as_u64()
        .ok_or_else(|| {
            Error::interp(
                "async load size cannot be represented as u64. Fix: use an in-range non-negative transfer size."
                    .to_string(),
            )
        })?;
    if request.source != "__legacy_src__" {
        let _ = program.buffer(request.source).ok_or_else(|| {
            Error::interp(format!(
                "async load references unknown source buffer `{}`. Fix: declare the source buffer before execution.",
                request.source
            ))
        })?;
    }
    if request.destination != "__legacy_dst__" {
        let _ = program.buffer(request.destination).ok_or_else(|| {
            Error::interp(format!(
                "async load references unknown destination buffer `{}`. Fix: declare the destination buffer before execution.",
                request.destination
            ))
        })?;
    }
    invocation.begin_async(request.tag)
}

fn eval_async_wait(tag: &str, invocation: &mut Invocation<'_>) -> Result<(), vyre::Error> {
    invocation.finish_async(tag)
}

fn eval_if<'a>(
    cond: &Expr,
    then: &'a [Node],
    otherwise: &'a [Node],
    node: &Node,
    invocation: &mut Invocation<'a>,
    memory: &mut Memory,
    program: &Program,
) -> Result<(), vyre::Error> {
    let cond_value = eval_expr::eval(cond, invocation, memory, program)?.truthy();
    if contains_barrier(then) || contains_barrier(otherwise) {
        invocation.uniform_checks.push((node_id(node), cond_value));
    }
    let branch = if cond_value { then } else { otherwise };
    invocation.push_scope();
    invocation.frames_mut().push(Frame::Nodes {
        nodes: branch,
        index: 0,
        scoped: true,
    });
    Ok(())
}

fn eval_loop<'a>(
    var: &'a str,
    from: &Expr,
    to: &Expr,
    body: &'a [Node],
    invocation: &mut Invocation<'a>,
    memory: &mut Memory,
    program: &Program,
) -> Result<(), vyre::Error> {
    let from_value = eval_expr::eval(from, invocation, memory, program)?;
    let to_value = eval_expr::eval(to, invocation, memory, program)?;
    let from = from_value.try_as_u32().ok_or_else(|| {
        Error::interp(format!(
                "loop lower bound {from_value:?} cannot be represented as u32. Fix: use an in-range unsigned loop bound."
        ))
    })?;
    let to = to_value.try_as_u32().ok_or_else(|| Error::interp(format!(
            "loop upper bound {to_value:?} cannot be represented as u32. Fix: use an in-range unsigned loop bound."
    )))?;
    invocation.frames_mut().push(Frame::Loop {
        var,
        next: from,
        to,
        body,
    });
    Ok(())
}

fn eval_return(invocation: &mut Invocation<'_>) -> Result<(), vyre::Error> {
    invocation.frames_mut().clear();
    invocation.returned = true;
    Ok(())
}

fn eval_block<'a>(nodes: &'a [Node], invocation: &mut Invocation<'a>) -> Result<(), vyre::Error> {
    invocation.push_scope();
    invocation.frames_mut().push(Frame::Nodes {
        nodes,
        index: 0,
        scoped: true,
    });
    Ok(())
}

fn eval_barrier(invocation: &mut Invocation<'_>) -> Result<(), vyre::Error> {
    invocation.waiting_at_barrier = true;
    Ok(())
}

/// Whether any statement in `nodes` may reach a [`Node::Barrier`], scanning
/// child statement lists recursively with an exhaustive [`Node`] match.
fn contains_barrier(nodes: &[Node]) -> bool {
    nodes.iter().any(node_contains_barrier)
}

fn node_contains_barrier(node: &Node) -> bool {
    match node {
        Node::Barrier => true,
        Node::Let { .. }
        | Node::Assign { .. }
        | Node::Store { .. }
        | Node::Return
        | Node::IndirectDispatch { .. }
        | Node::AsyncLoad { .. }
        | Node::AsyncStore { .. }
        | Node::AsyncWait { .. }
        | Node::Trap { .. }
        | Node::Resume { .. }
        | Node::Opaque(_) => false,
        Node::If {
            then, otherwise, ..
        } => contains_barrier(then) || contains_barrier(otherwise),
        Node::Loop { body, .. } => contains_barrier(body),
        Node::Block(body) => contains_barrier(body),
        _ => false,
    }
}

fn node_id(node: &Node) -> usize {
    std::ptr::from_ref(node).addr()
}
