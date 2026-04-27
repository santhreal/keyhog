//! Round-robin node stepping and expression-adjacent execution helpers.
//!
//! This module advances invocation frames one node at a time. Expression
//! evaluation stays in the root module; state ownership stays in `state`; buffer
//! lookup and mutation stay in `memory`.

use super::{
    eval_expr,
    memory::{buffer_mut, resolve_buffer, HashmapMemory},
    state::{HashmapAsyncTransfer, HashmapInvocation, HashmapResolvedCall},
    sync::{contains_barrier, node_id},
};
#[cfg(feature = "subgroup-ops")]
use super::{
    state::HashmapInvocationSnapshot, subgroup::subgroup_simulator, subgroup::subgroup_slice,
};
use crate::{oob, value::Value, workgroup::Frame};
use vyre::ir::{Expr, Node};
use vyre::Error;

pub(crate) fn step_round_robin(
    memory: &mut HashmapMemory,
    invocations: &mut [HashmapInvocation<'_>],
    #[cfg(feature = "subgroup-ops")] uses_subgroup_ops: bool,
) -> Result<bool, Error> {
    let mut made_progress = false;
    #[cfg(feature = "subgroup-ops")]
    let snapshots = if uses_subgroup_ops {
        capture_invocation_snapshots(invocations)
    } else {
        Vec::new()
    };
    for index in 0..invocations.len() {
        if invocations[index].done() || invocations[index].waiting_at_barrier {
            continue;
        }
        step(
            index,
            memory,
            invocations,
            #[cfg(feature = "subgroup-ops")]
            &snapshots,
        )?;
        made_progress = true;
    }
    Ok(made_progress)
}

fn step(
    index: usize,
    memory: &mut HashmapMemory,
    invocations: &mut [HashmapInvocation<'_>],
    #[cfg(feature = "subgroup-ops")] snapshots: &[HashmapInvocationSnapshot],
) -> Result<(), Error> {
    let invocation = &mut invocations[index];
    if invocation.done() || invocation.waiting_at_barrier {
        return Ok(());
    }
    loop {
        let Some(frame) = invocation.frames.pop() else {
            return Ok(());
        };
        match frame {
            Frame::Nodes {
                nodes,
                index,
                scoped,
            } => {
                if step_nodes_frame(
                    invocation,
                    memory,
                    nodes,
                    index,
                    scoped,
                    #[cfg(feature = "subgroup-ops")]
                    snapshots,
                )? {
                    return Ok(());
                }
            }
            Frame::Loop {
                var,
                next,
                to,
                body,
            } => {
                step_loop_frame(invocation, var, next, to, body)?;
                return Ok(());
            }
        }
    }
}

fn step_nodes_frame<'a>(
    invocation: &mut HashmapInvocation<'a>,
    memory: &mut HashmapMemory,
    nodes: &'a [Node],
    index: usize,
    scoped: bool,
    #[cfg(feature = "subgroup-ops")] snapshots: &[HashmapInvocationSnapshot],
) -> Result<bool, Error> {
    if index >= nodes.len() {
        if scoped {
            invocation.locals.pop_scope();
        }
        return Ok(false);
    }
    invocation.frames.push(Frame::Nodes {
        nodes,
        index: index + 1,
        scoped,
    });
    execute_node(
        &nodes[index],
        invocation,
        memory,
        #[cfg(feature = "subgroup-ops")]
        snapshots,
    )?;
    Ok(true)
}

fn step_loop_frame<'a>(
    invocation: &mut HashmapInvocation<'a>,
    var: &'a str,
    next: u32,
    to: u32,
    body: &'a [Node],
) -> Result<(), Error> {
    if next >= to {
        return Ok(());
    }
    invocation.frames.push(Frame::Loop {
        var,
        next: next.wrapping_add(1),
        to,
        body,
    });
    invocation.locals.push_scope();
    invocation.locals.bind_loop_var(var, Value::U32(next))?;
    invocation.frames.push(Frame::Nodes {
        nodes: body,
        index: 0,
        scoped: true,
    });
    Ok(())
}

fn execute_node<'a>(
    node: &'a Node,
    invocation: &mut HashmapInvocation<'a>,
    memory: &mut HashmapMemory,
    #[cfg(feature = "subgroup-ops")] snapshots: &[HashmapInvocationSnapshot],
) -> Result<(), Error> {
    match node {
        Node::Let { name, value } => {
            let v = eval_expr(
                value,
                invocation,
                memory,
                #[cfg(feature = "subgroup-ops")]
                snapshots,
            )?;
            invocation.locals.bind(name, v)?;
        }
        Node::Assign { name, value } => {
            let v = eval_expr(
                value,
                invocation,
                memory,
                #[cfg(feature = "subgroup-ops")]
                snapshots,
            )?;
            invocation.locals.assign(name, v)?;
        }
        Node::Store {
            buffer,
            index,
            value,
        } => {
            let idx = eval_expr (index , invocation , memory , #[cfg (feature = "subgroup-ops")] snapshots ,) ? . try_as_u32 () . ok_or_else (| | { Error :: interp ("store index cannot be represented as u32. Fix: use a non-negative scalar index within u32." ,) }) ? ;
            let v = eval_expr(
                value,
                invocation,
                memory,
                #[cfg(feature = "subgroup-ops")]
                snapshots,
            )?;
            let target = buffer_mut(memory, buffer)?;
            oob::store(target, idx, &v);
        }
        Node::If {
            cond,
            then,
            otherwise,
        } => {
            let cond_value = eval_expr(
                cond,
                invocation,
                memory,
                #[cfg(feature = "subgroup-ops")]
                snapshots,
            )?
            .truthy();
            if contains_barrier(then) || contains_barrier(otherwise) {
                invocation.uniform_checks.push((node_id(node), cond_value));
            }
            let branch = if cond_value { then } else { otherwise };
            invocation.locals.push_scope();
            invocation.frames.push(Frame::Nodes {
                nodes: branch,
                index: 0,
                scoped: true,
            });
        }
        Node::Loop {
            var,
            from,
            to,
            body,
        } => {
            let from_value = eval_expr (from , invocation , memory , #[cfg (feature = "subgroup-ops")] snapshots ,) ? . try_as_u32 () . ok_or_else (| | { Error :: interp ("loop lower bound cannot be represented as u32. Fix: use an in-range unsigned loop bound." ,) }) ? ;
            let to_value = eval_expr (to , invocation , memory , #[cfg (feature = "subgroup-ops")] snapshots ,) ? . try_as_u32 () . ok_or_else (| | { Error :: interp ("loop upper bound cannot be represented as u32. Fix: use an in-range unsigned loop bound." ,) }) ? ;
            invocation.frames.push(Frame::Loop {
                var,
                next: from_value,
                to: to_value,
                body,
            });
        }
        Node::Return => {
            invocation.frames.clear();
            invocation.returned = true;
        }
        Node::Block(nodes) => {
            invocation.locals.push_scope();
            invocation.frames.push(Frame::Nodes {
                nodes,
                index: 0,
                scoped: true,
            });
        }
        Node::Barrier => {
            invocation.waiting_at_barrier = true;
        }
        Node::IndirectDispatch {
            count_buffer,
            count_offset,
        } => {
            eval_indirect_dispatch(count_buffer, *count_offset, memory)?;
        }
        Node::AsyncLoad {
            source,
            destination,
            offset,
            size,
            tag,
        } => {
            eval_async_transfer(
                "AsyncLoad",
                source,
                destination,
                offset,
                size,
                tag,
                invocation,
                memory,
                #[cfg(feature = "subgroup-ops")]
                snapshots,
            )?;
        }
        Node::AsyncStore {
            source,
            destination,
            offset,
            size,
            tag,
        } => {
            eval_async_transfer(
                "AsyncStore",
                source,
                destination,
                offset,
                size,
                tag,
                invocation,
                memory,
                #[cfg(feature = "subgroup-ops")]
                snapshots,
            )?;
        }
        Node::AsyncWait { tag } => {
            let transfer = invocation.finish_async(tag)?;
            complete_async_transfer(tag, transfer, memory)?;
        }
        Node::Trap { address, tag } => {
            let address = eval_expr(
                address,
                invocation,
                memory,
                #[cfg(feature = "subgroup-ops")]
                snapshots,
            )?
            .try_as_u32()
            .ok_or_else(|| {
                Error::interp(format!(
                    "reference trap `{tag}` address is not a u32. Fix: pass a scalar u32 trap address."
                ))
            })?;
            return Err(Error::interp(format!(
                "reference dispatch trapped: address={address}, tag=`{tag}`. Fix: handle the trap condition or route this Program through a backend/runtime with replay support."
            )));
        }
        Node::Resume { tag } => {
            return Err(Error::interp(format!(
                "reference dispatch reached Resume `{tag}` without a replay runtime. Fix: lower Resume through a runtime-owned replay path before reference execution."
            )));
        }
        Node::Region { body, .. } => {
            invocation.frames.push(Frame::Nodes {
                nodes: body.as_slice(),
                index: 0,
                scoped: false,
            });
        }
        Node::Opaque(extension) => {
            return Err(Error::interp(format!(
                "hashmap reference interpreter does not support opaque node extension `{}`/`{}`. Fix: provide a reference evaluator for this NodeExtension or lower it to core Node variants before evaluation.",
                extension.extension_kind(),
                extension.debug_identity()
            )));
        }
        _ => {
            return Err(Error::interp(
                "hashmap reference interpreter encountered an unknown future Node variant. Fix: update vyre-reference before executing this IR.",
            ));
        }
    }
    Ok(())
}

fn eval_indirect_dispatch(
    count_buffer: &str,
    count_offset: u64,
    memory: &HashmapMemory,
) -> Result<(), Error> {
    if count_offset % 4 != 0 {
        return Err(Error::interp(format!(
            "indirect dispatch offset {count_offset} is not 4-byte aligned. Fix: use a u32-aligned dispatch tuple."
        )));
    }
    let required_end = count_offset.checked_add(12).ok_or_else(|| {
        Error::interp("indirect dispatch byte range overflowed u64. Fix: shrink the count offset.")
    })?;
    let buffer = resolve_buffer(memory, count_buffer).map_err(|_| {
        Error::interp(format!(
            "indirect dispatch buffer `{count_buffer}` is missing from hashmap reference memory. Fix: initialize the count buffer or route this Program through a runtime that owns indirect dispatch buffers."
        ))
    })?;
    let bytes = buffer.bytes.read().unwrap();
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) < required_end {
        return Err(Error::interp(format!(
            "indirect dispatch buffer `{count_buffer}` is too short for a 3-word dispatch tuple at byte offset {count_offset}. Fix: provide 12 readable bytes starting at that offset."
        )));
    }
    let start = usize::try_from(count_offset).map_err(|_| {
        Error::interp(
            "indirect dispatch offset does not fit host usize. Fix: shrink the count offset.",
        )
    })?;
    let counts = [
        read_u32_le(&bytes[start..start + 4]),
        read_u32_le(&bytes[start + 4..start + 8]),
        read_u32_le(&bytes[start + 8..start + 12]),
    ];
    Err(Error::interp(format!(
        "hashmap reference interpreter cannot execute Node::IndirectDispatch from `{count_buffer}` at byte offset {count_offset} (counts={counts:?}) because workgroup scheduling is fixed before node execution. Required runtime capability: dynamic indirect dispatch scheduling that reads the 3-u32 count buffer before creating workgroups. Fix: route through an indirect-dispatch-capable runtime or lower to explicit dispatch dimensions before reference evaluation."
    )))
}

#[allow(clippy::too_many_arguments)]
fn eval_async_transfer(
    node_kind: &'static str,
    source: &str,
    destination: &str,
    offset: &Expr,
    size: &Expr,
    tag: &str,
    invocation: &mut HashmapInvocation<'_>,
    memory: &mut HashmapMemory,
    #[cfg(feature = "subgroup-ops")] snapshots: &[HashmapInvocationSnapshot],
) -> Result<(), Error> {
    let offset = eval_expr(
        offset,
        invocation,
        memory,
        #[cfg(feature = "subgroup-ops")]
        snapshots,
    )?
    .try_as_u64()
    .ok_or_else(|| {
        Error::interp(format!(
            "{node_kind} `{tag}` offset cannot be represented as u64. Fix: use an in-range non-negative transfer offset."
        ))
    })?;
    let size = eval_expr(
        size,
        invocation,
        memory,
        #[cfg(feature = "subgroup-ops")]
        snapshots,
    )?
    .try_as_u64()
    .ok_or_else(|| {
        Error::interp(format!(
            "{node_kind} `{tag}` size cannot be represented as u64. Fix: use an in-range non-negative transfer size."
        ))
    })?;
    let transfer = if size == 0 && source == "__legacy_src__" && destination == "__legacy_dst__" {
        HashmapAsyncTransfer::Ready
    } else {
        prepare_async_transfer(node_kind, source, destination, offset, size, tag, memory)?
    };
    invocation.begin_async(tag, transfer)
}

fn prepare_async_transfer(
    node_kind: &'static str,
    source: &str,
    destination: &str,
    offset: u64,
    size: u64,
    tag: &str,
    memory: &mut HashmapMemory,
) -> Result<HashmapAsyncTransfer, Error> {
    let end = offset.checked_add(size).ok_or_else(|| {
        Error::interp(format!(
            "{node_kind} `{tag}` byte range overflows u64. Fix: reduce the transfer offset or size."
        ))
    })?;
    let start = usize::try_from(offset).map_err(|_| {
        Error::interp(format!(
            "{node_kind} `{tag}` offset does not fit host usize. Fix: reduce the transfer offset."
        ))
    })?;
    let end = usize::try_from(end).map_err(|_| {
        Error::interp(format!(
            "{node_kind} `{tag}` end offset does not fit host usize. Fix: reduce the transfer size."
        ))
    })?;
    if source == destination {
        let buffer = async_buffer(memory, source, node_kind, tag, "source/destination")?;
        let len = buffer.bytes.read().unwrap().len();
        if end > len {
            return Err(async_range_error(
                node_kind,
                tag,
                "source/destination",
                source,
                start,
                end,
                len,
            ));
        }
        return Ok(HashmapAsyncTransfer::Ready);
    }
    let payload = {
        let source_buffer = async_buffer(memory, source, node_kind, tag, "source")?;
        let source_bytes = source_buffer.bytes.read().unwrap();
        if end > source_bytes.len() {
            return Err(async_range_error(
                node_kind,
                tag,
                "source",
                source,
                start,
                end,
                source_bytes.len(),
            ));
        }
        source_bytes[start..end].to_vec()
    };
    let destination_buffer = async_buffer(memory, destination, node_kind, tag, "destination")?;
    let destination_len = destination_buffer.bytes.read().unwrap().len();
    if end > destination_len {
        return Err(async_range_error(
            node_kind,
            tag,
            "destination",
            destination,
            start,
            end,
            destination_len,
        ));
    }
    Ok(HashmapAsyncTransfer::Copy {
        destination: destination.to_string(),
        start,
        payload,
    })
}

fn complete_async_transfer(
    tag: &str,
    transfer: HashmapAsyncTransfer,
    memory: &mut HashmapMemory,
) -> Result<(), Error> {
    match transfer {
        HashmapAsyncTransfer::Ready => Ok(()),
        HashmapAsyncTransfer::Copy {
            destination,
            start,
            payload,
        } => {
            let end = start.checked_add(payload.len()).ok_or_else(|| {
                Error::interp(format!(
                    "AsyncWait `{tag}` completion byte range overflows usize. Fix: reduce the async transfer size."
                ))
            })?;
            let destination_buffer = buffer_mut(memory, &destination).map_err(|_| {
                Error::interp(format!(
                    "AsyncWait `{tag}` cannot complete because destination buffer `{destination}` is missing from hashmap reference memory. Fix: keep async transfer buffers alive until AsyncWait."
                ))
            })?;
            let mut destination_bytes = destination_buffer.bytes.write().unwrap();
            if end > destination_bytes.len() {
                return Err(async_range_error(
                    "AsyncWait",
                    tag,
                    "destination",
                    &destination,
                    start,
                    end,
                    destination_bytes.len(),
                ));
            }
            destination_bytes[start..end].copy_from_slice(&payload);
            Ok(())
        }
    }
}

fn async_buffer<'a>(
    memory: &'a HashmapMemory,
    name: &str,
    node_kind: &'static str,
    tag: &str,
    role: &'static str,
) -> Result<&'a crate::oob::Buffer, Error> {
    resolve_buffer(memory, name).map_err(|_| {
        Error::interp(format!(
            "{node_kind} `{tag}` requires {role} buffer `{name}` in hashmap reference memory. Fix: provide the buffer or route through a runtime with async IO state for this transfer."
        ))
    })
}

fn async_range_error(
    node_kind: &'static str,
    tag: &str,
    role: &'static str,
    buffer: &str,
    start: usize,
    end: usize,
    len: usize,
) -> Error {
    Error::interp(format!(
        "{node_kind} `{tag}` {role} buffer `{buffer}` does not contain byte range {start}..{end} (len={len}). Fix: grow the buffer or reduce the async transfer offset/size."
    ))
}

fn read_u32_le(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

#[cfg(feature = "subgroup-ops")]
fn capture_invocation_snapshots(
    invocations: &[HashmapInvocation<'_>],
) -> Vec<HashmapInvocationSnapshot> {
    invocations
        .iter()
        .map(|invocation| HashmapInvocationSnapshot {
            ids: invocation.ids,
            linear_local_index: invocation.linear_local_index,
            locals: invocation.locals.clone(),
        })
        .collect()
}

#[cfg(feature = "subgroup-ops")]
pub(crate) fn eval_expr_snapshot(
    expr: &Expr,
    invocation: &HashmapInvocationSnapshot,
    snapshots: &[HashmapInvocationSnapshot],
    memory: &HashmapMemory,
) -> Result<Value, Error> {
    match expr { Expr :: LitU32 (value) => Ok (Value :: U32 (* value)) , Expr :: LitI32 (value) => Ok (Value :: I32 (* value)) , Expr :: LitF32 (value) => Ok (Value :: Float (f64 :: from (* value))) , Expr :: LitBool (value) => Ok (Value :: Bool (* value)) , Expr :: Var (name) => invocation . locals . local (name) . ok_or_else (| | { Error :: interp (format ! ("reference to undeclared variable `{name}` during subgroup evaluation. Fix: ensure every active lane reaches the collective with the same bindings.")) }) , Expr :: Load { buffer , index } => { let idx = eval_expr_snapshot (index , invocation , snapshots , memory) ? . try_as_u32 () . ok_or_else (| | { Error :: interp ("subgroup load index cannot be represented as u32. Fix: use a non-negative scalar index within u32." ,) }) ? ; Ok (oob :: load (resolve_buffer (memory , buffer) ? , idx)) } Expr :: BufLen { buffer } => Ok (Value :: U32 (resolve_buffer (memory , buffer) ? . len ())) , Expr :: InvocationId { axis } => axis_value (invocation . ids . global , * axis) , Expr :: WorkgroupId { axis } => axis_value (invocation . ids . workgroup , * axis) , Expr :: LocalId { axis } => axis_value (invocation . ids . local , * axis) , Expr :: BinOp { op , left , right } => { let left = eval_expr_snapshot (left , invocation , snapshots , memory) ? ; let right = eval_expr_snapshot (right , invocation , snapshots , memory) ? ; crate :: typed_ops :: eval_binop (* op , left , right) } Expr :: UnOp { op , operand } => { let operand = eval_expr_snapshot (operand , invocation , snapshots , memory) ? ; crate :: typed_ops :: eval_unop (op . clone () , operand) } Expr :: Call { op_id , args } => { let mut input = Vec :: new () ; let lookup = vyre :: dialect_lookup () . ok_or_else (| | { Error :: interp (format ! ("unsupported call `{op_id}`: no DialectLookup is installed. Fix: initialize vyre-driver before running the reference interpreter or inline the callee as IR.")) }) ? ; let interned = lookup . intern_op (op_id) ; let def = lookup . lookup (interned) . ok_or_else (| | { Error :: interp (format ! ("unsupported call `{op_id}`. Fix: register the op in DialectRegistry or inline the callee as IR.")) }) ? ; if args . len () != def . signature . inputs . len () { return Err (Error :: interp (format ! ("call `{op_id}` received {} arguments but the primitive signature requires {}. Fix: pass exactly {1} arguments." , args . len () , def . signature . inputs . len ()))) ; } for (arg , param) in args . iter () . zip (def . signature . inputs . iter ()) { let declared_width = match param . ty { "u32" | "i32" | "f32" | "vec-count" => 4 , "u64" | "i64" | "f64" => 8 , "u8" | "i8" | "bool" => 1 , _ => 1 , } ; let bytes = eval_expr_snapshot (arg , invocation , snapshots , memory) ? . to_bytes_width (declared_width) ; input . extend_from_slice (& bytes) ; } let mut output = Vec :: new () ; (def . lowerings . cpu_ref) (& input , & mut output) ; let parsed_out_type = def . signature . outputs . first () . map (| param | match param . ty { "u32" => vyre :: ir :: DataType :: U32 , "i32" => vyre :: ir :: DataType :: I32 , "f32" => vyre :: ir :: DataType :: F32 , _ => vyre :: ir :: DataType :: Bytes , }) . unwrap_or (vyre :: ir :: DataType :: Bytes) ; Ok (crate :: eval_expr_cast :: spec_output_value (parsed_out_type , & output ,)) } Expr :: Select { cond , true_val , false_val , } => { let cond = eval_expr_snapshot (cond , invocation , snapshots , memory) ? . truthy () ; let true_val = eval_expr_snapshot (true_val , invocation , snapshots , memory) ? ; let false_val = eval_expr_snapshot (false_val , invocation , snapshots , memory) ? ; Ok (if cond { true_val } else { false_val }) } Expr :: Cast { target , value } => { let value = eval_expr_snapshot (value , invocation , snapshots , memory) ? ; crate :: eval_expr_cast :: cast_value (target . clone () , & value) } Expr :: Fma { a , b , c } => { let a = eval_expr_snapshot (a , invocation , snapshots , memory) ? . try_as_f32 () . ok_or_else (| | Error :: interp ("fma operand `a` is not a float. Fix: cast to f32 before fma.")) ? ; let b = eval_expr_snapshot (b , invocation , snapshots , memory) ? . try_as_f32 () . ok_or_else (| | Error :: interp ("fma operand `b` is not a float. Fix: cast to f32 before fma.")) ? ; let c = eval_expr_snapshot (c , invocation , snapshots , memory) ? . try_as_f32 () . ok_or_else (| | Error :: interp ("fma operand `c` is not a float. Fix: cast to f32 before fma.")) ? ; Ok (Value :: Float (f64 :: from (a . mul_add (b , c)))) } Expr :: SubgroupBallot { cond } => { let subgroup = subgroup_slice (snapshots , invocation . linear_local_index) ; let mask = subgroup . iter () . map (| lane | { eval_expr_snapshot (cond , lane , snapshots , memory) . map (| value | value . truthy ()) }) . collect :: < Result < Vec < _ > , _ > > () ? ; Ok (Value :: U32 (subgroup_simulator () . ballot_slice (& mask))) } Expr :: SubgroupShuffle { value , lane } => { let subgroup = subgroup_slice (snapshots , invocation . linear_local_index) ; let values = subgroup . iter () . map (| member | { eval_expr_snapshot (value , member , snapshots , memory) ? . try_as_u32 () . ok_or_else (| | { Error :: interp ("subgroup_shuffle value is not a u32. Fix: use subgroup collectives with integer lanes only." ,) }) }) . collect :: < Result < Vec < _ > , _ > > () ? ; let src_lanes = subgroup . iter () . map (| member | { eval_expr_snapshot (lane , member , snapshots , memory) ? . try_as_u32 () . ok_or_else (| | { Error :: interp ("subgroup_shuffle lane index is not a u32. Fix: use a scalar u32 lane argument." ,) }) }) . collect :: < Result < Vec < _ > , _ > > () ? ; let shuffled = subgroup_simulator () . shuffle (& values , & src_lanes) ; let local_offset = (invocation . linear_local_index as usize) % subgroup_simulator () . width () ; Ok (Value :: U32 (shuffled . get (local_offset) . copied () . unwrap_or (0))) } Expr :: SubgroupAdd { value } => { let subgroup = subgroup_slice (snapshots , invocation . linear_local_index) ; let values = subgroup . iter () . map (| lane | { eval_expr_snapshot (value , lane , snapshots , memory) ? . try_as_u32 () . ok_or_else (| | { Error :: interp ("subgroup_add value is not a u32. Fix: use subgroup collectives with integer lanes only." ,) }) }) . collect :: < Result < Vec < _ > , _ > > () ? ; Ok (Value :: U32 (subgroup_simulator () . add (& values))) } Expr :: Atomic { .. } => Err (Error :: interp ("subgroup operand contains an atomic expression. Fix: materialize the atomic result before entering the subgroup collective." ,)) , Expr :: Opaque (extension) => Err (Error :: interp (format ! ("hashmap reference interpreter does not support opaque expression extension `{}`/`{}`. Fix: provide a reference evaluator for this ExprNode or lower it to core Expr variants before evaluation." , extension . extension_kind () , extension . debug_identity ()))) , _ => Err (Error :: interp ("hashmap reference interpreter encountered an unknown expression variant during subgroup evaluation. Fix: add explicit reference semantics for the new ExprNode before dispatch." ,)) , }
}

pub(crate) fn eval_to_index(
    index: &Expr,
    context: &'static str,
    invocation: &mut HashmapInvocation<'_>,
    memory: &mut HashmapMemory,
    #[cfg(feature = "subgroup-ops")] snapshots: &[HashmapInvocationSnapshot],
) -> Result<u32, Error> {
    let value = eval_expr(
        index,
        invocation,
        memory,
        #[cfg(feature = "subgroup-ops")]
        snapshots,
    )?;
    value . try_as_u32 () . ok_or_else (| | { Error :: interp (format ! ("{context} {value:?} cannot be represented as u32. Fix: use a non-negative scalar index within u32." ,)) })
}

pub(crate) fn eval_call(
    call_expr: *const Expr,
    op_id: &str,
    args: &[Expr],
    invocation: &mut HashmapInvocation<'_>,
    memory: &mut HashmapMemory,
    #[cfg(feature = "subgroup-ops")] snapshots: &[HashmapInvocationSnapshot],
) -> Result<Value, Error> {
    let resolved = resolve_call(call_expr, op_id, invocation)?;
    let def = resolved.def;
    {
        if args.len() != def.signature.inputs.len() {
            return Err(Error::interp(format!(
                "call `{op_id}` received {} arguments but the primitive signature requires {}. Fix: pass exactly {1} arguments.",
                args.len(),
                def.signature.inputs.len()
            )));
        }
        let mut input = Vec::new();
        for (arg, param) in args.iter().zip(def.signature.inputs.iter()) {
            let declared_width = match param.ty {
                "u32" | "i32" | "f32" | "vec-count" => 4,
                "u64" | "i64" | "f64" => 8,
                "u8" | "i8" | "bool" => 1,
                _ => 1,
            };
            let bytes = eval_expr(
                arg,
                invocation,
                memory,
                #[cfg(feature = "subgroup-ops")]
                snapshots,
            )?
            .to_bytes_width(declared_width);
            let next_len = input . len () . checked_add (bytes . len ()) . ok_or_else (| | { Error :: interp (format ! ("call `{op_id}` input byte size overflows usize. Fix: reduce the argument count or byte payload size.")) }) ? ;
            const MAX_CALL_INPUT_BYTES: usize = 64 * 1024 * 1024;
            if next_len > MAX_CALL_INPUT_BYTES {
                return Err(Error::interp(format!(
                    "call `{op_id}` requires {next_len} input bytes, exceeding the {MAX_CALL_INPUT_BYTES}-byte reference budget. Fix: reduce call input size."
                )));
            }
            input.extend_from_slice(&bytes);
        }
        let mut output = Vec::new();
        let cpu_ref = def.lowerings.cpu_ref;
        cpu_ref(&input, &mut output);
        let parsed_out_type = def
            .signature
            .outputs
            .first()
            .map(|p| match p.ty {
                "u32" => vyre::ir::DataType::U32,
                "i32" => vyre::ir::DataType::I32,
                "f32" => vyre::ir::DataType::F32,
                "u8" => vyre::ir::DataType::Bytes,
                "bool" => vyre::ir::DataType::Bytes,
                _ => vyre::ir::DataType::Bytes,
            })
            .unwrap_or(vyre::ir::DataType::Bytes);
        Ok(crate::eval_expr_cast::spec_output_value(
            parsed_out_type,
            &output,
        ))
    }
}

fn resolve_call(
    call_expr: *const Expr,
    op_id: &str,
    invocation: &mut HashmapInvocation<'_>,
) -> Result<HashmapResolvedCall, Error> {
    if let Some(resolved) = invocation.op_cache.get(&call_expr).copied() {
        return Ok(resolved);
    }
    let lookup = vyre :: dialect_lookup () . ok_or_else (| | { Error :: interp (format ! ("unsupported call `{op_id}`: no DialectLookup is installed. Fix: initialize vyre-driver before running the reference interpreter or inline the callee as IR.")) }) ? ;
    let interned = lookup.intern_op(op_id);
    let def = lookup . lookup (interned) . ok_or_else (| | { Error :: interp (format ! ("unsupported call `{op_id}`. Fix: register the op in DialectRegistry or inline the callee as IR.")) }) ? ;
    let resolved = HashmapResolvedCall { def };
    invocation.op_cache.insert(call_expr, resolved);
    Ok(resolved)
}

pub(crate) fn axis_value(values: [u32; 3], axis: u8) -> Result<Value, Error> {
    values
        .get(axis as usize)
        .copied()
        .map(Value::U32)
        .ok_or_else(|| {
            Error::interp(format!(
                "invocation/workgroup ID axis {axis} out of range. Fix: use 0, 1, or 2."
            ))
        })
}
