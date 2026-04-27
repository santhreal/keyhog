//! Expression evaluator that gives the parity engine a pure-Rust ground truth
//! for every `Expr` variant.
//!
//! If a backend lowers `Expr::BinOp`, `Expr::Load`, or `Expr::Atomic` differently
//! than this evaluator, the conform gate reports the exact divergence. This module
//! exists so IR semantics are defined by Rust code, not by whatever a WGSL driver
//! happens to emit.

use vyre::ir::{AtomicOp, BinOp, BufferAccess, BufferDecl, DataType, Expr, Program, UnOp};

use smallvec::SmallVec;
use vyre::Error;

use crate::eval_expr_cast::cast_value;
use crate::{atomics, oob, value::Value, workgroup::Invocation, workgroup::Memory};

/// Re-export the OOB-guarded buffer type used by storage operations.
pub use crate::oob::Buffer;

#[derive(Clone)]
enum OpCode<'a> {
    Lit(Value),
    Var(&'a str),
    BufLen(&'a str),
    InvocationId(u8),
    WorkgroupId(u8),
    LocalId(u8),
    Load {
        buffer: &'a str,
    },
    BinOp(BinOp),
    UnOp(UnOp),
    Select,
    Cast(DataType),
    Fma,
    Call {
        call_expr: *const Expr,
        op_id: &'a str,
        args: &'a [Expr],
    },
    Atomic {
        op: AtomicOp,
        buffer: &'a str,
        has_expected: bool,
    },
    // Internal opcodes for Cat-C subgroup intrinsics evaluated on the
    // single-lane serial CPU oracle (SUBGROUP_WIDTH=1). Not part of the
    // wire format; these are interpreter-private.
    SubgroupBallot,
    SubgroupShuffle,
    SubgroupAdd,
}

/// Evaluate an expression through the flat opcode evaluator.
///
/// # Errors
///
/// Returns [`Error::Interp`] when expression lowering or flat execution
/// fails. The recursive evaluator is retained only as a test oracle.
pub fn eval(
    expr: &Expr,
    invocation: &mut Invocation<'_>,
    memory: &mut Memory,
    program: &Program,
) -> Result<Value, vyre::Error> {
    let mut ops = Vec::new();
    linearize_expr(expr, &mut ops)?;
    eval_flat_ops(&ops, invocation, memory, program)
}

fn linearize_expr<'a>(expr: &'a Expr, ops: &mut Vec<OpCode<'a>>) -> Result<(), vyre::Error> {
    match expr {
        Expr::LitU32(value) => ops.push(OpCode::Lit(Value::U32(*value))),
        Expr::LitI32(value) => ops.push(OpCode::Lit(Value::I32(*value))),
        Expr::LitF32(value) => ops.push(OpCode::Lit(Value::Float(f64::from(*value)))),
        Expr::LitBool(value) => ops.push(OpCode::Lit(Value::Bool(*value))),
        Expr::Var(name) => ops.push(OpCode::Var(name.as_ref())),
        Expr::BufLen { buffer } => ops.push(OpCode::BufLen(buffer.as_ref())),
        Expr::InvocationId { axis } => ops.push(OpCode::InvocationId(*axis)),
        Expr::WorkgroupId { axis } => ops.push(OpCode::WorkgroupId(*axis)),
        Expr::LocalId { axis } => ops.push(OpCode::LocalId(*axis)),
        Expr::Load { buffer, index } => {
            linearize_expr(index, ops)?;
            ops.push(OpCode::Load {
                buffer: buffer.as_ref(),
            });
        }
        Expr::BinOp { op, left, right } => {
            linearize_expr(left, ops)?;
            linearize_expr(right, ops)?;
            ops.push(OpCode::BinOp(*op));
        }
        Expr::UnOp { op, operand } => {
            linearize_expr(operand, ops)?;
            ops.push(OpCode::UnOp(op.clone()));
        }
        Expr::Call { op_id, args } => ops.push(OpCode::Call {
            call_expr: expr as *const Expr,
            op_id: op_id.as_ref(),
            args,
        }),
        Expr::Select {
            cond,
            true_val,
            false_val,
        } => {
            linearize_expr(cond, ops)?;
            linearize_expr(true_val, ops)?;
            linearize_expr(false_val, ops)?;
            ops.push(OpCode::Select);
        }
        Expr::Cast { target, value } => {
            linearize_expr(value, ops)?;
            ops.push(OpCode::Cast(target.clone()));
        }
        Expr::Fma { a, b, c } => {
            linearize_expr(a, ops)?;
            linearize_expr(b, ops)?;
            linearize_expr(c, ops)?;
            ops.push(OpCode::Fma);
        }
        Expr::Atomic {
            op,
            buffer,
            index,
            expected,
            value,
        } => {
            match (*op, expected.as_deref()) {
                (AtomicOp::CompareExchange, None) => {
                    return Err(Error::interp(
                        "compare-exchange atomic is missing expected value. Fix: set Expr::Atomic.expected for AtomicOp::CompareExchange.",
                    ));
                }
                (AtomicOp::CompareExchange, Some(_)) => {}
                (_, Some(_)) => {
                    return Err(Error::interp(
                        "non-compare-exchange atomic includes an expected value. Fix: use Expr::Atomic.expected only with AtomicOp::CompareExchange.",
                    ));
                }
                (_, None) => {}
            }
            linearize_expr(index, ops)?;
            if let Some(expected) = expected {
                linearize_expr(expected, ops)?;
            }
            linearize_expr(value, ops)?;
            ops.push(OpCode::Atomic {
                op: *op,
                buffer: buffer.as_ref(),
                has_expected: expected.is_some(),
            });
        }
        Expr::Opaque(node) => {
            return Err(Error::interp(format!(
                "unsupported opaque expression `{}` in vyre-reference. Fix: register a reference evaluator for this ExprNode extension.",
                node.extension_kind()
            )));
        }
        Expr::SubgroupBallot { cond } => {
            // Serial CPU ref: single-lane wave. Ballot is `cond ? 1u32 : 0u32`.
            linearize_expr(cond, ops)?;
            ops.push(OpCode::SubgroupBallot);
        }
        Expr::SubgroupShuffle { value, lane } => {
            // Serial CPU ref: single-lane wave. lane==0 returns value, else 0.
            linearize_expr(value, ops)?;
            linearize_expr(lane, ops)?;
            ops.push(OpCode::SubgroupShuffle);
        }
        Expr::SubgroupAdd { value } => {
            // Serial CPU ref: single-lane wave. Sum-reduction across one lane = value.
            linearize_expr(value, ops)?;
            ops.push(OpCode::SubgroupAdd);
        }
        other => {
            return Err(Error::interp(format!(
                "unsupported expression variant `{other:?}` in flat evaluator. Fix: extend vyre-reference for this Expr variant before dispatch."
            )));
        }
    }
    Ok(())
}

fn eval_flat_ops(
    ops: &[OpCode<'_>],
    invocation: &mut Invocation<'_>,
    memory: &mut Memory,
    program: &Program,
) -> Result<Value, vyre::Error> {
    let mut stack: SmallVec<[Value; 32]> = SmallVec::new();
    let mut pc = 0usize;
    while pc < ops.len() {
        match &ops[pc] {
            OpCode::Lit(value) => stack.push(value.clone()),
            OpCode::Var(name) => stack.push(eval_var(name, invocation)?),
            OpCode::BufLen(buffer) => stack.push(eval_buf_len(buffer, memory, program)?),
            OpCode::InvocationId(axis) => stack.push(eval_invocation_id(*axis, invocation)?),
            OpCode::WorkgroupId(axis) => stack.push(eval_workgroup_id(*axis, invocation)?),
            OpCode::LocalId(axis) => stack.push(eval_local_id(*axis, invocation)?),
            OpCode::Load { buffer } => {
                let value = pop_value(&mut stack, "load index")?;
                let idx = value.try_as_u32().ok_or_else(|| {
                    Error::interp(format!(
                        "load index {value:?} cannot be represented as u32. Fix: use a non-negative scalar index within u32."
                    ))
                })?;
                stack.push(oob::load(resolve_buffer(memory, program, buffer)?, idx));
            }
            OpCode::BinOp(op) => {
                let right = pop_value(&mut stack, "binary right operand")?;
                let left = pop_value(&mut stack, "binary left operand")?;
                stack.push(super::typed_ops::eval_binop(*op, left, right)?);
            }
            OpCode::UnOp(op) => {
                let operand = pop_value(&mut stack, "unary operand")?;
                stack.push(super::typed_ops::eval_unop(op.clone(), operand)?);
            }
            OpCode::Select => {
                let false_val = pop_value(&mut stack, "select false branch")?;
                let true_val = pop_value(&mut stack, "select true branch")?;
                let cond = pop_value(&mut stack, "select condition")?.truthy();
                stack.push(if cond { true_val } else { false_val });
            }
            OpCode::Cast(target) => {
                let value = pop_value(&mut stack, "cast value")?;
                stack.push(cast_value(target.clone(), &value)?);
            }
            OpCode::Fma => {
                let c = pop_f32(&mut stack, "fma operand c")?;
                let b = pop_f32(&mut stack, "fma operand b")?;
                let a = pop_f32(&mut stack, "fma operand a")?;
                stack.push(Value::Float(f64::from(a.mul_add(b, c))));
            }
            OpCode::Call {
                call_expr,
                op_id,
                args,
            } => {
                stack.push(crate::eval_call::eval_call(
                    *call_expr, op_id, args, invocation, memory, program,
                )?);
            }
            OpCode::SubgroupBallot => {
                // Serial CPU ref: single-lane wave. `cond ? 1u32 : 0u32`.
                let cond = pop_value(&mut stack, "subgroup_ballot cond")?.truthy();
                stack.push(Value::U32(u32::from(cond)));
            }
            OpCode::SubgroupShuffle => {
                // Serial CPU ref: single-lane wave. lane==0 returns value, else 0.
                let lane = pop_u32(&mut stack, "subgroup_shuffle lane")?;
                let value = pop_value(&mut stack, "subgroup_shuffle value")?;
                stack.push(if lane == 0 { value } else { Value::U32(0) });
            }
            OpCode::SubgroupAdd => {
                // Serial CPU ref: single-lane wave. Sum-reduction = value itself.
                // Stack top already holds `value`; no transformation required.
            }
            OpCode::Atomic {
                op,
                buffer,
                has_expected,
            } => {
                let value = pop_u32(&mut stack, "atomic value")?;
                let expected = if *has_expected {
                    Some(pop_u32(&mut stack, "atomic expected value")?)
                } else {
                    None
                };
                let index = pop_u32(&mut stack, "atomic index")?;
                let target = atomic_buffer_mut(memory, program, buffer)?;
                let Some(old) = oob::atomic_load(target, index) else {
                    stack.push(Value::U32(0));
                    pc += 1;
                    continue;
                };
                let (old, new) = atomics::apply(*op, old, expected, value)?;
                oob::atomic_store(target, index, new);
                stack.push(Value::U32(old));
            }
        }
        pc += 1;
    }
    pop_value(&mut stack, "expression result")
}

fn pop_value(stack: &mut SmallVec<[Value; 32]>, label: &str) -> Result<Value, vyre::Error> {
    stack.pop().ok_or_else(|| {
        Error::interp(format!(
            "{label} missing from flat expression stack. Fix: internal evaluator error."
        ))
    })
}

fn pop_u32(stack: &mut SmallVec<[Value; 32]>, label: &str) -> Result<u32, vyre::Error> {
    let value = pop_value(stack, label)?;
    value.try_as_u32().ok_or_else(|| {
        Error::interp(format!(
            "{label} {value:?} cannot be represented as u32. Fix: use a scalar u32-compatible argument."
        ))
    })
}

fn pop_f32(stack: &mut SmallVec<[Value; 32]>, label: &str) -> Result<f32, vyre::Error> {
    let value = pop_value(stack, label)?;
    value.try_as_f32().ok_or_else(|| {
        Error::interp(format!(
            "{label} {value:?} is not a float. Fix: cast to f32 before fma."
        ))
    })
}

/// Evaluate an expression for one invocation.
///
/// # Errors
///
/// Returns [`Error::Interp`] on operand type errors, malformed atomic or call
/// expressions, unimplemented variants, or float operands.
#[cfg(test)]
pub(crate) fn eval_frame_oracle(
    expr: &Expr,
    invocation: &mut Invocation<'_>,
    memory: &mut Memory,
    program: &Program,
) -> Result<Value, vyre::Error> {
    enum Frame<'a> {
        Expr(&'a Expr),
        BinOp(BinOp),
        UnOp(UnOp),
        Select,
        Cast(DataType),
        Fma,
        Load {
            buffer: &'a str,
        },
        AtomicIndex {
            op: AtomicOp,
            buffer: &'a str,
            expected: Option<&'a Expr>,
            value: &'a Expr,
        },
        AtomicExpected {
            op: AtomicOp,
            buffer: &'a str,
            index: u32,
            value: &'a Expr,
            expected_expr: &'a Expr,
        },
        AtomicValue {
            op: AtomicOp,
            buffer: &'a str,
            expected: Option<u32>,
            index: u32,
        },
    }

    let mut frames = vec![Frame::Expr(expr)];
    let mut values: Vec<Value> = Vec::new();

    while let Some(frame) = frames.pop() {
        match frame {
            Frame::Expr(expr) => match expr {
                Expr::LitU32(value) => values.push(Value::U32(*value)),
                Expr::LitI32(value) => values.push(Value::I32(*value)),
                Expr::LitF32(value) => values.push(Value::Float(f64::from(*value))),
                Expr::LitBool(value) => values.push(Value::Bool(*value)),
                Expr::Var(name) => values.push(eval_var(name, invocation)?),
                Expr::BufLen { buffer } => values.push(eval_buf_len(buffer, memory, program)?),
                Expr::InvocationId { axis } => values.push(eval_invocation_id(*axis, invocation)?),
                Expr::WorkgroupId { axis } => values.push(eval_workgroup_id(*axis, invocation)?),
                Expr::LocalId { axis } => values.push(eval_local_id(*axis, invocation)?),
                Expr::Load { buffer, index } => {
                    frames.push(Frame::Load { buffer });
                    frames.push(Frame::Expr(index));
                }
                Expr::BinOp { op, left, right } => {
                    frames.push(Frame::BinOp(*op));
                    frames.push(Frame::Expr(right));
                    frames.push(Frame::Expr(left));
                }
                Expr::UnOp { op, operand } => {
                    frames.push(Frame::UnOp(op.clone()));
                    frames.push(Frame::Expr(operand));
                }
                Expr::Select {
                    cond,
                    true_val,
                    false_val,
                } => {
                    frames.push(Frame::Select);
                    frames.push(Frame::Expr(false_val));
                    frames.push(Frame::Expr(true_val));
                    frames.push(Frame::Expr(cond));
                }
                Expr::Cast { target, value } => {
                    frames.push(Frame::Cast(target.clone()));
                    frames.push(Frame::Expr(value));
                }
                Expr::Fma { a, b, c } => {
                    frames.push(Frame::Fma);
                    frames.push(Frame::Expr(c));
                    frames.push(Frame::Expr(b));
                    frames.push(Frame::Expr(a));
                }
                Expr::Atomic {
                    op,
                    buffer,
                    index,
                    expected,
                    value,
                } => {
                    match (*op, expected.as_deref()) {
                        (AtomicOp::CompareExchange, None) => {
                            return Err(Error::interp(
                                "compare-exchange atomic is missing expected value. Fix: set Expr::Atomic.expected for AtomicOp::CompareExchange.",
                            ));
                        }
                        (AtomicOp::CompareExchange, Some(_)) => {}
                        (_, Some(_)) => {
                            return Err(Error::interp(
                                "non-compare-exchange atomic includes an expected value. Fix: use Expr::Atomic.expected only with AtomicOp::CompareExchange.",
                            ));
                        }
                        (_, None) => {}
                    }
                    frames.push(Frame::AtomicIndex {
                        op: *op,
                        buffer,
                        expected: expected.as_deref(),
                        value,
                    });
                    frames.push(Frame::Expr(index));
                }
                Expr::Call { op_id, args } => {
                    let val = crate::eval_call::eval_call(
                        expr as *const Expr,
                        op_id,
                        args,
                        invocation,
                        memory,
                        program,
                    )?;
                    values.push(val);
                }
                Expr::Opaque(extension) => {
                    return Err(Error::interp(format!(
                        "reference interpreter does not support opaque expression extension `{}`/`{}`. Fix: provide a reference evaluator for this ExprNode or lower it to core Expr variants before evaluation.",
                        extension.extension_kind(),
                        extension.debug_identity()
                    )));
                }
                _ => {
                    return Err(Error::interp(
                        "reference interpreter encountered an unknown expression variant. Fix: add explicit reference semantics for the new ExprNode before dispatch.",
                    ));
                }
            },
            Frame::BinOp(op) => {
                let right = values.pop().ok_or_else(|| {
                    Error::interp("binary op missing right operand. Fix: internal evaluator error.")
                })?;
                let left = values.pop().ok_or_else(|| {
                    Error::interp("binary op missing left operand. Fix: internal evaluator error.")
                })?;
                values.push(super::typed_ops::eval_binop(op, left, right)?);
            }
            Frame::UnOp(op) => {
                let operand = values.pop().ok_or_else(|| {
                    Error::interp("unary op missing operand. Fix: internal evaluator error.")
                })?;
                values.push(super::typed_ops::eval_unop(op, operand)?);
            }
            Frame::Select => {
                let false_val = values.pop().ok_or_else(|| {
                    Error::interp("select missing false branch. Fix: internal evaluator error.")
                })?;
                let true_val = values.pop().ok_or_else(|| {
                    Error::interp("select missing true branch. Fix: internal evaluator error.")
                })?;
                let cond = values
                    .pop()
                    .ok_or_else(|| {
                        Error::interp("select missing condition. Fix: internal evaluator error.")
                    })?
                    .truthy();
                values.push(if cond { true_val } else { false_val });
            }
            Frame::Cast(target) => {
                let value = values.pop().ok_or_else(|| {
                    Error::interp("cast missing value. Fix: internal evaluator error.")
                })?;
                values.push(cast_value(target.clone(), &value)?);
            }
            Frame::Fma => {
                let c = values
                    .pop()
                    .ok_or_else(|| {
                        Error::interp("fma missing operand c. Fix: internal evaluator error.")
                    })?
                    .try_as_f32()
                    .ok_or_else(|| {
                        Error::interp(
                            "fma operand `c` is not a float. Fix: cast to f32 before fma.",
                        )
                    })?;
                let b = values
                    .pop()
                    .ok_or_else(|| {
                        Error::interp("fma missing operand b. Fix: internal evaluator error.")
                    })?
                    .try_as_f32()
                    .ok_or_else(|| {
                        Error::interp(
                            "fma operand `b` is not a float. Fix: cast to f32 before fma.",
                        )
                    })?;
                let a = values
                    .pop()
                    .ok_or_else(|| {
                        Error::interp("fma missing operand a. Fix: internal evaluator error.")
                    })?
                    .try_as_f32()
                    .ok_or_else(|| {
                        Error::interp(
                            "fma operand `a` is not a float. Fix: cast to f32 before fma.",
                        )
                    })?;
                values.push(Value::Float(f64::from(a.mul_add(b, c))));
            }
            Frame::Load { buffer } => {
                let value = values.pop().ok_or_else(|| {
                    Error::interp("load missing index. Fix: internal evaluator error.")
                })?;
                let idx = value.try_as_u32().ok_or_else(|| {
                    Error::interp(format!(
                        "load index {value:?} cannot be represented as u32. Fix: use a non-negative scalar index within u32."
                    ))
                })?;
                values.push(oob::load(resolve_buffer(memory, program, buffer)?, idx));
            }
            Frame::AtomicIndex {
                op,
                buffer,
                expected,
                value,
            } => {
                let val = values.pop().ok_or_else(|| {
                    Error::interp("atomic missing index. Fix: internal evaluator error.")
                })?;
                let idx = val.try_as_u32().ok_or_else(|| {
                    Error::interp(format!(
                        "atomic index {val:?} cannot be represented as u32. Fix: use a non-negative scalar index within u32."
                    ))
                })?;
                if let Some(expected_expr) = expected {
                    frames.push(Frame::AtomicExpected {
                        op,
                        buffer,
                        index: idx,
                        value,
                        expected_expr,
                    });
                    frames.push(Frame::Expr(expected_expr));
                } else {
                    frames.push(Frame::AtomicValue {
                        op,
                        buffer,
                        expected: None,
                        index: idx,
                    });
                    frames.push(Frame::Expr(value));
                }
            }
            Frame::AtomicExpected {
                op,
                buffer,
                index,
                value,
                expected_expr,
            } => {
                let val = values.pop().ok_or_else(|| {
                    Error::interp(
                        "atomic compare-exchange missing expected value. Fix: internal evaluator error.",
                    )
                })?;
                let expected_val = val.try_as_u32().ok_or_else(|| {
                    Error::interp(format!(
                        "atomic expected value {expected_expr:?} cannot be represented as u32. Fix: use a scalar u32-compatible argument."
                    ))
                })?;
                frames.push(Frame::AtomicValue {
                    op,
                    buffer,
                    expected: Some(expected_val),
                    index,
                });
                frames.push(Frame::Expr(value));
            }
            Frame::AtomicValue {
                op,
                buffer,
                expected,
                index,
            } => {
                let val = values.pop().ok_or_else(|| {
                    Error::interp("atomic missing value. Fix: internal evaluator error.")
                })?;
                let value = val.try_as_u32().ok_or_else(|| {
                    Error::interp(
                        "atomic value cannot be represented as u32. Fix: use a scalar u32-compatible argument.",
                    )
                })?;
                let target = atomic_buffer_mut(memory, program, buffer)?;
                let Some(old) = oob::atomic_load(target, index) else {
                    values.push(Value::U32(0));
                    continue;
                };
                let (old, new) = atomics::apply(op, old, expected, value)?;
                oob::atomic_store(target, index, new);
                values.push(Value::U32(old));
            }
        }
    }

    values.pop().ok_or_else(|| {
        Error::interp("expression evaluation produced no value. Fix: internal evaluator error.")
    })
}

/// Return a mutable buffer only when the program declares it writable.
///
/// # Errors
///
/// Returns [`Error::Interp`] if the buffer is read-only, uniform,
/// or does not exist in the program declaration.
pub fn buffer_mut<'a>(
    memory: &'a mut Memory,
    program: &Program,
    name: &str,
) -> Result<&'a mut Buffer, vyre::Error> {
    let decl = buffer_decl(program, name)?;
    match decl.access() {
        BufferAccess::ReadWrite | BufferAccess::Workgroup => resolve_buffer_mut(memory, decl),
        BufferAccess::ReadOnly | BufferAccess::Uniform => Err(Error::interp(format!(
            "store target `{name}` is not writable. Fix: declare it ReadWrite or Workgroup."
        ))),
        _ => Err(Error::interp(format!(
            "store target `{name}` uses an unsupported access mode. Fix: use a supported BufferAccess."
        ))),
    }
}

fn eval_var(name: &str, invocation: &Invocation<'_>) -> Result<Value, vyre::Error> {
    invocation.local(name).cloned().ok_or_else(|| {
        Error::interp(format!(
            "reference to undeclared variable `{name}`. Fix: add a Let before this use."
        ))
    })
}

fn eval_buf_len(buffer: &str, memory: &Memory, program: &Program) -> Result<Value, vyre::Error> {
    Ok(Value::U32(resolve_buffer(memory, program, buffer)?.len()))
}

fn eval_invocation_id(axis: u8, invocation: &Invocation<'_>) -> Result<Value, vyre::Error> {
    axis_value(invocation.ids.global, axis)
}

fn eval_workgroup_id(axis: u8, invocation: &Invocation<'_>) -> Result<Value, vyre::Error> {
    axis_value(invocation.ids.workgroup, axis)
}

fn eval_local_id(axis: u8, invocation: &Invocation<'_>) -> Result<Value, vyre::Error> {
    axis_value(invocation.ids.local, axis)
}

fn resolve_buffer<'a>(
    memory: &'a Memory,
    program: &Program,
    name: &str,
) -> Result<&'a oob::Buffer, vyre::Error> {
    let decl = buffer_decl(program, name)?;
    if decl.access() == BufferAccess::Workgroup {
        memory.workgroup.get(name)
    } else {
        memory.storage.get(name)
    }
    .ok_or_else(|| {
        Error::interp(format!(
            "missing buffer `{name}`. Fix: initialize all declared buffers."
        ))
    })
}

fn resolve_buffer_mut<'a>(
    memory: &'a mut Memory,
    decl: &BufferDecl,
) -> Result<&'a mut oob::Buffer, vyre::Error> {
    let name = decl.name();
    if decl.access() == BufferAccess::Workgroup {
        memory.workgroup.get_mut(name)
    } else {
        memory.storage.get_mut(name)
    }
    .ok_or_else(|| {
        Error::interp(format!(
            "missing buffer `{name}`. Fix: initialize all declared buffers."
        ))
    })
}

fn atomic_buffer_mut<'a>(
    memory: &'a mut Memory,
    program: &Program,
    name: &str,
) -> Result<&'a mut oob::Buffer, vyre::Error> {
    let decl = buffer_decl(program, name)?;
    match decl.access() {
        BufferAccess::ReadWrite => resolve_buffer_mut(memory, decl),
        BufferAccess::Workgroup => Err(Error::interp(format!(
            "atomic target `{name}` is workgroup memory. Fix: atomics only support ReadWrite storage buffers."
        ))),
        BufferAccess::ReadOnly | BufferAccess::Uniform => Err(Error::interp(format!(
            "atomic target `{name}` is not writable. Fix: atomics only support ReadWrite storage buffers."
        ))),
        _ => Err(Error::interp(format!(
            "atomic target `{name}` uses an unsupported access mode. Fix: use a supported BufferAccess."
        ))),
    }
}

fn buffer_decl<'a>(program: &'a Program, name: &str) -> Result<&'a BufferDecl, vyre::Error> {
    program.buffer(name).ok_or_else(|| {
        Error::interp(format!(
            "unknown buffer `{name}`. Fix: declare it in Program::buffers."
        ))
    })
}

fn axis_value(values: [u32; 3], axis: u8) -> Result<Value, vyre::Error> {
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

#[cfg(test)]
mod tests {

    use proptest::prelude::*;
    use vyre::ir::{Expr, Program};

    use super::{eval, eval_frame_oracle};
    use crate::workgroup::{Invocation, InvocationIds, Memory};

    fn empty_memory() -> Memory {
        Memory {
            storage: Default::default(),
            workgroup: Default::default(),
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn prop_flat_evaluator_matches_frame_oracle(a in any::<u32>(), b in any::<u32>(), c in any::<u32>(), pick_left in any::<bool>()) {
            let program = Program::wrapped(Vec::new(), [1, 1, 1], Vec::new());
            let int_expr = Expr::select(
                Expr::bool(pick_left),
                Expr::add(Expr::u32(a), Expr::mul(Expr::u32(b), Expr::u32(c))),
                Expr::sub(Expr::u32(a), Expr::u32(b)),
            );
            let float_expr = Expr::fma(
                Expr::f32(((a & 0xffff) as f32) * 0.5),
                Expr::f32(((b & 0xff) as f32) + 1.0),
                Expr::f32(((c & 0xffff) as f32) * 0.25),
            );

            for expr in [&int_expr, &float_expr] {
                let mut flat_invocation = Invocation::new(InvocationIds::ZERO, program.entry());
                let mut frame_invocation = Invocation::new(InvocationIds::ZERO, program.entry());
                let mut flat_memory = empty_memory();
                let mut frame_memory = empty_memory();

                let flat = eval(expr, &mut flat_invocation, &mut flat_memory, &program)
                    .expect("Fix: flat evaluator must evaluate generated expression");
                let frame = eval_frame_oracle(expr, &mut frame_invocation, &mut frame_memory, &program)
                    .expect("Fix: frame oracle must evaluate generated expression");
                prop_assert_eq!(flat, frame);
            }
        }
    }
}
