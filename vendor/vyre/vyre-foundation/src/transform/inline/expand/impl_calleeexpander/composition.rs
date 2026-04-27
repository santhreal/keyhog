use super::super::CalleeExpander;
use crate::error::Result;
use crate::ir::{AtomicOp, BinOp, Expr, UnOp};

enum Frame<'a> {
    Enter(&'a Expr),
    Load {
        buffer: &'a str,
    },
    Bin {
        op: BinOp,
    },
    Un {
        op: UnOp,
    },
    Call {
        op_id: &'a str,
        args: usize,
    },
    Fma,
    Select,
    Cast {
        target: crate::ir::DataType,
    },
    Atomic {
        op: AtomicOp,
        buffer: &'a str,
        has_expected: bool,
    },
}

impl CalleeExpander<'_> {
    #[inline]
    pub(crate) fn rename_decl(&mut self, name: &str) -> String {
        let renamed = format!("{}{name}", self.prefix);
        self.vars.insert(name.to_string(), renamed.clone());
        renamed
    }

    #[inline]
    pub(crate) fn rename_use(&self, name: &str) -> String {
        self.vars
            .get(name)
            .cloned()
            .unwrap_or_else(|| name.to_string())
    }

    #[inline]
    pub(crate) fn rename_expr_vars(&self, expr: &Expr) -> Result<Expr> {
        let mut frames = vec![Frame::Enter(expr)];
        let mut values: Vec<Expr> = Vec::new();
        while let Some(frame) = frames.pop() {
            match frame {
                Frame::Enter(expr) => self.enter_expr_frame(expr, &mut frames, &mut values),
                Frame::Load { buffer } => push_load(buffer, &mut values)?,
                Frame::Bin { op } => push_bin(op, &mut values)?,
                Frame::Un { op } => push_un(op, &mut values)?,
                Frame::Call { op_id, args } => push_call(op_id, args, &mut values)?,
                Frame::Fma => push_fma(&mut values)?,
                Frame::Select => push_select(&mut values)?,
                Frame::Cast { target } => push_cast(target, &mut values)?,
                Frame::Atomic {
                    op,
                    buffer,
                    has_expected,
                } => push_atomic(op, buffer, has_expected, &mut values)?,
            }
        }
        values.pop().ok_or_else(|| {
            crate::error::Error::lowering(
                "IR inline expansion: expression rename produced no value. Fix: ensure the input Expr is well-formed.",
            )
        })
    }

    fn enter_expr_frame<'a>(
        &self,
        expr: &'a Expr,
        frames: &mut Vec<Frame<'a>>,
        values: &mut Vec<Expr>,
    ) {
        match expr {
            Expr::Var(name) => values.push(Expr::var(self.rename_use(name))),
            Expr::Load { buffer, index } => {
                frames.push(Frame::Load { buffer });
                frames.push(Frame::Enter(index));
            }
            Expr::BinOp { op, left, right } => {
                frames.push(Frame::Bin { op: *op });
                frames.push(Frame::Enter(right));
                frames.push(Frame::Enter(left));
            }
            Expr::UnOp { op, operand } => {
                frames.push(Frame::Un { op: op.clone() });
                frames.push(Frame::Enter(operand));
            }
            Expr::Call { op_id, args } => {
                frames.push(Frame::Call {
                    op_id,
                    args: args.len(),
                });
                for arg in args.iter().rev() {
                    frames.push(Frame::Enter(arg));
                }
            }
            Expr::Fma { a, b, c } => {
                frames.push(Frame::Fma);
                frames.push(Frame::Enter(c));
                frames.push(Frame::Enter(b));
                frames.push(Frame::Enter(a));
            }
            Expr::Select {
                cond,
                true_val,
                false_val,
            } => {
                frames.push(Frame::Select);
                frames.push(Frame::Enter(false_val));
                frames.push(Frame::Enter(true_val));
                frames.push(Frame::Enter(cond));
            }
            Expr::Cast { target, value } => {
                frames.push(Frame::Cast {
                    target: target.clone(),
                });
                frames.push(Frame::Enter(value));
            }
            Expr::Atomic {
                op,
                buffer,
                index,
                expected,
                value,
            } => {
                frames.push(Frame::Atomic {
                    op: *op,
                    buffer,
                    has_expected: expected.is_some(),
                });
                frames.push(Frame::Enter(value));
                if let Some(expected) = expected.as_deref() {
                    frames.push(Frame::Enter(expected));
                }
                frames.push(Frame::Enter(index));
            }
            Expr::InvocationId { .. }
            | Expr::WorkgroupId { .. }
            | Expr::LocalId { .. }
            | Expr::SubgroupLocalId
            | Expr::SubgroupSize => {
                values.push(Expr::u32(0));
            }
            Expr::LitU32(_)
            | Expr::LitI32(_)
            | Expr::LitF32(_)
            | Expr::LitBool(_)
            | Expr::BufLen { .. }
            | Expr::SubgroupBallot { .. }
            | Expr::SubgroupShuffle { .. }
            | Expr::SubgroupAdd { .. } => values.push(expr.clone()),
            Expr::Opaque(_) => values.push(expr.clone()),
        }
    }
}

fn missing(what: &str) -> crate::error::Error {
    crate::error::Error::lowering(format!(
        "IR inline expansion: {what} missing from expression stack. Fix: ensure the input Expr is well-formed."
    ))
}

fn push_load(buffer: &str, values: &mut Vec<Expr>) -> Result<()> {
    let index = values.pop().ok_or_else(|| missing("load index"))?;
    values.push(Expr::Load {
        buffer: buffer.into(),
        index: Box::new(index),
    });
    Ok(())
}

fn push_bin(op: BinOp, values: &mut Vec<Expr>) -> Result<()> {
    let right = values.pop().ok_or_else(|| missing("binop right operand"))?;
    let left = values.pop().ok_or_else(|| missing("binop left operand"))?;
    values.push(Expr::BinOp {
        op,
        left: Box::new(left),
        right: Box::new(right),
    });
    Ok(())
}

fn push_un(op: UnOp, values: &mut Vec<Expr>) -> Result<()> {
    let operand = values.pop().ok_or_else(|| missing("unop operand"))?;
    values.push(Expr::UnOp {
        op,
        operand: Box::new(operand),
    });
    Ok(())
}

fn push_call(op_id: &str, args: usize, values: &mut Vec<Expr>) -> Result<()> {
    let split_at = values
        .len()
        .checked_sub(args)
        .ok_or_else(|| missing("call argument count mismatch"))?;
    let args = values.split_off(split_at);
    values.push(Expr::call(op_id, args));
    Ok(())
}

fn push_fma(values: &mut Vec<Expr>) -> Result<()> {
    let c = values.pop().ok_or_else(|| missing("fma operand c"))?;
    let b = values.pop().ok_or_else(|| missing("fma operand b"))?;
    let a = values.pop().ok_or_else(|| missing("fma operand a"))?;
    values.push(Expr::Fma {
        a: Box::new(a),
        b: Box::new(b),
        c: Box::new(c),
    });
    Ok(())
}

fn push_select(values: &mut Vec<Expr>) -> Result<()> {
    let false_val = values.pop().ok_or_else(|| missing("select false branch"))?;
    let true_val = values.pop().ok_or_else(|| missing("select true branch"))?;
    let cond = values.pop().ok_or_else(|| missing("select condition"))?;
    values.push(Expr::Select {
        cond: Box::new(cond),
        true_val: Box::new(true_val),
        false_val: Box::new(false_val),
    });
    Ok(())
}

fn push_cast(target: crate::ir::DataType, values: &mut Vec<Expr>) -> Result<()> {
    let value = values.pop().ok_or_else(|| missing("cast value"))?;
    values.push(Expr::Cast {
        target,
        value: Box::new(value),
    });
    Ok(())
}

fn push_atomic(
    op: AtomicOp,
    buffer: &str,
    has_expected: bool,
    values: &mut Vec<Expr>,
) -> Result<()> {
    let value = values.pop().ok_or_else(|| missing("atomic value"))?;
    let expected = if has_expected {
        Some(Box::new(
            values
                .pop()
                .ok_or_else(|| missing("atomic expected value"))?,
        ))
    } else {
        None
    };
    let index = values.pop().ok_or_else(|| missing("atomic index"))?;
    values.push(Expr::Atomic {
        op,
        buffer: buffer.into(),
        index: Box::new(index),
        expected,
        value: Box::new(value),
    });
    Ok(())
}
