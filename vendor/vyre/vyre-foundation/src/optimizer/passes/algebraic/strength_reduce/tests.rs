use super::*;
use crate::ir::{BufferDecl, DataType, Expr, Node};
use crate::optimizer::passes::const_fold::ConstFold;
use crate::optimizer::{PassScheduler, ProgramPassKind};

mod complement_bounds;
mod float_division;
mod reciprocal;
mod scheduler_smoke;
mod self_inverse_select;
mod shift_add_horner;
mod shift_negation_fma;
