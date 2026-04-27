use crate::ir::Expr;
use crate::transform::inline::InlineCtx;
use std::collections::HashMap;

pub(crate) struct CalleeExpander<'a> {
    pub(crate) ctx: &'a mut InlineCtx,
    pub(crate) prefix: String,
    pub(crate) vars: HashMap<String, String>,
    pub(crate) input_args: HashMap<String, Expr>,
    pub(crate) output_name: String,
    pub(crate) result_name: String,
    pub(crate) saw_output: bool,
}
