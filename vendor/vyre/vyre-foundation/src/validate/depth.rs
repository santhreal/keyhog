use crate::validate::{err, ValidationError};

/// Default maximum nested operation-call depth accepted by validation.
pub const DEFAULT_MAX_CALL_DEPTH: usize = 32;

/// Default maximum `If`/`Loop`/`Block` nesting accepted by validation.
pub const DEFAULT_MAX_NESTING_DEPTH: usize = 64;

/// Default maximum statement node count accepted by validation.
pub const DEFAULT_MAX_NODE_COUNT: usize = 100_000;

/// Default maximum expression nesting accepted by validation.
pub const DEFAULT_MAX_EXPR_DEPTH: usize = 1_024;

/// Mutable state used while checking program size and nesting limits.
#[derive(Debug, Default)]
pub struct LimitState {
    /// Number of statement nodes visited so far.
    pub node_count: usize,
    /// Whether the nesting depth error has already been reported.
    pub nesting_reported: bool,
    /// Whether the node count error has already been reported.
    pub node_count_reported: bool,
}

/// Increment `limits` and emit errors if depth or node count exceeds defaults.
#[inline]
pub fn check_limits(limits: &mut LimitState, depth: usize, errors: &mut Vec<ValidationError>) {
    limits.node_count = limits.node_count.saturating_add(1);
    if limits.node_count > DEFAULT_MAX_NODE_COUNT && !limits.node_count_reported {
        limits.node_count_reported = true;
        errors.push(err(format!(
            "V019: program has more than {DEFAULT_MAX_NODE_COUNT} statement nodes. Fix: split the program into smaller kernels or run an optimization pass before lowering."
        )));
    }
    if depth > DEFAULT_MAX_NESTING_DEPTH && !limits.nesting_reported {
        limits.nesting_reported = true;
        errors.push(err(format!(
            "V018: program nesting depth {depth} exceeds max {DEFAULT_MAX_NESTING_DEPTH}. Fix: flatten nested If/Loop/Block structures or split the program before lowering."
        )));
    }
}

/// Return true when the expression nesting depth is still within bounds.
#[inline]
#[must_use]
pub fn check_expr_depth(depth: usize, errors: &mut Vec<ValidationError>) -> bool {
    if depth > DEFAULT_MAX_EXPR_DEPTH {
        errors.push(err(format!(
            "V033: expression nesting depth {depth} exceeds max {DEFAULT_MAX_EXPR_DEPTH}. Fix: split the expression into intermediate let-bindings before lowering."
        )));
        return false;
    }
    true
}

/// Compute the maximum call depth reachable from `op_id`.
///
/// Returns `Ok(max_depth)` when within [`DEFAULT_MAX_CALL_DEPTH`], or
/// `Err(depth)` if the limit is exceeded.
#[inline]
#[must_use]
pub fn max_call_depth(op_id: &str, depth: usize) -> Result<usize, usize> {
    let _ = op_id;
    if depth > DEFAULT_MAX_CALL_DEPTH {
        return Err(depth);
    }
    // Foundation does not own the dialect registry, so it cannot walk an
    // operation's callee graph on its own. Driver-level callers either pass
    // an already-inlined program (no Expr::Call nodes remain, so this
    // function is never invoked) or run their own registry-aware traversal
    // before validation. See `vyre-driver::pipeline::compile` for the full
    // call-depth walk that uses the DialectRegistry.
    Ok(depth)
}
