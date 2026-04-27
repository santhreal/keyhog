//! Cat-B atomic-read-modify-write compositions over a 1-slot state buffer.
//!
//! These builders live in `vyre-libs` because they are still compositions over
//! `Expr::Atomic`, but they are NOT Category A: correctness depends on the
//! backend owning the matching Naga atomic emission path. If a backend cannot
//! lower the atomic op, dispatch must fail loudly instead of silently treating
//! these as pure library sugar.
//!
//! Each op emits a single-invocation serial walk. For every i in
//! 0..n: write the pre-op state into `trace[i]`, apply the atomic op
//! to `state[0]`. The serial walk gives a byte-identical CPU reference
//! that matches `wrapping_{add,and,or,xor}`, `min`, `max`, `exchange`,
//! or `compare_exchange` semantics under single-lane contention.

use vyre::ir::{AtomicOp, BufferAccess, BufferDecl, DataType, Expr, Node, Program};

// --- Macros must be defined before `pub mod` declarations so child modules
// can name them. `macro_rules!` is textual and scoped to what appears
// lexically earlier in the file; submodules declared above the macros
// cannot see them and fail to compile with "cannot find macro …" errors.
// F-IR-35 reclassified atomics to Category::Intrinsic through these.

/// Helper macro to register a Cat-B atomic serial op in the dialect registry.
/// Every atomic op that emits `Expr::Atomic` must carry `Category::Intrinsic`
/// so the validator knows the backend must own the corresponding Naga arm.
macro_rules! register_atomic_serial_op {
    ($op_id:expr, $compose:expr) => {
        ::inventory::submit! {
            ::vyre_driver::registry::dialect::OpDefRegistration::new(|| ::vyre_driver::registry::OpDef {
                id: $op_id,
                dialect: "vyre-libs.math.atomic",
                category: ::vyre_driver::registry::Category::Intrinsic,
                signature: ::vyre_driver::registry::Signature {
                    inputs: &[
                        ::vyre_driver::registry::TypedParam { name: "values", ty: "buffer<u32>" },
                        ::vyre_driver::registry::TypedParam { name: "state", ty: "buffer<u32>" },
                        ::vyre_driver::registry::TypedParam { name: "trace", ty: "buffer<u32>" },
                    ],
                    outputs: &[],
                    attrs: &[],
                    bytes_extraction: false,
                },
                lowerings: ::vyre_foundation::dialect_lookup::LoweringTable::empty(),
                laws: &[],
                compose: Some($compose),
            })
        }
    };
}

/// Helper macro for `atomic_compare_exchange_u32` which has a different
/// input schema (`expected` + `desired` buffers).
macro_rules! register_atomic_cas_op {
    ($op_id:expr, $compose:expr) => {
        ::inventory::submit! {
            ::vyre_driver::registry::dialect::OpDefRegistration::new(|| ::vyre_driver::registry::OpDef {
                id: $op_id,
                dialect: "vyre-libs.math.atomic",
                category: ::vyre_driver::registry::Category::Intrinsic,
                signature: ::vyre_driver::registry::Signature {
                    inputs: &[
                        ::vyre_driver::registry::TypedParam { name: "expected", ty: "buffer<u32>" },
                        ::vyre_driver::registry::TypedParam { name: "desired", ty: "buffer<u32>" },
                        ::vyre_driver::registry::TypedParam { name: "state", ty: "buffer<u32>" },
                        ::vyre_driver::registry::TypedParam { name: "trace", ty: "buffer<u32>" },
                    ],
                    outputs: &[],
                    attrs: &[],
                    bytes_extraction: false,
                },
                lowerings: ::vyre_foundation::dialect_lookup::LoweringTable::empty(),
                laws: &[],
                compose: Some($compose),
            })
        }
    };
}

pub mod atomic_add;
pub mod atomic_and;
pub mod atomic_compare_exchange;
pub mod atomic_exchange;
pub mod atomic_lru_update;
pub mod atomic_max;
pub mod atomic_min;
pub mod atomic_or;
pub mod atomic_xor;

pub use atomic_add::atomic_add_u32;
pub use atomic_and::atomic_and_u32;
pub use atomic_compare_exchange::atomic_compare_exchange_u32;
pub use atomic_exchange::atomic_exchange_u32;
pub use atomic_lru_update::atomic_lru_update_u32;
pub use atomic_max::atomic_max_u32;
pub use atomic_min::atomic_min_u32;
pub use atomic_or::atomic_or_u32;
pub use atomic_xor::atomic_xor_u32;

/// Shared builder for the 7 single-value atomic variants
/// (add/and/or/xor/min/max/exchange). Constructs:
///
/// ```text
/// if idx == 0 {
///   for i in 0..buf_len(values) {
///     trace[i] = Atomic { op: <op>, buffer: state, index: 0, value: values[i] };
///   }
/// }
/// ```
///
/// Wrapped in `Node::Region` with `op_id` per the Region chain
/// invariant.
pub(crate) fn build_atomic_serial(
    op_id: &'static str,
    op: AtomicOp,
    values: &str,
    state: &str,
    trace: &str,
    n: u32,
) -> Program {
    let body = vec![crate::region::wrap_anonymous(
        op_id,
        vec![Node::if_then(
            Expr::eq(Expr::InvocationId { axis: 0 }, Expr::u32(0)),
            vec![Node::loop_for(
                "i",
                Expr::u32(0),
                Expr::buf_len(values),
                vec![
                    Node::let_bind(
                        "old",
                        Expr::Atomic {
                            op,
                            buffer: state.into(),
                            index: Box::new(Expr::u32(0)),
                            expected: None,
                            value: Box::new(Expr::load(values, Expr::var("i"))),
                        },
                    ),
                    Node::store(trace, Expr::var("i"), Expr::var("old")),
                ],
            )],
        )],
    )];
    Program::wrapped(
        vec![
            BufferDecl::storage(values, 0, BufferAccess::ReadOnly, DataType::U32).with_count(n),
            BufferDecl::read_write(state, 1, DataType::U32).with_count(1),
            BufferDecl::output(trace, 2, DataType::U32).with_count(n),
        ],
        [1, 1, 1],
        body,
    )
}

/// Shared builder for `atomic_compare_exchange_u32`. Walks two input
/// buffers (expected[i], desired[i]) against a 1-slot state.
pub(crate) fn build_atomic_compare_exchange(
    op_id: &'static str,
    expected: &str,
    desired: &str,
    state: &str,
    trace: &str,
    n: u32,
) -> Program {
    let body = vec![crate::region::wrap_anonymous(
        op_id,
        vec![Node::if_then(
            Expr::eq(Expr::InvocationId { axis: 0 }, Expr::u32(0)),
            vec![Node::loop_for(
                "i",
                Expr::u32(0),
                Expr::buf_len(expected),
                vec![
                    Node::let_bind(
                        "old",
                        Expr::Atomic {
                            op: AtomicOp::CompareExchange,
                            buffer: state.into(),
                            index: Box::new(Expr::u32(0)),
                            expected: Some(Box::new(Expr::load(expected, Expr::var("i")))),
                            value: Box::new(Expr::load(desired, Expr::var("i"))),
                        },
                    ),
                    Node::store(trace, Expr::var("i"), Expr::var("old")),
                ],
            )],
        )],
    )];
    Program::wrapped(
        vec![
            BufferDecl::storage(expected, 0, BufferAccess::ReadOnly, DataType::U32).with_count(n),
            BufferDecl::storage(desired, 1, BufferAccess::ReadOnly, DataType::U32).with_count(n),
            BufferDecl::read_write(state, 2, DataType::U32).with_count(1),
            BufferDecl::output(trace, 3, DataType::U32).with_count(n),
        ],
        [1, 1, 1],
        body,
    )
}

// Test helpers shared across atomic op unit tests.
#[cfg(test)]
pub(crate) mod testutil {
    use vyre_reference::value::Value;

    pub(crate) fn pack_u32(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|w| w.to_le_bytes()).collect()
    }

    pub(crate) fn run_serial(
        program: &vyre::ir::Program,
        values: &[u32],
        initial_state: u32,
    ) -> (u32, Vec<u32>) {
        let n = values.len().max(1);
        let inputs = vec![
            Value::Bytes(pack_u32(values).into()),
            Value::Bytes(pack_u32(&[initial_state]).into()),
            Value::Bytes(vec![0u8; n * 4].into()),
        ];
        let outputs = vyre_reference::reference_eval(program, &inputs).expect("atomic op must run");
        let state_bytes = outputs[0].to_bytes();
        let state = u32::from_le_bytes([
            state_bytes[0],
            state_bytes[1],
            state_bytes[2],
            state_bytes[3],
        ]);
        let trace_bytes = outputs[1].to_bytes();
        let trace = trace_bytes
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect::<Vec<_>>();
        (state, trace)
    }

    pub(crate) fn run_cas(
        program: &vyre::ir::Program,
        expected: &[u32],
        desired: &[u32],
        initial_state: u32,
    ) -> (u32, Vec<u32>) {
        let n = expected.len().max(1);
        let inputs = vec![
            Value::Bytes(pack_u32(expected).into()),
            Value::Bytes(pack_u32(desired).into()),
            Value::Bytes(pack_u32(&[initial_state]).into()),
            Value::Bytes(vec![0u8; n * 4].into()),
        ];
        let outputs = vyre_reference::reference_eval(program, &inputs).expect("cas op must run");
        let state_bytes = outputs[0].to_bytes();
        let state = u32::from_le_bytes([
            state_bytes[0],
            state_bytes[1],
            state_bytes[2],
            state_bytes[3],
        ]);
        let trace_bytes = outputs[1].to_bytes();
        let trace = trace_bytes
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect::<Vec<_>>();
        (state, trace)
    }
}
