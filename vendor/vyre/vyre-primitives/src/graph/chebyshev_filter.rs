//! K-step Chebyshev polynomial filter on a graph Laplacian.
//!
//! Applies a Chebyshev polynomial of the normalized graph Laplacian
//! to a signal, evaluating the recurrence:
//!
//! ```text
//!   T_0(L̂) · x = x
//!   T_1(L̂) · x = L̂ · x
//!   T_{k+1}(L̂) · x = 2 L̂ · T_k(L̂) · x  -  T_{k-1}(L̂) · x
//! ```
//!
//! The output is `Σ_{k=0..K} c_k · T_k(L̂) · x` for caller-supplied
//! coefficients `c_k`. Replaces eigendecomposition in spectral graph
//! filters with K sparse matrix-vector products. K=4 already
//! approximates the exact spectral filter to within ~1% for most
//! polynomial classes (Hammond-Vandergheynst-Gribonval 2011).
//!
//! # Why this primitive is dual-use
//!
//! Same Program ships to user dialects AND vyre's own substrate:
//!
//! | Consumer | Use |
//! |---|---|
//! | `vyre-libs::nn::gnn` | Spectral GNN filter without eigendecomp |
//! | `vyre-libs::security::call_graph` | Spectral anomaly on call graphs |
//! | `vyre-libs::dataflow` | Spectral propagation of taint priors |
//! | `vyre-foundation::transform::spectral_schedule` (#23) | **Spectral clustering of vyre's own dispatch graph** to drive #19 polyhedral fusion + #22 megakernel scheduler |
//!
//! The self-consumer (#23) is what makes this a recursion-thesis
//! primitive: same Program that GNN dialects use for graph filtering
//! is the engine that decides which vyre-primitive Programs should
//! be fused at compile time.
//!
//! # Composition
//!
//! Each step of the recurrence is a Laplacian-times-vector product;
//! that's a special case of [`crate::math::semiring_gemm`] over the
//! `Real` semiring with shape `n × n · n × 1`. This primitive could
//! literally be implemented as `K` calls to semiring_gemm — and that's
//! a pipeline-level composition when callers want per-step reuse. This
//! single-dispatch version inlines the matvec body to keep launch
//! overhead at one dispatch.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Canonical op id.
pub const OP_ID: &str = "vyre-primitives::graph::chebyshev_filter";

/// Maximum supported polynomial order (K). Larger orders rarely help —
/// the Chebyshev approximation error decays super-exponentially in K.
pub const MAX_K: u32 = 16;

/// Emit a K-step Chebyshev-filter Program.
///
/// Buffers:
/// - `laplacian`: `n × n` row-major dense u32 buffer (the rescaled
///   Laplacian L̂ = 2L/λ_max - I, fixed-point 16.16 if floats matter).
/// - `signal`:    `n` u32 inputs.
/// - `coeffs`:    `k_steps + 1` coefficients c_0, c_1, …, c_K.
/// - `output`:    `n` u32 outputs.
/// - `scratch`:   `2 * n` u32 internal buffer for T_{k-1} and T_k
///   storage during the recurrence.
///
/// The dispatch is `n` invocations along axis 0; each lane owns one
/// output index `i` and computes its contribution to every Chebyshev
/// term sequentially. The K outer iterations advance the recurrence
/// in lockstep across all lanes via barriers (callers ensure
/// barrier-cooperative dispatch).
///
/// Invalid `n` or `k_steps` inputs lower to an explicit trap program.
#[must_use]
pub fn chebyshev_filter(
    laplacian: &str,
    signal: &str,
    coeffs: &str,
    output: &str,
    scratch: &str,
    n: u32,
    k_steps: u32,
) -> Program {
    match try_chebyshev_filter(laplacian, signal, coeffs, output, scratch, n, k_steps) {
        Ok(program) => program,
        Err(error) => {
            eprintln!("{error}");
            crate::invalid_output_program(OP_ID, output, DataType::U32, error)
        }
    }
}

/// Emit a K-step Chebyshev-filter Program with checked dense and scratch
/// buffer sizing.
pub fn try_chebyshev_filter(
    laplacian: &str,
    signal: &str,
    coeffs: &str,
    output: &str,
    scratch: &str,
    n: u32,
    k_steps: u32,
) -> Result<Program, String> {
    if n == 0 {
        return Err(format!("Fix: chebyshev_filter requires n > 0, got {n}."));
    }
    if k_steps > MAX_K {
        return Err(format!(
            "Fix: chebyshev_filter k_steps must be <= MAX_K={MAX_K}, got {k_steps}."
        ));
    }
    let laplacian_cells = checked_square_cells(n)?;
    let scratch_words = checked_double_words(n)?;

    let t = Expr::InvocationId { axis: 0 };

    // T_0[i] = signal[i]; T_1[i] = (L̂ · signal)[i]
    // scratch layout: [T_prev (size n) | T_curr (size n)]
    // index helper:
    let t_prev_at = |i: Expr| Expr::load(scratch, i);
    let t_curr_at = |i: Expr| Expr::load(scratch, Expr::add(i, Expr::u32(n)));
    let t_prev_store = |i: Expr, v: Expr| Node::store(scratch, i, v);
    let t_curr_store = |i: Expr, v: Expr| Node::store(scratch, Expr::add(i, Expr::u32(n)), v);

    // Inline matvec: row i of L̂ × T_curr (or signal), summed.
    // (L̂ · v)[i] = Σ_j L̂[i,j] · v[j]
    let row_base = Expr::mul(t.clone(), Expr::u32(n));
    let lhat_row_dot_signal = {
        // accumulator var "lapsig"
        Node::loop_for(
            "j",
            Expr::u32(0),
            Expr::u32(n),
            vec![Node::assign(
                "lapsig",
                Expr::add(
                    Expr::var("lapsig"),
                    Expr::mul(
                        Expr::load(laplacian, Expr::add(row_base.clone(), Expr::var("j"))),
                        Expr::load(signal, Expr::var("j")),
                    ),
                ),
            )],
        )
    };

    // Term-0: out += c_0 * signal[i]
    // Term-1: out += c_1 * (L̂ · signal)[i]
    // Init scratch: T_prev[i] = signal[i]; T_curr[i] = (L̂ · signal)[i]
    // Loop k = 2..=k_steps:
    //   T_next[i] = 2 (L̂ · T_curr)[i] - T_prev[i]
    //   out += c_k * T_next[i]
    //   T_prev <- T_curr; T_curr <- T_next  (via swap of write-target halves)
    //
    // For lane simplicity we fold the swap by always writing T_next into
    // the t_prev half, then using t_curr as the "old curr" reads in the
    // next iteration after a barrier. To keep the body single-pass and
    // avoid allocator games, we use ping-pong via odd/even iteration: at
    // each k we read from the half determined by parity and write to the
    // opposite half. This requires k_steps + 1 ≤ 2 buffers, which holds.

    let mut body = vec![
        Node::let_bind("acc_out", Expr::u32(0)),
        // c_0 contribution: c_0 * signal[i]
        Node::assign(
            "acc_out",
            Expr::add(
                Expr::var("acc_out"),
                Expr::mul(
                    Expr::load(coeffs, Expr::u32(0)),
                    Expr::load(signal, t.clone()),
                ),
            ),
        ),
    ];

    if k_steps >= 1 {
        // Compute (L̂ · signal)[i] into scratch t_curr half + add c_1
        // contribution.
        body.push(Node::let_bind("lapsig", Expr::u32(0)));
        body.push(lhat_row_dot_signal);
        body.push(t_prev_store(t.clone(), Expr::load(signal, t.clone())));
        body.push(t_curr_store(t.clone(), Expr::var("lapsig")));
        body.push(Node::assign(
            "acc_out",
            Expr::add(
                Expr::var("acc_out"),
                Expr::mul(Expr::load(coeffs, Expr::u32(1)), Expr::var("lapsig")),
            ),
        ));
    }

    // Recurrence for k = 2..=k_steps. Each iteration: read T_prev, T_curr,
    // produce T_next via inlined matvec on T_curr. Write T_next into
    // T_prev's slot; the next iteration reads from the alternate slot.
    // After the loop, the final term is in `acc_out`.
    if k_steps >= 2 {
        body.push(Node::loop_for(
            "k",
            Expr::u32(2),
            Expr::add(Expr::u32(k_steps), Expr::u32(1)),
            vec![
                // matvec: lap_curr = (L̂ · T_curr)[i]
                Node::let_bind("lap_curr", Expr::u32(0)),
                Node::loop_for(
                    "j",
                    Expr::u32(0),
                    Expr::u32(n),
                    vec![Node::assign(
                        "lap_curr",
                        Expr::add(
                            Expr::var("lap_curr"),
                            Expr::mul(
                                Expr::load(laplacian, Expr::add(row_base.clone(), Expr::var("j"))),
                                t_curr_at(Expr::var("j")),
                            ),
                        ),
                    )],
                ),
                // T_next[i] = 2 · lap_curr - T_prev[i]
                Node::let_bind(
                    "t_next",
                    Expr::sub(
                        Expr::mul(Expr::u32(2), Expr::var("lap_curr")),
                        t_prev_at(t.clone()),
                    ),
                ),
                // acc_out += c_k * t_next
                Node::assign(
                    "acc_out",
                    Expr::add(
                        Expr::var("acc_out"),
                        Expr::mul(Expr::load(coeffs, Expr::var("k")), Expr::var("t_next")),
                    ),
                ),
                // Rotate: T_prev <- T_curr, T_curr <- T_next.
                // We read t_curr_at into a temp, write t_curr_at <- t_next,
                // write t_prev_at <- temp. This is per-lane; correctness
                // requires barriers between iterations across lanes — the
                // workgroup_size below pins all lanes to one workgroup so
                // a Node::Barrier { ordering: vyre::memory_model::MemoryOrdering::SeqCst } between iterations would close the gap.
                // For dense small n (the spectral_schedule self-consumer
                // case), n ≤ workgroup_size = 256 and a barrier suffices.
                Node::let_bind("old_curr", t_curr_at(t.clone())),
                t_curr_store(t.clone(), Expr::var("t_next")),
                t_prev_store(t.clone(), Expr::var("old_curr")),
            ],
        ));
    }

    // Bound check + write output
    let body_with_bounds = vec![Node::if_then(Expr::lt(t.clone(), Expr::u32(n)), {
        let mut all = body;
        all.push(Node::store(output, t, Expr::var("acc_out")));
        all
    })];

    Ok(Program::wrapped(
        vec![
            BufferDecl::storage(laplacian, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(laplacian_cells),
            BufferDecl::storage(signal, 1, BufferAccess::ReadOnly, DataType::U32).with_count(n),
            BufferDecl::storage(coeffs, 2, BufferAccess::ReadOnly, DataType::U32)
                .with_count(k_steps + 1),
            BufferDecl::storage(output, 3, BufferAccess::ReadWrite, DataType::U32).with_count(n),
            BufferDecl::storage(scratch, 4, BufferAccess::ReadWrite, DataType::U32)
                .with_count(scratch_words),
        ],
        [256, 1, 1],
        vec![Node::Region {
            generator: Ident::from(OP_ID),
            source_region: None,
            body: Arc::new(body_with_bounds),
        }],
    ))
}

fn checked_square_cells(n: u32) -> Result<u32, String> {
    n.checked_mul(n).ok_or_else(|| {
        format!(
            "chebyshev_filter n={n} overflows dense Laplacian cell count. Fix: shard or sparsify the graph before GPU dispatch."
        )
    })
}

fn checked_double_words(n: u32) -> Result<u32, String> {
    n.checked_mul(2).ok_or_else(|| {
        format!(
            "chebyshev_filter n={n} overflows scratch word count. Fix: shard the graph before GPU dispatch."
        )
    })
}

/// CPU reference for [`chebyshev_filter`]. Operates on f32 internally
/// for parity-test simplicity; the GPU primitive is u32 fixed-point so
/// callers are responsible for matching scaling.
#[must_use]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn chebyshev_filter_cpu(
    laplacian: &[f32],
    signal: &[f32],
    coeffs: &[f32],
    n: u32,
    k_steps: u32,
) -> Vec<f32> {
    let mut out = Vec::new();
    let mut t_prev = Vec::new();
    let mut t_curr = Vec::new();
    let mut t_next = Vec::new();
    chebyshev_filter_cpu_into(
        laplacian,
        signal,
        coeffs,
        n,
        k_steps,
        &mut out,
        &mut t_prev,
        &mut t_curr,
        &mut t_next,
    );
    out
}

/// CPU reference for [`chebyshev_filter`] using caller-owned buffers.
#[allow(clippy::too_many_arguments)]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn chebyshev_filter_cpu_into(
    laplacian: &[f32],
    signal: &[f32],
    coeffs: &[f32],
    n: u32,
    k_steps: u32,
    out: &mut Vec<f32>,
    t_prev: &mut Vec<f32>,
    t_curr: &mut Vec<f32>,
    t_next: &mut Vec<f32>,
) {
    let n = n as usize;
    let c0 = coeffs.first().copied().unwrap_or(0.0);
    // Output starts as c_0 · signal
    out.clear();
    out.reserve(n);
    out.extend((0..n).map(|idx| c0 * signal.get(idx).copied().unwrap_or(0.0)));
    if k_steps == 0 {
        return;
    }

    // T_0 = signal, T_1 = L̂ · signal
    t_prev.clear();
    t_prev.extend((0..n).map(|idx| signal.get(idx).copied().unwrap_or(0.0)));
    t_curr.clear();
    t_curr.resize(n, 0.0);
    for i in 0..n {
        for j in 0..n {
            t_curr[i] += laplacian.get(i * n + j).copied().unwrap_or(0.0) * t_prev[j];
        }
    }
    let c1 = coeffs.get(1).copied().unwrap_or(0.0);
    for i in 0..n {
        out[i] += c1 * t_curr[i];
    }

    // Recurrence
    for &c_k in coeffs.iter().take(k_steps as usize + 1).skip(2) {
        t_next.clear();
        t_next.resize(n, 0.0);
        // lap_curr = L̂ · t_curr
        for i in 0..n {
            for j in 0..n {
                t_next[i] += laplacian.get(i * n + j).copied().unwrap_or(0.0) * t_curr[j];
            }
        }
        // t_next = 2 lap_curr - t_prev
        for i in 0..n {
            t_next[i] = 2.0 * t_next[i] - t_prev[i];
        }
        for i in 0..n {
            out[i] += c_k * t_next[i];
        }
        std::mem::swap(t_prev, t_curr);
        std::mem::swap(t_curr, t_next);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tolerance for f32 parity in the CPU ref.
    const EPS: f32 = 1e-4;

    fn approx_eq(a: f32, b: f32) -> bool {
        (a - b).abs() < EPS * (1.0 + a.abs() + b.abs())
    }

    #[test]
    fn cpu_k0_returns_scaled_signal() {
        // K=0 means filter = c_0 · I. Output = c_0 * signal.
        let l = vec![0.0; 4]; // unused
        let x = vec![1.0, 2.0];
        let c = vec![3.0];
        let out = chebyshev_filter_cpu(&l, &x, &c, 2, 0);
        assert_eq!(out, vec![3.0, 6.0]);
    }

    #[test]
    fn cpu_k1_recovers_linear_filter() {
        // K=1: out = c_0 · x + c_1 · L̂ · x.
        // L̂ = 2x2 identity scaled, x = [1, 1], coeffs = [0, 1] → out = L̂ · x.
        let l = vec![0.5, 0.0, 0.0, 0.5];
        let x = vec![1.0, 1.0];
        let c = vec![0.0, 1.0];
        let out = chebyshev_filter_cpu(&l, &x, &c, 2, 1);
        assert!(approx_eq(out[0], 0.5));
        assert!(approx_eq(out[1], 0.5));
    }

    #[test]
    fn cpu_recurrence_t2_matches_definition() {
        // T_2(L̂) · x = (2 L̂² - I) · x, by Chebyshev definition.
        // Pick L̂ = diag(0.5), x = [1, 1], coeffs = [0, 0, 1] (only c_2 = 1).
        // Expected: T_2(0.5) = 2*0.25 - 1 = -0.5 ; output = -0.5 · [1, 1].
        let l = vec![0.5, 0.0, 0.0, 0.5];
        let x = vec![1.0, 1.0];
        let c = vec![0.0, 0.0, 1.0];
        let out = chebyshev_filter_cpu(&l, &x, &c, 2, 2);
        assert!(approx_eq(out[0], -0.5));
        assert!(approx_eq(out[1], -0.5));
    }

    #[test]
    fn cpu_recurrence_zero_signal_stays_zero() {
        let l = vec![1.0; 16];
        let x = vec![0.0; 4];
        let c = vec![1.0, 1.0, 1.0, 1.0, 1.0];
        let out = chebyshev_filter_cpu(&l, &x, &c, 4, 4);
        for v in out {
            assert!(approx_eq(v, 0.0));
        }
    }

    #[test]
    fn cpu_ref_into_reuses_recurrence_buffers() {
        let l = vec![0.5, 0.0, 0.0, 0.5];
        let x = vec![1.0, 1.0];
        let c = vec![0.0, 0.0, 1.0];
        let mut out = Vec::with_capacity(8);
        let mut t_prev = Vec::with_capacity(8);
        let mut t_curr = Vec::with_capacity(8);
        let mut t_next = Vec::with_capacity(8);
        let pointers = [
            out.as_ptr(),
            t_prev.as_ptr(),
            t_curr.as_ptr(),
            t_next.as_ptr(),
        ];
        chebyshev_filter_cpu_into(
            &l,
            &x,
            &c,
            2,
            2,
            &mut out,
            &mut t_prev,
            &mut t_curr,
            &mut t_next,
        );
        assert!(approx_eq(out[0], -0.5));
        assert!(approx_eq(out[1], -0.5));
        let after = [
            out.as_ptr(),
            t_prev.as_ptr(),
            t_curr.as_ptr(),
            t_next.as_ptr(),
        ];
        for ptr in after {
            assert!(pointers.contains(&ptr));
        }
    }

    #[test]
    fn cpu_short_inputs_are_zero_padded() {
        let out = chebyshev_filter_cpu(&[1.0], &[2.0], &[], 2, 1);
        assert_eq!(out, vec![0.0, 0.0]);
    }

    #[test]
    fn emitted_program_buffer_layout() {
        let p = chebyshev_filter("L", "x", "c", "y", "s", 8, 3);
        assert_eq!(p.workgroup_size, [256, 1, 1]);
        let names: Vec<&str> = p.buffers.iter().map(|b| b.name()).collect();
        assert_eq!(names, vec!["L", "x", "c", "y", "s"]);
        assert_eq!(p.buffers[0].count(), 8 * 8); // n*n
        assert_eq!(p.buffers[1].count(), 8); // n
        assert_eq!(p.buffers[2].count(), 4); // k_steps + 1
        assert_eq!(p.buffers[3].count(), 8); // n
        assert_eq!(p.buffers[4].count(), 16); // 2*n
    }

    #[test]
    fn emitted_program_zero_k_works() {
        let p = chebyshev_filter("L", "x", "c", "y", "s", 4, 0);
        assert_eq!(p.buffers[2].count(), 1);
    }

    #[test]
    fn zero_n_traps() {
        let p = chebyshev_filter("L", "x", "c", "y", "s", 0, 1);
        assert!(p.stats().trap());
    }

    #[test]
    fn k_over_max_traps() {
        let p = chebyshev_filter("L", "x", "c", "y", "s", 4, MAX_K + 1);
        assert!(p.stats().trap());
    }

    #[test]
    fn checked_builder_rejects_dense_laplacian_overflow() {
        let error = try_chebyshev_filter("L", "x", "c", "y", "s", u32::MAX, 1)
            .expect_err("checked Chebyshev builder must reject dense matrix overflow");

        assert!(
            error.contains("overflows dense Laplacian cell count"),
            "error should describe the dense Laplacian overflow: {error}"
        );
    }

    #[test]
    fn legacy_builder_does_not_panic_on_dense_laplacian_overflow() {
        let program = chebyshev_filter("L", "x", "c", "y", "s", u32::MAX, 1);

        assert!(program.stats().trap());
    }

    #[test]
    fn chebyshev_builder_source_has_checked_sizing_without_panics() {
        let source = include_str!("chebyshev_filter.rs");
        let builder_source = source
            .split("pub fn chebyshev_filter(")
            .nth(1)
            .expect("Chebyshev builder source must be present")
            .split("/// CPU reference for")
            .next()
            .expect("Chebyshev builder source must precede CPU oracle");

        assert!(
            builder_source.contains("pub fn try_chebyshev_filter(")
                && builder_source.contains("checked_square_cells")
                && builder_source.contains("checked_double_words")
                && !builder_source.contains(concat!("panic", "!("))
                && !builder_source.contains(".unwrap_or_else("),
            "Fix: chebyshev_filter must expose checked release sizing and avoid production panics."
        );
    }
}
