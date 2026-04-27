# Per-op Surface Contract

Closes #28 A.4 per-op surface complete.

Every registered op (Tier 2 intrinsic, Tier 2.5 primitive, Tier 3
dialect) exposes eight properties. Ops without all eight are WIP,
listed explicitly in `composition_discipline::every_op_has_test_fixtures_or_is_explicitly_exempt`
(and the WIP list shrinks every cycle).

## The eight properties

| Property | Purpose | Enforcement |
|---|---|---|
| **witness** | `test_inputs: fn() -> Vec<Vec<Vec<u8>>>` — a canonical input corpus. | CI test `every_op_has_test_fixtures_or_is_explicitly_exempt` (tightened by CONFORM M7 to require both test_inputs AND expected_output, not just either). |
| **ref** | `expected_output: fn() -> Vec<Vec<Vec<u8>>>` — the CPU reference computed by vyre-reference. | Same CI test. |
| **dispatch** | `build: fn() -> Program` — the op body itself, exposed for dispatch. | Every `inventory::submit!` call sets `build`. |
| **emit** | Naga lowering path. For Tier-2 ops, a dedicated arm in `vyre-driver-wgpu/src/lowering/naga_emit/`. For Tier-3 ops, the chain through Region + intrinsics proves out automatically. | CI runs `cargo test -p vyre-driver-wgpu --tests` (includes `naga_deeper_regressions.rs`). |
| **cert** | Certificate signed by `vyre-conform-runner prove`. | CI mints a fresh cert every release; CONFORM C2 seeds keys with OsRng so a certification run is non-reproducible by design. |
| **parity** | CPU↔GPU parity lens. `compare_output_buffers` checks bytewise or within-ULP. | `cat_a_gpu_differential.rs` + `lens_gpu_parity.rs`. |
| **ULP** | F32 transcendental ops declare a per-op ULP budget; `fp_parity::f32_ulp_tolerance` consults the registry (M5 tracked). | `fp_parity.rs` gate. |
| **fuzz/proptest** | Proptest generators per input type + a gap test checking the "arbitrary input in, never panic" invariant. | Per-crate `proptest!` blocks + nightly structural fuzz. |

## Worked example — `vyre-primitives::bitset::and::bitset_and`

- **witness:** `bitset_and_test_inputs()` emits three 256-bit input
  pairs (zero × zero, all × zero, alternating).
- **ref:** `bitset_and_expected` computes the component-wise AND on
  host for each input.
- **dispatch:** `bitset_and()` is the `fn() -> Program` builder.
- **emit:** bitset_and composes Tier 2.5 ops that emit directly;
  the Region chain in `print-composition bitset_and` terminates at
  `vyre-intrinsics::hardware::popcount_u32` via `bitset::popcount`.
- **cert:** included in every `prove` run (F-C2 close-out).
- **parity:** `cat_a_conform::bitset_and_cpu_gpu_agrees` in
  `vyre-driver-wgpu`.
- **ULP:** N/A (integer op).
- **fuzz/proptest:** `bitset::proptest::and_commutative` (landed).

## Open / WIP ops

The inventory hole: ops where one or more of the eight are absent
land in `wip_exemptions` in `composition_discipline.rs`. The list
today:

- `vyre-libs::parsing::c_lexer` + `c_keyword` — test fixtures land
  with the C11 compliance pass.
- `vyre-libs::security::*` — bodies are inert pending the
  `vyre-primitives-graph` Tier-2.5 migration; CPU reference +
  expected_output land when the underlying graph primitives move
  into `vyre-primitives` and these compositions wire through.

WIP_EXEMPTIONS shrinks every cycle. A growing list is a regression.
