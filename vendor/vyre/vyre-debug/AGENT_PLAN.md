# vyre-debug — agent build plan

You (the agent) are building a brand-new crate `vyre-debug` that gives Claude Code (CC) the ability to triage GPU kernel bugs by inspecting the IR statically — without dispatching to a real backend. The crate is a thin layer on top of `vyre-foundation`, `vyre-lower`, and `vyre-emit-naga`. Read those crates' public APIs (start at `lib.rs` of each) before writing code.

This plan is binding. Implement exactly what is here. If something here is impossible, stop and report — don't substitute. If you discover a bug in the underlying crates while doing this work, fix it in a separate PR; this crate must not work around bugs.

## Why this exists

CC is currently fixing a class of bugs where the WGSL emitted by `vyre-emit-naga` references SSA handles that are out of scope (naga's "no definition in scope for identifier" error). Tracking each one down by hand takes 30+ minutes per bug: pick a smaller input, dispatch via wgpu, parse the WGSL error, eyeball the descriptor structure, reason about which body emitted which handle. This crate replaces that workflow with one shell command:

```
$ cargo run -p vyre-debug --bin vyre-dbg find-dangling-refs --prog c11_extract_calls --num-tokens 4
DanglingRef {
    handle: 324,
    produced_in_body_path: [0, 0, 0, 1, 2],
    referenced_in_body_path: [0, 0, 0, 1],
    referencing_op_index: 47,
    referencing_op_kind: "Select",
}
1 dangling reference found.
```

Not optional: the crate must ship the binary `vyre-dbg`. CC will use it.

## Crate location and layout

Crate root: `vyre/vyre-debug/`

Add to the workspace `Cargo.toml` `members` list. Workspace root is `vyre/Cargo.toml`.

Files to create:

```
vyre/vyre-debug/
├── Cargo.toml
├── README.md                  (≤ 60 lines, what it does + 3 cli examples)
├── src/
│   ├── lib.rs                 (re-exports + module declarations only)
│   ├── descriptor_dump.rs     (fn dump_descriptor)
│   ├── descriptor_diff.rs     (fn diff_descriptors, fn bisect_rewrites)
│   ├── dangling.rs            (fn find_dangling_refs)
│   ├── carriers.rs            (fn find_uncarriered_assigns, fn carrier_summary)
│   ├── wgsl.rs                (fn dump_wgsl, fn dump_wgsl_with_lines)
│   ├── source_walker.rs       (fn walk_source_assigns — used by carriers.rs)
│   └── bin/
│       └── vyre_dbg.rs        (clap CLI; maps subcommands to fns above)
└── tests/
    ├── descriptor_dump_tests.rs
    ├── descriptor_diff_tests.rs
    ├── dangling_tests.rs
    ├── carriers_tests.rs
    ├── wgsl_tests.rs
    └── cli_tests.rs           (uses assert_cmd to invoke vyre-dbg)
```

`Cargo.toml` deps:

```toml
[package]
name = "vyre-debug"
version = "0.6.0"
edition = "2021"

[lib]

[[bin]]
name = "vyre-dbg"
path = "src/bin/vyre_dbg.rs"

[dependencies]
vyre = { path = "../vyre-core" }
vyre-foundation = { path = "../vyre-foundation" }
vyre-lower = { path = "../vyre-lower" }
vyre-emit-naga = { path = "../vyre-emit-naga" }
naga = { version = "=25.0.1", features = ["wgsl-out"] }
clap = { version = "4", features = ["derive"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"

[dev-dependencies]
assert_cmd = "2"
predicates = "3"
```

Lib boundary contract: every public `fn` listed below must be `pub` from `lib.rs` (re-exported). The CLI never duplicates logic — it calls these functions.

## Public API surface (exact signatures)

Use these signatures verbatim. Don't add fields, don't change names.

```rust
// lib.rs

pub use descriptor_dump::{dump_descriptor, DescriptorDumpOptions, DescriptorDump};
pub use descriptor_diff::{diff_descriptors, DescriptorDiff, bisect_rewrites, RewriteBisectResult};
pub use dangling::{find_dangling_refs, DanglingRef};
pub use carriers::{find_uncarriered_assigns, UncarrieredAssign, carrier_summary, CarrierSummary};
pub use wgsl::{dump_wgsl, dump_wgsl_with_lines, WgslDump};
```

### `dump_descriptor`

```rust
pub struct DescriptorDumpOptions {
    /// Include literal pool contents per body. Default: true.
    pub show_literals: bool,
    /// Include `result` ids next to ops. Default: true.
    pub show_result_ids: bool,
    /// Truncate ops per body to this count. Default: usize::MAX.
    pub max_ops_per_body: usize,
}

pub struct DescriptorDump {
    /// Multi-line pretty-printed text, ready to print.
    pub text: String,
    /// Body path → op count. Lets callers spot huge bodies.
    pub op_counts_by_path: std::collections::BTreeMap<Vec<usize>, usize>,
}

pub fn dump_descriptor(
    desc: &vyre_lower::KernelDescriptor,
    options: &DescriptorDumpOptions,
) -> DescriptorDump;
```

Format spec for `text`:

```
KernelDescriptor id=<id_first_8_hex>
bindings:
  slot=0 name=<name> count=Some(<n>) access=ReadOnly mc=Global
  slot=1 ...
dispatch: workgroup_size=[64, 1, 1]
body[]:
  [0] Region(vyre.program.root) ops=[0]
    body[0,0]:
      [0] Literal ops=[0] result=Some(0)
      [1] LoopCarrier(cursor) ops=[0] result=Some(8)
      ...
      [12] StructuredIfThen ops=[10, 0]
        body[0,0,12,0]:
          [0] BinOpKind(Add) ops=[5, 8] result=Some(34)
          ...
literals:
  body[]:    []
  body[0,0]: [U32(0), U32(8), U32(1)]
  ...
```

Indent two spaces per nesting level. Body path is a `Vec<usize>` of child indices; `[]` means the root body, `[0,0]` means root's child[0]'s child[0].

### `find_dangling_refs`

```rust
pub struct DanglingRef {
    /// SSA result id (from the descriptor's per-body id space).
    pub ref_id: u32,
    /// Body path where the id was produced.
    pub produced_in_body_path: Vec<usize>,
    /// `body.ops` index of the producing op.
    pub producing_op_index: usize,
    /// Producing op's `KernelOpKind` rendered with `{:?}`.
    pub producing_op_kind: String,
    /// Body path of the body that references the id.
    pub referenced_in_body_path: Vec<usize>,
    /// `body.ops` index of the referencing op.
    pub referencing_op_index: usize,
    /// Referencing op's `KernelOpKind` rendered with `{:?}`.
    pub referencing_op_kind: String,
    /// Operand position within the referencing op.
    pub operand_position: usize,
}

/// Walk the descriptor body tree. For every op operand classified as
/// `OperandClass::ResultRef` (use `vyre_lower::verify::classify_operand`
/// — make it `pub` if it isn't already; that's a one-line change to
/// vyre-lower; do that change in the same PR), check whether the
/// operand id is produced in an ancestor body OR the same body OR a
/// completed sibling child body's results that are visible through the
/// inherited-results scope rules used by `vyre_lower::verify`. Return
/// every operand that fails that rule.
///
/// Implementation tip: this is a re-statement of vyre-lower's
/// `verify_body` `DanglingResultRef` check. Reuse the same scope
/// machinery (`inherited_results`, `produced_so_far`,
/// `completed_child_results`) so this tool's verdict matches the
/// verifier's verdict exactly. Add a `pub use verify::*` re-export in
/// vyre-lower if needed.
///
/// Returns ALL dangling refs, not just the first. Callers want the full
/// list to triage in batch.
pub fn find_dangling_refs(
    desc: &vyre_lower::KernelDescriptor,
) -> Vec<DanglingRef>;
```

### `find_uncarriered_assigns`

```rust
pub struct UncarrieredAssign {
    /// Source-level variable name being assigned.
    pub name: String,
    /// Path through the source IR `Node` tree to the enclosing
    /// `Node::Loop`. Each entry is "Loop(var)" / "If" / "Region(name)" /
    /// "Block" / "IfElse-then" / "IfElse-else".
    pub loop_path: Vec<String>,
    /// Whether the descriptor produced by lowering contains a matching
    /// `KernelOpKind::LoopCarrier { name: <this name> }` op inside the
    /// loop's child body. False = lowering forgot to carrier this var.
    pub has_carrier_op: bool,
    /// Whether the descriptor contains a matching `LoopCarrierFinal`
    /// op in the loop's parent body. False = post-loop reads will see
    /// the pre-loop value, not the accumulated one.
    pub has_final_op: bool,
}

/// Walk the source `Program` node tree. For every `Node::Loop`, scan
/// its body for `Node::Assign { name, .. }`. For each such name, check
/// whether `name` exists in the loop's incoming source-level scope (any
/// ancestor `Node::Let { name }` or `Node::Assign { name }` reachable
/// without crossing another `Node::Loop`). For every reassigned name
/// that IS in incoming scope, look up the lowered descriptor for the
/// matching `LoopCarrier` / `LoopCarrierFinal` ops. Return all entries
/// where either op is missing.
///
/// This is the static counterpart to the live runtime debug. Use it
/// when a kernel runs but produces stale values — usually a missing
/// carrier.
pub fn find_uncarriered_assigns(
    program: &vyre::ir::Program,
    desc: &vyre_lower::KernelDescriptor,
) -> Vec<UncarrieredAssign>;
```

### `carrier_summary`

```rust
pub struct CarrierSummary {
    /// Carrier name → count of `LoopCarrier` ops with that name.
    pub carrier_reads: std::collections::BTreeMap<String, usize>,
    /// Carrier name → count of `LoopCarrierEnd` ops.
    pub carrier_writes: std::collections::BTreeMap<String, usize>,
    /// Carrier name → count of `LoopCarrierFinal` ops.
    pub carrier_finals: std::collections::BTreeMap<String, usize>,
    /// Function-scope locals named `vyre_named_carry_<name>` after
    /// `vyre_emit_naga::emit`.
    pub function_locals: Vec<String>,
}

pub fn carrier_summary(
    desc: &vyre_lower::KernelDescriptor,
) -> CarrierSummary;
```

The `function_locals` field requires running `vyre_emit_naga::emit(desc)` and walking the resulting `naga::Module`'s entry-point function locals.

### `dump_wgsl`

```rust
pub struct WgslDump {
    pub text: String,
    /// Map from source-level variable name (best-effort from emit-naga
    /// local naming) to the WGSL line it first appears on.
    pub variable_lines: std::collections::BTreeMap<String, usize>,
}

/// Lower the Program through `vyre_lower::lower_for_emit`, emit through
/// `vyre_emit_naga::emit`, then serialize to WGSL via `naga::back::wgsl`.
/// Returns the WGSL text. Fails (returns Err) if any of those steps
/// fail — callers want to know exactly where the pipeline broke.
pub fn dump_wgsl(program: &vyre::ir::Program) -> Result<WgslDump, String>;

/// Same as `dump_wgsl` but the returned text is line-numbered (1-based,
/// 5-char width, " | " separator) so error messages quoting WGSL line
/// numbers can be dereferenced quickly.
pub fn dump_wgsl_with_lines(program: &vyre::ir::Program) -> Result<WgslDump, String>;
```

### `diff_descriptors` and `bisect_rewrites`

```rust
pub struct DescriptorDiff {
    /// Bindings that exist in `before` but not `after` (slot id only).
    pub bindings_dropped: Vec<u32>,
    /// Bindings that exist in `after` but not `before`.
    pub bindings_added: Vec<u32>,
    /// Op-count delta per body path. Positive = ops added, negative =
    /// ops removed.
    pub op_count_delta: std::collections::BTreeMap<Vec<usize>, i64>,
    /// Top-level body shape changed (different number of root ops or
    /// different root op kinds in the same position).
    pub root_shape_changed: bool,
}

pub fn diff_descriptors(
    before: &vyre_lower::KernelDescriptor,
    after: &vyre_lower::KernelDescriptor,
) -> DescriptorDiff;

pub struct RewriteBisectResult {
    /// Name of the first rewrite that made `verify` fail (if any).
    pub first_failing_rewrite: Option<String>,
    /// `verify` errors after that rewrite, rendered with `{:?}`.
    pub verify_errors: Vec<String>,
    /// Per-rewrite delta: name + DescriptorDiff vs the previous step.
    pub rewrite_history: Vec<(String, DescriptorDiff)>,
}

/// Run vyre-lower's `lower(program)`, then apply each rewrite from the
/// canonical `run_all_once` sequence (strength_reduce, shared_mem_promote,
/// bank_conflict_pad, const_buffer_promote, descriptor_const_fold,
/// identity_elim, branch_collapse, loop_unroll, licm, load_forwarding,
/// descriptor_dce#1, dead_store, descriptor_dce#2, canonicalize,
/// descriptor_cse, drop_unused_bindings, drop_unused_literals,
/// drop_unused_child_bodies) ONE AT A TIME, calling `verify` after each.
/// Stop at the first verify failure. Always populate `rewrite_history`
/// so callers see the diff sequence even on success.
pub fn bisect_rewrites(
    program: &vyre::ir::Program,
) -> Result<RewriteBisectResult, String>;
```

Implementation note: vyre-lower's `rewrites::run_all_once` is one big function. You'll need to either refactor it to be addressable rewrite-by-rewrite (preferred) or call each public rewrite function in the same order it does. The names above must match the strings used in `rewrite_history`.

If `vyre-lower::rewrites` doesn't already publicly expose every individual rewrite as `pub fn`, do a one-line `pub use` per rewrite in `vyre-lower/src/rewrites/mod.rs`. Don't change semantics.

## CLI binary (`vyre-dbg`)

clap derive subcommands:

```
vyre-dbg dump-descriptor   --prog <NAME>  [--num-tokens N]
vyre-dbg dump-wgsl         --prog <NAME>  [--num-tokens N]  [--lines]
vyre-dbg find-dangling     --prog <NAME>  [--num-tokens N]  [--json]
vyre-dbg find-uncarriered  --prog <NAME>  [--num-tokens N]  [--json]
vyre-dbg carrier-summary   --prog <NAME>  [--num-tokens N]  [--json]
vyre-dbg bisect-rewrites   --prog <NAME>  [--num-tokens N]
vyre-dbg diff-descriptors  --prog-a <NAME> --prog-b <NAME>
```

`--prog NAME` selects from a hardcoded fixture registry. Build the registry as a `match name { ... }` returning `vyre::ir::Program`. Required entries (you must wire all of these):

| name                      | builder                                                                                              |
|---------------------------|------------------------------------------------------------------------------------------------------|
| `c11_lexer`               | `vyre_libs::parsing::c::lex::lexer::c11_lexer("hs", "tt", "ts", "tl", "tc", num_tokens)`             |
| `c11_extract_calls`       | `vyre_libs::parsing::c::parse::structure::c11_extract_calls("tt","pp","fns",Expr::u32(num_tokens),Expr::u32(num_tokens),"oc","cn")` |
| `c11_build_vast_nodes`    | `vyre_libs::parsing::c::parse::vast::c11_build_vast_nodes(...)`                                      |
| `bracket_match`           | `vyre_primitives::matching::bracket_match::bracket_match("k","s","mp",num_tokens, num_tokens)`       |
| `loop_carry_smoke`        | the same Program built in `vyre-frontend-c/tests/loop_carry_smoke.rs` (factor that out into a public helper if needed; the tests still need to use it) |

Add `vyre-libs` and `vyre-primitives` as deps of `vyre-debug` (with the `c-parser` feature on `vyre-libs`).

`--json` flag: serialize the result struct via `serde_json::to_string_pretty`. Default output: human-readable plain text.

CLI exit codes:
- 0: tool ran AND found nothing wrong (no dangling refs, no uncarriered assigns, etc.).
- 1: tool ran AND found problems. Print the count to stderr, the details to stdout.
- 2: tool failed to run (lower/emit error).
- 3: invalid CLI arguments.

## Tests (mandatory; CI must run all of these)

Each test below is a real `#[test]` fn. Naming: `mod_test_name`. Use the public API only — no `pub(crate)` shortcuts.

### `tests/descriptor_dump_tests.rs` (4 tests)

1. `dump_descriptor_renders_minimal_program` — a one-Store program lowers, dumps, the text contains "KernelDescriptor", "bindings:", "body[]:", and the result id of the literal.
2. `dump_descriptor_op_counts_match_walk` — for a program with one outer loop and a nested if, the `op_counts_by_path` map's values sum to the descriptor's total op count (run a manual walk, compare).
3. `dump_descriptor_truncates_when_max_ops_per_body_set` — set `max_ops_per_body = 2`, dump a body with 5 ops, assert the rendered text shows "... <3 more ops>" and that body's three additional ops are not rendered (still counted in `op_counts_by_path`).
4. `dump_descriptor_show_literals_false_omits_literals_section` — set `show_literals = false`, assert "literals:" header is absent.

### `tests/dangling_tests.rs` (5 tests)

1. `find_dangling_refs_clean_program_returns_empty` — lower the loop_carry_smoke program, run `find_dangling_refs`, assert empty Vec.
2. `find_dangling_refs_handcrafted_descriptor_finds_known_break` — manually construct a `KernelDescriptor` where a parent-body op references an SSA id only produced inside a child body (no carrier/control-flow operand). Assert exactly one DanglingRef with the expected handle, body paths, and op kinds.
3. `find_dangling_refs_matches_verifier_verdict` — for that same descriptor, assert that `vyre_lower::verify::verify(&desc)` returns at least one `VerifyErrorKind::DanglingResultRef` with `ref_id` matching one of `find_dangling_refs`'s entries. The two must agree on every detected break (set equality on ref ids).
4. `find_dangling_refs_handles_deep_nesting_six_levels` — construct a 6-level nested body where the dangling ref is at level 5 and the producer is at level 6. Assert detected.
5. `find_dangling_refs_does_not_flag_completed_child_results` — a program where op-after-StructuredIfThen-in-parent references an id produced inside the if's child body. Verifier accepts this (it's `completed_child_results`). Tool must also accept it. Assert empty.

### `tests/carriers_tests.rs` (4 tests)

1. `find_uncarriered_assigns_smoke_program_returns_empty` — loop_carry_smoke lowers correctly with carriers; tool returns empty.
2. `find_uncarriered_assigns_flags_a_loop_with_no_carrier` — construct a Program where Node::Loop body has Node::Assign("x", ...) and "x" is bound by Node::let_bind in the outer scope, BUT manually strip the LoopCarrier op from the lowered descriptor (clone, mutate). Assert one UncarrieredAssign with `name="x"`, `has_carrier_op=false`.
3. `carrier_summary_counts_match_descriptor_walk` — for c11_lexer, run `carrier_summary`, then independently walk the descriptor and count `LoopCarrier`/`LoopCarrierEnd`/`LoopCarrierFinal` per name. Assert the maps are identical.
4. `carrier_summary_includes_function_locals` — for c11_lexer, assert `function_locals` contains at least `"vyre_named_carry_tok_idx"`.

### `tests/wgsl_tests.rs` (3 tests)

1. `dump_wgsl_minimal_program_returns_compute_entry` — single store, returned text contains `@compute @workgroup_size` and `fn main`.
2. `dump_wgsl_with_lines_prefixes_each_line` — same program, every non-empty line in `text` matches `^\s*\d+ \| `.
3. `dump_wgsl_propagates_naga_validation_failure` — manually construct a Program that lowers but emits invalid naga (e.g. a Store with mismatched type that bypasses my coercion — pick something concrete, comment why it fails). Assert `Err` with a message containing "naga".

### `tests/descriptor_diff_tests.rs` (3 tests)

1. `diff_descriptors_identical_returns_empty_diff` — same program twice through `lower_for_emit`, diff should be all-empty + `root_shape_changed=false`.
2. `diff_descriptors_after_descriptor_dce_removes_ops` — apply `descriptor_dce` to a descriptor with dead ops; diff should show negative `op_count_delta` for affected body paths.
3. `bisect_rewrites_clean_program_no_failure` — loop_carry_smoke; assert `first_failing_rewrite` is None and `rewrite_history.len()` == 18 (the full canonical sequence).

### `tests/cli_tests.rs` (3 tests)

Use `assert_cmd::Command::cargo_bin("vyre-dbg")`.

1. `cli_find_dangling_clean_program_exits_0` — invoke `vyre-dbg find-dangling --prog loop_carry_smoke --num-tokens 8`, assert exit code 0, stdout contains "0 dangling".
2. `cli_find_dangling_with_json_emits_array` — same with `--json`, parse stdout as `serde_json::Value`, assert `is_array()`.
3. `cli_invalid_prog_name_exits_3` — `vyre-dbg dump-descriptor --prog nope`, exit code 3, stderr contains "unknown program".

Total: **22 tests**. All must pass.

## Done criteria — verify ALL of these before declaring done

1. `cargo check -p vyre-debug` → 0 warnings, 0 errors.
2. `cargo clippy -p vyre-debug --all-targets -- -D warnings` → 0 warnings.
3. `cargo test -p vyre-debug --lib --tests` → all 22 tests pass.
4. `cargo build -p vyre-debug --bin vyre-dbg --release` → produces a binary.
5. **End-to-end smoke (run this and paste the full output into the PR):**
   ```
   ./target/release/vyre-dbg find-dangling --prog c11_extract_calls --num-tokens 4
   ```
   Expected: exit code 1 (the c11_extract_calls bug CC is currently chasing — at least one dangling ref). The stdout must include `produced_in_body_path` and `referenced_in_body_path` for every flagged ref.
6. `cargo test -p vyre-lower --lib && cargo test -p vyre-emit-naga --lib` → still 100% pass (no regressions from your one-line `pub use` exposures).
7. README.md exists, ≤ 60 lines, includes the 3 cli examples shown above.
8. Workspace `Cargo.toml` includes `vyre-debug` in `members`.

## Things you must NOT do

- Do not add a "fix" mode that auto-rewrites IR. This crate is read-only against vyre-lower / emit-naga.
- Do not add a wgpu dispatch mode. Static-only. Runtime tracing is a future PR.
- Do not invent your own descriptor-walk recursion if vyre-lower already exposes one. Reuse `verify::verify_body`-style walks where possible.
- Do not add features that aren't in this plan (no graphviz output, no IDE plugin, etc.). One thing at a time.
- Do not skip any of the 22 tests. If a test as specified is impossible to write because the API can't support it, that's a signal the API is wrong — STOP and report.
- Do not introduce any panics or `unwrap()` in library code. Use `Result<_, String>` for fallible paths.
- Do not bump any dependency versions that aren't already in vyre's `Cargo.lock`.

## How CC will use this once it's shipped

After your PR lands, CC will run, on every WGSL "no definition in scope" failure:

```
$ vyre-dbg find-dangling --prog <suspect> --num-tokens 4
```

And on every "kernel runs but returns wrong value" failure:

```
$ vyre-dbg find-uncarriered --prog <suspect> --num-tokens 4
$ vyre-dbg carrier-summary --prog <suspect>
```

That's the contract. Build to it.
