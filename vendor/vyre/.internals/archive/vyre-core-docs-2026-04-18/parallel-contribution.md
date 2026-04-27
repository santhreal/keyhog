# Parallel contribution — how 100 contributors add 100 ops in parallel without stepping on each other

This chapter covers Parallel contribution — how 100 contributors add 100 ops in parallel without stepping on each other in the vyre project.

## The promise

You and 99 other contributors are each adding a new op. You all push to main simultaneously. Your PRs all merge cleanly. No rebase hell. No "wait for the other PR to land." No coordinated releases. No release train. No central maintainer acting as a router for every change. No 3 AM Slack messages asking whether it is safe to merge.

This chapter explains how that promise holds from the contributor's perspective. It complements [zero-conflict.md](zero-conflict.md), which describes the architectural rules in the abstract, and [ARCHITECTURE.md](../../ARCHITECTURE.md), which describes the system-level design. This chapter is about what it actually feels like to contribute when the architecture has removed every reason to conflict with another human being.

The short version: your job is to add a leaf. One file. One item. One clear path. The system handles the rest.

## The file-per-responsibility rule

In vyre, one responsibility equals exactly one file. One op is one file. One gate is one file. One oracle is one file. One backend is one file. One TOML rule is one file. One trait implementation is one file. One helper function is one file. A file with two structs is a CI failure. An `impl` block with two methods is a CI failure. A helper function hidden at the bottom of a struct file is a CI failure.

If you add `primitive.math.gcd`, you create exactly one new leaf: `src/ops/primitive/math/gcd.rs`. That file contains the `OpSpec` declaration, the CPU reference kernel, and any op-specific algebraic laws. It does not contain a second op. It does not contain a shared helper. It does not contain a module declaration for its sibling. It does not import anything via `super` or wildcard. Every dependency is referenced by its full crate path. It is exactly one responsibility, fully self-contained.

If you add `primitive.hash.fnv1a32`, you create `src/ops/hash/fnv1a32.rs`. If you add a conformance gate, you drop a single file into `vyre-conform/src/enforce/gates/`. If you add an oracle, you drop a single file into `vyre-conform/src/oracles/`. If you add a backend, you implement `VyreBackend` in a single new module. If you add a TOML rule, you drop a single file into `conform/rules/`.

Every new contribution is a new leaf file. Adding never requires modifying an existing file elsewhere. You do not open a central enum. You do not append to a `match` statement. You do not edit `mod.rs`. You do not update a registry array. You do not touch `lib.rs`. You do not edit a `Cargo.toml` for a routine op addition. The file count grows, but the edit surface stays at exactly one file per contributor for routine additions.

This rule is the foundation of the zero-conflict property. Because every contribution is a file creation rather than a file modification, Git's three-way merge has nothing to conflict on. Two branches that each create a new file in the same directory merge trivially. The filesystem namespace is the only coordination surface, and filenames are cheap.

The rule also makes the codebase easier to navigate. The filename tells you exactly what the file contains. There is no scrolling through a thousand-line god file to find the one method you need. If you want to know how `gcd` works, you open `gcd.rs`. If you want to change it, you edit exactly one file. The path is the index.

## The three collision points

Only three places in the entire codebase can cause merge conflicts between routine contributors. Everything else is collision-free by construction.

### 1. Cargo.toml

`Cargo.toml` at the workspace root contains workspace members and dependency versions. This file changes when a new crate is added to the workspace or when a dependency version is bumped. Adding an op does not touch `Cargo.toml`. Adding a gate does not touch `Cargo.toml`. Adding an oracle does not touch `Cargo.toml`. This file changes only when the workspace structure itself changes, which is rare and usually planned.

### 2. lib.rs

`src/lib.rs` is the frozen public API. It contains crate-level attributes, the crate doc comment, and a single `include!()` pointing at a build-script-generated module tree. No hand-edited `pub mod` lines. No contributor ever edits it for a routine op addition. The frozen `lib.rs` is the keystone of the architecture. Once it is locked, no contributor can add a centralized hook. There is no escape hatch back to the old pattern of "just add one more line to `lib.rs`." The crate root becomes a constant, not a variable.

The current `src/lib.rs` looks like this:

```rust
#![warn(clippy::pedantic)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
// ... lint attributes locked here ...
//! # vyre — GPU compute intermediate representation

pub mod bytecode;
pub mod backend;
pub mod conform;
pub mod engine;
pub mod error;
pub mod ir;
pub mod lower;
pub mod match_result;
pub mod ops;
pub mod runtime;
mod util;

pub use error::{Error, Result};
pub use backend::{BackendError, DispatchConfig, VyreBackend};
pub use ir::{validate, Program};
pub use match_result::Match;
```

Anything else in this file is forbidden. A PR that adds another `pub mod` line here is rejected by CI.

### 3. Frozen traits

`VyreBackend`, `EnforceGate`, `Oracle`, `Finding`, `Archetype`, and `MutationClass` are the six frozen traits documented in [contracts.md](contracts.md). These are the extensibility contracts. Their required method signatures are frozen at 1.0. Changing one forces every downstream implementation to rewrite, so edits here are forbidden without a major version bump and CEO approval.

Two contributors adding ops in different categories touch disjoint paths. Two contributors adding ops in the same category touch different files in the same directory. Two contributors adding gates touch different files in `vyre-conform/src/enforce/gates/`. Git merges all of these automatically because there is no shared line to conflict over.

The collision surface is intentionally minimized to these three points. If you are not adding a new workspace crate, editing the frozen public API, or breaking a frozen trait, you cannot conflict with another contributor. Full stop.

## How automod + build_scan make it work

Two build-time mechanisms eliminate the need for manual registration lists. Both treat the filesystem as the source of truth, and both run automatically on every build.

### explicit_mod_list!

`explicit_mod_list!` is a compile-time macro that reads a directory and emits `pub mod` declarations for every `.rs` file it finds. A parent module in vyre looks like this:

```rust
// src/ops/primitive/math/mod.rs
explicit_mod_list!(pub "src/ops/primitive/math");
```

When you add `gcd.rs` to that directory, the next compilation automatically includes it as `pub mod gcd;`. No human edits the `mod.rs`. No human even thinks about it. The module tree updates itself from the filesystem. The same pattern is used throughout the codebase wherever a directory contains a collection of independent leaf modules.

Because `mod.rs` files are never written by hand for leaf discovery, the most common source of Rust merge conflicts is completely removed. In a conventional Rust project, every new file requires a matching `mod.rs` edit. Two contributors adding files to the same directory will conflict on the `mod.rs` even if their files are completely unrelated. In vyre, that conflict is impossible.

### vyre-build-scan

`vyre-build-scan` is a build-time filesystem scanner. `build.rs` walks `src/ops`, discovers every `spec.toml` file co-located with an op implementation, validates the `id` and `archetype` fields, checks for duplicate ids, and emits `walked_ops.rs` to `$OUT_DIR`. The generated file contains a static slice of every op id and archetype discovered on disk:

```rust
pub fn walked_ops() -> &'static [(&'static str, &'static str)] {
    &[
        ("primitive.math.gcd", "binary-arithmetic"),
        ("primitive.hash.fnv1a32", "hash-bytes-to-u32"),
        ("primitive.bitwise.xor", "binary-bitwise"),
        // ... every other op discovered at build time
    ]
}
```

When you add `fnv1a32.rs` with its co-located `spec.toml`, the registry includes it automatically on the next build. There is no `ALL_OPS` array in source control for contributors to conflict over. The generated list lives in the build output directory, which is regenerated from scratch on every build. The build script also validates op ids against a strict ASCII format and rejects duplicates with actionable error messages like:

```
Fix: remove duplicate op id `primitive.hash.fnv1a32` from src/ops/hash/fnv1a32.rs; it is already declared by src/ops/hash/fnv1a32.rs
```

### Why this matters

Neither mechanism needs a registration list. Neither needs a `mod.rs` edit for routine additions. The filesystem is the source of truth. The build script is the only entity that touches the generated lists, and it runs deterministically on every build. Contributors never think about module trees or registries. They create their file, run the tests, and open the PR.

This is the mechanism that makes mass contribution possible. In a conventional Rust project, 100 contributors adding 100 modules would produce 100 conflicts on the root `mod.rs` and 100 conflicts on the central enum. In vyre, those conflicts are structurally impossible because those files do not exist.

## What to do when you want to add X

These are the contributor flows, condensed from [contributing.md](contributing.md). Every flow is a single-file drop. No flow requires editing a file you did not create.

### New op

Copy `src/ops/template_op.rs` to the correct category directory — for example, `src/ops/primitive/math/gcd.rs`. Fill in the `OpSpec`, implement the CPU reference kernel, and run:

```bash
cargo test -p vyre-conform -- gcd
```

Your PR touches exactly one file.

### New gate

Create one file in `vyre-conform/src/enforce/gates/` — for example, `integer_overflow.rs`. Implement `EnforceGate`, export a `REGISTERED` const:

```rust
pub struct IntegerOverflow;
impl EnforceGate for IntegerOverflow { /* ... */ }
pub const REGISTERED: IntegerOverflow = IntegerOverflow;
```

Run:

```bash
cargo test -p vyre-conform -- integer_overflow
```

`vyre-build-scan` wires it into `ALL_GATES` automatically.

### New oracle

Create one file in `vyre-conform/src/oracles/` — for example, `point_parity.rs`. Implement `Oracle`, export a `REGISTERED` const. The conformance runner discovers it at startup. Run:

```bash
cargo test -p vyre-conform -- point_parity
```

### New backend

Implement the frozen `VyreBackend` trait in a new crate or module. Pass the full conformance suite:

```bash
cargo test -p vyre-conform --features gpu
```

Then generate a certificate:

```bash
cargo run -p vyre-conform --bin certify
```

The backend trait signature never changes, so your implementation compiles against vyre 1.5 without modification.

### New TOML rule

Copy an example from `conform/rules/examples/witness.toml`, edit it to target your op or declare a new law, and drop it into `conform/rules/my_rule.toml`. Every `.toml` file under `conform/rules/` is auto-discovered at startup. Run:

```bash
cargo test -p vyre-conform
```

In every case, the instruction is the same: create one file, fill it in, test it. There is no step two.

## What to do when 5 contributors are adding ops in the same category

Nothing.

Imagine five contributors each add a different op under `src/ops/hash/`:

- Contributor A adds `fnv1a32.rs`
- Contributor B adds `crc32.rs`
- Contributor C adds `md5.rs`
- Contributor D adds `blake3.rs`
- Contributor E adds `entropy.rs`

Each creates their own file. Each file is independent. `explicit_mod_list!` discovers all five simultaneously. `vyre-build-scan` registers all five simultaneously. The only files changed by any of the PRs are the five new leaf files. Git merges all five branches cleanly because no two branches edit the same file.

This is the difference between "parallel-friendly" and "parallel-native." In a conventional codebase, five contributors adding items to the same module would conflict on `mod.rs`, the central enum, and the dispatch table. In vyre, there is no `mod.rs` to conflict over and no central enum to append to. The directory is the namespace. The filename is the registry key.

The same logic applies to gates. Ten contributors could each add a new gate in `vyre-conform/src/enforce/gates/` and none of their PRs would conflict. The filesystem namespace scales linearly with the number of contributors.

## What breaks parallel contribution (and what we do about it)

Three actions break the guarantee. CI blocks all of them before they reach `main`.

### Editing lib.rs

Any hand-edited `pub mod` or `mod ` declaration in `src/lib.rs` outside the locked header fails the conformance build. The frozen `lib.rs` policy is enforced mechanically. If a contributor opens a PR that adds a `pub mod` line to `lib.rs`, CI rejects it. The architecture is self-defending. A regression to the old centralized pattern is impossible because the build will not pass.

### Editing a frozen trait

Any change to a required method signature on `VyreBackend`, `EnforceGate`, `Oracle`, `Finding`, `Archetype`, or `MutationClass` is caught by `scripts/check_trait_freeze.sh`. These six traits are the only places where external code is expected to implement a vyre trait. Changing one breaks every downstream backend, gate, and oracle. Proposed edits to the frozen surface require a major version bump and CEO approval. This is not a guideline. It is a hard gate.

### Editing a shared utility

Modifying a utility in `src/util/` or a common helper can affect every consumer of that helper. This does not break Git's merge algorithm — two contributors editing different parts of a shared utility might merge cleanly — but it creates semantic coupling. A bug in a shared helper becomes a bug in every op that uses it. Reviewers treat shared-utility edits with higher scrutiny. The one-item-per-file rule minimizes the need for shared helpers by pushing most logic into leaf files where it belongs.

The boundaries are not social. They are enforced by the build. A PR that passes every test but violates the max-five-entries-per-directory rule is rejected. A PR that adds a `mod.rs` is rejected. A PR that touches a frozen trait without the major-version ritual is rejected. The architecture defends itself.

## The 5-year bet

The frozen surface — `lib.rs`, the six traits, and the core IR types — is designed to remain unchanged for five years. If that bet pays off, the op catalog can grow 100x without any central coordination. One thousand ops. One thousand contributors. One thousand leaf files. All parallel. All automatic.

This is possible because vyre is a substrate, not a framework. Primitives are stable; algorithms are compositions. See [extensibility.md](extensibility.md) for the full thesis: "primitives stable, algorithms grow." Every new op is either a Category A composition of existing primitives or a Category C hardware intrinsic with a strict, unchanging signature. Neither kind requires a substrate change.

The cost of the thousandth op is the same as the cost of the first: create one file, write one item, open one PR. There is no queue. There is no release train. There is no central maintainer routing every change. The system only ever grows at the leaves.

That is the 5-year bet. Freeze the core. Grow the leaves. Scale forever.

## See also

- [zero-conflict.md](zero-conflict.md) for the architectural rules
- [contributing.md](contributing.md) for the step-by-step flows
- [extensibility.md](extensibility.md) for the thesis ('primitives stable, algorithms grow')
- [contracts.md](contracts.md) for the frozen trait definitions
- [ARCHITECTURE.md](../../ARCHITECTURE.md) for the system-level design