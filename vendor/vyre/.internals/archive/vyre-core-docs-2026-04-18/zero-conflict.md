# Zero-Conflict Architecture — how vyre scales to 100 contributors

## The problem

When N contributors edit the same file, they collide. Central enums, central `mod.rs`, central registry lists — every one is a collision point that gates parallelism down to single-contributor-at-a-time. No amount of review tooling fixes this. The file itself is the bottleneck.

In most Rust codebases, adding an operation means touching a chain of shared files:

1. Open the central enum and add a variant.
2. Open the root `mod.rs` and add a `pub mod` line.
3. Open a dispatch table and wire in the new variant.
4. Open a test registry and append a pointer.
5. Open the benchmark list and add an entry.

Every step touches a file that every other contributor also wants to touch. Merge conflicts are guaranteed. Rebasing is mandatory. Velocity collapses to the speed of the slowest review. In a large project, the queue becomes the primary cost.

The pain is not linear. With ten active contributors, the conflict rate is manageable. With fifty, it becomes a tax on every change. With a hundred, the project stops scaling. Contributors spend more time resolving merge conflicts than writing code. Reviewers spend more time verifying rebase correctness than reviewing substance. The codebase does not slow down because the compiler is slower. It slows down because the humans are fighting over shared mutable state.

Consider a concrete example. Agent A adds `OpA` to the central enum on line 47. Agent B adds `OpB` to the same enum on line 47. Both changes are correct in isolation. When they meet, Git produces a conflict. Neither agent edited the other's operation. They edited the *list*. The list is the bottleneck. In vyre, there is no list. Agent A creates `src/ops/category/op_a/spec.toml`. Agent B creates `src/ops/category/op_b/spec.toml`. The files are on different branches of the tree. Git merges them automatically. The compiler sees both. Both operations exist. Zero human coordination was required.

vyre does not accept this. The architecture is built so that 100 contributors can each add a leaf file with zero merge conflicts, zero `lib.rs` edits, and zero central registry edits. This is not a tooling trick. It is a structural property enforced by five hard rules that are checked in CI and have no exceptions.

## The 5 rules

1. **One top-level item per file.**
   Every `.rs` file under `src/` contains exactly one of: a `struct`, an `enum`, a `trait`, a `type`, a `const`, a `static`, a single `fn`, or one `impl` block with exactly one associated item. A file with two structs is a CI failure. An `impl` block with two methods is a CI failure. A helper function hidden at the bottom of a struct file is a CI failure. No exceptions. No `#[allow]` escape hatch. Never.

   This rule makes the file the unit of contribution. If you want to add a method to a type, you create a new file. If you want to add a helper, you create a new file. The file count goes up, but the conflict count goes to zero. Searching the codebase is faster too: the filename tells you what it contains, and there is no scrolling through a thousand-line god file to find the one method you need.

2. **Max 5 entries per directory.**
   A directory may contain at most five entries, counting both `.rs` files and subdirectories. If a sixth item is needed, the directory splits into a deeper level. The tree fans out as the catalog grows. Flat directories are forbidden because flat directories become battlegrounds.

   Five is small enough that you can read a directory listing at a glance. It is large enough that the tree does not become excessively deep. When a directory fills up, you group related items into a new subdirectory and continue. The directory structure becomes a taxonomy, not a dumping ground. A contributor looking for a validation method knows to look under `src/ir/program/methods/validation/`. A contributor looking for a bitwise op knows to look under `src/ops/primitive/bitwise/`. The path is the index.

Directory names are chosen to be searchable and stable. Once a directory exists, it is never renamed without a dedicated refactor commit. This keeps historical diffs readable and prevents widespread import churn. The stability of the tree is as important as its shape.

3. **No `mod.rs` files.**
   `mod.rs` does not exist anywhere under `src/`. Not written by hand, not generated, not present. The build script owns the module tree. Contributors do not. This removes the most common source of Rust merge conflicts entirely.

   In a conventional Rust project, every new file requires a matching `mod.rs` edit. Two contributors adding files to the same directory will conflict on the `mod.rs` even if their files are completely unrelated. Removing `mod.rs` removes the conflict. The build script generates the module tree from the filesystem, so the tree is always correct by construction.

4. **`lib.rs` is frozen.**
   `lib.rs` contains only crate-level attributes, the crate doc comment, and a single `include!()` pointing at a build-script-generated module tree. It has no hand-edited `pub mod` lines. Its body never changes. Contributors do not open it. Reviewers do not debate it.

   The frozen `lib.rs` is the keystone of the architecture. Once it is locked, no contributor can add a centralized hook. There is no escape hatch back to the old pattern. The crate root becomes a constant, not a variable.

5. **No central enum, no central list, no central registry.**
   Every catalog is a trait implemented by per-file types, collected at link time via a distributed slice. `Finding` is a trait, not an enum. `OpMetadata` self-registers at link time. Algebraic laws are trait implementations, not enum variants. Any design that requires "add a variant to the central enum to hook in your feature" is an architecture failure and is banned from the codebase.

   Central enums are seductive. They are type-safe, exhaustive, and easy to match on. They are also serial bottlenecks. In vyre, exhaustiveness is checked by tests and oracles, not by the compiler matching on a single enum definition. The tradeoff is intentional: we sacrifice compiler-enforced exhaustiveness for human-enforced parallelism.

## Why it works

The rules remove every shared mutation point.

Two contributors cannot conflict if they never touch the same file. With one item per file, every new operation is a new file. With max-five entries per directory, sibling files are few enough that even directory-level overlap is rare, and deep paths are cheap. With no `mod.rs`, nobody fights over module declarations. With a frozen `lib.rs`, nobody edits the crate root. With distributed slices, nobody appends to a central list.

The result is a system that grows monotonically at the leaves. It never requires a central edit. Twenty contributors. Two hundred contributors. Two thousand contributors. The merge remains trivial because the only changes are file additions at disjoint paths. Rebase hell disappears because there is no shared baseline to rebase against.

This is the engineering property that makes vyre legendary. It is not the 500-line file ceiling in isolation, and it is not the one-item-per-file rule by itself. It is the guarantee that the system only ever grows by adding leaf files. That guarantee lets parallel waves of contributors produce hundreds of operations in an afternoon without a single rebase or a single edit to a file they do not own.

Most large codebases slow down as they grow. vyre speeds up. Every new op deepens the catalog without widening the conflict surface. The cost of adding the thousandth op is the same as the cost of adding the first: create one file, write one item, open one PR. There is no coordination overhead. There is no waiting for a wave to settle. There is no central maintainer acting as a router.

Other projects approximate this with plugin systems. Bevy uses plugins. LLVM uses passes. But plugins solve the problem at the macro level, not the semantic level. In vyre, every individual struct, every individual function, every individual trait implementation is a leaf. The parallelism is not at the crate boundary or the plugin boundary. It is at the file boundary. That is the difference between "parallel-friendly" and "parallel-native".

## The mechanism

### Module-tree generation in `build.rs`

`vyre/core/build.rs` walks `src/`, discovers every `.rs` file except `lib.rs` itself, and emits `$OUT_DIR/vyre_tree.rs`. That generated file contains a flat list of `#[path = "<abs-path>"] mod __vyre_auto_<hash>;` declarations, wrapped in nested `pub mod` shims that recreate the directory structure as a Rust module tree.

For example, a file at:

```
src/ir/program/methods/validation/validate_workgroups.rs
```

is emitted as a module at path `ir::program::methods::validation::validate_workgroups`. The build script also scans the leaf file for optional re-export directives such as `//! @root_export Program`, and emits `pub use <path>::Program;` at the crate root when it finds one.

The generated tree is idempotent. Cargo reruns the build script only when the `src/` tree changes, via `cargo:rerun-if-changed` on each subdirectory. The contributor adds a file. Cargo regenerates the tree. No human edits a module declaration. No human even thinks about it.

The build script computes the crate path by stripping the `src/` prefix and the `.rs` extension, then replacing path separators with `::`. A file at `src/ir/buffer_decl.rs` becomes module `ir::buffer_decl`. A file at `src/ir/node/kinds/load.rs` becomes `ir::node::kinds::load`. The mapping is deterministic and reversible. If you know the filesystem path, you know the module path.

This is the same principle as the `automod` pattern used in other high-velocity Rust projects: the filesystem is the source of truth for the module tree, not a hand-maintained list of `mod` statements. The difference is that vyre enforces it as a hard rule rather than an optional convenience.

The frozen `lib.rs` looks like this:

```rust
#![warn(clippy::pedantic)]
// crate-level lint attributes are locked here
//! # vyre — GPU compute intermediate representation
//! (doc comment stays here, locked)

include!(concat!(env!("OUT_DIR"), "/vyre_tree.rs"));
```

Nothing else is permitted. Anything else is a rule violation.

### Leaf file shape

A leaf file is a complete, self-contained unit. It imports nothing via `super` or wildcard. Every dependency is referenced by its full crate path. This makes navigation trivial: click any type name and jump directly to its file. It also means a leaf file can be moved or renamed without chasing relative import breakage.

A struct leaf:

```rust
// src/ir/program/type.rs
//! @root_export Program
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Program {
    pub buffers: Vec<crate::ir::buffer_decl::BufferDecl>,
    pub workgroup_size: [u32; 3],
    pub entry: Vec<crate::ir::node::Node>,
    pub entry_op_id: Option<String>,
}
```

A constructor leaf:

```rust
// src/ir/program/methods/construction/new.rs
impl crate::ir::program::ProgramType {
    pub fn new(
        buffers: Vec<crate::ir::buffer_decl::BufferDecl>,
        workgroup_size: [u32; 3],
        entry: Vec<crate::ir::node::Node>,
    ) -> Self {
        Self { buffers, workgroup_size, entry, entry_op_id: None }
    }
}
```

A validation leaf:

```rust
// src/ir/program/methods/validation/is_valid.rs
impl crate::ir::program::ProgramType {
    pub fn is_valid(&self) -> bool {
        crate::ir::validate::validate_program::validate_program(self).is_empty()
    }
}
```

Notice the pattern: each file does exactly one thing, and it does it with explicit paths. There is no `use super::*` hiding context. There is no nested module creating indentation debt. The file is the module. The module does one thing.

Explicit paths also make the codebase friendlier to automated tooling. A regex search for `crate::ir::program::Program` finds every usage without ambiguity. An IDE's "Go to Definition" jumps straight to the single file that defines the item. A code-review tool can display a complete diff in a single screen because the file is short. These are side effects of the one-item-per-file rule, but they compound into a codebase that is easier to read, review, and maintain.

### Trait-impl registries with `vyre-build-scan`

Not everything can be discovered from the filesystem alone. Some registries need to know which types implement a particular trait. For this, vyre uses `vyre-build-scan`.

`vyre-build-scan` is a compile-time scanner that walks the crate, identifies trait implementations, and generates static registration tables. It replaces the manual step of "add your type to the central registry" with an automated scan that runs during the build.

For example, instead of maintaining a central enum of every `Finding`, vyre declares `Finding` as a trait. Each finding lives in its own file and implements the trait:

```rust
// src/findings/missing_binding_0.rs
use linkme::distributed_slice;
use crate::finding::Finding;

#[distributed_slice(crate::finding::FINDINGS)]
static MISSING_BINDING_0: Finding = Finding {
    id: "missing-binding-0",
    enforcer: |op| { /* ... */ },
    // ...
};
```

Adding a finding is `touch src/findings/<id>.rs` with one static registration. Zero central file edits. The collection happens at link time via the `linkme` crate. Parallel-safe. `vyre-build-scan` provides the same capability for more complex trait-impl registries that need structured metadata rather than raw slices.

The distributed slice approach scales linearly with the number of registered items. There is no runtime registry builder that iterates over a growing list. The linker collects the slices into a single static array. Registration cost is paid at link time, not at startup. For a system that may eventually register thousands of operations, laws, and findings, this matters.

Together, `build.rs` and `vyre-build-scan` eliminate the two remaining reasons to touch a shared file: module declarations and registry entries. The build owns both. The contributors own only their leaf files.

This design also makes reverts safe. If one contributor's leaf file is wrong, a revert deletes exactly one file. No other contributor's work is affected. There is no central file to roll back to a previous version. There is no cascade of broken imports across unrelated modules. The isolation that prevents conflicts also prevents regressions from spreading.

### CI enforcement

The rules are not aspirational. They are enforced mechanically by the conformance suite:

- Any `mod.rs` under `src/` fails the build.
- Any `.rs` file with more than one top-level item fails the build.
- Any directory with more than five entries fails the build.
- Any `pub mod` or `mod ` declaration in `lib.rs` outside the locked header fails the build.

These four checks are the legendary-property gate. They guarantee that no contributor can accidentally reintroduce a shared mutation point. The architecture is self-defending. A regression is impossible because CI will catch it before it reaches `main`.

The conformance suite treats these structural checks as seriously as it treats algebraic law verification or GPU parity. A PR that passes every test but violates the max-five-entries rule is rejected. The rules are not guidelines. They are the foundation of the project's scalability.

## The consequence

100 contributors, 100 new ops, zero conflicts.

This is not a social contract. It is not a request to "please try to avoid conflicts." It is a mechanical property of the filesystem layout. When every contributor adds a new leaf file in a directory no one else is touching, Git has nothing to merge. The changes are disjoint by construction.

The architecture makes vyre parallel-native. It is the reason a large team can move at the speed of individual contributors rather than the speed of a serialized queue. That property is what rustc does not have, LLVM does not have, and most plugin-based frameworks only approximate. In vyre, it is built into the tree.

If you are contributing to vyre, you should internalize this: your job is to add a leaf. One file. One item. One clear path. The system handles the rest.

The keystone commit that froze `lib.rs` and introduced `build.rs` was serial. Everything after it is parallel. A hundred-agent wave can run safely because each agent produces distinct target leaf file paths, no two agents write the same file, and no two agents edit `lib.rs`, `mod.rs`, or any central list. That is not an accident. It is the architecture working as designed.

That is the zero-conflict promise. That is what makes vyre scale.
