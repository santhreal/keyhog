# Getting Started

This chapter takes you from zero to a working vyre program in five
minutes. By the end, you will have constructed an IR program,
lowered it to WGSL, and verified it produces correct output.

## What you need

- Rust 1.85+ (`rustup update stable`)
- A GPU adapter (any GPU supported by wgpu — NVIDIA, AMD, Intel, Apple)
- The vyre workspace cloned

```bash
git clone https://github.com/santhsecurity/vyre.git
cd vyre
```

## Your first Program

A vyre Program is a complete GPU compute dispatch. It declares
buffers, a workgroup size, and an entry body executed by each
GPU invocation. Let's build one that XORs two arrays element-wise.

```rust
use vyre::ir::*;

let program = Program::new(
    vec![
        BufferDecl::read("a", 0, DataType::U32),
        BufferDecl::read("b", 1, DataType::U32),
        BufferDecl::read_write("out", 2, DataType::U32),
    ],
    [64, 1, 1],  // workgroup size
    vec![
        // Each invocation processes one element
        Node::let_bind("idx", Expr::gid_x()),
        // Bounds check: skip if idx >= output length
        Node::if_then(
            Expr::lt(Expr::var("idx"), Expr::buf_len("out")),
            vec![Node::store(
                "out",
                Expr::var("idx"),
                Expr::bitxor(
                    Expr::load("a", Expr::var("idx")),
                    Expr::load("b", Expr::var("idx")),
                ),
            )],
        ),
    ],
);
```

That's the entire program. Three buffers (two inputs, one output),
a workgroup size of 64, and a body that reads from `a` and `b`,
XORs them, and writes to `out`.

## Validate it

Before lowering, validate that the program is well-formed:

```rust
let errors = vyre::ir::validate(&program);
assert!(errors.is_empty(), "validation failed: {errors:?}");
```

Validation checks:
- Buffer names are unique
- Binding slots are unique
- Every `Load`/`Store`/`Atomic` references a declared buffer
- Stores target `ReadWrite` buffers only
- Variables are declared before use
- Workgroup size components are ≥ 1
- Invocation/workgroup ID axes are 0, 1, or 2

If validation passes, the program is guaranteed to lower without panic.

## Lower to WGSL

The lowering translates your IR program to a WGSL compute shader:

```rust
let wgsl = vyre::lower::wgsl::lower(&program)
    .expect("validated program must lower");

println!("{wgsl}");
```

This produces a complete, compilable WGSL shader with:
- Buffer struct and binding declarations
- A `main` entry point with `@compute @workgroup_size(64, 1, 1)`
- Division-by-zero guards (returns 0)
- Shift amount masking (`b & 31`)
- OOB load guards (returns 0)

The WGSL is ready for wgpu's shader compiler.

## Use it with an existing primitive

You don't have to build Programs by hand. Every primitive operation
in vyre has a `program()` function that returns a ready-to-use
`ir::Program`:

```rust
use vyre::ops::primitive::xor;

let program = xor::Xor::program();
let wgsl = vyre::lower::wgsl::lower(&program).unwrap();
```

All primitives work this way. Each is a `const OpSpec` with a
`program()` function.

## Verify with conform

The conformance suite proves your program produces correct output
on a real GPU:

```bash
# Run all conformance tests (CPU-only, fast)
cargo test -p vyre-conform --lib

# Run GPU parity tests (requires GPU adapter)
cargo test -p vyre-conform --lib --features gpu
```

The GPU parity tests dispatch every primitive's shader on a real GPU
and compare the output byte-for-byte against the CPU reference. If
any byte differs, the test fails.

## What's next

- **[Adding Your First Op](tutorial-new-op.md)** — create a new
  operation from scratch with spec.toml, kernel.rs, and conformance
- **[IR Overview](ir/overview.md)** — deep dive into the IR
- **[Operations Overview](ops/overview.md)** — the standard library
- **[OpSpec](ops/trait.md)** — how operations are declared

## The key ideas

1. **Programs are data.** An `ir::Program` is a Rust struct, not
   a string. You construct it with builders, validate it with
   `validate()`, lower it with `lower()`, and dispatch it with a
   backend. The same Program works on every backend.

2. **The IR is the contract.** Everything else — the ops, the
   lowering, the engines, the conformance suite — is built on the
   IR. If you understand `Program`, `Node`, `Expr`, and
   `BufferDecl`, you understand vyre.

3. **Composition is free.** Operations compose via `Expr::Call`.
   The lowering inlines the callee, producing the same WGSL a
   human would write by hand. There is no runtime overhead from
   composition.

4. **The conformance suite is the proof.** vyre's promise of
   byte-identical output across backends is not a claim — it's a
   mathematical proof verified by exhaustive testing on the u8
   domain and witnessed on the u32 domain.
