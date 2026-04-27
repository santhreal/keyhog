# Program

A `Program` is the unit of work in vyre IR. It describes one complete compute
entry point in a target-independent form:

```rust
pub struct Program {
    pub buffers: Vec<BufferDecl>,
    pub workgroup_size: [u32; 3],
    pub entry: Vec<Node>,
}
```

The host supplies concrete buffers and dispatch dimensions. The program supplies
the buffer interface, local workgroup shape, and statement body that each
invocation runs.

## BufferDecl

`BufferDecl` declares one memory binding:

```rust
pub struct BufferDecl {
    pub name: String,
    pub binding: u32,
    pub access: BufferAccess,
    pub element: DataType,
    pub count: u32,
}
```

`name` is the program-local identifier used by `Expr::Load`, `Expr::BufLen`,
`Expr::Atomic`, and `Node::Store`. Names must be unique within a program.

`binding` is the numeric binding slot used by the lowering. In WGSL reference
lowering, every buffer is placed in `@group(0)` and the slot becomes
`@binding(binding)`. Binding slots must be unique within a program.

`access` defines how the entry body may use the buffer. `ReadOnly` buffers may
be loaded but not stored. `ReadWrite` buffers may be loaded, stored, and used by
atomic operations. `Uniform` buffers are read-only parameter buffers intended
for small configuration data. `Workgroup` buffers are fast, workgroup-local
shared arrays. They do not use a binding slot and must have a positive
`count`.

`count` is the number of elements. For `Workgroup` memory it is the static
array length. For storage and uniform buffers it is `0` (runtime-sized).

## workgroup_size

`workgroup_size` is `[x, y, z]` and maps to the compute shader workgroup size.
Each component must be at least `1`. The value defines the range of
`Expr::LocalId { axis }`: axis `0` is in `0..x`, axis `1` is in `0..y`, and axis
`2` is in `0..z`.

The host dispatch controls how many workgroups run. The program controls how
many local invocations are in each workgroup. Together they define the global
invocation grid. `Expr::InvocationId { axis }` addresses the global invocation
coordinate produced by that combination.

## Entry Point Body

`entry` is an ordered `Vec<Node>`. Each invocation executes the statements from
first to last until the body ends or a `Return` node exits early.

The entry body has a root lexical scope for `Let` bindings. Nested `Block`,
`If`, and `Loop` bodies create child scopes as described in `nodes.md`.
Statements may read buffers, write read-write buffers, bind locals, branch,
loop over bounded ranges, synchronize workgroups, and return.

## Well-Formed Programs

A program is well-formed when it passes validation and every semantic reference
can be resolved unambiguously. At minimum:

- Buffer names are unique.
- Binding slots are unique.
- Every `Load`, `BufLen`, `Store`, and `Atomic` references a declared buffer.
- Stores and atomics target `ReadWrite` buffers.
- Every variable reference resolves to a prior `Let` or loop variable in scope.
- Local names do not shadow another live local name.
- Every invocation/workgroup/local ID axis is `0`, `1`, or `2`.
- Every workgroup size component is at least `1`.
- Loops are bounded by `from` and `to` expressions, with `from` inclusive and
  `to` exclusive.

Validation is structural. It does not prove that host dispatch dimensions cover
the desired output length. Programs that index by global invocation ID must
guard stores and loads with bounds checks when the dispatch grid may exceed the
buffer length.

## Relationship To GPU Dispatch

A program executes once per invocation. The usual pattern is:

1. Read the global invocation ID.
2. Compare it to an output length or input length.
3. Return or skip work for out-of-range invocations.
4. Load input elements.
5. Compute deterministic integer results.
6. Store output elements.

The IR does not store the host dispatch dimensions because those are execution
parameters. A backend may dispatch any grid that is compatible with the
program's workgroup size. Correct programs must be safe for every invocation
that the host launches.

## XOR Example

The following program XORs two `u32` input buffers element-wise into a
read-write output buffer. It uses the global x invocation as the element index
and guards the store with `idx < arrayLength(out)`.

```rust
use vyre::ir::{BufferAccess, BufferDecl, BinOp, DataType, Expr, Node, Program};

let program = Program {
    buffers: vec![
        BufferDecl::storage("a", 0, BufferAccess::ReadOnly, DataType::U32),
        BufferDecl::storage("b", 1, BufferAccess::ReadOnly, DataType::U32),
        BufferDecl::storage("out", 2, BufferAccess::ReadWrite, DataType::U32),
        // Workgroup example (not used in the XOR logic above):
        // BufferDecl::workgroup("scratch", 256, DataType::U32),
    ],
    workgroup_size: [64, 1, 1],
    entry: vec![
        Node::let_bind("idx", Expr::InvocationId { axis: 0 }),
        Node::if_then(
            Expr::BinOp {
                op: BinOp::Lt,
                left: Box::new(Expr::Var("idx".into())),
                right: Box::new(Expr::BufLen { buffer: "out".into() }),
            },
            vec![Node::store(
                "out",
                Expr::Var("idx".into()),
                Expr::BinOp {
                    op: BinOp::BitXor,
                    left: Box::new(Expr::Load {
                        buffer: "a".into(),
                        index: Box::new(Expr::Var("idx".into())),
                    }),
                    right: Box::new(Expr::Load {
                        buffer: "b".into(),
                        index: Box::new(Expr::Var("idx".into())),
                    }),
                },
            )],
        ),
    ],
};
```

For every valid index `i`, the observable result is
`out[i] = a[i] ^ b[i]`. The same bytes are required from the CPU reference,
WGSL lowering, and any future backend.
