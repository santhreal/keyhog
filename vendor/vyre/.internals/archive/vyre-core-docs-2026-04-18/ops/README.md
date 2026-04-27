# Operation Library

The vyre operation library is split into two implementation layers.

Layer 1 contains primitive operations. These are the 32 small, domain-agnostic
atoms in `core/src/ops/primitive/`: arithmetic, comparison, bitwise, and packed
bit-field helpers. Primitive ops are ordinary Category A compositions with
`OpSpec` metadata, algebraic laws, and complete `ir::Program` builders.

Layer 2 contains domain operations. These are byte-buffer, graph, compression,
string, matching, hash, and collection programs composed from Layer 1
primitives and IR expressions. They remain Category A unless an operation is
explicitly declared as a Category C hardware intrinsic. Category B runtime
abstraction is forbidden; see [IR categories](../ir/categories.md).

## Domains

| Domain | Purpose |
|--------|---------|
| `primitive` | Layer 1 u32 arithmetic, comparison, bitwise, and packed field atoms. |
| `decode` | Layer 2 base64, hex, URL percent, and Unicode escape byte decoding. |
| `hash` | Layer 2 byte-buffer reductions such as FNV-1a, CRC-32, rolling hash, and entropy. |
| `string` | Layer 2 tokenization and byte-stream text structure. |
| `graph` | Layer 2 CSR graph traversal, BFS, and reachability. |
| `match_ops` | Layer 2 DFA and related matching programs. |
| `compression` | Layer 2 packed-byte block decompression for LZ4 and zstd raw/RLE blocks. |
| `collection` | Planned Layer 2 sort, filter, reduce, scan, scatter, and gather programs. |

## Category A Example

The example below builds a small Category A composition. The operation is a
complete `Program`, but the expression uses `Expr::Call` to name primitive ops
instead of duplicating their definitions. During lowering, call inlining expands
those primitive programs before WGSL emission.

```rust
use vyre::ir::{BufferDecl, DataType, Expr, Node, Program};
use vyre::ops::{Law, OpSpec};

pub const EXAMPLE_LAWS: &[Law] = &[Law::Commutative, Law::Bounded { lo: 0, hi: 32 }];

pub const SPEC: OpSpec = OpSpec::composition(
    "example.masked_add",
    &[DataType::U32, DataType::U32, DataType::U32],
    &[DataType::U32],
    EXAMPLE_LAWS,
    program,
);

pub fn program() -> Program {
    let idx = Expr::var("idx");
    let left = Expr::load("left", idx.clone());
    let right = Expr::load("right", idx.clone());
    let mask = Expr::load("mask", idx.clone());
    let sum = Expr::Call {
        op_id: "primitive.math.add".to_string(),
        args: vec![left, right],
    };
    let value = Expr::Call {
        op_id: "primitive.bitwise.and".to_string(),
        args: vec![sum, mask],
    };

    Program::new(
        vec![
            BufferDecl::read("left", 0, DataType::U32),
            BufferDecl::read("right", 1, DataType::U32),
            BufferDecl::read("mask", 2, DataType::U32),
            BufferDecl::read_write("out", 3, DataType::U32),
        ],
        [64, 1, 1],
        vec![
            Node::let_bind("idx", Expr::gid_x()),
            Node::if_then(
                Expr::lt(idx.clone(), Expr::buf_len("out")),
                vec![Node::store("out", idx, value)],
            ),
        ],
    )
}
```

The program carries only IR. It does not embed shader text, dynamic dispatch, or
runtime callbacks. The primitive calls are a construction-time abstraction that
must disappear before backend code is emitted.

## See also

- [Operations Overview](overview.md)
- [Primitive Overview](primitive/overview.md)
- [OpSpec](trait.md)

