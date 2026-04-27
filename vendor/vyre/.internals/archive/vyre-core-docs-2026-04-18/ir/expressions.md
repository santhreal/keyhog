# Expressions

Expressions produce values. Most expressions are pure reads and computations.
`Atomic` is the exception: it updates a read-write buffer and returns the value
that was present before the update. Every expression appears inside a statement
or another expression and is evaluated according to the CPU reference semantics
in `vyre-conform/SPEC.md`.

## LitU32

```rust
LitU32(u32)
```

`LitU32` is an unsigned 32-bit constant. Arithmetic on `U32` values uses
wrapping modulo `2^32` semantics where specified by the operation.

## LitI32

```rust
LitI32(i32)
```

`LitI32` is a signed 32-bit constant. Signed values use two's-complement
representation. Cross-type interpretation must be expressed with `Cast`; it is
not implied by the literal.

## LitBool

```rust
LitBool(bool)
```

`LitBool` is a boolean constant. `Bool` is distinct in the IR type system and is
stored as a 32-bit value in GPU-compatible representations, with false as `0`
and true as `1`.

## Var

```rust
Var(String)
```

`Var` resolves a local binding by name. The name must refer to a prior `Let` or
the current loop induction variable in lexical scope. Resolution searches the
current scope and then outer scopes, but shadowing is invalid, so a valid
program has at most one live binding for a name.

## Load

```rust
Load { buffer: String, index: Box<Expr> }
```

`Load` reads one element from a declared buffer. The index expression is an
element offset, not a byte offset. The result type is the buffer's element
`DataType`.

The buffer may be `ReadOnly`, `ReadWrite`, or `Uniform`. Out-of-bounds behavior
must be specified by the memory model and CPU reference; program authors should
guard indexes when dispatch size and buffer length can differ.

## BufLen

```rust
BufLen { buffer: String }
```

`BufLen` returns the element count of a declared buffer. In WGSL it maps to
`arrayLength` for runtime-sized storage arrays. The returned value is a `U32`.

For fixed-size or uniform-backed representations, the lowering must supply the
same element count that the CPU reference uses for the invocation.

## InvocationId

```rust
InvocationId { axis: u8 }
```

`InvocationId` returns the global invocation coordinate for axis `0`, `1`, or
`2`. Axis `0` is x, `1` is y, and `2` is z. The value is a `U32` in the range
launched by the host dispatch multiplied by the program's workgroup size.

## WorkgroupId

```rust
WorkgroupId { axis: u8 }
```

`WorkgroupId` returns the workgroup coordinate for axis `0`, `1`, or `2`. The
range is determined by the host dispatch dimensions. It is independent of the
local invocation coordinate within a workgroup.

## LocalId

```rust
LocalId { axis: u8 }
```

`LocalId` returns the invocation coordinate inside the current workgroup for
axis `0`, `1`, or `2`. Its range is `0..workgroup_size[axis]`. This expression
is used for workgroup-local indexing and cooperative algorithms.

## BinOp

```rust
BinOp { op: BinOp, left: Box<Expr>, right: Box<Expr> }
```

`BinOp` evaluates `left` and `right`, then applies the selected binary operator.
The ground truth binary operators are documented in `binary-ops.md` and
`vyre-conform/SPEC.md`. Division and modulo by zero produce `0`; shift amounts
are masked to `0..31`; comparisons and logical operations produce `0` or `1`.

## UnOp

```rust
UnOp { op: UnOp, operand: Box<Expr> }
```

`UnOp` evaluates `operand`, then applies the selected unary operator. The
ground truth unary operators are documented in `unary-ops.md` and
`vyre-conform/SPEC.md`. `Clz(0)` and `Ctz(0)` both return `32`.

## Call

```rust
Call { op_id: String, args: Vec<Expr> }
```

`Call` invokes another operation by hierarchical identifier. Arguments are
evaluated as values and passed to the callee. The call is semantically an inline
expansion of the callee's value computation: it does not import the caller's
local variables, does not create implicit buffer aliases, and does not share
buffers except through explicit value arguments and the callee program contract.

The callee identifier must resolve through the operation registry used by the
compiler or conformance harness. A lowering that cannot resolve a call must
return an actionable error.

## Select

```rust
Select {
    cond: Box<Expr>,
    true_val: Box<Expr>,
    false_val: Box<Expr>,
}
```

`Select` is a value-level conditional. It returns `true_val` when `cond` is true
and `false_val` otherwise. Both branch values are evaluated; `Select` is not
short-circuiting control flow. Use `Node::If` when only one branch may execute
side effects.

This rule matters for atomics and invalid indexes. If either branch expression
has an atomic or invalid memory access, placing it in `Select` does not hide it.

## Cast

```rust
Cast { target: DataType, value: Box<Expr> }
```

`Cast` converts `value` to `target` using the explicit conversion rules
documented in `casts.md` and the ground truth spec. Casts are the only way to
request a type reinterpretation or numeric conversion. Backends must not invent
implicit casts to satisfy a target shader language.

## Atomic

```rust
Atomic {
    op: AtomicOp,
    buffer: String,
    index: Box<Expr>,
    expected: Option<Box<Expr>>,
    value: Box<Expr>,
}
```

`Atomic` performs an atomic read-modify-write on a declared `ReadWrite` buffer
element and returns the value before the operation. Atomic operations are
sequentially consistent in the ground truth semantics. `CompareExchange`
requires `expected: Some(expr)` and updates the element to `value` only when
the previous value equals `expected`. All other atomic operations require
`expected: None` and use `value` as their single operand.

The target buffer must support atomic representation for its element type on the
backend. If a valid IR atomic cannot be lowered for the target, the backend must
return an error rather than emulate a non-atomic read/write sequence.
