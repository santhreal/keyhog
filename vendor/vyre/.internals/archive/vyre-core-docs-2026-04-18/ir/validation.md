# IR Validation

Validation rejects structurally invalid programs before optimization or
lowering. A validator must report actionable errors and continue collecting
independent errors where possible. Error text should follow the format:

```text
vyre IR validation: <problem>. Fix: <specific corrective action>.
```

The rule identifiers below are stable. Backends, tests, and diagnostics may use
them to classify failures.

## V001: No Duplicate Buffer Names

Checks: Every `BufferDecl::name` is unique within `Program::buffers`.

Why: Expressions and statements refer to buffers by name. Duplicate names make
`Load`, `Store`, `BufLen`, and `Atomic` ambiguous and can cause different
backends to choose different bindings.

Error message format:

```text
vyre IR validation: duplicate buffer name `<name>`. Fix: each buffer must have a unique name.
```

## V002: No Duplicate Bindings

Checks: Every `BufferDecl::binding` is unique within `Program::buffers`.
`BufferAccess::Workgroup` buffers are exempt because they do not consume
binding slots.

Why: Lowerings map bindings to target resource slots. Two buffers at the same
binding slot alias at the shader interface and cannot be supplied
unambiguously by the host.

Error message format:

```text
vyre IR validation: duplicate binding slot <binding> (buffer `<name>`). Fix: each buffer must have a unique binding.
```

## V003: Workgroup Size Components Are At Least One

Checks: `Program::workgroup_size[0]`, `[1]`, and `[2]` are each `>= 1`.

Why: GPU compute workgroup dimensions cannot be zero. A zero dimension also
makes `LocalId` ranges nonsensical.

Error message format:

```text
vyre IR validation: workgroup_size[<axis>] is 0. Fix: all workgroup dimensions must be >= 1.
```

## V004: Buffer References Resolve

Checks: Every buffer name used by `Expr::Load`, `Expr::BufLen`, `Expr::Atomic`,
and `Node::Store` exists in `Program::buffers`.

Why: Lowering needs a declared binding, access mode, and element type for every
buffer reference. Unknown buffers are construction errors, not backend-specific
runtime failures.

Error message formats:

```text
vyre IR validation: load from unknown buffer `<name>`. Fix: declare it in Program::buffers.
vyre IR validation: buflen of unknown buffer `<name>`. Fix: declare it in Program::buffers.
vyre IR validation: atomic on unknown buffer `<name>`. Fix: declare it in Program::buffers.
vyre IR validation: store to unknown buffer `<name>`. Fix: declare it in Program::buffers.
```

## V005: Store Only To Writable Buffers

Checks: Every `Node::Store` targets a buffer declared with
`BufferAccess::ReadWrite` or `BufferAccess::Workgroup`.

Why: `ReadOnly` and `Uniform` buffers are immutable from the program's point of
view. Allowing writes to them would make the host interface lie and would map to
invalid target shader code.

Error message format:

```text
vyre IR validation: store to non-writable buffer `<name>`. Fix: declare it with BufferAccess::ReadWrite or BufferAccess::Workgroup.
```

## V006: Variable References Have A Prior Let

Checks: Every `Expr::Var` resolves to a prior `Let` binding or an in-scope loop
induction variable. `Node::Assign` also requires an existing in-scope binding.

Why: Variables are local SSA-like names with explicit declaration points.
Implicit declaration would hide spelling mistakes and make scope-sensitive
lowering ambiguous.

Error message formats:

```text
vyre IR validation: reference to undeclared variable `<name>`. Fix: add `let <name> = ...;` before this use.
vyre IR validation: assignment to undeclared variable `<name>`. Fix: add `let <name> = ...;` before this assignment.
```

## V007: ID Axes Are In Range

Checks: `Expr::InvocationId`, `Expr::WorkgroupId`, and `Expr::LocalId` use only
axis `0`, `1`, or `2`.

Why: GPU compute grids are three-dimensional. Other axis values have no stable
meaning and must not be lowered to backend-specific behavior.

Error message format:

```text
vyre IR validation: invocation/workgroup ID axis <axis> out of range. Fix: use 0 (x), 1 (y), or 2 (z).
```

## V008: No Local Shadowing

Checks: A `Let` binding or loop induction variable must not reuse a name that is
already live in the current scope or any outer scope.

Why: The IR resolves variables by name. Prohibiting shadowing keeps resolution
unique across validators, visitors, optimizers, and lowerings.

Error message format:

```text
vyre IR validation: duplicate local binding `<name>`. Fix: choose a unique local name; shadowing is not allowed.
```

## V009: Atomic Only On ReadWrite Buffers

Checks: Every `Expr::Atomic` targets a buffer declared with
`BufferAccess::ReadWrite`.

Why: Atomics modify memory. They cannot be valid on read-only storage or uniform
buffers, even though they return a value.

Error message format:

```text
vyre IR validation: atomic on non-writable buffer `<name>`. Fix: declare it with BufferAccess::ReadWrite.
```

## V010: Barrier Must Be Uniformly Reachable

Checks: A `Barrier` must not appear in control flow where only a subset of live
invocations in a workgroup can reach it.

Why: GPU workgroup barriers require all live invocations in the workgroup to
arrive. Divergent barriers can deadlock a workgroup or be rejected by target
shader compilers.

Error message format:

```text
vyre IR validation: barrier may be reached by only part of a workgroup. Fix: move the barrier to uniform control flow.
```

## V011: No Assignment To Loop Variable

Checks: `Node::Assign` must not target a loop induction variable.

Why: Loop variables are immutable by design. Allowing assignment would break
static termination analysis and create confusion about which iteration is
active.

Error message format:

```text
vyre IR validation: assignment to loop variable `<name>`. Fix: loop variables are immutable.
```

## V012: Casts Must Be Supported

Checks: `Expr::Cast { target, value }` must appear in the supported cast table
in `casts.md`. Non-`Bytes` casts to `Bytes` are reported by `V023` because the
WGSL lowering surface exposes byte data through buffers rather than scalar
expressions.

Why: Casts are the only legal type conversion path. Undefined casts would force
backends to invent implicit conversion rules, producing divergent bytes.

Error message format:

```text
vyre IR validation: unsupported cast from `<source>` to `<target>`. Fix: see casts.md for valid conversions.
```

## V013: Buffer Element Type Supports Operation

Checks: `Expr::Load`, `Node::Store`, and `Expr::Atomic` must not target a
buffer whose element type is `Bytes`.

Why: `Bytes` is a variable-length byte buffer with no defined element-wise
load/store semantics at the IR level. Accessing it as a typed scalar is
undefined.

Error message format:

```text
vyre IR validation: operation on buffer `<name>` with element type `bytes` is not supported. Fix: use a typed buffer.
```

## V014: Atomic Buffer Element Must Be U32

Checks: `Expr::Atomic` must target a buffer whose element type is `U32`.

Why: All atomic operations in vyre are defined on 32-bit unsigned integers.
Allowing atomics on other element types would map to invalid or
vendor-specific backend code.

Error message format:

```text
vyre IR validation: atomic on buffer `<name>` with non-u32 element type `<type>`. Fix: atomics only support U32 elements.
```

## V015: Loop Bounds Must Be U32

Checks: The `from` and `to` expressions of a `Node::Loop` must evaluate to
`U32`.

Why: The induction variable is defined as `U32`. Using a different type for the
bounds would make the iteration count undefined.

Error message format:

```text
vyre IR validation: loop bound expression must be `u32`, got `<type>`. Fix: ensure `from` and `to` are U32.
```

## V021: Binary Operands Must Be U32

Checks: Both operands of every `Expr::BinOp` must resolve to `U32`.

Why: All current binary operations are defined over 32-bit unsigned operands.
Comparison and logical binary operators also consume `U32` values and return
`U32` encoded as `0` or `1`. Allowing `Bool`, `I32`, vector, or byte operands
would force lowerings to invent implicit conversions.

Error message format:

```text
vyre IR validation: binary operation <left|right> operand must be `u32`, got `<type>`. Fix: cast or rewrite the operand to produce U32.
```

## V022: If Condition Must Be U32 Or Bool

Checks: `Node::If::cond` must resolve to `U32` or `Bool`.

Why: Conditions are either explicit booleans or the standard vyre integer
predicate encoding where `0` is false and any non-zero `u32` is true. Other
types have no stable truthiness.

Error message format:

```text
vyre IR validation: if condition must be `u32` or `bool`, got `<type>`. Fix: cast or rewrite the condition to produce U32 or Bool.
```

## V020: Calls Must Target Inlinable Operations

Checks: `Expr::Call { op_id, .. }` may only target registered operations whose
`OpSpec` is marked inlinable.

Why: Some operations consume variable-length buffers or require dedicated
backend lowering. Expanding those calls as scalar expressions would silently
change semantics.

Error message format:

```text
vyre IR validation: V020: call to non-inlinable op `<op_id>` is rejected by validation. Fix: lower this operation through its dedicated backend path or rewrite the caller with explicit IR.
```

## V023: Cast To Bytes Is Unsupported In WGSL Lowering

Checks: `Expr::Cast { target: DataType::Bytes, value }` is only valid when the
source type is already `Bytes`.

Why: `Bytes` is variable-length buffer data, not a scalar lane value. WGSL byte
data must move through buffer load/store paths with an explicit length model.

Error message format:

```text
vyre IR validation: V023: cast to Bytes is unsupported in WGSL lowering. Fix: use buffer load/store directly for byte data.
```

## V024: Workgroup Buffer Must Have Positive Count

Checks: Every `BufferDecl` with `BufferAccess::Workgroup` has `count > 0`.

Why: Workgroup arrays are statically sized in target shaders. A zero-length
array is invalid WGSL and useless for shared computation.

Error message format:

```text
vyre IR validation: workgroup buffer `<name>` has count 0. Fix: declare a positive element count.
```

## V025: Atomics Not On Workgroup Buffers

Checks: `Expr::Atomic` must not target a `BufferAccess::Workgroup` buffer.

Why: The vyre atomic memory model is currently defined only for `ReadWrite`
storage buffers. Workgroup atomics require additional OOB and ordering
guarantees that are not yet specified.

Error message format:

```text
vyre IR validation: atomic on non-writable buffer `<name>`. Fix: declare it with BufferAccess::ReadWrite.
```


## V016: Known Operation IDs

Checks: `Expr::Call::op_id` must exist in `core::ops::registry::known_op_ids()`.

Why: Unregistered operations cannot be lowered to target shader code or analyzed by static passes.

Error message format:

```text
vyre IR validation: V016: unknown op `<op_id>`. Fix: use a registered op id or add the op to core::ops::*.
```

## V017: Maximum Call Depth

Checks: The call depth of operations must not exceed `DEFAULT_MAX_CALL_DEPTH` (32).

Why: Operations can call other operations via their composition programs. Malicious or mutually recursive operations can cause static analysis and lowering to explode exponentially or infinitely loop.

Error message format:

```text
vyre IR validation: V017: call depth exceeds maximum of 32. Fix: reduce call nesting or mutually recursive operations.
```

## V018: Maximum Nesting Depth

Checks: The nesting depth of `If`, `Loop`, and `Block` nodes must not exceed `DEFAULT_MAX_NESTING_DEPTH` (64).

Why: Deeply nested control flow can overflow the stack of target shader compilers and analysis passes.

Error message format:

```text
vyre IR validation: V018: program nesting depth <depth> exceeds max 64. Fix: flatten nested If/Loop/Block structures or split the program before lowering.
```

## V019: Maximum Node Count

Checks: The total number of statement and expression nodes in a program must not exceed `DEFAULT_MAX_NODE_COUNT` (100,000).

Why: Overly large programs can consume excessive memory during compilation and lowering. Limits are necessary to bound worst-case resource usage.

Error message format:

```text
vyre IR validation: V019: program has more than 100000 statement nodes. Fix: split the program into smaller kernels or run an optimization pass before lowering.
```
