# Statement Nodes

Statement nodes execute effects. They bind local names, mutate local variables,
write buffers, branch, loop, return, group statements into scopes, and
synchronize workgroups. A program entry point is an ordered list of `Node`
values.

Every statement executes within a lexical scope. The root scope is the entry
body. `Block`, `If` branches, and `Loop` bodies create child scopes. A name is
visible from its declaration to the end of the enclosing block. Shadowing is not
allowed: a `Let` or loop variable must not reuse a name that is already live.

## Let

```rust
Let { name: String, value: Expr }
```

`Let` evaluates `value` and binds the result to `name` in the current scope.
The binding is visible only after the `Let`, not inside the initializer. The
binding remains visible until the end of the enclosing block.

The name must not already be live in the current scope or an outer scope.
Disallowing shadowing keeps lowering simple and prevents bugs where a backend
accidentally resolves a variable to a different storage slot than the CPU
reference.

## Assign

```rust
Assign { name: String, value: Expr }
```

`Assign` evaluates `value` and replaces the current value of an existing local
binding. The target must have been introduced by a prior `Let` in scope. A loop
induction variable is immutable and must not be assigned.

Assignment never creates a new binding. If no prior binding exists, the program
is invalid. This rule catches spelling mistakes and prevents backend-specific
implicit variable creation.

## Store

```rust
Store { buffer: String, index: Expr, value: Expr }
```

`Store` writes one element to a declared buffer. `index` is an element offset,
not a byte offset. `value` is converted according to the buffer element type
only through explicitly specified IR casts; stores do not perform implicit
semantic conversions.

The target buffer must exist and must have `BufferAccess::ReadWrite`. Storing
to `ReadOnly` or `Uniform` buffers is invalid. The program is responsible for
guarding indexes when dispatch dimensions may exceed buffer length.

## If

```rust
If { cond: Expr, then: Vec<Node>, otherwise: Vec<Node> }
```

`If` evaluates `cond` and executes `then` when the condition is true, otherwise
it executes `otherwise`. Boolean conditions use the IR truth convention of the
condition expression's type; for integer-producing comparisons and logical ops,
`0` is false and nonzero is true.

Each branch receives its own child scope cloned from the parent scope. Bindings
created inside either branch are not visible after the `If`, even when both
branches create a binding with the same name. Assignments to bindings that
already existed before the branch remain assignments to that outer binding.

## Loop

```rust
Loop { var: String, from: Expr, to: Expr, body: Vec<Node> }
```

`Loop` is a bounded loop equivalent to `for var in from..to`. `from` is
inclusive and `to` is exclusive. The loop has no unbounded form because GPU
programs must have statically representable termination structure.

The induction variable is a **`U32`**. The `from` and `to` expressions must
produce `U32` values; the bound comparison uses unsigned wrapping semantics.
The induction variable is visible only inside the loop body. It must not shadow
a live name and must not be assigned. Bindings created inside the loop body are
not visible after the loop. If `from >= to` under unsigned `U32` comparison
semantics, the body executes zero times.

## Return

```rust
Return
```

`Return` exits the entry point early for the current invocation. It does not
stop other invocations in the dispatch. Writes performed by the invocation
before `Return` remain observable according to the memory model; statements
after `Return` are not executed by that invocation.

Backends must lower `Return` as a real control-flow exit or an equivalent
structured form that prevents subsequent side effects from executing.

## Block

```rust
Block(Vec<Node>)
```

`Block` executes a sequence of statements in order inside a new child scope.
Bindings introduced inside the block are not visible after the block. Existing
outer bindings may be read and assigned from inside the block.

Blocks are used by optimizers and generators to group statements without
introducing new semantics beyond scope and sequencing.

## Barrier

```rust
Barrier
```

`Barrier` synchronizes all invocations in the current workgroup. It has the
combined meaning of a storage barrier and a workgroup barrier. Storage writes
that must be visible within the workgroup are ordered across the barrier, and no
invocation in the workgroup proceeds beyond the barrier until all live
invocations in that workgroup have reached it.

A barrier is workgroup-local. It does not synchronize different workgroups and
does not provide a global device-wide ordering point. Programs must not place a
barrier in control flow where only some invocations in a workgroup can reach it;
that is invalid for GPU execution even if the IR structure can represent it.
