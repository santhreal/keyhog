# Property-based testing for GPU IR

## The generator is the test

A property test's claim is universal: for every input in the
distribution, some relation holds. The distribution is
determined by the generator. A weak generator covers a thin
slice of the input space; a strong generator covers the
shapes that matter. The proptest framework runs the test on
thousands of samples, but it can only sample from the
distribution the generator produces. If the distribution
misses the interesting inputs, the test misses the bugs.

Writing a good generator for `ir::Program` is harder than
writing a good generator for flat values like `u32` or
`Vec<u8>`. `ir::Program` is recursive, structured, and has
internal consistency requirements (references must resolve,
types must match, control flow must be well-formed). A naive
generator that fills in random bytes produces mostly invalid
Programs that fail at the validation stage before reaching the
code under test. A careful generator produces valid Programs
that exercise the real shapes users write.

This chapter is about writing generators that matter. It goes
beyond the basic proptest usage in [Property
tests](../categories/property.md) and into the design
decisions that determine whether a property test catches bugs.

## Structured generation

A structured generator builds the target value compositionally
rather than randomly. For `ir::Program`, composition means:
pick a number of buffers, generate each buffer's declaration,
pick an entry node shape, generate each expression recursively.
At each step, the generator picks from options that produce
valid values, constrained by the context of the previous
choices.

```rust
pub fn arb_program() -> impl Strategy<Value = Program> {
    (1..5usize, 1..10u32).prop_flat_map(|(num_buffers, workgroup_size)| {
        prop::collection::vec(arb_buffer_decl(), num_buffers).prop_flat_map(
            move |buffers| {
                let entry = arb_node(Depth::new(4), &buffers);
                entry.prop_map(move |entry| Program {
                    buffers: buffers.clone(),
                    workgroup_size,
                    entry,
                })
            },
        )
    })
}
```

The generator first picks the number of buffers and the
workgroup size. Then it generates the buffer declarations.
Then it generates the entry node, passing the buffer list so
the node generator can reference existing buffers by name
without inventing names that do not exist. The nested
`prop_flat_map` calls thread the generated values through the
construction.

The structural approach has a cost: it is more code than a
random-bytes generator. It has a benefit: the values it
produces are mostly valid, which means property tests actually
exercise the code under test rather than being rejected at
validation.

## Depth bounding

Recursive generators must bound their recursion. A generator
for `Node` that calls itself on nested nodes will recurse
unboundedly if not bounded. Proptest's generators are not
lazy; they generate the full value upfront, and unbounded
recursion produces programs too large to terminate.

```rust
pub fn arb_node(depth: Depth, buffers: &[BufferDecl]) -> impl Strategy<Value = Node> {
    let base = prop_oneof![
        Just(Node::Return),
        Just(Node::Nop),
        arb_store(buffers),
    ];

    if depth.exhausted() {
        return base.boxed();
    }

    let recursive = {
        let inner = arb_node(depth.decrement(), buffers);
        let inner_clone = inner.clone();
        prop_oneof![
            base,
            (arb_expr(), inner, inner_clone.prop_map(Some).boxed())
                .prop_map(|(cond, then, else_)| Node::If {
                    cond,
                    then: Box::new(then),
                    else_: else_.map(Box::new),
                }),
            // ... loops, composition, etc.
        ]
    };

    recursive.boxed()
}
```

The `Depth` type carries a counter. `exhausted()` returns true
when the counter is zero. `decrement()` produces a new `Depth`
with the counter reduced by one. When the counter is
exhausted, the generator falls back to the base case (non-recursive
Node variants).

The starting depth controls the typical size of generated
Programs. A depth of 4 produces Programs with up to roughly
4 levels of nesting, which is representative of real user
Programs. A depth of 20 produces Programs so deep that
validation usually rejects them, which defeats the purpose.
Pick a depth that balances coverage against generation cost.

## Weighting the choices

`prop_oneof!` picks uniformly from its alternatives by
default. Uniform picking means the generator produces complex
shapes (If, Loop, nested compositions) as often as simple ones
(Return, Nop). Complex shapes are interesting but expensive;
simple shapes are cheap and still valuable.

Weight the choices to favor simple shapes:

```rust
prop_oneof![
    5 => Just(Node::Return),
    5 => Just(Node::Nop),
    5 => arb_store(buffers),
    2 => arb_if_node(inner.clone(), buffers),
    2 => arb_loop_node(inner.clone(), buffers),
    1 => arb_composition_node(inner, buffers),
]
```

The weights bias the generator toward simple nodes without
eliminating complex ones entirely. A generator weighted 5:5:5:2:2:1
produces about 70% simple nodes, 22% control flow, 5%
composition. The distribution can be tuned based on what the
property test is exercising.

Without weighting, the generator produces Programs that are
almost all complex, which makes shrinking slow (proptest has
to shrink through many nested layers) and makes debugging
hard (failing cases are large).

## Covering rare variants

A naive generator covers the common variants well and the
rare variants poorly. `Atomic` nodes appear in a few percent
of generated Programs if left to default weighting, which
means property tests exercise them rarely and bugs in atomic
handling go unnoticed.

The fix is to explicitly raise the weight of rare variants:

```rust
prop_oneof![
    5 => Just(Node::Return),
    5 => arb_store(buffers),
    3 => arb_atomic(buffers),   // boosted to ensure coverage
    2 => arb_workgroup_barrier(),
    // ...
]
```

Boosting rare variants costs a little coverage in the common
path but gains a lot in the rare path. The trade-off is
worth it because the rare paths are where bugs hide.

## Using archetypes in generators

Generated inputs in property tests can be further improved by
including archetype values. Instead of generating fully
random inputs for every operand, the generator includes
known-bad values from the archetype catalog with some
probability:

```rust
pub fn arb_u32_value() -> impl Strategy<Value = u32> {
    prop_oneof![
        1 => Just(0u32),
        1 => Just(1u32),
        1 => Just(u32::MAX),
        1 => Just(u32::MAX - 1),
        1 => Just(0x55555555),
        1 => Just(0xAAAAAAAA),
        1 => Just(0xDEADBEEF),
        1 => Just(0xCAFEBABE),
        1 => Just(0x80000000),
        10 => any::<u32>(),
    ]
}
```

The strategy picks from a set of specific archetype values
with high probability, and otherwise generates fully random
u32. The effect is that property tests exercise the archetype
values frequently while still sampling the broader input
space.

## Shrinking

When a property test fails, proptest shrinks the failing
input to the smallest case that still fails. Shrinking is how
property test failures become actionable: a large random
Program that fails is useless for debugging; a small shrunk
Program is a clear reproducer.

Proptest's shrinking works automatically for values built with
the standard strategies. It walks the generation tree and
tries simpler alternatives at each level. For structural
generators written compositionally, shrinking usually works
well out of the box: it reduces the number of buffers, the
depth of nesting, the values of leaf inputs, until the
failing case is minimal.

For generators that use `prop_map` with complex transformations,
shrinking may not work as well. If the transformation is not
reversible, proptest cannot shrink past it. The fix is usually
to keep the generator compositional — use `prop_flat_map` to
thread state rather than `prop_map` to transform after the
fact.

When shrinking is not producing small failing cases, the
generator needs restructuring. See the proptest documentation
for the details of shrinking semantics.

## Coverage metrics for generators

A generator's quality can be measured by what it covers. Vyre
tracks:

- **Which Expr variants appear in generated Programs.**
- **Which Node variants appear.**
- **What distribution of program sizes is produced.**
- **What fraction of generated Programs are valid (pass
  validation) versus invalid.**

A generator that produces 99% invalid Programs is wasting
effort — most cases never reach the code under test. A
generator that produces 100% valid Programs but missing some
variants is missing coverage. The target is high validity
(above 80%) with full variant coverage (every variant appears
in at least a small percentage of programs).

Vyre tracks these metrics in a dedicated test:

```rust
#[test]
fn generator_coverage_meets_targets() {
    let mut variant_counts = HashMap::new();
    let mut valid_count = 0;

    for _ in 0..10_000 {
        let program = arb_program().new_tree(&mut test_runner).unwrap().current();
        if validate(&program).is_empty() {
            valid_count += 1;
        }
        count_variants(&program, &mut variant_counts);
    }

    assert!(valid_count as f64 / 10_000.0 >= 0.80, "validity below 80%");

    for variant in all_node_variants() {
        let count = variant_counts.get(&variant).copied().unwrap_or(0);
        assert!(count > 0, "variant {:?} never generated", variant);
    }
}
```

The test generates 10,000 Programs, measures validity and
variant coverage, and asserts the targets are met. A
regression that weakens the generator trips this test.

## Generators for specific subjects

Different property tests need different generators. A round-trip
test needs arbitrary Programs; a determinism test needs
Programs that terminate quickly; a law-preservation test needs
Programs that compose ops in specific ways. Having one
`arb_program` strategy is a start, but serious property tests
often define their own strategies tailored to the test's
needs.

```rust
pub fn arb_short_running_program() -> impl Strategy<Value = Program> {
    // Shorter depth, tighter resource bounds, no loops.
    // Used by determinism tests that run programs many times.
    arb_program_with_config(GeneratorConfig {
        max_depth: 2,
        allow_loops: false,
        max_workgroup_size: 4,
    })
}

pub fn arb_compositional_program() -> impl Strategy<Value = Program> {
    // Programs with explicit composition shapes: diamonds,
    // chains, cross-products. Used by law preservation tests.
    arb_program_with_config(GeneratorConfig {
        force_composition: true,
        max_depth: 5,
        ..Default::default()
    })
}
```

Per-test generators are a sign the discipline is mature.
Early in a project, one shared generator is enough. As the
suite grows, tailored generators let each property test focus
on its specific distribution.

## Summary

Property test quality depends on generator quality. Good
generators are structural, depth-bounded, weighted toward
simple shapes, explicitly cover rare variants, include
archetype values, produce mostly valid outputs, and shrink
well. Coverage metrics catch generator drift. Per-test
tailored generators let serious property tests focus on their
specific needs.

Next: [Differential fuzzing](differential-fuzzing.md).
