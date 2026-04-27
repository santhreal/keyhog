# Collection Operations

## The algorithms you do not write

Every GPU program, at some point, needs to sort. Or filter. Or
reduce an array to a sum. Or compute a prefix sum. Or scatter values
to indexed positions. Or gather values from indexed positions. These
are not domain-specific operations. They are the *connective tissue*
of parallel programming — the algorithms that sit between the
domain-specific computation and the result the user sees.

A DFA scanner produces unsorted match rows in atomic-append order.
Before the user sees them, they must be sorted. A taint analysis
produces a visited bitmap per source node. Before the user sees
reachable sinks, the bitmap must be reduced (OR across sources) and
filtered (extract set bits). A tokenizer produces per-byte token
types. Before the scanner uses them, the token boundaries must be
identified by scanning for transitions (a prefix-sum variant). At
every stage of every pipeline, collection operations are doing the
work that makes the domain-specific output usable.

On the CPU, these operations are trivial. `sort()` is in the
standard library. `filter()` is a one-liner. `sum()` is a fold.
Prefix sum is a loop. Nobody thinks about them because they are
solved.

On the GPU, these operations are not trivial. Parallel sort is a
research topic with fifty years of literature. Parallel prefix sum
requires careful barrier placement and workgroup coordination.
Parallel filter (stream compaction) composes prefix sum with
scatter. Each algorithm has optimal and suboptimal implementations,
and the difference matters: a naive parallel sort is O(N^2) where
bitonic sort is O(N log^2 N), and the constant factor depends on
memory access coalescing, workgroup size, and register pressure.

Every GPU project reimplements these algorithms. Every
reimplementation makes different tradeoffs. Every reimplementation
is tested to whatever standard the project had time for. The
algorithms are well-known and well-studied — there is no research
contribution in reimplementing bitonic sort for the hundredth time.
The contribution is implementing it once, correctly, with
conformance coverage, and making it composable with everything else.

That is what vyre's collection operations provide.

## Why collection ops are last

The collection module is currently empty. This is not an oversight;
it is a sequencing decision. Collection operations are the most
architecturally demanding compound ops in vyre because they require
features that simpler compound ops do not:

**Workgroup memory.** Bitonic sort swaps elements between
invocations within a workgroup. The swap buffer is workgroup-local
shared memory. The IR's `BufferAccess::Workgroup` support must be
fully mature before sort can be expressed as an `ir::Program`.

**Barriers.** Every phase of bitonic sort, every level of parallel
prefix sum, every pass of stream compaction requires a barrier
between phases. The invocations within a workgroup must synchronize
after each compare-and-swap round. The IR's `Node::Barrier` must
lower correctly on every backend.

**Multi-dispatch orchestration.** For arrays larger than one
workgroup, sort and prefix sum require multiple dispatches. A
workgroup can sort 256 elements internally, but sorting 1 million
elements requires a merge phase that spans workgroups — which means
a second dispatch, because barriers do not synchronize across
workgroups. The engine that orchestrates these dispatches is more
complex than the ops themselves.

**Atomic coordination.** Scatter-add (accumulating values at indexed
positions) uses atomics. Filter uses an atomic counter for the
compacted output position. The IR's atomic support must be correct
under contention.

These features are all supported by the IR specification. They are
all implemented in the WGSL lowering. But they are exercised by
relatively few ops today (mostly in the BFS shader and the scatter
engine). Collection ops will be the stress test that proves these
features work at scale.

The sequencing is: primitives first (proven), then decode/hash/string
(simple compositions), then graph/match/compression (complex but
single-dispatch), then collection ops (complex, multi-dispatch,
barrier-heavy, workgroup-memory-dependent). Each layer proves the
infrastructure the next layer needs.

## Planned operations

### collection.sort

**Planned identifier:** `collection.sort`

**Planned signature:** `(U32[]) -> U32[]`

**Specification:** Bitonic merge sort. Sorts an array of `u32`
values in ascending unsigned order.

Bitonic sort is a *sorting network* — a fixed sequence of
compare-and-swap operations whose structure depends only on the
input size, not the input values. This is the critical property for
GPU execution: every invocation performs the same operations in the
same order, with no data-dependent branching. The GPU's SIMT
execution model handles this perfectly because there is no warp
divergence.

**Algorithm structure:**

Bitonic sort proceeds in phases. Phase `k` (for k from 1 to
log2(N)) merges adjacent bitonic sequences of length `2^k` into
sorted sequences. Each phase has `k` steps. Each step is a
parallel pass where invocations compare elements at a specific
distance and swap if out of order:

```text
for k in 1..=log2(N):
    for j in (0..k).rev():
        distance = 1 << j
        for each invocation i in parallel:
            partner = i XOR distance
            if partner > i:
                ascending = ((i >> k) & 1) == 0
                if ascending and data[i] > data[partner]:
                    swap(data[i], data[partner])
                elif not ascending and data[i] < data[partner]:
                    swap(data[i], data[partner])
        Barrier
```

The total number of compare-and-swap rounds is
`log2(N) * (log2(N) + 1) / 2`. For N = 1024, that is 55 rounds.
Each round is one barrier-separated parallel pass.

**Workgroup-local sort:** For arrays up to workgroup size (e.g., 256
elements), the entire sort fits in one dispatch using workgroup
memory. The elements are loaded from global memory into workgroup
memory, sorted in-place with barriers between rounds, and written
back to global memory.

**Global sort (future):** For arrays larger than one workgroup, the
sort requires a multi-dispatch merge phase. Each workgroup sorts its
local chunk, then a series of merge dispatches combine adjacent
chunks. This is orchestrated by the engine layer, not by the op
itself. The op handles the within-workgroup sort; the engine handles
the cross-workgroup merge.

**Determinism:** Bitonic sort is deterministic by construction. The
sorting network is fixed. The compare-and-swap operations use
unsigned integer comparison, which is bit-exact. The sort order for
equal elements depends on their initial positions, not on scheduling.
Two backends that implement the same network produce the same output
for the same input.

**Stability:** Bitonic sort is NOT stable (equal elements may change
relative order). If stable sort is needed, it will be a separate op
(`collection.stable_sort`) using a different algorithm (merge sort
or radix sort).

### collection.filter

**Planned identifier:** `collection.filter`

**Planned signature:** `(U32[], U32[]) -> U32[]` (values, predicate
mask → compacted values)

**Specification:** Stream compaction. Given an array of values and a
parallel boolean mask, produce a dense array containing only the
values where the mask is non-zero, preserving the original order of
retained elements.

**Algorithm:** Stream compaction decomposes into two steps:

1. **Prefix sum** of the mask: compute the exclusive prefix sum of
   the mask array. `prefix[i]` gives the output index where
   `values[i]` should be written if it is retained.

2. **Scatter** the retained values: for each `i` where
   `mask[i] != 0`, write `values[i]` to `output[prefix[i]]`.

This means `collection.filter` depends on `collection.scan` and
`collection.scatter`. The composition is explicit: the filter op
calls scan, uses the result to compute scatter indices, and calls
scatter. The IR inlines all of it.

**Why filter is important:** Every pipeline stage produces
intermediate results that include garbage, duplicates, or
out-of-range values. DFA match rows include duplicates (multiple
invocations discovering the same match). Taint analysis bitmaps
include false reachability. Decode results include failed regions.
Filter is how the pipeline cleans up intermediate results before
the next stage.

### collection.reduce

**Planned identifier:** `collection.reduce`

**Planned signature:** `(U32[]) -> U32`

**Specification:** Parallel reduction. Reduce an array of `u32`
values to a single value using a specified binary operation. The
supported operations are: sum, min, max, count (number of non-zero
elements), bitwise OR, bitwise AND.

**Algorithm:** Tree reduction. In each round, adjacent pairs of
elements are combined. After `log2(N)` rounds, one value remains.
The tree structure is fixed (canonical balanced binary tree), so the
result is deterministic regardless of GPU scheduling.

**Determinism for sum:** Wrapping `u32` addition is associative and
commutative. The tree reduction produces the same result as a
sequential sum because wrapping addition has no precision loss. This
is unlike floating-point reduction, where the order of additions
affects the result. Integer reduction is inherently deterministic.

### collection.scan

**Planned identifier:** `collection.scan`

**Planned signature:** `(U32[]) -> U32[]`

**Specification:** Parallel prefix sum (exclusive or inclusive). The
output at position `i` is:

- **Exclusive:** the sum of elements at positions `0..i`. Position 0
  is 0.
- **Inclusive:** the sum of elements at positions `0..=i`.

**Algorithm:** Blelloch scan (work-efficient parallel prefix sum).
Two phases: the up-sweep (reduce phase) and the down-sweep (scatter
phase). Each phase is `log2(N)` rounds with barriers between rounds.
Total work is O(N), total depth is O(log N).

**Why prefix sum is foundational:** Prefix sum is to GPU programming
what `for` loops are to CPU programming. Stream compaction uses it.
Histogram equalization uses it. Load balancing uses it. Radix sort
uses it. Sparse matrix operations use it. If vyre's prefix sum is
correct and fast, every algorithm built on it inherits both
properties.

### collection.scatter

**Planned identifier:** `collection.scatter`

**Planned signature:** `(U32[], U32[], U32[]) -> U32[]` (values,
indices, output → indexed write)

**Specification:** Index-directed write. For each position `i`,
write `values[i]` to `output[indices[i]]`. Out-of-bounds indices
(where `indices[i] >= output.len()`) are no-ops per vyre's OOB
policy.

**Collision handling:** If two positions scatter to the same output
index, the result depends on the variant:

- **scatter (last-writer-wins):** the output contains one of the
  values, but which one is nondeterministic. This variant is
  acceptable only when the caller guarantees unique indices.
- **scatter_add (accumulating):** the output contains the sum of all
  values scattered to that index, using `atomicAdd`. This variant
  is deterministic because wrapping addition is commutative and
  associative.

**Relationship to the scatter engine:** `engine::scatter` uses
scatter-write to distribute DFA matches into per-rule bitmaps. The
engine currently contains its own inline scatter implementation.
When `collection.scatter` exists, the engine can compose it instead
of reimplementing the algorithm.

### collection.gather

**Planned identifier:** `collection.gather`

**Planned signature:** `(U32[], U32[]) -> U32[]` (source, indices →
gathered values)

**Specification:** Index-directed read. For each position `i`,
`output[i] = source[indices[i]]`. Out-of-bounds indices return zero
per vyre's OOB policy.

**Why gather:** Gather is the read complement of scatter. Lookup
tables, permutations, indirect indexing, and all forms of "read from
computed position" are gather operations. The DFA transition table
lookup (`transitions[state * 256 + byte]`) is a gather. Making
gather explicit as a named op clarifies intent and enables the IR
optimizer to recognize and optimize gather patterns.

## The relationship between collection ops and engines

Collection ops are primitives that engines compose. The relationship
is:

```text
collection.scan + collection.scatter = collection.filter
collection.sort + collection.filter = deduplication
engine::scatter = collection.scatter + domain-specific mapping
engine::dfa readback = collection.sort (match deduplication)
engine::dataflow = collection.reduce (convergence detection)
```

When collection ops exist, engines become thinner. The scatter engine
calls `collection.scatter` instead of reimplementing atomic scatter.
The DFA engine calls `collection.sort` for match deduplication
instead of relying on host-side sort after readback. The dataflow
engine calls `collection.reduce` for convergence detection instead
of an ad-hoc atomic flag.

This is the composability payoff. The engines lose nothing — the
performance is identical because the collection ops inline at
lowering time (Category A). The engines gain composability,
testability, and portability. A bug in scatter is found in
`collection.scatter`'s conformance tests, not in a scanner's
production run.

## What the conformance suite will verify

**Sort:**
- Already-sorted input. Expected: unchanged.
- Reverse-sorted input. Expected: correctly sorted.
- All-equal input. Expected: unchanged.
- Single element. Expected: unchanged.
- Power-of-two sizes and non-power-of-two sizes (padding behavior).
- Random input, 100 runs. Expected: identical sorted output.

**Filter:**
- All-zero mask. Expected: empty output.
- All-one mask. Expected: identical to input.
- Alternating mask. Expected: every other element.
- Single retained element at the end. Expected: `[last_element]`.

**Reduce:**
- Empty input. Expected: identity element (0 for sum, MAX for min,
  0 for OR, MAX for AND).
- Single element. Expected: that element.
- Known sum (1 + 2 + ... + N = N*(N+1)/2). Expected: exact value.
- Overflow. Expected: wrapping (for sum).

**Scan:**
- All zeros. Expected: all zeros (exclusive).
- All ones. Expected: `[0, 1, 2, 3, ...]` (exclusive).
- Known prefix sums against hand-computed values.

**Scatter:**
- Unique indices. Expected: correct placement.
- Out-of-bounds indices. Expected: no-op for those positions.
- scatter_add with collisions. Expected: correct sums.

**Determinism:** Every op, same input, 100 runs. Expected: identical
output.

## Permanence

Operation identifiers listed in this chapter are planned, not yet
permanent. They become permanent when published with conformance
coverage.

Once published, the algorithms are permanent. Bitonic sort uses the
same sorting network forever. Blelloch scan uses the same up-sweep/
down-sweep structure forever. These are mathematical constructions.
They do not have versions. They do not evolve.

Optimizations may improve constant factors (better workgroup
utilization, fewer barriers via warp-level primitives) but must not
change the output. A sort that produces `[1, 2, 3]` today produces
`[1, 2, 3]` in every future version. If a new sort algorithm
produces different tie-breaking behavior for equal elements, it is a
new op, not a new version.
