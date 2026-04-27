# Graph Operations

Graph operations provide GPU-accelerated traversal primitives over
CSR-encoded directed graphs. They are the algorithmic foundation of
interprocedural analysis in vyre, supporting taint tracking,
reachability queries, and data-flow propagation.

## Every program is a graph

Before a security scanner can answer "does user input reach
`eval()`?", it must answer a prior question: what is the structure
of this program? Which functions call which other functions? Which
variables flow into which expressions? Which modules import which
dependencies? These questions are graph questions. The program is a
graph. The call relationships are edges. The data flows are edges.
The import chains are edges. The security question — "can an
attacker's input reach a dangerous function?" — is a reachability
question on that graph.

This is not a metaphor. Taint analysis, the most important
interprocedural security analysis technique, is literally
breadth-first search. You start from a source (user input), you
follow edges (data flows, function calls, assignments), and you
check whether you can reach a sink (eval, exec, SQL query, file
write, DOM mutation). If the path exists, the vulnerability exists.
If a sanitizer sits on the path, the path is blocked. If the
sanitizer has a bypass, the path is unblocked. Every real-world
taint analysis engine — from academic frameworks to commercial
SAST tools — is a graph traversal engine with domain-specific
transfer functions.

The same structure appears in dependency analysis (can a compromised
npm package reach your production code?), permission propagation
(does this IAM role transitively grant admin access?), malware
analysis (does this binary's call graph reach a known-malicious
API?), and supply chain verification (is this artifact reachable
from a trusted build pipeline?). Different domains, same algorithm:
start from sources, propagate along edges, report what you reach.

GPU hardware is built for this. A graph with 100,000 nodes has
100,000 independent starting points for BFS. Each starting point
is one GPU invocation. A GPU with 10,000 active invocations
processes 10,000 BFS traversals simultaneously. The traversal at
each level is also parallel: every node in the current frontier
expands its neighbors independently. Graph algorithms have both
inter-traversal and intra-level parallelism, and GPUs exploit both.

vyre provides graph operations as Layer 2 compound ops because graph
traversal is the algorithmic foundation of interprocedural security
analysis, and every tool that does interprocedural analysis needs
the same primitives: a graph representation, a BFS traversal, a
reachability query. Reimplementing these per tool is wasted effort
and a source of divergence. vyre's graph ops provide a single
tested implementation that every tool inherits.

## The CSR representation

Every graph algorithm on the GPU starts with the same question: how
do you store a graph in flat arrays? Adjacency matrices waste space
(O(N^2) for a graph with N nodes, regardless of edge count).
Adjacency lists use pointer-based linked lists, which GPUs cannot
traverse efficiently (random memory access, no coalescing, cache
misses on every hop).

Compressed Sparse Row (CSR) is the answer the GPU computing
community converged on decades ago. CSR stores a directed graph as
three flat arrays:

```text
offsets:   [u32; node_count + 1]
targets:   [u32; edge_count]
node_data: [u32; node_count]
```

The `offsets` array is an index into `targets`. The outgoing edges
of node `n` are `targets[offsets[n] .. offsets[n+1]]`. The `offsets`
array is monotonically non-decreasing, starts at 0, and ends at
`edge_count`. The `node_data` array carries per-node metadata —
in vyre's case, the node's role in the analysis (source, sink,
sanitizer, normal).

CSR is optimal for GPU traversal because the memory access pattern
is coalesced. Adjacent invocations processing adjacent nodes read
adjacent regions of `offsets` (one read per node, sequential
addresses) and then adjacent regions of `targets` (one read per
edge, sequential within each node's edge range). The GPU's memory
controller can service these reads in bulk, hiding latency behind
parallelism.

CSR is also compact. A graph with N nodes and E edges uses
`N + 1 + E + N` words of storage: `N+1` for offsets, `E` for
targets, `N` for node_data. No pointers, no padding, no
per-node allocation overhead. The entire graph is three contiguous
GPU buffers.

### Construction

`to_csr(node_count, edges)` converts a list of `(source, target)`
directed edges into a `CsrGraph`. The algorithm is:

1. Count outgoing edges per node (histogram).
2. Compute prefix sum of the histogram to get `offsets`.
3. Scatter edges into `targets` at the positions determined by
   `offsets`, decrementing a per-node counter to fill each node's
   edge range.

Invalid edges (source or target outside `0..node_count`) are
silently omitted by `to_csr` and produce an error in `try_to_csr`.
The silent omission in `to_csr` is a deliberate robustness choice:
a malformed graph extracted from an untrusted program should not
crash the scanner; it should be scanned with whatever valid edges
exist.

### Validation

`CsrGraph::validate()` enforces the structural invariants that the
GPU shader assumes. Every invariant corresponds to a specific
failure mode in the shader if violated:

| Invariant | What breaks without it |
|-----------|----------------------|
| `offsets.len() == node_count + 1` | The shader reads past the end of the offsets buffer, triggering OOB (returns zero, causing incorrect neighbor enumeration). |
| `offsets` is monotonically non-decreasing | The shader computes a negative edge range (`offsets[n+1] < offsets[n]`), which wraps around as unsigned and enumerates millions of garbage edges. |
| `offsets[node_count] == targets.len()` | The shader reads valid offsets that point past the end of the targets buffer. |
| Every target is `< node_count` | The shader follows an edge to a nonexistent node, reading garbage from `node_labels` and `edge_offsets`. |

A CSR graph that fails validation must not be dispatched. The
validation errors are actionable: they identify which invariant was
violated, which array position contains the invalid value, and what
the valid range is.

## Operations

### graph.bfs

**Identifier:** `graph.bfs`

**Current state:** IR-first. `graph.bfs` is implemented as an
`ir::Program` composition using workgroup queues, atomic visited
bitmaps, and conditional frontier expansion. It lowers through the
standard vyre IR pipeline and participates in the conformance parity
harness.

**Signature:** `(Bytes) -> Bytes` (simplified; actual buffer
interface is complex)

**What this operation does:** Multi-source breadth-first search
over a CSR graph with labeled nodes. One GPU invocation per source
node. Each invocation runs a complete BFS from its assigned source,
expanding level by level up to a configurable maximum depth. When
the traversal reaches a sink node, it emits a finding. When it
reaches a sanitizer node, it stops expanding along that path.

**Why one invocation per source, not one invocation per node:**
There are two natural parallelization strategies for multi-source
BFS. The first is source-parallel: each invocation handles one
complete BFS from one source. The second is frontier-parallel: all
sources share a single frontier, and each invocation expands one
node from the frontier.

vyre uses source-parallel because it eliminates cross-invocation
synchronization during traversal. Each invocation has its own
visited bitmap, its own frontier queue, its own depth counter. No
barriers, no atomic coordination (except for finding emission), no
cross-workgroup communication. The invocations are completely
independent.

The cost is redundant work: if two sources share a subgraph, both
invocations traverse it independently. The benefit is simplicity,
correctness, and determinism. Frontier-parallel BFS requires
careful synchronization to avoid lost updates, duplicate frontier
entries, and nondeterministic traversal order. Source-parallel BFS
has none of these problems.

For the graph sizes encountered in security scanning (typically
10K–1M nodes per analyzed program), source-parallel BFS saturates
the GPU's compute units without needing frontier-parallel
optimization. For billion-node graphs (social networks, web
graphs), frontier-parallel would be necessary, and vyre's
architecture supports adding it as a separate engine without
changing the source-parallel BFS op.

**Buffer layout:**

| Binding | Name | Access | Content |
|---------|------|--------|---------|
| 0 | `node_labels` | ReadOnly | Per-node metadata (role encoded in bits 16..23) |
| 1 | `edge_offsets` | ReadOnly | CSR offsets array |
| 2 | `edge_targets` | ReadOnly | CSR targets array |
| 3 | `source_nodes` | ReadOnly | Array of source node IDs to start BFS from |
| 4 | `findings` | ReadWrite | Output: `vec4<u32>(source, sink, depth, source_idx)` |
| 5 | `finding_count` | ReadWrite | Atomic counter for finding emission |
| 6 | `params` | Uniform | Configuration: `{num_sources, num_nodes, max_findings, max_depth, words_per_source}` |
| 7 | `visited_set` | ReadWrite | Per-source visited bitmaps |

**Node labels:**

The label type occupies bits 16..23 of each node's label word. The
remaining bits are available for domain-specific metadata (e.g.,
language-specific node type, file ID, line number).

| Value | Role | Traversal behavior |
|-------|------|-------------------|
| 0 | Normal | Traversed; no special action |
| 1 | Source | BFS starts here; if reached from another source, not reported as finding |
| 2 | Sink | Reaching this from a source emits a finding |
| 3 | Source AND sink | Both roles simultaneously |
| 4 | Sanitizer | Blocks propagation — outgoing edges are not followed |

The sanitizer role is critical for reducing false positives. A taint
analysis that reports every source-to-sink path without considering
sanitizers produces thousands of findings that are not
vulnerabilities because the data was sanitized before reaching the
sink. The BFS shader checks the sanitizer label and skips the node's
outgoing edges, pruning the entire subgraph beyond the sanitizer.

**The frontier queue:**

Each invocation maintains a private frontier queue as a fixed-size
array in registers/local memory:

```text
var queue: array<u32, 4096>;
var queue_head: u32 = 0;
var queue_tail: u32 = 1;
queue[0] = start_node;
```

The queue size (4096 entries) is a compile-time constant that limits
the maximum frontier width per source. For security scanning
workloads, 4096 is sufficient because the graphs are sparse
(function call graphs have low average degree). For denser graphs,
the constant can be increased at the cost of register pressure.

If the frontier overflows (more than 4096 nodes at one BFS level),
the excess nodes are silently dropped. This is a known limitation
documented in the op's specification. The overflow is detectable
(the queue wraps and `queue_tail` exceeds `MAX_BFS_QUEUE`) but not
currently reported to the host. A future version may add an overflow
counter to the output.

**The visited bitmap:**

Each source node gets its own visited bitmap:

```text
visited_set[source_idx * words_per_source + node / 32] bit (node % 32)
```

where `words_per_source = ceil(num_nodes / 32)`. Setting a bit is
an atomic OR to handle the case where two sources' BFS invocations
run on the same workgroup and share the same `visited_set` buffer.

Why per-source bitmaps instead of a shared bitmap: if all sources
shared one visited bitmap, the first source to reach a node would
mark it visited, and all other sources would skip it. This would
cause sources to miss findings that pass through shared subgraphs.
Per-source bitmaps ensure each source's BFS is independent.

**Findings output:**

```text
findings[idx] = vec4<u32>(source_node, sink_node, depth, source_idx)
```

Findings are appended atomically via `atomicAdd(&finding_count, 1)`.
The atomic append means findings are written in nondeterministic
order (depending on GPU scheduling). The host must sort findings
into a deterministic order after readback. The canonical sort key is
`(source_node, sink_node, depth)`.

If `finding_count` exceeds `max_findings`, excess findings are not
written but the counter continues incrementing, providing a total
finding count for diagnostics. The host can detect overflow by
comparing the counter value against `max_findings`.

**Workgroup size:** 64. One invocation per source node. A dispatch
of `ceil(num_sources / 64)` workgroups processes all sources.

### graph.reachability

**Identifier:** `graph.reachability`

**Current state:** Has both a CPU reference implementation and a GPU
path that delegates to `graph.bfs`.

**Signature:** `(Bytes) -> Bytes`

**What this operation does:** Multi-source reachability — a
higher-level interface over `graph.bfs`. Given a CSR graph, a list
of source nodes, and a maximum depth, compute all `(source, node,
depth)` tuples where `node` is reachable from `source` within
`max_depth` hops. Sanitizer nodes block traversal.

**The CPU reference:** `reachable_nodes()` is a pure-Rust
implementation of the same algorithm using `VecDeque` for the
frontier and `Vec<bool>` for visited state. It exists for two
purposes:

1. **Conformance oracle.** The GPU output must match the CPU output
   exactly (after sorting) for every valid CSR graph and source set.
   If they disagree on any input, the GPU shader has a bug.

2. **Fallback.** When no GPU is available, consumers can call the
   CPU reference directly. This is an application-level fallback,
   not a vyre-internal one — vyre itself does not fall back; it
   returns `Err(NoGpuAdapter)` and the application decides.

**Dependencies:** `graph.bfs` for GPU execution.

### graph.csr (not an Op)

`CsrGraph` is a data structure, not a GPU operation. It lives in
the graph module because every graph op consumes CSR input. The
construction (`to_csr`, `try_to_csr`) and validation
(`CsrGraph::validate()`) are host-side utilities that prepare data
for GPU dispatch. They are not `Op` implementations because they
run on the CPU and produce data, not `ir::Program` values.

## Beyond security scanning

Graph traversal was motivated by taint analysis, but graphs are everywhere:

- **Social network analysis.** Influence propagation, community detection,
  and friend-of-friend queries are BFS and connected-component algorithms
  on social graphs with billions of nodes. GPU BFS processes these at
  scale.

- **Supply chain analysis.** Dependency graphs for npm, PyPI, Maven, and
  Cargo form DAGs with millions of nodes. "Does this vulnerable package
  transitively affect my production code?" is a reachability query.

- **Knowledge graphs.** Entity-relationship graphs in databases, ontologies,
  and recommendation systems use BFS for path finding and PageRank for
  importance scoring.

- **Compiler analysis.** Control-flow graphs, data-flow graphs, and
  call graphs are the foundation of every compiler optimization. A GPU
  compiler built on vyre would use vyre's own graph ops for its analyses.

- **Network routing.** Shortest-path and reachability queries on network
  topologies are graph algorithms. GPU acceleration enables real-time
  routing table computation.

The graph ops are domain-agnostic traversal primitives. Taint analysis is
one application. Every application that needs to answer "what can I reach
from here?" on a large graph is a potential consumer.

## How graph ops compose with the rest of vyre

The graph ops are the foundation of the `engine::dataflow` engine.
The relationship between the layers is:

```text
Layer 1: primitive ops (bitwise, arithmetic, comparison)
    ↓ composed into
Layer 2: graph.bfs, graph.reachability
    ↓ orchestrated by
Layer 3: engine::dataflow (fixpoint iteration with transfer function)
    ↓ consumed by
Application: pyrograph (taint analysis with language-specific parsers)
```

Each layer adds domain knowledge without changing the layer below.

- **graph.bfs** knows about CSR traversal. It does not know about
  taint, about JavaScript, about call graphs. It traverses nodes
  and reports reachability.

- **engine::dataflow** knows about convergence. It dispatches
  `graph.bfs` (or a generalized fixpoint step) repeatedly until no
  new facts are discovered. It knows about transfer functions — the
  pluggable logic that decides whether a fact propagates across an
  edge. It does not know about specific languages or security
  domains.

- **pyrograph** knows about taint. It parses JavaScript (or Rust, or
  Python, or Go) into a control/data-flow graph, labels source nodes
  (user input), sink nodes (dangerous functions), and sanitizer
  nodes (input validation). It calls `engine::dataflow` and
  interprets the results as security findings. It does not know
  about GPU dispatch, CSR layout, or BFS implementation.

This separation is what makes each layer independently testable. The
graph ops can be tested with synthetic graphs that have nothing to
do with security. The dataflow engine can be tested with synthetic
transfer functions that have nothing to do with taint. pyrograph can
be tested with real code against known vulnerabilities. A bug in any
layer is localized to that layer.

## Migration to IR-first

The BFS shader is currently a monolithic WGSL string — 100+ lines
of hand-written shader code. Migrating it to an `ir::Program`
requires expressing every construct in IR terms:

| WGSL construct | IR equivalent |
|----------------|--------------|
| `var queue: array<u32, 4096>` | `BufferDecl` with `Workgroup` access and `count: 4096` |
| `while queue_head < queue_tail` | `Node::Loop` with dynamic bounds |
| `visited_set[...] \| start_bit` | `Expr::Atomic { op: AtomicOp::Or }` |
| `atomicAdd(&finding_count, 1)` | `Expr::Atomic { op: AtomicOp::Add }` |
| `if label_type == LABEL_SANITIZER { continue; }` | `Node::If` with early `Node::Return` or skip logic |
| `for (var e = edge_start; e < edge_end; e++)` | `Node::Loop { var: "e", from: edge_start, to: edge_end }` |

The IR supports all of these constructs. The migration is
mechanical: translate each WGSL statement to its IR equivalent,
verify the lowered WGSL matches the original, run the parity
harness against the CPU reference.

The payoff of migration:

1. **Retargeting.** The BFS runs on SPIR-V, PTX, Metal — any backend
   that lowers vyre IR. Today it only works on WGSL/wgpu.

2. **Optimization.** The IR optimizer can specialize the BFS for
   specific graph structures. A graph with no sanitizers can have
   the sanitizer check eliminated. A graph with a known maximum
   depth can have the depth check hoisted.

3. **Composition.** The BFS can be called from a composed program.
   A taint analysis that needs to run BFS and then immediately
   evaluate results can compose both into one dispatch, eliminating
   the intermediate buffer.

4. **Conformance.** The BFS participates in the parity harness with
   generated graph inputs — random graphs, degenerate graphs
   (disconnected, complete, star, chain, DAG, cyclic), boundary
   cases (empty graph, single node, maximum depth reached).

## What the conformance suite will verify

When graph ops are migrated to IR-first:

**Structural archetypes:**
- Empty graph (0 nodes, 0 edges). Expected: no findings.
- Single node, self-loop. Expected: no finding (source == sink not
  reported unless node has both labels).
- Complete graph (all-to-all edges). Expected: every sink reachable
  from every source at depth 1.
- Linear chain (A→B→C→...→Z). Expected: sinks reachable at
  predictable depths.
- Star graph (one hub, N spokes). Expected: all spokes reachable at
  depth 1 from hub.
- Binary tree. Expected: depths match tree level.
- DAG with diamond merge. Expected: shortest-path depth reported.
- Graph with a cycle. Expected: BFS terminates (visited bitmap
  prevents infinite loop). Cycle does not produce duplicate findings.
- Disconnected components. Expected: sources in one component do
  not reach sinks in another.

**Sanitizer archetypes:**
- Sanitizer on the only path from source to sink. Expected: no
  finding.
- Sanitizer on one path but not another. Expected: finding via the
  unsanitized path.
- Sanitizer that is also a sink (label 4 and 2 simultaneously — if
  allowed by encoding). Expected: sanitizer behavior takes
  precedence (no finding, no further traversal).

**Scale archetypes:**
- Graph with exactly `MAX_BFS_QUEUE` frontier nodes at one level.
  Expected: all processed correctly.
- Graph with `MAX_BFS_QUEUE + 1` frontier nodes. Expected: overflow
  — some nodes silently dropped. The test asserts the shader does
  not crash.
- Graph where `num_sources * words_per_source` approaches buffer
  size limits. Expected: either successful dispatch or structured
  resource-exceeded error.

**Determinism:**
- Same graph, same sources, 100 runs. Expected: identical findings
  (after sorting) every time.
- Same graph, different dispatch dimensions (varying workgroup
  count). Expected: identical findings.

## Permanence

The operation identifiers (`graph.bfs`, `graph.reachability`) are
permanent. The CSR format (offsets, targets, node_data with the
specified invariants) is permanent. The node label encoding (role in
bits 16..23, values 0–4 with the specified traversal semantics) is
permanent. The finding format
`vec4<u32>(source, sink, depth, source_idx)` is permanent. The
sanitizer semantics (label type 4 blocks outgoing edge traversal)
are permanent.

Future graph ops — connected components, PageRank, topological sort,
shortest path — will be added as new identifiers. They will consume
the same CSR format and the same node label encoding. The existing
ops will not change behavior.

## See also

- [Operations Overview](../overview.md)
- [Match Operations](../match_ops/overview.md)
- [Engine Dataflow](../../engine/dataflow.md)

