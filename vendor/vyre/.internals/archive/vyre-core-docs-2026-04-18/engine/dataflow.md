# Dataflow Engine

## Overview

The dataflow engine runs graph fixpoint computations on the GPU. Its primary
consumer is taint analysis: start from source nodes, propagate facts through a
control/data-flow graph, and report reached sink nodes.

## CSR Graph Format

Graphs use compressed sparse row storage:

```text
offsets: len node_count + 1
targets: len edge_count
node_data: len node_count
neighbors(node) = targets[offsets[node] .. offsets[node + 1])
```

`offsets` must be nondecreasing, `offsets[0] = 0`, and
`offsets[node_count] = edge_count`. Every target must be `< node_count`.

## Multi-Source BFS

The standard reachability engine runs one frontier per source. Visited state is a
bitmap with `words_per_source = ceil(node_count / 32)`.

```text
visited[source_idx][node / 32] bit node%32
```

A source starts with its source node visited. Traversal expands edges until the
frontier is empty or `max_depth` is reached.

## Level-Synchronous Iteration

The portable execution model is level-synchronous:

1. Process the current frontier.
2. Apply the transfer function to candidate edges.
3. Atomically mark newly reached nodes in the next frontier.
4. Detect whether any new node was added.
5. Stop when no additions occur or the configured depth bound is reached.

Global synchronization between levels requires separate dispatches or a backend
runtime loop. A single dispatch may process bounded depth only when the generated
program can prove workgroup-local synchronization is sufficient.

## Convergence Detection

Convergence is represented by an atomic changed flag or frontier count. Each
newly visited node atomically sets `changed = 1` or increments the next-frontier
count. When the host observes zero changes after a level, the fixpoint is
complete.

## Transfer Function

The transfer function decides whether a fact flows across an edge. It is
pluggable through an `Op` and receives at minimum:

```text
source_id, current_node, target_node, edge_or_node_metadata
```

It returns `0` to block propagation or `1` to allow propagation. More advanced
transfer functions may return a transformed fact word.

Community-provided TOML rules may define source labels, sink labels, sanitizer
patterns, and transfer-function parameters. TOML affects inputs to the engine; it
does not change IR semantics.

## Taint Analysis Contract

For taint analysis, `node_data` encodes node role:

```text
0 = normal
1 = source
2 = sink
3 = source and sink
```

The engine reports `(source, sink, depth)` for every sink reached from a source
within `max_depth`. Output order must be deterministic after readback sorting.

## Validation

Reject malformed CSR arrays, source IDs outside the graph, `source_count *
node_count` overflow, output capacity overflow, and resource sizes that exceed
backend limits.
