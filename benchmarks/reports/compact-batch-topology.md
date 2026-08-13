# Compact coalesced batch topology

Small CPU/SIMD work lanes now reference ranges in one flat chunk-index buffer. Large chunks remain independent lane descriptors.

| Topology metric | Legacy | Candidate | Change |
|---|---:|---:|---:|
| Heap allocations | 42 | 2 | 95.23809523809523% fewer, 21x reduction |
| Allocated bytes | 17,152 | 8,960 | 47.76119402985074% fewer |
| Small lanes | 32 | 32 | unchanged |
| Stored small indices | 1,024 | 1,024 | unchanged |
| Small-lane byte ceiling | 512 KiB | 512 KiB | unchanged |

The allocation counter wraps the production topology builder for 1,024 one-byte chunks, the 64 KiB small-chunk threshold, and 32 workers. The legacy reference executes the retired per-lane ownership algorithm in the same process. The candidate owns one flat index vector and one lane descriptor vector instead of one vector for every small lane.

Chunk order, worker partitioning, large-chunk isolation, and the 512 KiB lane ceiling retain exact regression coverage. The topology cases exercise the shared CPU/SIMD scheduling plan without requiring accelerator hardware.

This receipt measures topology-construction allocations. It does not claim a 21x whole-scan wall-time improvement or allocator-internal retained-memory behavior.

Receipt: [`compact-batch-topology.json`](compact-batch-topology.json)
