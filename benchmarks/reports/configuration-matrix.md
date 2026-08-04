# KeyHog configuration matrix

Measured on **AMD Ryzen 9 9950X 16-Core Processor** with **NVIDIA GeForce RTX 5090**, 32 logical cores, 15,000 fixtures, 3,000 labeled positives, and 2,430,321 input bytes. Scanner: `KeyHog v0.5.63`. The tracked source tree was clean.

#### Full scan by execution route

All rows use the default detection policy with incremental cache and daemon off. The automatic row records the requested policy, but the benchmark result does not bind the selected persisted route, so it is not routing proof. GPU rows include acquisition and full scanner startup on this small corpus; they are not GPU kernel crossover measurements.

| Requested route | Wall | Throughput | Peak RSS | F1 |
|---|---:|---:|---:|---:|
| Hyperscan/SIMD | 929 ms | 2.49 MB/s | 997 MiB | 0.9447 |
| Pure-Rust CPU | 1.03 s | 2.26 MB/s | 893 MiB | 0.9447 |
| CUDA | 2.21 s | 1.05 MB/s | 1517 MiB | 0.9447 |
| WGPU | 2.13 s | 1.09 MB/s | 1403 MiB | 0.9447 |
| Automatic | 1.04 s | 2.23 MB/s | 996 MiB | 0.9447 |

#### Detection policy on Hyperscan/SIMD

The route, cache, daemon state, corpus, and host remain fixed. Presets change detection work, so compare precision and recall as well as time.

| Policy | Wall | Precision | Recall | F1 | Findings |
|---|---:|---:|---:|---:|---:|
| Fast | 774 ms | 0.9733 | 0.9113 | 0.9413 | 2,816 |
| Default | 929 ms | 0.9708 | 0.9200 | 0.9447 | 2,868 |
| Deep | 893 ms | 0.9708 | 0.9207 | 0.9451 | 2,874 |
| Precision | 851 ms | 0.9691 | 0.8057 | 0.8799 | 2,495 |

#### Incremental warm rerun

The benchmark populates the BLAKE3 Merkle index, then times the second identical scan. The small synthetic tree changes little because scanner startup dominates; measure your repository before claiming a speedup.

| Hyperscan/SIMD default policy | Wall | Throughput | Peak RSS |
|---|---:|---:|---:|
| Cache off | 929 ms | 2.49 MB/s | 997 MiB |
| Warm incremental cache | 937 ms | 2.47 MB/s | 1068 MiB |
