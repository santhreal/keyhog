# KeyHog configuration matrix

Measured on **AMD Ryzen 9 9950X 16-Core Processor** with **NVIDIA GeForce RTX 5090**, 32 logical cores, 15,000 fixtures, 3,000 labeled positives, and 2,431,242 input bytes. Scanner: `KeyHog v0.5.70`. The tracked source tree was clean.

#### Full scan by execution route

All rows use the default detection policy with incremental cache and daemon off. The automatic row records the requested policy, but the benchmark result does not bind the selected persisted route, so it is not routing proof. GPU rows include acquisition and full scanner startup on this small corpus; they are not GPU kernel crossover measurements.

| Requested route | Wall | Throughput | Peak RSS | F1 |
|---|---:|---:|---:|---:|
| Hyperscan/SIMD | 860 ms | 2.70 MB/s | 416 MiB | 0.9328 |
| Pure-Rust CPU | 903 ms | 2.57 MB/s | 509 MiB | 0.9328 |
| CUDA | 2.03 s | 1.14 MB/s | 963 MiB | 0.9328 |
| WGPU | 1.97 s | 1.18 MB/s | 1264 MiB | 0.9328 |
| Automatic | 1.46 s | 1.59 MB/s | 634 MiB | 0.9328 |

#### Detection policy on Hyperscan/SIMD

The route, cache, daemon state, corpus, and host remain fixed. Presets change detection work, so compare precision and recall as well as time.

| Policy | Wall | Precision | Recall | F1 | Findings |
|---|---:|---:|---:|---:|---:|
| Fast | 737 ms | 0.9700 | 0.8837 | 0.9248 | 2,738 |
| Default | 860 ms | 0.9651 | 0.9027 | 0.9328 | 2,816 |
| Deep | 861 ms | 0.9645 | 0.9067 | 0.9347 | 2,845 |
| Precision | 849 ms | 0.9590 | 0.6397 | 0.7674 | 2,001 |

#### Incremental warm rerun

The benchmark populates the BLAKE3 Merkle index, then times the second identical scan. The small synthetic tree changes little because scanner startup dominates; measure your repository before claiming a speedup.

| Hyperscan/SIMD default policy | Wall | Throughput | Peak RSS |
|---|---:|---:|---:|
| Cache off | 860 ms | 2.70 MB/s | 416 MiB |
| Warm incremental cache | 617 ms | 3.76 MB/s | 457 MiB |
