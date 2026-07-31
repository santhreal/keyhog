# KeyHog configuration matrix

Measured on **AMD Ryzen 9 9950X 16-Core Processor** with **NVIDIA GeForce RTX 5090**, 32 logical cores, 15,000 fixtures, 3,000 labeled positives, and 2,430,321 input bytes. Scanner: `KeyHog v0.5.49`. Documentation changes were uncommitted; the measured KeyHog v0.5.49 executable and detector digests were identical across every row. Treat these as development-host configuration comparisons, not release routing evidence.

#### Full scan by execution route

All rows use the default detection policy with incremental cache and daemon off. The automatic row records the requested policy, but the benchmark result does not bind the selected persisted route, so it is not routing proof. GPU rows include acquisition and full scanner startup on this small corpus; they are not GPU kernel crossover measurements.

| Requested route | Wall | Throughput | Peak RSS | F1 |
|---|---:|---:|---:|---:|
| Hyperscan/SIMD | 1.15 s | 2.01 MB/s | 1055 MiB | 0.9447 |
| Pure-Rust CPU | 2.66 s | 0.87 MB/s | 1073 MiB | 0.9447 |
| CUDA | 12.10 s | 0.19 MB/s | 1754 MiB | 0.9447 |
| WGPU | 11.81 s | 0.20 MB/s | 1662 MiB | 0.9447 |
| Automatic | 2.59 s | 0.89 MB/s | 1166 MiB | 0.9447 |

#### Detection policy on Hyperscan/SIMD

The route, cache, daemon state, corpus, and host remain fixed. Presets change detection work, so compare precision and recall as well as time.

| Policy | Wall | Precision | Recall | F1 | Findings |
|---|---:|---:|---:|---:|---:|
| Fast | 1.03 s | 0.9733 | 0.9113 | 0.9413 | 2,816 |
| Default | 1.15 s | 0.9708 | 0.9200 | 0.9447 | 2,868 |
| Deep | 1.15 s | 0.9708 | 0.9207 | 0.9451 | 2,875 |
| Precision | 1.05 s | 0.9690 | 0.8033 | 0.8784 | 2,488 |

#### Incremental warm rerun

The benchmark populates the BLAKE3 Merkle index, then times the second identical scan. The small synthetic tree changes little because scanner startup dominates; measure your repository before claiming a speedup.

| Hyperscan/SIMD default policy | Wall | Throughput | Peak RSS |
|---|---:|---:|---:|
| Cache off | 1.15 s | 2.01 MB/s | 1055 MiB |
| Warm incremental cache | 1.22 s | 1.90 MB/s | 1080 MiB |
