# KeyHog daemon matrix

One deterministic 8 MiB regular file (`sha256:afafbe7b6487fd62866f510e7c281a9e7bfeaa8dc585d7b0478c92ee6c4f5ef5`) was scanned once in process and once through an owned daemon after one warmup request. Daemon time is the client request; daemon RSS belongs to the resident server.

| Explicit route | In process | Warm daemon | Warm / one-shot | In-process RSS | Daemon RSS |
|---|---:|---:|---:|---:|---:|
| Hyperscan/SIMD | 649 ms | 275 ms | 0.42× | 725 MiB | 745 MiB |
| Pure-Rust CPU | 2.05 s | 195 ms | 0.10× | 730 MiB | 792 MiB |
| CUDA | 1.74 s | 257 ms | 0.15× | 1148 MiB | 1173 MiB |
| WGPU | 1.72 s | 293 ms | 0.17× | 1072 MiB | 1108 MiB |

The daemon is not a general directory or CI accelerator. It accepts only eligible single-file and bounded-stdin requests on Unix, and it serializes execution.
