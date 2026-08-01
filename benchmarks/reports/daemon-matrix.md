# KeyHog daemon matrix

One deterministic 8 MiB regular file (`sha256:afafbe7b6487fd62866f510e7c281a9e7bfeaa8dc585d7b0478c92ee6c4f5ef5`) was scanned once in process and once through an owned daemon after one warmup request. Daemon time is the client request; daemon RSS belongs to the resident server.

| Explicit route | In process | Warm daemon | Warm / one-shot | In-process RSS | Daemon RSS |
|---|---:|---:|---:|---:|---:|
| Hyperscan/SIMD | 594 ms | 264 ms | 0.45× | 724 MiB | 744 MiB |
| Pure-Rust CPU | 2.21 s | 175 ms | 0.08× | 744 MiB | 764 MiB |
| CUDA | 6.18 s | 306 ms | 0.05× | 1138 MiB | 1178 MiB |
| WGPU | 2.09 s | 341 ms | 0.16× | 1088 MiB | 1102 MiB |

The daemon is not a general directory or CI accelerator. It accepts only eligible single-file and bounded-stdin requests on Unix, and it serializes execution.
