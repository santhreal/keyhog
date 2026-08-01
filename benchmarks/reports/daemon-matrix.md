# KeyHog daemon matrix

One deterministic 8 MiB regular file (`sha256:afafbe7b6487fd62866f510e7c281a9e7bfeaa8dc585d7b0478c92ee6c4f5ef5`) was scanned once in process and once through an owned daemon after one warmup request. Daemon time is the client request; daemon RSS belongs to the resident server.

| Explicit route | In process | Warm daemon | Warm / one-shot | In-process RSS | Daemon RSS |
|---|---:|---:|---:|---:|---:|
| Hyperscan/SIMD | 833 ms | 318 ms | 0.38× | 729 MiB | 723 MiB |
| Pure-Rust CPU | 3.01 s | 259 ms | 0.09× | 740 MiB | 780 MiB |
| CUDA | 2.76 s | 514 ms | 0.19× | 1148 MiB | 1171 MiB |
| WGPU | 2.39 s | 402 ms | 0.17× | 1091 MiB | 1116 MiB |

The daemon is not a general directory or CI accelerator. It accepts only eligible single-file and bounded-stdin requests on Unix, and it serializes execution.
