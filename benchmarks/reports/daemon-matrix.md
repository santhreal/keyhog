# KeyHog daemon matrix

One deterministic 8 MiB regular file (`sha256:afafbe7b6487fd62866f510e7c281a9e7bfeaa8dc585d7b0478c92ee6c4f5ef5`) was scanned once in process and once through an owned daemon after one warmup request. Daemon time is the client request; daemon RSS belongs to the resident server.

| Explicit route | In process | Warm daemon | Warm / one-shot | In-process RSS | Daemon RSS |
|---|---:|---:|---:|---:|---:|
| Hyperscan/SIMD | 580 ms | 282 ms | 0.49× | 729 MiB | 777 MiB |
| Pure-Rust CPU | 1.92 s | 170 ms | 0.09× | 738 MiB | 760 MiB |
| CUDA | 1.50 s | 237 ms | 0.16× | 1154 MiB | 1177 MiB |
| WGPU | 1.50 s | 226 ms | 0.15× | 1092 MiB | 1102 MiB |

The daemon is not a general directory or CI accelerator. It accepts only eligible single-file and bounded-stdin requests on Unix, and it serializes execution.
