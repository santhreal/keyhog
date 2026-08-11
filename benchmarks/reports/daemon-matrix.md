# KeyHog daemon matrix

One deterministic 8 MiB regular file (`sha256:afafbe7b6487fd62866f510e7c281a9e7bfeaa8dc585d7b0478c92ee6c4f5ef5`) was scanned once in process and once through an owned daemon after one warmup request. Daemon time is the client request; daemon RSS belongs to the resident server.

| Explicit route | In process | Warm daemon | Warm / one-shot | In-process RSS | Daemon RSS |
|---|---:|---:|---:|---:|---:|
| Hyperscan/SIMD | 323 ms | 106 ms | 0.33× | 63 MiB | 74 MiB |
| Pure-Rust CPU | 278 ms | 109 ms | 0.39× | 62 MiB | 66 MiB |
| CUDA | 1.65 s | 232 ms | 0.14× | 674 MiB | 666 MiB |
| WGPU | 1.33 s | 237 ms | 0.18× | 596 MiB | 600 MiB |

The daemon is not a general directory or CI accelerator. It accepts only eligible single-file and bounded-stdin requests on Unix, and it serializes execution.
