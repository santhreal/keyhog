# KeyHog daemon matrix

One deterministic 8 MiB regular file (`sha256:afafbe7b6487fd62866f510e7c281a9e7bfeaa8dc585d7b0478c92ee6c4f5ef5`) was scanned once in process and once through an owned daemon after one warmup request. Daemon time is the client request; daemon RSS belongs to the resident server.

| Explicit route | In process | Warm daemon | Warm / one-shot | In-process RSS | Daemon RSS |
|---|---:|---:|---:|---:|---:|
| Hyperscan/SIMD | 519 ms | 231 ms | 0.44× | 733 MiB | 760 MiB |
| Pure-Rust CPU | 1.84 s | 178 ms | 0.10× | 746 MiB | 767 MiB |
| CUDA | 1.62 s | 230 ms | 0.14× | 1145 MiB | 1161 MiB |
| WGPU | 1.49 s | 237 ms | 0.16× | 1087 MiB | 1109 MiB |

The daemon is not a general directory or CI accelerator. It accepts only eligible single-file and bounded-stdin requests on Unix, and it serializes execution.
