# KeyHog daemon matrix

One deterministic 8 MiB regular file (`sha256:afafbe7b6487fd62866f510e7c281a9e7bfeaa8dc585d7b0478c92ee6c4f5ef5`) was scanned once in process and once through an owned daemon after one warmup request. Daemon time is the client request; daemon RSS belongs to the resident server.

| Explicit route | In process | Warm daemon | Warm / one-shot | In-process RSS | Daemon RSS |
|---|---:|---:|---:|---:|---:|
| Hyperscan/SIMD | 394 ms | 157 ms | 0.40× | 599 MiB | 630 MiB |
| Pure-Rust CPU | 380 ms | 160 ms | 0.42× | 598 MiB | 633 MiB |
| CUDA | 1.33 s | 212 ms | 0.16× | 1187 MiB | 1175 MiB |
| WGPU | 1.32 s | 214 ms | 0.16× | 1100 MiB | 1113 MiB |

The daemon is not a general directory or CI accelerator. It accepts only eligible single-file and bounded-stdin requests on Unix, and it serializes execution.
