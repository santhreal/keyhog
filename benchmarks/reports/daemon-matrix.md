# KeyHog daemon matrix

One deterministic 8 MiB regular file (`sha256:afafbe7b6487fd62866f510e7c281a9e7bfeaa8dc585d7b0478c92ee6c4f5ef5`) was scanned once in process and once through an owned daemon after one warmup request. Daemon time is the client request; daemon RSS belongs to the resident server.

| Explicit route | In process | Warm daemon | Warm / one-shot | In-process RSS | Daemon RSS |
|---|---:|---:|---:|---:|---:|
| Hyperscan/SIMD | 369 ms | 148 ms | 0.40× | 575 MiB | 609 MiB |
| Pure-Rust CPU | 364 ms | 146 ms | 0.40× | 568 MiB | 603 MiB |
| CUDA | 1.39 s | 217 ms | 0.16× | 1189 MiB | 1211 MiB |
| WGPU | 1.32 s | 218 ms | 0.17× | 1110 MiB | 1131 MiB |

The daemon is not a general directory or CI accelerator. It accepts only eligible single-file and bounded-stdin requests on Unix, and it serializes execution.
