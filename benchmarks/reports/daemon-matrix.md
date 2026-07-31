# KeyHog daemon matrix

One deterministic 8 MiB regular file (`sha256:afafbe7b6487fd62866f510e7c281a9e7bfeaa8dc585d7b0478c92ee6c4f5ef5`) was scanned once in process and once through an owned daemon after one warmup request. Daemon time is the client request; daemon RSS belongs to the resident server.

| Explicit route | In process | Warm daemon | Warm / one-shot | In-process RSS | Daemon RSS |
|---|---:|---:|---:|---:|---:|
| Hyperscan/SIMD | 572 ms | 227 ms | 0.40× | 729 MiB | 755 MiB |
| Pure-Rust CPU | 1.73 s | 159 ms | 0.09× | 739 MiB | 756 MiB |
| CUDA | 1.52 s | 232 ms | 0.15× | 1142 MiB | 1169 MiB |
| WGPU | 1.49 s | 245 ms | 0.16× | 1085 MiB | 1121 MiB |

The daemon is not a general directory or CI accelerator. It accepts only eligible single-file and bounded-stdin requests on Unix, and it serializes execution.
