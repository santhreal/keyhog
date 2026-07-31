# KeyHog daemon matrix

One deterministic 8 MiB regular file (`sha256:afafbe7b6487fd62866f510e7c281a9e7bfeaa8dc585d7b0478c92ee6c4f5ef5`) was scanned once in process and once through an owned daemon after one warmup request. Daemon time is the client request; daemon RSS belongs to the resident server.

| Explicit route | In process | Warm daemon | Warm / one-shot | In-process RSS | Daemon RSS |
|---|---:|---:|---:|---:|---:|
| Hyperscan/SIMD | 518 ms | 221 ms | 0.43× | 734 MiB | 777 MiB |
| Pure-Rust CPU | 1.71 s | 155 ms | 0.09× | 744 MiB | 781 MiB |
| CUDA | 1.60 s | 222 ms | 0.14× | 1142 MiB | 1152 MiB |
| WGPU | 1.51 s | 264 ms | 0.17× | 1096 MiB | 1110 MiB |

The daemon is not a general directory or CI accelerator. It accepts only eligible single-file and bounded-stdin requests on Unix, and it serializes execution.
