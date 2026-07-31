# KeyHog daemon matrix

One deterministic 8 MiB regular file (`sha256:afafbe7b6487fd62866f510e7c281a9e7bfeaa8dc585d7b0478c92ee6c4f5ef5`) was scanned once in process and once through an owned daemon after one warmup request. Daemon time is the client request; daemon RSS belongs to the resident server.

| Explicit route | In process | Warm daemon | Warm / one-shot | In-process RSS | Daemon RSS |
|---|---:|---:|---:|---:|---:|
| Hyperscan/SIMD | 503 ms | 217 ms | 0.43× | 735 MiB | 758 MiB |
| Pure-Rust CPU | 1.64 s | 148 ms | 0.09× | 739 MiB | 771 MiB |
| CUDA | 1.37 s | 219 ms | 0.16× | 1144 MiB | 1163 MiB |
| WGPU | 1.37 s | 219 ms | 0.16× | 1081 MiB | 1096 MiB |

The daemon is not a general directory or CI accelerator. It accepts only eligible single-file and bounded-stdin requests on Unix, and it serializes execution.
