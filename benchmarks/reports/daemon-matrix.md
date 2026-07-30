# KeyHog daemon matrix

One deterministic 8 MiB regular file (`sha256:afafbe7b6487fd62866f510e7c281a9e7bfeaa8dc585d7b0478c92ee6c4f5ef5`) was scanned once in process and once through an owned daemon after one warmup request. Daemon time is the client request; daemon RSS belongs to the resident server.

| Explicit route | In process | Warm daemon | Warm / one-shot | In-process RSS | Daemon RSS |
|---|---:|---:|---:|---:|---:|
| Hyperscan/SIMD | 534 ms | 184 ms | 0.34× | 719 MiB | 762 MiB |
| Pure-Rust CPU | 1.44 s | 134 ms | 0.09× | 725 MiB | 782 MiB |
| CUDA | 1.52 s | 180 ms | 0.12× | 1153 MiB | 1160 MiB |
| WGPU | 1.42 s | 186 ms | 0.13× | 1091 MiB | 1091 MiB |

The daemon is not a general directory or CI accelerator. It accepts only eligible single-file and bounded-stdin requests on Unix, and it serializes execution.
