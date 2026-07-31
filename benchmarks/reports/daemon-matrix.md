# KeyHog daemon matrix

One deterministic 8 MiB regular file (`sha256:afafbe7b6487fd62866f510e7c281a9e7bfeaa8dc585d7b0478c92ee6c4f5ef5`) was scanned once in process and once through an owned daemon after one warmup request. Daemon time is the client request; daemon RSS belongs to the resident server.

| Explicit route | In process | Warm daemon | Warm / one-shot | In-process RSS | Daemon RSS |
|---|---:|---:|---:|---:|---:|
| Hyperscan/SIMD | 488 ms | 214 ms | 0.44× | 733 MiB | 769 MiB |
| Pure-Rust CPU | 1.60 s | 155 ms | 0.10× | 739 MiB | 779 MiB |
| CUDA | 1.43 s | 220 ms | 0.15× | 1141 MiB | 1160 MiB |
| WGPU | 1.33 s | 214 ms | 0.16× | 1090 MiB | 1109 MiB |

The daemon is not a general directory or CI accelerator. It accepts only eligible single-file and bounded-stdin requests on Unix, and it serializes execution.
