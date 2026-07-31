# KeyHog daemon matrix

One deterministic 8 MiB regular file (`sha256:afafbe7b6487fd62866f510e7c281a9e7bfeaa8dc585d7b0478c92ee6c4f5ef5`) was scanned once in process and once through an owned daemon after one warmup request. Daemon time is the client request; daemon RSS belongs to the resident server.

| Explicit route | In process | Warm daemon | Warm / one-shot | In-process RSS | Daemon RSS |
|---|---:|---:|---:|---:|---:|
| Hyperscan/SIMD | 495 ms | 216 ms | 0.44× | 738 MiB | 743 MiB |
| Pure-Rust CPU | 1.59 s | 152 ms | 0.10× | 746 MiB | 778 MiB |
| CUDA | 1.34 s | 213 ms | 0.16× | 1137 MiB | 1161 MiB |
| WGPU | 1.28 s | 220 ms | 0.17× | 1078 MiB | 1089 MiB |

The daemon is not a general directory or CI accelerator. It accepts only eligible single-file and bounded-stdin requests on Unix, and it serializes execution.
