# KeyHog daemon matrix

One deterministic 8 MiB regular file (`sha256:afafbe7b6487fd62866f510e7c281a9e7bfeaa8dc585d7b0478c92ee6c4f5ef5`) was scanned once in process and once through an owned daemon after one warmup request. Daemon time is the client request; daemon RSS belongs to the resident server.

| Explicit route | In process | Warm daemon | Warm / one-shot | In-process RSS | Daemon RSS |
|---|---:|---:|---:|---:|---:|
| Hyperscan/SIMD | 498 ms | 219 ms | 0.44× | 732 MiB | 762 MiB |
| Pure-Rust CPU | 1.63 s | 162 ms | 0.10× | 737 MiB | 761 MiB |
| CUDA | 1.40 s | 224 ms | 0.16× | 1150 MiB | 1172 MiB |
| WGPU | 1.37 s | 223 ms | 0.16× | 1078 MiB | 1108 MiB |

The daemon is not a general directory or CI accelerator. It accepts only eligible single-file and bounded-stdin requests on Unix, and it serializes execution.
