# KeyHog daemon matrix

One deterministic 8 MiB regular file (`sha256:afafbe7b6487fd62866f510e7c281a9e7bfeaa8dc585d7b0478c92ee6c4f5ef5`) was scanned once in process and once through an owned daemon after one warmup request. Daemon time is the client request; daemon RSS belongs to the resident server.

| Explicit route | In process | Warm daemon | Warm / one-shot | In-process RSS | Daemon RSS |
|---|---:|---:|---:|---:|---:|
| Hyperscan/SIMD | 554 ms | 240 ms | 0.43× | 732 MiB | 757 MiB |
| Pure-Rust CPU | 1.74 s | 175 ms | 0.10× | 746 MiB | 759 MiB |
| CUDA | 1.49 s | 226 ms | 0.15× | 1152 MiB | 1179 MiB |
| WGPU | 1.45 s | 238 ms | 0.16× | 1077 MiB | 1116 MiB |

The daemon is not a general directory or CI accelerator. It accepts only eligible single-file and bounded-stdin requests on Unix, and it serializes execution.
