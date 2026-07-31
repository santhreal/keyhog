# KeyHog daemon matrix

One deterministic 8 MiB regular file (`sha256:afafbe7b6487fd62866f510e7c281a9e7bfeaa8dc585d7b0478c92ee6c4f5ef5`) was scanned once in process and once through an owned daemon after one warmup request. Daemon time is the client request; daemon RSS belongs to the resident server.

| Explicit route | In process | Warm daemon | Warm / one-shot | In-process RSS | Daemon RSS |
|---|---:|---:|---:|---:|---:|
| Hyperscan/SIMD | 566 ms | 236 ms | 0.42× | 728 MiB | 763 MiB |
| Pure-Rust CPU | 1.84 s | 168 ms | 0.09× | 736 MiB | 758 MiB |
| CUDA | 1.60 s | 223 ms | 0.14× | 1153 MiB | 1154 MiB |
| WGPU | 1.43 s | 216 ms | 0.15× | 1077 MiB | 1095 MiB |

The daemon is not a general directory or CI accelerator. It accepts only eligible single-file and bounded-stdin requests on Unix, and it serializes execution.
