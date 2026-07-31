# KeyHog daemon matrix

One deterministic 8 MiB regular file (`sha256:afafbe7b6487fd62866f510e7c281a9e7bfeaa8dc585d7b0478c92ee6c4f5ef5`) was scanned once in process and once through an owned daemon after one warmup request. Daemon time is the client request; daemon RSS belongs to the resident server.

| Explicit route | In process | Warm daemon | Warm / one-shot | In-process RSS | Daemon RSS |
|---|---:|---:|---:|---:|---:|
| Hyperscan/SIMD | 558 ms | 229 ms | 0.41× | 734 MiB | 757 MiB |
| Pure-Rust CPU | 1.77 s | 166 ms | 0.09× | 744 MiB | 772 MiB |
| CUDA | 1.55 s | 236 ms | 0.15× | 1141 MiB | 1171 MiB |
| WGPU | 1.56 s | 219 ms | 0.14× | 1083 MiB | 1106 MiB |

The daemon is not a general directory or CI accelerator. It accepts only eligible single-file and bounded-stdin requests on Unix, and it serializes execution.
