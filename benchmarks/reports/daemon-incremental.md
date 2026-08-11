# Mass daemon incremental filesystem benchmark

KeyHog v0.5.70 at commit `4b505ed6e0a9032c3c514253fdff7aef5fa2256f` scanned a 512-file, 1,024,000,000-byte logical filesystem tree through the local mass-daemon SIMD route. The tree contained 511 unchanged clean files and one finding-producing file. The finding-producing file remained outside the published clean-file generation and was rescanned on every trial.

| State | Trials | Median wall time | Source bytes scanned | Source chunks scanned | Findings |
| --- | ---: | ---: | ---: | ---: | ---: |
| Incremental disabled | 5 | 6,588.507 ms | 1,158,217,728 | 1,536 | 1 |
| Incremental population | 1 | 6,634.972 ms | 1,158,217,728 | 1,536 | 1 |
| Warm incremental | 5 | 99.710 ms | 2,262,144 | 3 | 1 |

The warm incremental median was **66.08× faster** than the non-incremental median. Every trial completed with `scan_status=success`, no coverage gaps, exit code 1, and one finding. The complete ordered finding array had SHA-256 `60e39b0cc923123f7a4845c3db3499878a0a34201218a7155800a201a9985531` in both modes. Peak daemon RSS was 138,700 KiB.

The measured executable was 31,294,320 bytes with SHA-256 `8f14da33f7494b5d24a5206d1c922dedce7167f44ae36ddad8d858c28285c62e`. The host ran Linux 6.17.0-19-generic on an AMD Ryzen 9 9950X with 32 logical CPUs. The detector identity was `926-4168e2c6c93a16ca`.

This result measures unchanged high-byte files. It does not claim the same latency ratio for tiny-file trees, where directory traversal and metadata checks dominate after file content is skipped. The complete machine-readable trials and provenance are in [`daemon-incremental.json`](daemon-incremental.json).
