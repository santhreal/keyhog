# Performance

| Scanner | Config | Corpus | Wall | Throughput | Peak RSS |
|---|---|---|---|---|---|
| Betterleaks | `default-nocache-nodaemon-no-validate` | mirror | 0.74s | 3.1 MB/s | 198 MB |
| Nosey Parker | `default-nocache-nodaemon-no-git-history` | mirror | 0.82s | 2.8 MB/s | 285 MB |
| KeyHog | `simd-nocache-nodaemon-full` | mirror | 1.05s | 2.2 MB/s | 416 MB |
| TruffleHog | `default-nocache-nodaemon-no-verify` | mirror | 1.59s | 1.5 MB/s | 300 MB |
| Titus | `default-nocache-nodaemon-no-validate` | mirror | 2.86s | 0.8 MB/s | 115 MB |
| Kingfisher | `default-nocache-nodaemon-low-no-validate` | mirror | 4.81s | 0.5 MB/s | 402 MB |
