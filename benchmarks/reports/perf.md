# Performance

| Scanner | Config | Corpus | Wall | Throughput | Peak RSS |
|---|---|---|---|---|---|
| BetterLeaks | `default-nocache-nodaemon-no-validate` | mirror | 0.63s | 3.7 MB/s | 206 MB |
| Nosey Parker | `default-nocache-nodaemon-no-git-history` | mirror | 0.75s | 3.1 MB/s | 283 MB |
| KeyHog | `simd-nocache-nodaemon-full` | mirror | 1.15s | 2.0 MB/s | 1157 MB |
| TruffleHog | `default-nocache-nodaemon-no-verify` | mirror | 1.36s | 1.7 MB/s | 337 MB |
| Titus | `default-nocache-nodaemon-no-validate` | mirror | 2.58s | 0.9 MB/s | 117 MB |
| Kingfisher | `default-nocache-nodaemon-low-no-validate` | mirror | 4.22s | 0.5 MB/s | 427 MB |
