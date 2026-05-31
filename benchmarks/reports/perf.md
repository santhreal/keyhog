# Performance

| Scanner | Config | Corpus | Wall | Throughput | Peak RSS |
|---|---|---|---|---|---|
| BetterLeaks | `default-nocache-nodaemon-no-validate` | mirror | 0.71s | 3.3 MB/s | 183 MB |
| Nosey Parker | `default-nocache-nodaemon-no-git-history` | mirror | 0.72s | 3.2 MB/s | 526 MB |
| KeyHog | `simd-nocache-nodaemon-full` | mirror | 1.27s | 1.8 MB/s | 1064 MB |
| TruffleHog | `default-nocache-nodaemon-no-verify` | mirror | 1.42s | 1.6 MB/s | 329 MB |
| Titus | `default-nocache-nodaemon-no-validate` | mirror | 2.63s | 0.9 MB/s | 119 MB |
| Kingfisher | `default-nocache-nodaemon-low-no-validate` | mirror | 4.59s | 0.5 MB/s | 493 MB |
