# Performance

| Scanner | Config | Corpus | Wall | Throughput | Peak RSS |
|---|---|---|---|---|---|
| Nosey Parker | `default-nocache-nodaemon-no-git-history` | mirror | 0.75s | 3.1 MB/s | 285 MB |
| BetterLeaks | `default-nocache-nodaemon-no-validate` | mirror | 0.77s | 3.0 MB/s | 192 MB |
| TruffleHog | `default-nocache-nodaemon-no-verify` | mirror | 1.73s | 1.3 MB/s | 308 MB |
| KeyHog | `simd-nocache-nodaemon-full` | mirror | 1.94s | 1.2 MB/s | 1077 MB |
| Titus | `default-nocache-nodaemon-no-validate` | mirror | 2.53s | 0.9 MB/s | 117 MB |
| BetterLeaks | `default-nocache-nodaemon-no-validate` | creddata | 3.07s | 316.5 MB/s | 261 MB |
| KeyHog | `simd-nocache-nodaemon-full` | creddata | 4.02s | 241.3 MB/s | 1807 MB |
| Kingfisher | `default-nocache-nodaemon-low-no-validate` | mirror | 4.88s | 0.5 MB/s | 421 MB |
| Kingfisher | `default-nocache-nodaemon-low-no-validate` | creddata | 8.13s | 119.4 MB/s | 657 MB |
