# Performance

#### Synthetic SecretBench-shape mirror corpus

| Scanner | Config | Corpus | Wall | Throughput | Peak RSS |
|---|---|---|---|---|---|
| Betterleaks | `default-nocache-nodaemon-no-validate` | mirror | 0.74s | 3.1 MB/s | 198 MB |
| Nosey Parker | `default-nocache-nodaemon-no-git-history` | mirror | 0.82s | 2.8 MB/s | 285 MB |
| KeyHog | `simd-nocache-nodaemon-full` | mirror | 1.05s | 2.2 MB/s | 416 MB |
| TruffleHog | `default-nocache-nodaemon-no-verify` | mirror | 1.59s | 1.5 MB/s | 300 MB |
| Titus | `default-nocache-nodaemon-no-validate` | mirror | 2.86s | 0.8 MB/s | 115 MB |
| Kingfisher | `default-nocache-nodaemon-low-no-validate` | mirror | 4.81s | 0.5 MB/s | 402 MB |

#### Competitor homefield / home-turf rule corpus

| Scanner | Config | Corpus | Wall | Throughput | Peak RSS |
|---|---|---|---|---|---|
| Betterleaks | `default-nocache-nodaemon-no-validate` | homefield | 0.58s | 1.3 MB/s | 192 MB |
| Nosey Parker | `default-nocache-nodaemon-no-git-history` | homefield | 0.68s | 1.1 MB/s | 265 MB |
| KeyHog | `simd-nocache-nodaemon-full` | homefield | 0.72s | 1.1 MB/s | 384 MB |
| TruffleHog | `default-nocache-nodaemon-no-verify` | homefield | 1.22s | 0.6 MB/s | 280 MB |
| Titus | `default-nocache-nodaemon-no-validate` | homefield | 2.15s | 0.4 MB/s | 110 MB |
| Kingfisher | `default-nocache-nodaemon-low-no-validate` | homefield | 2.14s | 0.4 MB/s | 390 MB |
