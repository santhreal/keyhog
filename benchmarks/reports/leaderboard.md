# Leaderboard - mirror

Corpus: **mirror** - 15000 fixtures, 3000 labeled positives. Every scanner scored identically (SecretBench overlap rule); the answer-key manifest is excluded from the scan tree.

| Rank | Scanner | F1 | Precision | Recall | Findings | Wall | Peak RSS |
|---|---|---|---|---|---|---|---|
| 1 | **KeyHog** | **0.9328** | 0.9651 | 0.9027 | 2816 | 1.05s | 416 MB |
| 2 | TruffleHog | 0.5294 | 1.0000 | 0.3600 | 1080 | 1.59s | 300 MB |
| 3 | Kingfisher | 0.4683 | 0.3877 | 0.5913 | 5255 | 4.81s | 402 MB |
| 4 | Titus | 0.4207 | 0.3381 | 0.5567 | 5151 | 2.86s | 115 MB |
| 5 | Nosey Parker | 0.4186 | 0.3511 | 0.5183 | 4529 | 0.82s | 285 MB |
| 6 | Betterleaks | 0.3498 | 0.2241 | 0.7970 | 11113 | 0.74s | 198 MB |

### Result provenance

| Scanner | Scanner version / executable digest | Corpus identity | Host identity | Run date |
|---|---|---|---|---|
| KeyHog | version: KeyHog v0.5.70<br>Commit: d1eb2e09eb2c289181d93d719ce3f62411aeaf2c<br>Detector Set: 926 (926-4168e2c6c93a16ca)<br>Build Target: x86_64-linux<br>ML Model Version: moe-v1-246a05b92bec9aa3<br>ML Model Card: recorded 2026-07-15; features 55; synthetic F1 0.971 / P 0.945 / R 0.999; real F1 0.832 / P 0.753 / R 0.931 / recall@0.40 0.938; zero-recall detectors 2/32; six-scanner differential unavailable<br>executable SHA-256: `2899ee53789bff9c531f72645f6c8380a7c873230dfb2b6857079467bc8d2dcd` | mirror; 15,000 fixtures; 3,000 labeled positives; 2,431,242 bytes | hostname SHA-256/12: `82fcd9288623`<br>Linux 6.17.0-19-generic<br>AMD Ryzen 9 9950X 16-Core Processor | 2026-08-11T01:29:39Z |
| TruffleHog | version: trufflehog 3.96.0<br>executable SHA-256: `6eb1f98fb890bf9361d8833c061e122dcb4f14fb7b71c65e603b7c096153c724` | mirror; 15,000 fixtures; 3,000 labeled positives; 2,431,242 bytes | hostname SHA-256/12: `82fcd9288623`<br>Linux 6.17.0-19-generic<br>AMD Ryzen 9 9950X 16-Core Processor | 2026-08-11T01:29:58Z |
| Kingfisher | version: kingfisher 1.94.0<br>executable SHA-256: `a49f8e9838d7f1da1e9f328a4dbc45a16996bce5078cde3ff1b8ad422d8ab07a` | mirror; 15,000 fixtures; 3,000 labeled positives; 2,431,242 bytes | hostname SHA-256/12: `82fcd9288623`<br>Linux 6.17.0-19-generic<br>AMD Ryzen 9 9950X 16-Core Processor | 2026-08-11T01:29:50Z |
| Titus | version: Titus v1.1.20 (Go port of NoseyParker)<br>executable SHA-256: `0b9c126a6c280ba28c6ed8795f88bf9bd793164c15959a34921f47a7ed276bcf` | mirror; 15,000 fixtures; 3,000 labeled positives; 2,431,242 bytes | hostname SHA-256/12: `82fcd9288623`<br>Linux 6.17.0-19-generic<br>AMD Ryzen 9 9950X 16-Core Processor | 2026-08-11T01:30:03Z |
| Nosey Parker | version: noseyparker 0.24.0 Build Configuration: Build Timestamp:    2025-05-08T21:11:15.600909923Z Commit Timestamp:   2025-05-08T17:04:47.000000000-04:00 Commit Branch:      HEAD Commit SHA:         61fa4ca67e4ded1b47b3b9ecce618ae91f1ff2fe Cargo Features:     color_backtrace,default,disable_trace,github,log,mimalloc,parquet,release Debug:              true Optimization:       3 Target Triple:      x86_64-unknown-linux-gnu Build System: OS:                 Ubuntu OS Version:         Linux (Ubuntu 22.04) CPU Vendor:         AuthenticAMD CPU Brand:          AMD EPYC 7763 64-Core Processor CPU Cores:          2 rustc Version:      1.86.0 rustc Channel:      stable rustc Host Triple:  x86_64-unknown-linux-gnu rustc Commit Date:  2025-03-31 rustc Commit SHA:   05f9846f893b09a1be1fc8560e33fc3c815cfecb rustc LLVM Version: 19.1<br>executable SHA-256: `42d6e88bf77904866a9dda49d7cf333501e76b62e9054b112e67f81dc88e2b71` | mirror; 15,000 fixtures; 3,000 labeled positives; 2,431,242 bytes | hostname SHA-256/12: `82fcd9288623`<br>Linux 6.17.0-19-generic<br>AMD Ryzen 9 9950X 16-Core Processor | 2026-08-11T01:29:53Z |
| Betterleaks | version: betterleaks version dev<br>executable SHA-256: `466f7d34e1ebcf12ecd5939494f509c17125e54416226976fced2f046da56ba4` | mirror; 15,000 fixtures; 3,000 labeled positives; 2,431,242 bytes | hostname SHA-256/12: `82fcd9288623`<br>Linux 6.17.0-19-generic<br>AMD Ryzen 9 9950X 16-Core Processor | 2026-08-11T01:29:43Z |
