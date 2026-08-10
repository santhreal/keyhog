# Leaderboard - mirror

Corpus: **mirror** - 15000 fixtures, 3000 labeled positives. Every scanner scored identically (SecretBench overlap rule); the answer-key manifest is excluded from the scan tree.

| Rank | Scanner | F1 | Precision | Recall | Findings | Wall | Peak RSS |
|---|---|---|---|---|---|---|---|
| 1 | **KeyHog** | **0.9328** | 0.9651 | 0.9027 | 2816 | 0.83s | 418 MB |
| 2 | Kingfisher | 0.4683 | 0.3877 | 0.5913 | 5255 | 4.47s | 421 MB |
| 3 | Betterleaks | 0.3498 | 0.2241 | 0.7970 | 11113 | 0.67s | 198 MB |

### Result provenance

| Scanner | Scanner version / executable digest | Corpus identity | Host identity | Run date |
|---|---|---|---|---|
| KeyHog | version: KeyHog v0.5.69<br>Commit: f870641d2b40210457c81ee3441cc1cfef8b4b06<br>Detector Set: 926 (926-4168e2c6c93a16ca)<br>Build Target: x86_64-linux<br>ML Model Version: moe-v1-246a05b92bec9aa3<br>ML Model Card: recorded 2026-07-15; features 55; synthetic F1 0.971 / P 0.945 / R 0.999; real F1 0.832 / P 0.753 / R 0.931 / recall@0.40 0.938; zero-recall detectors 2/32; six-scanner differential unavailable<br>executable SHA-256: `78ae0cb540e450aecefdfde8d5aff988c3ae1b73cff7a6748f0d640a67a02fcc` | mirror; 15,000 fixtures; 3,000 labeled positives; 2,431,242 bytes | hostname SHA-256/12: `82fcd9288623`<br>Linux 6.17.0-19-generic<br>AMD Ryzen 9 9950X 16-Core Processor | 2026-08-10T12:51:17Z |
| Kingfisher | version: kingfisher 1.94.0<br>executable SHA-256: `a49f8e9838d7f1da1e9f328a4dbc45a16996bce5078cde3ff1b8ad422d8ab07a` | mirror; 15,000 fixtures; 3,000 labeled positives; 2,431,242 bytes | hostname SHA-256/12: `82fcd9288623`<br>Linux 6.17.0-19-generic<br>AMD Ryzen 9 9950X 16-Core Processor | 2026-08-10T12:51:26Z |
| Betterleaks | version: betterleaks version dev<br>executable SHA-256: `466f7d34e1ebcf12ecd5939494f509c17125e54416226976fced2f046da56ba4` | mirror; 15,000 fixtures; 3,000 labeled positives; 2,431,242 bytes | hostname SHA-256/12: `82fcd9288623`<br>Linux 6.17.0-19-generic<br>AMD Ryzen 9 9950X 16-Core Processor | 2026-08-10T12:51:20Z |
