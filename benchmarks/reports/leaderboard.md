# Leaderboard - mirror

Corpus: **mirror** - 15000 fixtures, 3000 labeled positives. Every scanner scored identically (SecretBench overlap rule); the answer-key manifest is excluded from the scan tree.

| Rank | Scanner | F1 | Precision | Recall | Findings | Wall | Peak RSS |
|---|---|---|---|---|---|---|---|
| 1 | **KeyHog** | **0.9447** | 0.9708 | 0.9200 | 2868 | 2.20s | 1030 MB |
| 2 | Kingfisher | 0.4720 | 0.3912 | 0.5947 | 5241 | 5.16s | 406 MB |
| 3 | Betterleaks | 0.3585 | 0.2313 | 0.7967 | 10828 | 1.25s | 189 MB |

### Result provenance

| Scanner | Scanner version / executable digest | Corpus identity | Host identity | Run date |
|---|---|---|---|---|
| KeyHog | version: KeyHog v0.5.49<br>Commit: 2b5135057589dfd651980e0d7f799ac1b9ef2e19<br>Detector Set: 923 (923-8785f8837d2cd505)<br>Build Target: x86_64-linux<br>ML Model Version: moe-v1-246a05b92bec9aa3<br>ML Model Card: recorded 2026-07-15; features 55; synthetic F1 0.971 / P 0.945 / R 0.999; real F1 0.832 / P 0.753 / R 0.931 / recall@0.40 0.938; zero-recall detectors 2/32; six-scanner differential unavailable<br>executable SHA-256: `88c971f8c92a4a4bf3e7a6dbdf424577b60550b3b8f5737cfa40a5665b609f19` | mirror; 15,000 fixtures; 3,000 labeled positives; 2,430,321 bytes | hostname SHA-256/12: `82fcd9288623`<br>Linux 6.17.0-19-generic<br>AMD Ryzen 9 9950X 16-Core Processor | 2026-07-31T06:18:44Z |
| Kingfisher | version: kingfisher 1.94.0<br>executable SHA-256: `a49f8e9838d7f1da1e9f328a4dbc45a16996bce5078cde3ff1b8ad422d8ab07a` | mirror; 15,000 fixtures; 3,000 labeled positives; 2,430,321 bytes | hostname SHA-256/12: `82fcd9288623`<br>Linux 6.17.0-19-generic<br>AMD Ryzen 9 9950X 16-Core Processor | 2026-07-31T06:18:56Z |
| Betterleaks | version: betterleaks version dev<br>executable SHA-256: `466f7d34e1ebcf12ecd5939494f509c17125e54416226976fced2f046da56ba4` | mirror; 15,000 fixtures; 3,000 labeled positives; 2,430,321 bytes | hostname SHA-256/12: `82fcd9288623`<br>Linux 6.17.0-19-generic<br>AMD Ryzen 9 9950X 16-Core Processor | 2026-07-31T06:18:48Z |
