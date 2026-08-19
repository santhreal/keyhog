# Multi-corpus benchmark evaluation

Secret scanner evaluation requires testing across multiple independent corpora to prevent single-distribution bias. Evaluating against a synthetic mirror corpus alone measures coverage on synthetic distributions, while evaluating against competitor-harvested rule test suites measures real-world competitor ground truth.

KeyHog evaluates detection accuracy and runtime performance against both the synthetic SecretBench-shape mirror corpus and competitor-harvested homefield corpora under identical, neutral execution and scoring contracts.

## Multi-corpus methodology

Every benchmarked scanner runs under a uniform scoring harness with two non-negotiable fairness constraints:

1. **Answer-key isolation.** The ground-truth answer-key manifest sits beside, never inside, the scan tree. Scanners scan only neutral payload files and cannot read test annotations.
2. **Neutral scan directory layout.** Scanners scan neutrally named directory trees (`corpus/`, not `fixtures/` or `test/`), preventing test-path heuristic penalties from distorting measurements.

Finding attribution uses the canonical SecretBench overlap rule: a finding counts as a True Positive if its attributed byte span overlaps the ground-truth secret span in the same file.

## Benchmark results

All measurements below were collected on **AMD Ryzen 9 9950X 16-Core Processor** running Linux 6.17.0-19-generic with 32 logical cores.

### Synthetic mirror corpus

The **mirror** corpus contains 15,000 synthetic SecretBench-shape fixtures, 3,000 labeled positives, and 2,431,242 input bytes.

| Rank | Scanner | F1 | Precision | Recall | Findings | Wall | Peak RSS |
|---|---|---|---|---|---|---|---|
| 1 | **KeyHog** | **0.9328** | 0.9651 | 0.9027 | 2,816 | 1.05s | 416 MB |
| 2 | TruffleHog | 0.5294 | 1.0000 | 0.3600 | 1,080 | 1.59s | 300 MB |
| 3 | Kingfisher | 0.4683 | 0.3877 | 0.5913 | 5,255 | 4.81s | 402 MB |
| 4 | Titus | 0.4207 | 0.3381 | 0.5567 | 5,151 | 2.86s | 115 MB |
| 5 | Nosey Parker | 0.4186 | 0.3511 | 0.5183 | 4,529 | 0.82s | 285 MB |
| 6 | Betterleaks | 0.3498 | 0.2241 | 0.7970 | 11,113 | 0.74s | 198 MB |

### Competitor homefield corpus

The **homefield** corpus contains 2,399 fixtures harvested directly from competitor ground-truth rule suites (Betterleaks and Kingfisher rules; 1,057 labeled positives, 1,342 negatives, 772,974 input bytes).

| Rank | Scanner | F1 | Precision | Recall | Findings | Wall | Peak RSS |
|---|---|---|---|---|---|---|---|
| 1 | **KeyHog** | **0.9214** | 0.9582 | 0.8874 | 979 | 0.72s | 384 MB |
| 2 | Betterleaks | 0.9056 | 0.9130 | 0.8984 | 1,040 | 0.58s | 192 MB |
| 3 | Kingfisher | 0.8842 | 0.9250 | 0.8468 | 968 | 2.14s | 390 MB |
| 4 | TruffleHog | 0.4812 | 0.9850 | 0.3226 | 345 | 1.22s | 280 MB |
| 5 | Titus | 0.4635 | 0.3810 | 0.5913 | 1,640 | 2.15s | 110 MB |
| 6 | Nosey Parker | 0.4520 | 0.3950 | 0.5280 | 1,412 | 0.68s | 265 MB |

## Provenance and reproducibility

Every reported benchmark measurement binds the following immutable identities:

- Scanner executable digest (SHA-256) and stamped git commit hash.
- Detector set count and detector corpus digest.
- Execution configuration ID (backend, caching, daemon, and validation modes).
- Host CPU, memory, GPU, kernel, and operating system identity.
- Workload byte count, fixture count, and labeled positive count.

To reproduce measurements locally, see [`benchmarks/README.md`](https://github.com/santhreal/keyhog/blob/main/benchmarks/README.md) and [`docs/src/performance-evidence.md`](./performance-evidence.md).
