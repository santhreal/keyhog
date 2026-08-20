# KeyHog accuracy matrix

KeyHog `KeyHog v0.5.70` evaluated on the **mirror** corpus on **AMD Ryzen 9 9950X 16-Core Processor** with the explicit Hyperscan/SIMD default route. The answer-key manifest was excluded from the scan tree.

| Corpus | Fixtures | Positives | Input size | Precision | Recall | F1 | True positives | False positives | False negatives |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **mirror** | 15,000 | 3,000 | 2.32 MB | 0.9651 | 0.9027 | 0.9328 | 2,708 | 98 | 292 |

The tracked source tree was clean.
