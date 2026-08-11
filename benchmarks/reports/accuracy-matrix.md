# KeyHog accuracy matrix

KeyHog `KeyHog v0.5.70` scanned the **mirror** corpus: 15,000 fixtures, 3,000 labeled positives, and 2,431,242 input bytes. The answer-key manifest was excluded from the scan tree. The row uses the default policy on the explicit Hyperscan/SIMD route on **AMD Ryzen 9 9950X 16-Core Processor**.

| Precision | Recall | F1 | True positives | False positives | False negatives |
|---:|---:|---:|---:|---:|---:|
| 0.9651 | 0.9027 | 0.9328 | 2,708 | 98 | 292 |

The tracked source tree was clean.
