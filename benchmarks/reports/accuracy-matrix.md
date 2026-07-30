# KeyHog accuracy matrix

KeyHog `KeyHog v0.5.48` scanned the **mirror** corpus: 15,000 fixtures, 3,000 labeled positives, and 2,430,321 input bytes. The answer-key manifest was excluded from the scan tree. The row uses the default policy on the explicit Hyperscan/SIMD route on **AMD Ryzen 9 9950X 16-Core Processor**.

| Precision | Recall | F1 | True positives | False positives | False negatives |
|---:|---:|---:|---:|---:|---:|
| 0.9708 | 0.9200 | 0.9447 | 2,760 | 83 | 240 |

Documentation changes were uncommitted; the measured KeyHog v0.5.48 executable and detector digests were identical across every row. Treat these as development-host configuration comparisons, not release routing evidence.
