# LR3 launch — engine correctness + contract surface

**After LR2 merge green.** 10 agents, ≥40 tests each (A1–A7).

| Agent | Mandate |
|-------|---------|
| A1 | SARIF/JSON contract snapshots; dedup edge adversarial |
| A2 | KH-GAP-001 megakernel parity fix or SPEC waiver |
| A3 | encoding_explosion strict green; decode splice regressions |
| A4 | PEM private-key recall; multiline regressions |
| A5 | git staged/diff/history integration; archive bombs |
| A6 | verify handler mock matrix per class |
| A7 | e2e every subcommand; daemon contract |
| A8 | contracts_runner strict; top 4 runners |
| A9 | README perf table criterion repro |
| A10 | release build evidence |

**Exit:** full tests/contract/ on 5 crates; parity fixed or waived.
