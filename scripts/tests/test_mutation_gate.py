"""Unit tests for `scripts/gates/mutation_gate.py` (Row 9)."""

from __future__ import annotations

import unittest

from scripts.gates import mutation_gate as mg


class MutationGateTests(unittest.TestCase):
    def test_mutation_generation_inverts_comparisons(self) -> None:
        code = "fn check(x: i32) -> bool { x > 10 }\n"
        mutations = mg.generate_mutations(code)
        self.assertTrue(any(m[1].name == "invert_gt" for m in mutations))

    def test_mutation_generation_skips_comments(self) -> None:
        code = "// x > 10\nfn check(x: i32) -> bool { true }\n"
        mutations = mg.generate_mutations(code)
        for mut_code, mut, orig_line in mutations:
            self.assertNotIn("//", orig_line)

    def test_self_test(self) -> None:
        mg.self_test()


if __name__ == "__main__":
    unittest.main()
