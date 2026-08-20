"""Unit tests for `scripts/gates/regression_contracts.py`."""

import unittest
from scripts.gates import regression_contracts as rc


class RegressionContractsGateTests(unittest.TestCase):
    def test_self_test_passes(self) -> None:
        self.assertEqual(rc.self_test(), 0)

    def test_missing_why_detected(self) -> None:
        fixture = """
        #[test]
        fn test_something() {
            assert!(true);
        }
        """
        violations = rc.validate_regression_content(fixture, "sample.rs")
        self.assertTrue(any("missing `WHY:`" in v for v in violations))

    def test_missing_what_it_does_not_catch_detected(self) -> None:
        fixture = """
        //! WHY: Closes the bug where x was broken.
        #[test]
        fn test_something() {
            assert!(true);
        }
        """
        violations = rc.validate_regression_content(fixture, "sample.rs")
        self.assertTrue(any("what it does not catch" in v for v in violations))

    def test_literal_member_list_detected(self) -> None:
        fixture = """
        //! WHY: Closes the defect. What it does not catch: future plugins.
        #[test]
        fn test_something() {
            let expected_variants = ["CpuFallback", "SimdCpu", "GpuCuda"];
            assert_eq!(expected_variants.len(), 3);
        }
        """
        violations = rc.validate_regression_content(fixture, "sample.rs")
        self.assertTrue(any("literal member list" in v for v in violations))

    def test_valid_fixture_accepted(self) -> None:
        fixture = """
        //! WHY: Closes the defect class for boundary reassembly.
        //! What it does not catch: external dynamic plugin invocations.
        use keyhog_scanner::capability_ledger::HostClass;

        #[test]
        fn test_something() {
            for class in HostClass::ALL {
                assert_eq!(class.label().len(), 2);
            }
        }
        """
        violations = rc.validate_regression_content(fixture, "sample.rs")
        self.assertEqual(violations, [])

    def test_live_scan_passes(self) -> None:
        violations = rc.scan_all_regression_files()
        self.assertEqual(violations, [])


if __name__ == "__main__":
    unittest.main()
