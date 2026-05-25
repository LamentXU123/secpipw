import unittest

from secured_pip import Severity, parse_severity


class SeverityTests(unittest.TestCase):
    def test_has_four_levels_with_info(self) -> None:
        self.assertEqual(
            list(Severity),
            [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH],
        )

    def test_levels_are_ordered(self) -> None:
        self.assertLess(Severity.INFO, Severity.LOW)
        self.assertLess(Severity.LOW, Severity.MEDIUM)
        self.assertLess(Severity.MEDIUM, Severity.HIGH)

    def test_parse_severity(self) -> None:
        self.assertEqual(parse_severity("info"), Severity.INFO)
        self.assertEqual(parse_severity("low"), Severity.LOW)
        self.assertEqual(parse_severity("MEDIUM"), Severity.MEDIUM)
        self.assertEqual(parse_severity(" high "), Severity.HIGH)

    def test_parse_unknown_severity_raises(self) -> None:
        with self.assertRaises(ValueError):
            parse_severity("critical")


if __name__ == "__main__":
    unittest.main()
