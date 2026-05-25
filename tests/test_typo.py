import unittest
from dataclasses import dataclass

from secured_pip.severity import Severity
from secured_pip.typo import TypoDetector, detect_typos_in_resolved_packages


@dataclass(frozen=True)
class FakePackage:
    name: str


class FakePyPIClient:
    def __init__(self, project_names=None, fail=False):
        self.project_names = list(project_names or [])
        self.fail = fail
        self.load_cached_project_names_calls = 0

    def load_cached_project_names(self) -> list[str]:
        self.load_cached_project_names_calls += 1
        if self.fail:
            raise RuntimeError("boom")
        return self.project_names


class TypoDetectorTests(unittest.TestCase):
    def test_medium_severity_for_existing_single_edit_match(self) -> None:
        detector = TypoDetector(
            FakePyPIClient(project_names=["requests", "requsets", "numpy"])
        )

        alert = detector.detect("requsets")

        self.assertIsNotNone(alert)
        self.assertEqual(alert.matched_name, "requests")
        self.assertEqual(alert.severity, Severity.MEDIUM)

    def test_medium_severity_for_nonexistent_single_edit_match(self) -> None:
        detector = TypoDetector(FakePyPIClient(project_names=["pandas"]))

        alert = detector.detect("pandaz")

        self.assertIsNotNone(alert)
        self.assertEqual(alert.matched_name, "pandas")
        self.assertEqual(alert.severity, Severity.MEDIUM)

    def test_medium_severity_for_reqests_match(self) -> None:
        detector = TypoDetector(FakePyPIClient(project_names=["requests"]))

        alert = detector.detect("reqests")

        self.assertIsNotNone(alert)
        self.assertEqual(alert.matched_name, "requests")
        self.assertEqual(alert.severity, Severity.MEDIUM)

    def test_low_severity_for_weaker_nonexistent_similarity(self) -> None:
        detector = TypoDetector(FakePyPIClient(project_names=["six"]))

        alert = detector.detect("sixth")

        self.assertIsNotNone(alert)
        self.assertEqual(alert.matched_name, "six")
        self.assertEqual(alert.severity, Severity.LOW)

    def test_no_alert_for_exact_match_without_close_competitor(self) -> None:
        detector = TypoDetector(FakePyPIClient(project_names=["requests", "numpy"]))

        self.assertIsNone(detector.detect("requests"))

    def test_uses_local_project_names_once(self) -> None:
        client = FakePyPIClient(project_names=["requests", "numpy", "pandas"])
        detector = TypoDetector(client)

        first = detector.detect("requets")
        second = detector.detect("numppy")

        self.assertIsNotNone(first)
        self.assertIsNotNone(second)
        self.assertEqual(client.load_cached_project_names_calls, 1)

    def test_falls_back_to_bootstrap_names_when_local_cache_fails(self) -> None:
        detector = TypoDetector(FakePyPIClient(fail=True))

        alert = detector.detect("requets")

        self.assertIsNotNone(alert)
        self.assertEqual(alert.matched_name, "requests")
        self.assertEqual(alert.severity, Severity.MEDIUM)

    def test_exact_popular_package_does_not_alert(self) -> None:
        detector = TypoDetector(FakePyPIClient(project_names=["requests", "numpy"]))

        self.assertIsNone(detector.detect("requests"))

    def test_exact_popular_package_skips_close_competitor_alert(self) -> None:
        detector = TypoDetector(
            FakePyPIClient(project_names=["requests", "requestsh", "numpy"])
        )

        self.assertIsNone(detector.detect("requests"))

    def test_detect_typos_in_resolved_packages_deduplicates_names(self) -> None:
        alerts = detect_typos_in_resolved_packages(
            [FakePackage("requsets"), FakePackage("requsets")],
            detector=TypoDetector(
                FakePyPIClient(project_names=["requests", "requsets"])
            ),
        )

        self.assertEqual(len(alerts), 1)

    def test_uses_cached_names_outside_bootstrap_list(self) -> None:
        detector = TypoDetector(FakePyPIClient(project_names=["internal-toolkit"]))

        alert = detector.detect("internal-toollkit")

        self.assertIsNone(alert)


if __name__ == "__main__":
    unittest.main()
